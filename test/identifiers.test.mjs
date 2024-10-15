/**
 * What an `id` is allowed to be, and what happens to a document that ignores it.
 *
 * The README states the contract in one line -- `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
 * for an action id and for a policy rule id -- and nothing held the code to it.
 * Replacing `ID_PATTERN` with `/^[\s\S]*$/` left the whole suite green on the
 * 160-test tree while a plan whose only action was named
 * `ok/id~with<newline> and 300 more characters` came back `pass` at exit 0, with
 * that id carried into the verdict rows. The vocabularies around it -- effects,
 * scopes, data classes, decisions -- are each closed lists whose mistakes their
 * own tests catch; the id pattern is the one input contract in this tool that a
 * mistake lets THROUGH rather than refuses.
 *
 * Two further guarantees rest on this one, which is why it is pinned rather than
 * left to the reader:
 *
 * - a pointer is built as `/actions/<id>`, and `sanitisation.test.mjs` records
 *   that the RFC 6901 escaping of `~` and `/` is unreachable from a document
 *   "because ID_PATTERN admits neither character". That sentence is only true
 *   while this test passes.
 * - an id is bounded at 64 characters before it ever reaches a report, so the
 *   excerpt limit is a second line of defence rather than the only one.
 *
 * Both halves are asserted: the refusals, and the ordinary ids that must still
 * be accepted -- a pattern that refused everything would pass every refusal here
 * while making the tool useless.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { ID_PATTERN, checkApprovalBoundary } from '../src/index.mjs'
import {
  FIXED_NOW_MS, actionsDocument, policyDocument, prepare, runCli, workspaceRead, workspace,
} from './helpers.mjs'

/** 64 characters: the longest id the documented pattern admits. */
const LONGEST_ACCEPTED = `a${'b'.repeat(63)}`

async function reportFor(t, actions, policy = policyDocument()) {
  const directory = await workspace(t)
  const { actionsPath, policyPath, args } = await prepare(directory, actions, policy)
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => FIXED_NOW_MS,
  })
  return { report, args }
}

test('the pattern the README documents is the pattern the code holds', () => {
  assert.equal(ID_PATTERN.source, '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
  assert.equal(LONGEST_ACCEPTED.length, 64)
})

for (const [shape, id] of [
  ['a slash, which would break the JSON Pointer built from it', 'read/brief'],
  ['a tilde, which RFC 6901 escapes', 'read~brief'],
  ['a space', 'read brief'],
  ['a newline, which would forge a line in the human report', 'read\nbrief'],
  ['a leading dot', '.hidden'],
  ['a leading hyphen', '-brief'],
  ['a leading underscore', '_brief'],
  ['a colon', 'read:brief'],
  ['a character above the ASCII range', 'readébrief'],
  ['nothing at all', ''],
  ['one character more than the documented bound', `a${'b'.repeat(64)}`],
]) {
  test(`an action id carrying ${shape} is refused, not classified`, async (t) => {
    const { report, args } = await reportFor(t, actionsDocument([workspaceRead({ id })]))

    assert.equal(report.status, 'incomplete', `"${id}" is outside the documented pattern`)
    assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['action-malformed'])
    assert.match(report.findings[0].message, /"id" must match \^\[A-Za-z0-9\]\[A-Za-z0-9\._-\]\{0,63\}\$/)
    assert.deepEqual(report.decisions, [], 'a malformed plan produces no verdicts at all')
    assert.equal(report.summary.checked, 0)
    assert.equal(report.summary.unexamined, 1)

    const run = await runCli([...args, '--json'])
    assert.equal(run.code, 2, 'and the refusal reaches the shell rather than exiting 0')
  })

  test(`a policy rule id carrying ${shape} is refused, not applied`, async (t) => {
    const { report, args } = await reportFor(
      t,
      actionsDocument([workspaceRead()]),
      policyDocument({ rules: [{ id, effects: ['read'], scopes: ['workspace'], decision: 'allowed' }] }),
    )

    assert.equal(report.status, 'incomplete', `"${id}" is outside the documented pattern`)
    assert.ok(report.findings.some((finding) => finding.ruleId === 'policy-rule-malformed'))
    assert.deepEqual(report.decisions, [])

    const run = await runCli([...args, '--json'])
    assert.equal(run.code, 2)
  })
}

test('an id that is not a string at all is refused rather than coerced into one', async (t) => {
  for (const id of [42, null, true, ['read-brief'], { toString: () => 'read-brief' }]) {
    const { report } = await reportFor(t, actionsDocument([workspaceRead({ id })]))
    assert.equal(report.status, 'incomplete', `${JSON.stringify(id)} is not an id`)
    assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['action-malformed'])
    assert.deepEqual(report.decisions, [])
  }
})

test('the ids the pattern documents are accepted, and reach the verdict and the pointer unchanged', async (t) => {
  // The other half of the pin. Every character class the pattern names is
  // exercised, at both ends of the length bound.
  for (const id of ['a', 'Z', '9', 'read-release-brief', 'fs.readFile_v2', 'a.b-c_d.9', LONGEST_ACCEPTED]) {
    const { report, args } = await reportFor(t, actionsDocument([workspaceRead({ id })]))

    assert.equal(report.status, 'pass', `"${id}" matches the documented pattern and must be accepted`)
    assert.deepEqual(report.findings, [])
    assert.deepEqual(report.decisions.map((entry) => entry.id), [id])
    assert.equal(report.decisions[0].outcome, 'allowed')
    assert.equal((await runCli(args)).code, 0)
  }
})

test('an accepted id needs no RFC 6901 escaping, which is what makes that escaper unreachable', async (t) => {
  // Every character the pattern admits is a character a JSON Pointer segment
  // carries literally. If that ever stops being true, the pointers below change
  // shape and this fails before the claim in sanitisation.test.mjs goes stale.
  const { report } = await reportFor(
    t,
    actionsDocument([workspaceRead({ id: 'a.b-c_d.9', effect: 'sideways' })]),
  )
  assert.equal(report.status, 'incomplete')
  assert.deepEqual(
    report.findings.map((finding) => finding.location.pointer),
    ['/actions/a.b-c_d.9/effect'],
    'no ~0 or ~1 appears, because no admitted character needs one',
  )
})

test('two actions the pattern accepts may not share an id', async (t) => {
  const { report } = await reportFor(t, actionsDocument([workspaceRead(), workspaceRead()]))
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.some((finding) => finding.ruleId === 'action-duplicate-id'))
  assert.deepEqual(report.decisions, [])
})
