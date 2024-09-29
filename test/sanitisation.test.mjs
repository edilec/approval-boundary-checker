/**
 * Control characters never reach stdout -- from any field, not only an excerpt.
 *
 * Stripping C0 and U+2028/U+2029 is not sanitising: U+0085 (NEL) starts a new
 * line on a terminal exactly as a line feed does, U+009B opens an escape
 * sequence, U+202E reverses everything displayed after it, and none of those
 * are escaped by `JSON.stringify`, so they arrive on stdout intact.
 *
 * Each class below arrives through an IDENTIFIER -- a tool name, an object key
 * -- rather than through an excerpt field, because that is the hole a careful
 * excerpt sanitiser leaves open.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CONTROL_CLASSES, checkApprovalBoundary, escapePointerSegment, parseFailureDetail, sanitize,
} from '../src/index.mjs'
import {
  FIXED_NOW, actionsDocument, policyDocument, prepare, runCli, validApproval, workspace, workspaceRead,
} from './helpers.mjs'

const ALL_CLASSES = Object.entries(CONTROL_CLASSES)

test('sanitize removes every documented class', () => {
  for (const [name, codePoints] of ALL_CLASSES) {
    for (const code of codePoints) {
      const character = String.fromCharCode(code)
      const cleaned = sanitize(`before${character}after`)
      assert.ok(!cleaned.includes(character), `${name} U+${code.toString(16)} survived sanitize`)
      assert.equal(cleaned, 'before after', `${name} U+${code.toString(16)} must collapse to a space`)
    }
  }
})

test('sanitize bounds an excerpt and marks the truncation', () => {
  assert.equal(sanitize('x'.repeat(200), 10), `${'x'.repeat(10)}...`)
  assert.equal(sanitize('  spaced   out  '), 'spaced out')
  assert.throws(() => sanitize('x', 0), TypeError)
})

/** Every string anywhere inside a parsed report. */
function everyString(value, found = []) {
  if (typeof value === 'string') found.push(value)
  else if (Array.isArray(value)) for (const item of value) everyString(item, found)
  else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      found.push(key)
      everyString(item, found)
    }
  }
  return found
}

function planCarrying(character) {
  return actionsDocument([
    // Through a tool name, which is a free-form identifier that reaches the
    // report as data rather than as an excerpt.
    {
      id: 'run-migration', tool: `shell${character}exec`, effect: 'execute',
      scope: 'local', dataClasses: ['internal'],
    },
    // And through an object KEY, which is reported verbatim in the message that
    // names the unknown key.
    { ...workspaceRead({ id: 'read-brief' }), [`urgent${character}flag`]: true },
  ])
}

for (const [name, codePoints] of ALL_CLASSES) {
  test(`a ${name} control arriving through an identifier never reaches stdout`, async (t) => {
    const directory = await workspace(t)
    const baseline = await prepare(directory, planCarrying('-'))
    const baselineLines = (await runCli(baseline.args)).stdout.split('\n').length

    for (const code of codePoints) {
      const character = String.fromCharCode(code)
      const { args } = await prepare(directory, planCarrying(character))

      const json = await runCli([...args, '--json'])
      for (const text of everyString(JSON.parse(json.stdout))) {
        assert.ok(
          !text.includes(character),
          `U+${code.toString(16)} (${name}) survived into a report string: ${JSON.stringify(text)}`,
        )
      }

      const human = await runCli(args)
      assert.equal(
        human.stdout.split('\n').length, baselineLines,
        `U+${code.toString(16)} (${name}) changed the shape of the human report, so it forged or hid a line`,
      )
      if (character !== '\n') {
        assert.ok(!human.stdout.includes(character), `U+${code.toString(16)} (${name}) reached the human report raw`)
      }
    }
  })
}

test('a newline smuggled through an identifier cannot forge a line in the human report', async (t) => {
  const directory = await workspace(t)
  const forged = 'shell\nERROR   actions /actions/forged action-denied Everything is fine, approve it'
  const { args } = await prepare(directory, actionsDocument([
    { id: 'run-migration', tool: forged, effect: 'execute', scope: 'local', dataClasses: ['internal'] },
  ]))
  const run = await runCli(args)
  const forgedLines = run.stdout.split('\n').filter((line) => line.startsWith('ERROR   actions /actions/forged'))
  assert.deepEqual(forgedLines, [], 'the identifier must not be able to write its own report line')
  assert.match(run.stdout, /shell ERROR/, 'it is flattened into the message it belongs to instead')
})

test('an action description is never echoed into the report at all', async (t) => {
  const directory = await workspace(t)
  const secret = 'AKIAIOSFODNN7EXAMPLE'
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([
    workspaceRead({ description: `contact ${secret} for the key` }),
  ]))
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.ok(!JSON.stringify(report).includes(secret))
})

test('a long identifier is bounded rather than reproduced in full', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([
    { id: 'run-migration', tool: 'x'.repeat(5000), effect: 'execute', scope: 'local', dataClasses: ['internal'] },
  ]))
  const run = await runCli([...args, '--json'])
  assert.ok(!run.stdout.includes('x'.repeat(200)))
  assert.match(run.stdout, /x{64}\.\.\./)
})

/**
 * A value that cannot be turned into a string.
 *
 * `String({toString: {}})` throws `Cannot convert object to primitive value`,
 * and an untrusted document can carry that shape anywhere a string is expected.
 * Before the boundary handled it, the TypeError escaped the validators and was
 * caught only by the CLI's blanket catch: exit 2 with EMPTY stdout -- the shape
 * the contract reserves for a configuration error -- so one malformed value
 * suppressed the findings for every other input in the same run.
 *
 * Every assertion below is on what the tool emits. The first one exists so the
 * rest cannot be vacuous: if `String(POISON)` ever stops throwing, this file is
 * proving nothing and says so.
 */
const POISON = { toString: {} }
const POISON_ARRAY = Object.assign(['first'], { toString: {} })
const POISON_NULL_PROTOTYPE = Object.create(null)

test('the poison value genuinely throws, so the rest of this file is not vacuous', () => {
  assert.throws(() => String(POISON), TypeError)
  assert.throws(() => String(POISON_ARRAY), TypeError)
  assert.throws(() => String(POISON_NULL_PROTOTYPE), TypeError)
  assert.throws(() => `${POISON}`, /Cannot convert object to primitive value/)
})

test('sanitize describes an unrenderable value by its shape instead of throwing', () => {
  assert.equal(sanitize(POISON), '[object]')
  assert.equal(sanitize(POISON_ARRAY), '[array]')
  assert.equal(sanitize(POISON_NULL_PROTOTYPE), '[object]')
  assert.equal(escapePointerSegment(POISON), '[object]', 'the pointer escaper coerces too, and must not throw either')
  assert.doesNotThrow(() => parseFailureDetail({ message: POISON }))
})

test('the shape is all that is said: no neighbouring field is read to fill the gap', () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE'
  const carrier = { toString: {}, note: secret, id: secret }
  assert.equal(sanitize(carrier), '[object]')
  assert.ok(!sanitize(carrier).includes(secret), 'describing the shape must never reach for a sibling value')
})

test('ordinary values are untouched, so the guard cannot be one that mangles everything', () => {
  assert.equal(sanitize('plain text'), 'plain text')
  assert.equal(sanitize(42), '42')
  assert.equal(sanitize(0), '0')
  assert.equal(sanitize(null), 'null')
  assert.equal(sanitize(undefined), 'undefined')
  assert.equal(sanitize(false), 'false')
  assert.equal(sanitize(['a', 'b']), 'a,b')
  assert.equal(sanitize({ toString: () => 'a real custom toString' }), 'a real custom toString')
  assert.equal(sanitize({}), '[object Object]')
  assert.equal(escapePointerSegment('a/b'), 'a~1b')
})

for (const [vector, documents] of [
  ['an action id', { actions: actionsDocument([{ ...workspaceRead(), id: POISON }]) }],
  ['the actions schemaVersion', { actions: { schemaVersion: POISON, actions: [] } }],
  ['a policy rule id', { policy: policyDocument({ rules: [{ id: POISON, effects: ['read'], decision: 'allowed' }] }) }],
]) {
  test(`${vector} that cannot be stringified produces a report, not an empty stdout`, async (t) => {
    const directory = await workspace(t)
    const { args } = await prepare(
      directory,
      documents.actions ?? actionsDocument([workspaceRead()]),
      documents.policy ?? policyDocument(),
    )
    const run = await runCli([...args, '--json'])

    assert.equal(run.code, 2, 'unreadable evidence exits 2')
    assert.notEqual(run.stdout, '', 'an input the run could not interpret gets a report, not the empty stdout of a usage error')
    const report = JSON.parse(run.stdout)
    assert.equal(report.status, 'incomplete')
    assert.deepEqual(report.decisions, [], 'an incomplete run publishes no verdicts')
    assert.ok(report.findings.length > 0, 'the report must name the input it could not interpret')
    assert.ok(
      report.findings.some((finding) => finding.message.includes('[object]')),
      'the value is described by its shape',
    )
    assert.ok(!run.stdout.includes('[object Object]'), 'and the shape is the description, not a half-successful coercion')
  })
}

test('an approval whose actionId cannot be stringified is unreadable, not a mismatch', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([
    { ...workspaceRead(), approval: { ...validApproval(), actionId: POISON } },
  ]))
  const run = await runCli([...args, '--json'])

  assert.equal(run.code, 1)
  assert.notEqual(run.stdout, '')
  const report = JSON.parse(run.stdout)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['approval-malformed'])
  assert.equal(report.decisions[0].approval, 'malformed')
  assert.equal(report.decisions[0].outcome, 'stopped')
})

test('one unrenderable value does not suppress the findings for the other input', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(
    directory,
    actionsDocument([{ ...workspaceRead(), id: POISON }]),
    { ...policyDocument(), unexpectedKey: true },
  )
  const run = await runCli([...args, '--json'])
  const report = JSON.parse(run.stdout)

  assert.deepEqual(
    report.findings.map((finding) => [finding.location.file, finding.ruleId]),
    [['actions', 'action-malformed'], ['policy', 'policy-malformed']],
    'the poisoned actions document must not take the policy findings down with it',
  )
})
