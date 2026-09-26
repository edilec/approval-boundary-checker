/**
 * Approval evidence.
 *
 * The distinction this file exists to defend: "no approval was supplied" and
 * "an approval was supplied and could not be read" are different facts, and
 * reporting the first when the second happened sends an operator to fetch
 * something they already have while the real defect stays in the document.
 *
 * The clock is injected everywhere here. `now` is a function passed in, never a
 * read inside the tool, so a test can step it across an expiry and watch a
 * cleared action become a stopped one.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { checkApprovalBoundary, validateApproval } from '../src/index.mjs'
import {
  FIXED_NOW, actionsDocument, externalWrite, prepare, runCli, validApproval, workspace,
} from './helpers.mjs'

async function verdict(t, approval, options = {}) {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(
    directory, actionsDocument([externalWrite(approval === undefined ? {} : { approval })]),
  )
  return checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW), ...options,
  })
}

test('a missing approval and an unreadable one are different findings with different messages', async (t) => {
  const missing = await verdict(t, undefined)
  const malformed = await verdict(t, { approvedBy: 'release-manager', approvedAt: 'yesterday' })

  assert.deepEqual(missing.findings.map((finding) => finding.ruleId), ['approval-missing'])
  assert.deepEqual(malformed.findings.map((finding) => finding.ruleId), ['approval-malformed'])
  assert.match(missing.findings[0].message, /none was supplied/)
  assert.doesNotMatch(
    malformed.findings[0].message,
    /none was supplied|no approval was supplied/,
    'an approval that exists must never be reported as an approval that does not',
  )
  assert.match(malformed.findings[0].message, /could not be read/)
  assert.equal(missing.decisions[0].approval, 'none')
  assert.equal(malformed.decisions[0].approval, 'malformed')
  for (const report of [missing, malformed]) assert.equal(report.decisions[0].outcome, 'stopped')
})

test('an approval is not accepted merely because a date string parses somewhere', async (t) => {
  for (const approvedAt of ['03/04/2026', '2026-09-14 08:30:00', '2026-09-14T08:30:00+05:30', 1757836800000]) {
    const report = await verdict(t, { approvedBy: 'release-manager', approvedAt })
    assert.deepEqual(
      report.findings.map((finding) => finding.ruleId), ['approval-malformed'],
      `"${approvedAt}" must be refused: a timestamp that decides a side effect may not be ambiguous`,
    )
  }
})

test('an approval record with an unknown key is unreadable rather than partly believed', async (t) => {
  const report = await verdict(t, { ...validApproval(), approvedFor: 'anything else too' })
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['approval-malformed'])
  assert.match(report.findings[0].message, /approvedFor/)
})

test('an approval naming a different action is a mismatch, not an approval', async (t) => {
  const report = await verdict(t, validApproval({ actionId: 'some-other-action' }))
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['approval-scope-mismatch'])
  assert.equal(report.decisions[0].approval, 'mismatched')
  assert.equal(report.decisions[0].outcome, 'stopped')
})

test('an approval that expires before it was granted is unreadable', async (t) => {
  const report = await verdict(t, validApproval({ expiresAt: '2026-09-14T08:00:00Z' }))
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['approval-malformed'])
})

test('stepping the injected clock past the expiry turns a cleared action into a stopped one', async (t) => {
  const approval = validApproval({ expiresAt: '2026-09-14T12:00:00Z' })
  const expiry = Date.parse('2026-09-14T12:00:00Z')

  const before = await verdict(t, approval, { now: () => expiry - 1 })
  assert.equal(before.status, 'pass')
  assert.equal(before.decisions[0].approval, 'valid')
  assert.equal(before.decisions[0].outcome, 'allowed')

  const atTheInstant = await verdict(t, approval, { now: () => expiry })
  assert.equal(atTheInstant.status, 'fail', 'expiry is inclusive: at the instant it expires it is expired')
  assert.equal(atTheInstant.decisions[0].approval, 'expired')

  const after = await verdict(t, approval, { now: () => expiry + 86400000 })
  assert.equal(after.status, 'fail')
  assert.deepEqual(after.findings.map((finding) => finding.ruleId), ['approval-expired'])
  assert.equal(after.decisions[0].outcome, 'stopped')
})

test('--now is wired through to the expiry check, not merely accepted', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(
    directory,
    actionsDocument([externalWrite({ approval: validApproval({ expiresAt: '2026-09-14T12:00:00Z' }) })]),
  )
  const base = ['--actions', actionsPath, '--policy', policyPath]

  const live = await runCli([...base, '--now', '2026-09-14T11:59:59Z'])
  const lapsed = await runCli([...base, '--now', '2026-09-15T00:00:00Z'])
  assert.equal(live.code, 0)
  assert.equal(lapsed.code, 1)
  assert.match(lapsed.stdout, /approval-expired/)
})

test('--now refuses anything that is not a strict ISO 8601 UTC instant', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([externalWrite()]))
  for (const value of ['tomorrow', '2026-09-14', '2026-09-14T09:00:00+02:00']) {
    const run = await runCli(['--actions', actionsPath, '--policy', policyPath, '--now', value])
    assert.equal(run.code, 2)
    assert.equal(run.stdout, '', 'a usage error carries no report on stdout')
    assert.match(run.stderr, /--now must be an ISO 8601 UTC instant/)
  }
})

test('validateApproval reports absence and malformation as distinct states', () => {
  assert.deepEqual(validateApproval({ id: 'a' }, '/actions/a'), { state: 'absent' })
  assert.equal(validateApproval({ id: 'a', approval: null }, '/actions/a').state, 'malformed')
  assert.equal(validateApproval({ id: 'a', approval: validApproval() }, '/actions/a').state, 'present')
  assert.equal(validateApproval({ id: 'a', approval: validApproval({ actionId: 'b' }) }, '/actions/a').state, 'mismatched')
})
