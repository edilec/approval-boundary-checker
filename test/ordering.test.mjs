/**
 * Ordering, pinned behaviourally.
 *
 * Scanning this tool's own source for `.localeCompare(` is not a determinism
 * test: substituting `Intl.Collator` produces identical collation drift with
 * different source text, so the scan passes while the output silently becomes
 * machine-dependent.
 *
 * So the inputs below are chosen because code-unit order and collation order
 * genuinely DISAGREE about them, and the assertions are the exact emitted
 * sequence. Measured on this machine's ICU data:
 *
 *   "Z-audit" < "a-audit"  by code unit;  collation puts "a-audit" first
 *   "aXb"     < "a_b"      by code unit;  collation ignores the underscore and
 *                                         puts "a_b" first
 *
 * Substituting a collator anywhere on the report path flips both and fails this
 * file.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { byCodeUnit, checkApprovalBoundary } from '../src/index.mjs'
import { FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, workspace } from './helpers.mjs'

const CASE_AND_PUNCTUATION = ['Z-audit', 'a-audit', 'aXb', 'a_b']

test('the comparator itself orders by code unit', () => {
  assert.equal(byCodeUnit('Z-audit', 'a-audit'), -1)
  assert.equal(byCodeUnit('aXb', 'a_b'), -1)
  assert.equal(byCodeUnit('README', 'assets'), -1)
  assert.equal(byCodeUnit('same', 'same'), 0)
  for (const [left, right] of [['Z-audit', 'a-audit'], ['aXb', 'a_b'], ['README', 'assets']]) {
    assert.notEqual(
      Math.sign(left.localeCompare(right)), byCodeUnit(left, right),
      `${left} vs ${right} must be a pair the two orderings disagree about, or this file proves nothing`,
    )
  }
})

test('findings come back in code-unit order of their pointers, not collation order', async (t) => {
  const directory = await workspace(t)
  // Declared deliberately out of order, so emission order cannot be what is
  // being observed.
  const plan = actionsDocument([...CASE_AND_PUNCTUATION].reverse().map((id) => externalWrite({ id })))
  const { actionsPath, policyPath } = await prepare(directory, plan)
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })

  assert.deepEqual(
    report.findings.map((finding) => finding.location.pointer),
    ['/actions/Z-audit', '/actions/a-audit', '/actions/aXb', '/actions/a_b'],
  )
  assert.deepEqual(report.decisions.map((entry) => entry.id), ['Z-audit', 'a-audit', 'aXb', 'a_b'])
  assert.notDeepEqual(
    report.decisions.map((entry) => entry.id),
    [...CASE_AND_PUNCTUATION].sort((left, right) => left.localeCompare(right)),
    'collation would emit a_b, a-audit, aXb, Z-audit; this report must not',
  )
})

test('location.file is the primary sort key, ahead of the pointer', async (t) => {
  const directory = await workspace(t)
  /**
   * The pointers have to DISAGREE with the file names, or this proves nothing.
   *
   * The fixture here before used `/actions/aaa/effect` and `/rules/zzz/decision`
   * and claimed that comparing the pointer first would reverse them. It would
   * not: `a` precedes `r` by code unit, so both orderings agree and deleting the
   * primary key left the suite green while a real report came out reversed.
   *
   * So: the actions finding takes the LATE pointer and the policy finding the
   * early one. By file, actions precedes policy. By pointer alone,
   * `/defaultDecision` precedes `/schemaVersion` and the pair swaps.
   */
  const { actionsPath, policyPath } = await prepare(
    directory,
    actionsDocument([], { schemaVersion: '2' }),
    policyDocument({ defaultDecision: 'allowed' }),
  )
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  const emitted = report.findings.map((finding) => [finding.location.file, finding.location.pointer])
  assert.deepEqual(emitted, [['actions', '/schemaVersion'], ['policy', '/defaultDecision']])

  const byPointerAlone = [...emitted].sort((left, right) => byCodeUnit(left[1], right[1]))
  assert.notDeepEqual(
    byPointerAlone, emitted,
    'the fixture must be one the two orderings disagree about, or dropping the file key would pass',
  )
})

test('the rule id breaks a tie between two findings on the same action', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([
    {
      id: 'unmatched-and-unapproved', tool: 'shell.exec', effect: 'execute',
      scope: 'local', dataClasses: ['internal'],
    },
  ]))
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['action-unmatched', 'approval-missing'],
    'both sit on the same pointer, so the rule id decides and "action-" precedes "approval-" by code unit',
  )
})

test('matched rule ids inside one verdict are ordered by code unit too', async (t) => {
  const directory = await workspace(t)
  const policy = policyDocument({
    rules: [
      { id: 'a_b', effects: ['send'], scopes: ['external'], decision: 'allowed' },
      { id: 'aXb', effects: ['send'], scopes: ['external'], decision: 'allowed' },
      { id: 'Z-audit', effects: ['send'], scopes: ['external'], decision: 'allowed' },
    ],
  })
  const { actionsPath, policyPath } = await prepare(
    directory, actionsDocument([externalWrite({ effect: 'send' })]), policy,
  )
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(report.decisions[0].matchedRules, ['Z-audit', 'aXb', 'a_b'])
  assert.notDeepEqual(
    report.decisions[0].matchedRules,
    ['a_b', 'aXb', 'Z-audit'],
    'that is the order a collator would produce',
  )
})
