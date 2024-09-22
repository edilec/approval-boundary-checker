/**
 * Severity, pinned behaviourally.
 *
 * A severity table asserted against a hand-written expected-value map in a test
 * is three declarations agreeing with each other, and one coordinated edit
 * satisfies all three. So every row below drives a REAL input through the REAL
 * entry point and asserts the observable outcome -- the report status, written
 * as a literal at the assertion site. Status is computed from the severities
 * that were actually emitted; it is not a declaration anybody can edit to
 * agree.
 *
 * `error` therefore shows up as `fail` (or `incomplete`, when the error is
 * about evidence rather than about a verdict), and `warning` and `info` show up
 * as `pass`. Flipping any security-relevant rule down to `warning` changes a
 * status here and fails this file.
 *
 * The status-to-exit-code wiring is pinned separately and once, at the bottom,
 * rather than by spawning a process for each of the thirty rows.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { RULE_SEVERITY, checkApprovalBoundary } from '../src/index.mjs'
import {
  FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, runCli, validApproval,
  workspace, workspaceRead, writeFixture,
} from './helpers.mjs'

const NOT_UTF8 = Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x20, 0x22, 0xff, 0xfe, 0x22, 0x7d])

/**
 * One row per rule id. `status` is the whole point of the row: it is what the
 * tool observably concluded, with that rule's severity as the only input that
 * decided it.
 */
const ROWS = [
  {
    ruleId: 'action-denied',
    status: 'fail',
    actions: () => actionsDocument([externalWrite({ effect: 'send', dataClasses: ['secret'] })]),
  },
  {
    ruleId: 'action-duplicate-id',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead(), workspaceRead()]),
  },
  {
    ruleId: 'action-malformed',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead({ effect: 'wirte' })]),
  },
  {
    ruleId: 'action-unknown-key',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead({ urgent: true })]),
  },
  {
    ruleId: 'action-unmatched',
    status: 'pass',
    actions: () => actionsDocument([
      { id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local', dataClasses: ['internal'], approval: validApproval() },
    ]),
  },
  { ruleId: 'actions-malformed', status: 'incomplete', actions: () => [] },
  { ruleId: 'actions-not-json', status: 'incomplete', actions: () => '{"schemaVersion":' },
  { ruleId: 'actions-not-utf8', status: 'incomplete', actions: () => NOT_UTF8 },
  {
    ruleId: 'actions-schema-unsupported',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead()], { schemaVersion: '2' }),
  },
  {
    ruleId: 'actions-too-large',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead()]),
    limits: { maxActionsBytes: 16 },
  },
  { ruleId: 'actions-unreadable', status: 'incomplete', missingActions: true },
  {
    ruleId: 'approval-expired',
    status: 'fail',
    actions: () => actionsDocument([externalWrite({ approval: validApproval({ expiresAt: '2026-09-14T08:45:00Z' }) })]),
  },
  {
    ruleId: 'approval-malformed',
    status: 'fail',
    actions: () => actionsDocument([externalWrite({ approval: { approvedBy: 'someone' } })]),
  },
  { ruleId: 'approval-missing', status: 'fail', actions: () => actionsDocument([externalWrite()]) },
  {
    ruleId: 'approval-scope-mismatch',
    status: 'fail',
    actions: () => actionsDocument([externalWrite({ approval: validApproval({ actionId: 'another' }) })]),
  },
  {
    ruleId: 'approval-superfluous',
    status: 'pass',
    actions: () => actionsDocument([workspaceRead({ approval: validApproval() })]),
  },
  { ruleId: 'no-actions', status: 'incomplete', actions: () => actionsDocument([]) },
  {
    ruleId: 'policy-malformed',
    status: 'incomplete',
    policy: () => policyDocument({ defaultDecision: 'allowed' }),
  },
  { ruleId: 'policy-not-json', status: 'incomplete', policy: () => 'rules: []' },
  { ruleId: 'policy-not-utf8', status: 'incomplete', policy: () => NOT_UTF8 },
  {
    ruleId: 'policy-rule-duplicate-id',
    status: 'incomplete',
    policy: () => policyDocument({
      rules: [
        { id: 'same', effects: ['read'], decision: 'allowed' },
        { id: 'same', effects: ['write'], decision: 'denied' },
      ],
    }),
  },
  {
    ruleId: 'policy-rule-malformed',
    status: 'incomplete',
    policy: () => policyDocument({ rules: [{ id: 'odd', effects: ['read'], decision: 'maybe' }] }),
  },
  {
    ruleId: 'policy-rule-unselective',
    status: 'incomplete',
    policy: () => policyDocument({ rules: [{ id: 'everything', decision: 'allowed' }] }),
  },
  { ruleId: 'policy-schema-unsupported', status: 'incomplete', policy: () => policyDocument({ schemaVersion: '9' }) },
  { ruleId: 'policy-too-large', status: 'incomplete', limits: { maxPolicyBytes: 16 } },
  { ruleId: 'policy-unreadable', status: 'incomplete', missingPolicy: true },
  { ruleId: 'time-budget-exceeded', status: 'incomplete', limits: { timeoutMs: 0 } },
  {
    ruleId: 'too-many-actions',
    status: 'incomplete',
    actions: () => actionsDocument([workspaceRead(), workspaceRead({ id: 'read-two' })]),
    limits: { maxActions: 1 },
  },
  { ruleId: 'too-many-rules', status: 'incomplete', limits: { maxRules: 1 } },
]

async function runRow(t, row) {
  const directory = await workspace(t)
  const actions = row.actions === undefined ? actionsDocument([workspaceRead()]) : row.actions()
  const policy = row.policy === undefined ? policyDocument() : row.policy()
  const actionsPath = row.missingActions === true
    ? `${directory}/absent-actions.json`
    : await writeFixture(directory, 'actions.json', actions)
  const policyPath = row.missingPolicy === true
    ? `${directory}/absent-policy.json`
    : await writeFixture(directory, 'policy.json', policy)
  return checkApprovalBoundary({
    actions: actionsPath,
    policy: policyPath,
    limits: row.limits ?? {},
    now: () => Date.parse(FIXED_NOW),
  })
}

test('every rule id in the severity table has a row here', () => {
  const covered = new Set(ROWS.map((row) => row.ruleId))
  const declared = Object.keys(RULE_SEVERITY)
  assert.deepEqual(
    declared.filter((ruleId) => !covered.has(ruleId)), [],
    'a rule with no row is a severity nothing observes',
  )
  assert.deepEqual([...covered].filter((ruleId) => !declared.includes(ruleId)), [])
  assert.equal(ROWS.length, declared.length)
})

for (const row of ROWS) {
  test(`${row.ruleId} produces status ${row.status}`, async (t) => {
    const report = await runRow(t, row)
    assert.ok(
      report.findings.some((finding) => finding.ruleId === row.ruleId),
      `the fixture for ${row.ruleId} did not actually produce it: ${report.findings.map((f) => f.ruleId).join(', ') || 'no findings'}`,
    )
    assert.equal(report.status, row.status)
    if (row.status === 'incomplete') {
      assert.equal(report.decisions.length, 0, 'an incomplete run produces no per-action verdicts')
      assert.equal(report.summary.checked, 0)
    }
  })
}

/**
 * The status-to-exit-code wiring, pinned once through real processes.
 *
 * A report that says `fail` while the CLI exits 0 is the failure mode this
 * catalog has shipped. Each literal below is the number a build gate reads.
 */
test('status reaches the shell as the documented exit code', async (t) => {
  const directory = await workspace(t)
  const cases = [
    { status: 'pass', exit: 0, actions: actionsDocument([workspaceRead()]) },
    { status: 'fail', exit: 1, actions: actionsDocument([externalWrite()]) },
    { status: 'incomplete', exit: 2, actions: actionsDocument([]) },
  ]
  for (const item of cases) {
    const { args } = await prepare(directory, item.actions)
    const run = await runCli([...args, '--json'])
    assert.equal(JSON.parse(run.stdout).status, item.status)
    assert.equal(run.code, item.exit, `status ${item.status} must exit ${item.exit}`)
  }
})

test('a warning alone never fails a run, and an error always does', async (t) => {
  const directory = await workspace(t)

  const warningOnly = await prepare(directory, actionsDocument([
    { id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local', dataClasses: ['internal'], approval: validApproval() },
  ]))
  const warned = await runCli([...warningOnly.args, '--json'])
  const warnedReport = JSON.parse(warned.stdout)
  assert.equal(warnedReport.summary.warnings, 1)
  assert.equal(warnedReport.summary.errors, 0)
  assert.equal(warned.code, 0)

  const errorCase = await prepare(directory, actionsDocument([externalWrite()]))
  const errored = await runCli([...errorCase.args, '--json'])
  assert.equal(JSON.parse(errored.stdout).summary.errors, 1)
  assert.equal(errored.code, 1)
})
