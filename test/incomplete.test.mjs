/**
 * Unknown evidence is never a pass, and never half a verdict.
 *
 * The rule this file defends: when the run could not obtain the evidence it
 * needed, it says so and produces NO per-action verdicts at all. A plan checked
 * halfway is not a smaller answer -- the actions that happened to be classified
 * before the budget ran out would sit in an approval queue looking cleared.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { assertReportInvariants, checkApprovalBoundary } from '../src/index.mjs'
import {
  FIXED_NOW, FIXED_NOW_MS, actionsDocument, externalWrite, importSourceWithSubstitution, policyDocument,
  prepare, runCli, validApproval, workspace, workspaceRead, writeFixture,
} from './helpers.mjs'

/** A monotonic clock that reads `0` for a while and then jumps past any budget. */
function clockThatJumpsAfter(readings) {
  const queue = [...readings]
  return () => (queue.length > 1 ? queue.shift() : queue[0])
}

test('a time budget expiring mid-loop discards the verdicts already reached', async (t) => {
  const directory = await workspace(t)
  const plan = actionsDocument([
    workspaceRead({ id: 'a-read', approval: undefined }),
    workspaceRead({ id: 'b-read' }),
    workspaceRead({ id: 'c-read' }),
  ])
  const { actionsPath, policyPath } = await prepare(directory, plan)

  // Every one of these three would be cleared outright with time to spare.
  const unhurried = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(unhurried.status, 'pass')
  assert.equal(unhurried.summary.allowed, 3)

  // started = 0, first action = 0, second action = 9000: the budget expires
  // after one action has already been classified as allowed.
  const hurried = await checkApprovalBoundary({
    actions: actionsPath,
    policy: policyPath,
    now: () => Date.parse(FIXED_NOW),
    monotonic: clockThatJumpsAfter([0, 0, 9000]),
    limits: { timeoutMs: 1000 },
  })
  assert.equal(hurried.status, 'incomplete')
  assert.deepEqual(hurried.decisions, [], 'no verdict survives a run that ran out of time')
  assert.equal(hurried.summary.checked, 0)
  assert.equal(hurried.summary.allowed, 0)
  assert.equal(hurried.summary.unexamined, 3)
  assert.ok(!JSON.stringify(hurried).includes('"outcome"'), 'not one cleared row may leak into the report')
  const budget = hurried.findings.find((finding) => finding.ruleId === 'time-budget-exceeded')
  assert.match(budget.message, /1 of 3 actions/)
})

test('the documented timeout is wired through the CLI, and zero means zero', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([workspaceRead()]))
  const generous = await runCli([...args, '--timeout-ms', '10000'])
  assert.equal(generous.code, 0)
  const none = await runCli([...args, '--timeout-ms', '0', '--json'])
  assert.equal(none.code, 2)
  const report = JSON.parse(none.stdout)
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.some((finding) => finding.ruleId === 'time-budget-exceeded'))
})

test('one uninterpretable action withdraws the verdict on the whole plan', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([
    workspaceRead({ id: 'fine-one' }),
    workspaceRead({ id: 'fine-two' }),
    { id: 'broken', tool: 'fs.rm', effect: 'obliterate', scope: 'workspace', dataClasses: ['internal'] },
  ]))
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(report.status, 'incomplete')
  assert.deepEqual(report.decisions, [])
  assert.equal(report.summary.unexamined, 3)
  assert.ok(!report.findings.some((finding) => finding.ruleId === 'approval-missing'))
})

test('both unreadable inputs are named, so a consumer knows which one to fix', async (t) => {
  const directory = await workspace(t)
  const report = await checkApprovalBoundary({
    actions: `${directory}/absent-actions.json`,
    policy: `${directory}/absent-policy.json`,
    now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(
    report.findings.map((finding) => [finding.location.file, finding.ruleId]),
    [['actions', 'actions-unreadable'], ['policy', 'policy-unreadable']],
  )
  assert.equal(report.status, 'incomplete')
})

/**
 * The guard on the vacuous pass.
 *
 * `no-actions` is a WARNING, so the `incomplete: true` beside it is the only
 * thing between an empty plan and a green exit 0. That makes it exactly the
 * kind of invariant that is true by accident until somebody deletes one line.
 * This test asserts the exit code, and `assertReportInvariants` -- which runs
 * in production, not only here -- refuses to build such a report at all.
 */
test('an empty plan cannot exit 0, and a pass with nothing checked cannot be built', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath, args } = await prepare(directory, actionsDocument([]))
  const run = await runCli([...args, '--json'])
  assert.equal(run.code, 2)
  const report = JSON.parse(run.stdout)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)

  const forged = { ...report, status: 'pass' }
  assert.deepEqual(
    assertReportInvariants(forged),
    ['a pass was produced with nothing checked'],
    'the production invariant, not just this test, refuses a pass over no evidence',
  )

  /**
   * The second half of the name, asserted rather than asserted ABOUT.
   *
   * Everything above shows that `assertReportInvariants` can name the violation
   * when it is handed one. It does not show that `finish` refuses to RETURN
   * such a report, because no input reaches that state while the guard above is
   * in place -- so the enforcement line survived being replaced by
   * `void violations` with all of this green. Removing the guard from a copy of
   * the source makes the violating report reachable, and the copy must refuse
   * to build it.
   */
  const withoutTheEmptyPlanGuard = await importSourceWithSubstitution(t, {
    file: 'index.mjs',
    find: '  if (declared === 0) {',
    replace: '  if (false) {',
  })
  const options = { actions: actionsPath, policy: policyPath, now: () => FIXED_NOW_MS }
  assert.equal((await checkApprovalBoundary(options)).status, 'incomplete', 'the shipped guard still holds')
  await assert.rejects(
    () => withoutTheEmptyPlanGuard.checkApprovalBoundary(options),
    /Report invariant violated: a pass was produced with nothing checked/,
    'with that guard gone the builder would have returned status pass over checked 0; it has to throw instead',
  )
})

test('the production invariants refuse every shape of a dishonest report', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([externalWrite()]))
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(assertReportInvariants(report), [], 'the real report is honest')

  assert.deepEqual(
    assertReportInvariants({ ...report, status: 'pass' }),
    ['a pass was produced with error findings'],
  )
  assert.deepEqual(
    assertReportInvariants({
      ...report,
      decisions: report.decisions.map((entry) => ({ ...entry, outcome: 'allowed' })),
    }),
    ['action "publish-notes" was cleared while carrying an error finding'],
  )
  assert.deepEqual(
    assertReportInvariants({ ...report, status: 'incomplete' }),
    ['an incomplete run produced per-action verdicts'],
  )
  assert.deepEqual(
    assertReportInvariants({
      ...report,
      findings: report.findings.map((finding) => ({ ...finding, severity: 'info' })),
    }),
    ['finding "approval-missing" carries a severity the table does not declare'],
  )
  assert.deepEqual(
    assertReportInvariants({
      ...report,
      decisions: report.decisions.map((entry) => ({ ...entry, decision: 'denied', outcome: 'allowed' })),
    }),
    [
      'action "publish-notes" was cleared while carrying an error finding',
      'denied action "publish-notes" was not stopped',
    ],
  )
})

test('a document that could not be parsed still produces a report on stdout, per the contract', async (t) => {
  const directory = await workspace(t)
  const actionsPath = await writeFixture(directory, 'actions.json', '{"schemaVersion": "1", "actions": [')
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())
  const run = await runCli(['--actions', actionsPath, '--policy', policyPath, '--json'])
  assert.equal(run.code, 2)
  assert.notEqual(run.stdout, '', 'an unreadable INPUT exits 2 with a report; only a usage error exits 2 silent')
  assert.equal(JSON.parse(run.stdout).status, 'incomplete')
})

test('limits are enforced, not merely accepted', async (t) => {
  const directory = await workspace(t)
  const plan = actionsDocument([workspaceRead(), workspaceRead({ id: 'read-two' }), workspaceRead({ id: 'read-three' })])
  const { actionsPath, policyPath } = await prepare(directory, plan)
  const options = { actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW) }

  assert.equal((await checkApprovalBoundary(options)).status, 'pass')
  assert.equal((await checkApprovalBoundary({ ...options, limits: { maxActions: 2 } })).status, 'incomplete')
  assert.equal((await checkApprovalBoundary({ ...options, limits: { maxRules: 3 } })).status, 'incomplete')
  assert.equal((await checkApprovalBoundary({ ...options, limits: { maxActionsBytes: 64 } })).status, 'incomplete')
  assert.equal((await checkApprovalBoundary({ ...options, limits: { maxPolicyBytes: 64 } })).status, 'incomplete')
})

test('an unknown limit key is refused rather than ignored', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([workspaceRead()]))
  await assert.rejects(
    () => checkApprovalBoundary({ actions: actionsPath, policy: policyPath, limits: { maxAction: 1 } }),
    /Unknown limit "maxAction"/,
  )
})

test('a policy with no rules at all still refuses an external write', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(
    directory, actionsDocument([externalWrite()]), policyDocument({ rules: [] }),
  )
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(report.decisions[0].decision, 'requires-approval')
  assert.equal(report.status, 'fail')

  const { actionsPath: approvedPath } = await prepare(
    directory, actionsDocument([externalWrite({ approval: validApproval() })]), policyDocument({ rules: [] }),
  )
  const approved = await checkApprovalBoundary({
    actions: approvedPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(approved.status, 'pass')
})
