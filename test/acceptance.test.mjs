/**
 * The acceptance criteria, item by item.
 *
 * "An external write lacking approval is stopped; unknown actions default to
 * review; no action is executed by the checker."
 *
 * Each is asserted on what the tool OBSERVABLY emits -- the status, the exit
 * code, the verdict row a queue would read -- rather than on a declaration
 * inside the source that says the same thing.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { checkApprovalBoundary } from '../src/index.mjs'
import {
  FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, runCli, validApproval,
  workspace, workspaceRead, writeFixture,
} from './helpers.mjs'

test('an external write lacking approval is stopped', async (t) => {
  const directory = await workspace(t)
  const { args, actionsPath, policyPath } = await prepare(directory, actionsDocument([externalWrite()]))

  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.stopped, 1)
  assert.equal(report.summary.allowed, 0)
  assert.deepEqual(
    report.decisions.map((entry) => [entry.id, entry.decision, entry.approval, entry.outcome]),
    [['publish-notes', 'requires-approval', 'none', 'stopped']],
  )
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['approval-missing'])

  const run = await runCli(args)
  assert.equal(run.code, 1, 'the CLI must refuse, not merely mention it')
  assert.match(run.stdout, /STOPPED publish-notes/)
})

test('the same external write with a valid approval on record is cleared', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([externalWrite({ approval: validApproval() })]))
  const run = await runCli(args)
  assert.equal(run.code, 0)
  assert.match(run.stdout, /ALLOWED publish-notes/)
})

test('an approval does not lift a denial', async (t) => {
  const directory = await workspace(t)
  const action = externalWrite({
    id: 'upload-key', effect: 'send', dataClasses: ['secret'], approval: validApproval(),
  })
  const { args, actionsPath, policyPath } = await prepare(directory, actionsDocument([action]))

  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(report.decisions[0].approval, 'valid', 'the approval itself is in good order')
  assert.equal(report.decisions[0].decision, 'denied')
  assert.equal(report.decisions[0].outcome, 'stopped')
  assert.equal(report.status, 'fail')
  assert.equal((await runCli(args)).code, 1)
})

test('an unknown action defaults to review rather than to a pass', async (t) => {
  const directory = await workspace(t)
  // execute / local is selected by no rule in the policy at all.
  const unknown = { id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local', dataClasses: ['internal'] }
  const { args, actionsPath, policyPath } = await prepare(directory, actionsDocument([unknown]))

  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(report.decisions[0].matchedRules, [], 'no rule selected it')
  assert.equal(report.decisions[0].decision, 'requires-approval', 'it must land on review, not on allowed')
  assert.equal(report.decisions[0].outcome, 'stopped')
  assert.equal(report.summary.unmatched, 1)
  assert.equal(report.status, 'fail')
  assert.equal((await runCli(args)).code, 1)
})

test('an unknown action that a human did approve proceeds, and still says the policy has a gap', async (t) => {
  const directory = await workspace(t)
  const unknown = {
    id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local',
    dataClasses: ['internal'], approval: validApproval(),
  }
  const { args, actionsPath, policyPath } = await prepare(directory, actionsDocument([unknown]))

  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.equal(report.status, 'pass')
  assert.equal(report.decisions[0].outcome, 'allowed')
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['action-unmatched'])
  assert.equal(report.findings[0].severity, 'warning')
  assert.equal((await runCli(args)).code, 0)
})

test('a policy cannot declare that unknown actions are allowed', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(
    directory,
    actionsDocument([workspaceRead()]),
    policyDocument({ defaultDecision: 'allowed' }),
  )
  const run = await runCli(args)
  assert.equal(run.code, 2, 'a default-allow policy is refused, not honoured')
  const report = JSON.parse((await runCli([...args, '--json'])).stdout)
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.some((finding) => finding.ruleId === 'policy-malformed'
    && finding.location.pointer === '/defaultDecision'))
})

test('a catch-all rule that would rubber-stamp the policy is refused', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(
    directory,
    actionsDocument([externalWrite()]),
    policyDocument({ rules: [{ id: 'everything', decision: 'allowed' }] }),
  )
  const run = await runCli([...args, '--json'])
  assert.equal(run.code, 2)
  const report = JSON.parse(run.stdout)
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.some((finding) => finding.ruleId === 'policy-rule-unselective'))
})

test('the strictest matching rule decides, whatever order the rules are written in', async (t) => {
  const directory = await workspace(t)
  const action = externalWrite({ id: 'leak', effect: 'send', dataClasses: ['secret', 'public'] })
  const strictFirst = policyDocument({
    rules: [
      { id: 'secret-egress', scopes: ['external'], dataClasses: ['secret'], decision: 'denied' },
      { id: 'public-send', effects: ['send'], scopes: ['external'], decision: 'allowed' },
    ],
  })
  const looseFirst = policyDocument({ rules: [...strictFirst.rules].reverse() })

  for (const policy of [strictFirst, looseFirst]) {
    const { actionsPath, policyPath } = await prepare(directory, actionsDocument([action]), policy)
    const report = await checkApprovalBoundary({
      actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
    })
    assert.equal(report.decisions[0].decision, 'denied')
    assert.deepEqual(report.decisions[0].matchedRules, ['public-send', 'secret-egress'])
  }
})

test('an action declaring no data classes is refused rather than slipping past the data rules', async (t) => {
  const directory = await workspace(t)
  const action = { id: 'leak', tool: 'http.post', effect: 'send', scope: 'external' }
  const { args } = await prepare(directory, actionsDocument([action]))
  const run = await runCli([...args, '--json'])
  assert.equal(run.code, 2)
  const report = JSON.parse(run.stdout)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.decisions.length, 0, 'an uninterpretable plan yields no verdicts at all')
  assert.ok(report.findings.some((finding) => finding.ruleId === 'action-malformed'
    && finding.message.includes('dataClasses')))
})

test('the shipped examples behave as the README says they do', async () => {
  const clear = await runCli([
    '--actions', 'examples/allowed/actions.json', '--policy', 'examples/policy.json', '--now', FIXED_NOW,
  ])
  assert.equal(clear.code, 0)

  const blocked = await runCli([
    '--actions', 'examples/blocked/actions.json', '--policy', 'examples/policy.json', '--now', FIXED_NOW, '--json',
  ])
  assert.equal(blocked.code, 1)
  const report = JSON.parse(blocked.stdout)
  assert.equal(report.status, 'fail')
  assert.deepEqual(
    report.decisions.map((entry) => [entry.id, entry.outcome]),
    [['publish-release-notes', 'stopped'], ['run-migration-script', 'stopped'], ['upload-signing-key', 'stopped']],
  )
})

test('an approval recorded on an action the policy allows outright is reported, and does not fail the run', async (t) => {
  const directory = await workspace(t)
  const { args, actionsPath, policyPath } = await prepare(
    directory, actionsDocument([workspaceRead({ approval: validApproval() })]),
  )
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  assert.deepEqual(report.findings.map((finding) => [finding.ruleId, finding.severity]), [['approval-superfluous', 'info']])
  assert.equal(report.status, 'pass')
  assert.equal((await runCli(args)).code, 0)
})

test('a report never carries an absolute host path', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([externalWrite()]))
  const run = await runCli([...args, '--json'])
  assert.ok(!run.stdout.includes(directory), 'the scratch directory must not appear anywhere in the report')
  const report = JSON.parse(run.stdout)
  assert.deepEqual(report.inputs, { actions: 'actions.json', policy: 'policy.json' })
  for (const finding of report.findings) {
    assert.ok(['actions', 'policy'].includes(finding.location.file))
  }
})

test('a plan declaring no actions is incomplete, not clear', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([]))
  const run = await runCli([...args, '--json'])
  assert.equal(run.code, 2)
  const report = JSON.parse(run.stdout)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.ok(report.findings.some((finding) => finding.ruleId === 'no-actions'))
})

test('a plan whose actions document is simply missing names the input that was not read', async (t) => {
  const directory = await workspace(t)
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())
  const run = await runCli(['--actions', `${directory}/absent.json`, '--policy', policyPath, '--json'])
  assert.equal(run.code, 2)
  const report = JSON.parse(run.stdout)
  assert.equal(report.status, 'incomplete')
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['actions-unreadable'])
  assert.equal(report.findings[0].location.file, 'actions')
})
