/**
 * The command-line surface.
 *
 * Exit 2 has two shapes and this file pins both: a USAGE error means the run
 * never had a subject, so stdout is empty; an INPUT that could not be read
 * means the run had a subject and failed to obtain evidence about it, so stdout
 * carries an `incomplete` report naming which input.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { actionsDocument, externalWrite, prepare, runCli, workspace, workspaceRead, writeFixture } from './helpers.mjs'

test('--help explains the tool and exits 0', async () => {
  for (const flag of ['--help', '-h']) {
    const run = await runCli([flag])
    assert.equal(run.code, 0)
    assert.match(run.stdout, /approval-boundary-checker/)
    assert.match(run.stdout, /This tool executes nothing/)
    assert.match(run.stdout, /Exit codes:/)
    assert.equal(run.stderr, '')
  }
})

test('an unknown option is refused, not ignored', async () => {
  const run = await runCli(['--actions', 'a.json', '--policy', 'p.json', '--strict'])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '', 'a usage error never emits a report')
  assert.match(run.stderr, /Unknown option "--strict"/)
})

test('a one-character typo in a limit flag cannot turn a real failure into a green run', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([externalWrite()]))
  const run = await runCli([...args, '--max-action', '1'])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '')
  assert.match(run.stderr, /Unknown option "--max-action"/)
})

test('a repeated flag is a configuration error rather than a silent last-wins', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([workspaceRead()]))
  const run = await runCli([...args, '--policy', 'somewhere-else.json'])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '')
  assert.match(run.stderr, /--policy was given more than once/)
})

test('both required inputs must be named', async () => {
  for (const [args, expected] of [
    [[], /--actions is required/],
    [['--actions', 'a.json'], /--policy is required/],
    [['--policy', 'p.json'], /--actions is required/],
  ]) {
    const run = await runCli(args)
    assert.equal(run.code, 2)
    assert.equal(run.stdout, '')
    assert.match(run.stderr, expected)
  }
})

test('a flag that needs a value and does not get one is refused', async () => {
  const run = await runCli(['--actions', '--policy', 'p.json'])
  assert.equal(run.code, 2)
  assert.match(run.stderr, /--actions requires a value/)
})

test('a limit flag rejects anything that is not an integer in range', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([workspaceRead()]))
  for (const value of ['0', 'many', '-1', '2.5']) {
    const run = await runCli([...args, '--max-actions', value])
    assert.equal(run.code, 2, `--max-actions ${value} must be refused`)
    assert.equal(run.stdout, '')
  }
  assert.equal((await runCli([...args, '--timeout-ms', '0', '--json'])).code, 2, 'but --timeout-ms 0 is a real value')
})

test('stdout in --json mode is nothing but the report', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([externalWrite()]))
  const run = await runCli([...args, '--json'])
  const parsed = JSON.parse(run.stdout)
  assert.equal(parsed.tool, 'approval-boundary-checker')
  assert.equal(parsed.schemaVersion, '1')
  assert.notEqual(run.stderr, '', 'diagnostics go to stderr, where they cannot break a pipe')
})

test('the human summary says which clock judged the approvals', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([workspaceRead()]))
  const withoutNow = await runCli(['--actions', actionsPath, '--policy', policyPath])
  assert.match(withoutNow.stderr, /system clock; pass --now for a reproducible verdict/)
  const withNow = await runCli(['--actions', actionsPath, '--policy', policyPath, '--now', '2026-01-01T00:00:00Z'])
  assert.match(withNow.stderr, /--now 2026-01-01T00:00:00\.000Z/)
})

test('the human report always states that nothing was executed', async (t) => {
  const directory = await workspace(t)
  for (const plan of [actionsDocument([workspaceRead()]), actionsDocument([externalWrite()]), actionsDocument([])]) {
    const { args } = await prepare(directory, plan)
    const run = await runCli(args)
    assert.match(run.stdout, /No action was executed\./)
  }
})

test('an unreadable input exits 2 WITH a report, unlike a usage error', async (t) => {
  const directory = await workspace(t)
  const policyPath = await writeFixture(directory, 'policy.json', { schemaVersion: '1', defaultDecision: 'denied', rules: [] })
  const usage = await runCli(['--actions'])
  assert.equal(usage.code, 2)
  assert.equal(usage.stdout, '')

  const unreadable = await runCli(['--actions', `${directory}/gone.json`, '--policy', policyPath, '--json'])
  assert.equal(unreadable.code, 2)
  assert.notEqual(unreadable.stdout, '')
  assert.equal(JSON.parse(unreadable.stdout).status, 'incomplete')
})
