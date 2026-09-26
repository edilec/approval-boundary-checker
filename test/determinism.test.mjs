/**
 * Two runs over the same documents produce byte-identical stdout.
 *
 * The report carries no timestamp, no locale-dependent ordering, no absolute
 * path and no object-key order taken from the input, so the only thing that can
 * change between runs is the wall clock -- and the wall clock reaches exactly
 * one decision, approval expiry, through an injected value the CLI exposes as
 * `--now`.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { checkApprovalBoundary } from '../src/index.mjs'
import {
  FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, runCli, validApproval, workspace,
  workspaceRead, writeFixture,
} from './helpers.mjs'

const PLAN = [
  externalWrite({ id: 'publish' }),
  workspaceRead({ id: 'read-brief' }),
  externalWrite({ id: 'upload-key', effect: 'send', dataClasses: ['secret'], approval: validApproval() }),
  { id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local', dataClasses: ['internal'] },
]

test('the same inputs produce byte-identical stdout, run after run', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument(PLAN))
  const first = await runCli([...args, '--json'])
  const second = await runCli([...args, '--json'])
  assert.equal(first.code, 1)
  assert.equal(first.stdout, second.stdout)
  assert.notEqual(first.stdout.length, 0)
})

test('reordering the actions in the document changes nothing about the report', async (t) => {
  const directory = await workspace(t)
  const forward = await prepare(directory, actionsDocument(PLAN))
  const forwardOut = (await runCli([...forward.args, '--json'])).stdout
  const backward = await prepare(directory, actionsDocument([...PLAN].reverse()))
  const backwardOut = (await runCli([...backward.args, '--json'])).stdout
  assert.equal(forwardOut, backwardOut)
})

/**
 * The fourth sort key is the one carrying the weight here.
 *
 * Two unknown keys at the top of the same document produce two findings with
 * the same `location.file`, no pointer at all and the same `ruleId`, so
 * `message` is the ONLY key that separates them. Without it the sort is stable
 * on emission order, emission order is the order the keys happen to sit in the
 * input, and stdout then depends on how somebody typed their JSON -- which the
 * README promises it does not. The same file name is reused for both runs so
 * that byte-identity is a fair comparison.
 */
test('two findings alike but for their message are ordered by it, not by the order of the input keys', async (t) => {
  const directory = await workspace(t)
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())
  const runOver = async (document) => {
    const actionsPath = await writeFixture(directory, 'actions.json', document)
    return runCli(['--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW, '--json'])
  }

  const zzzFirst = await runOver('{"schemaVersion":"1","zzz":1,"aaa":2,"actions":[]}')
  const aaaFirst = await runOver('{"schemaVersion":"1","aaa":2,"zzz":1,"actions":[]}')
  assert.equal(zzzFirst.code, 2)
  assert.deepEqual(
    JSON.parse(zzzFirst.stdout).findings.map((finding) => finding.message),
    [
      'The actions document declares the unknown key "aaa".',
      'The actions document declares the unknown key "zzz".',
    ],
    'the message decides, so the document that lists zzz first still reports aaa first',
  )
  assert.equal(zzzFirst.stdout, aaaFirst.stdout, 'input key order reached stdout')
})

test('no timestamp reaches the report', async (t) => {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument(PLAN))
  const serialised = JSON.stringify(await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  }))
  assert.doesNotMatch(serialised, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, 'a report carrying a clock reading is not reproducible')
})

test('the wall clock reaches the verdict only through an approval expiry', async (t) => {
  const directory = await workspace(t)
  // No expiry anywhere in this plan, so two wildly different clocks must agree.
  const { actionsPath, policyPath } = await prepare(directory, actionsDocument([
    workspaceRead(), externalWrite({ approval: validApproval() }),
  ]))
  const early = await checkApprovalBoundary({ actions: actionsPath, policy: policyPath, now: () => 0 })
  const late = await checkApprovalBoundary({ actions: actionsPath, policy: policyPath, now: () => 4102444800000 })
  assert.equal(JSON.stringify(early), JSON.stringify(late))
  assert.equal(early.status, 'pass')
})
