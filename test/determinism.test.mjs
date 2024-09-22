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
  FIXED_NOW, actionsDocument, externalWrite, prepare, runCli, validApproval, workspace, workspaceRead,
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
