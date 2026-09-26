/**
 * The documented catalog and the severity table agree, in both directions.
 *
 * This is a source-of-truth check, NOT the severity guard: two declarations
 * agreeing with each other are satisfied by one coordinated edit, and this
 * catalog has measured 40 of 52 error rules surviving exactly that flip. The
 * guard is `test/severity-outcomes.test.mjs`, which drives each rule through the
 * real entry point and asserts what the tool observably concluded.
 *
 * What this file is for is the other failure: a rule that exists in the code and
 * is documented nowhere, or documented and no longer emitted. Documentation
 * overclaims are defects here.
 */

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import {
  DATA_CLASSES, DEFAULT_DECISIONS, DEFAULT_LIMITS, EFFECTS, RULE_DECISIONS, RULE_SEVERITY, SCOPES, TOOL_ID,
} from '../src/index.mjs'
import { PACKAGE_ROOT, runCli } from './helpers.mjs'

const readme = await readFile(join(PACKAGE_ROOT, 'README.md'), 'utf8')

/** The rows of the README's rule table, as `ruleId -> severity`. */
function documentedRules(text) {
  const rows = {}
  for (const line of text.split('\n')) {
    const match = /^\| `([a-z0-9-]+)` \| (error|warning|info) \| /.exec(line)
    if (match !== null) rows[match[1]] = match[2]
  }
  return rows
}

test('the tool id equals the directory name and is exported', () => {
  assert.equal(TOOL_ID, 'approval-boundary-checker')
  assert.equal(TOOL_ID, PACKAGE_ROOT.split('/').at(-1))
})

test('every rule in the table is documented, and every documented rule exists', () => {
  const documented = documentedRules(readme)
  assert.ok(Object.keys(documented).length > 20, 'the table was not parsed at all')
  assert.deepEqual(
    Object.keys(RULE_SEVERITY).filter((ruleId) => documented[ruleId] === undefined), [],
    'a rule the code can emit that the README does not list',
  )
  assert.deepEqual(
    Object.keys(documented).filter((ruleId) => RULE_SEVERITY[ruleId] === undefined), [],
    'a rule the README promises that the code cannot emit',
  )
  for (const [ruleId, severity] of Object.entries(documented)) {
    assert.equal(RULE_SEVERITY[ruleId], severity, `${ruleId} is documented as ${severity}`)
  }
})

/**
 * A document may not describe a WEAKER rule than the code applies either.
 *
 * `approval.test.mjs` drives the boundary through the real entry point and
 * records that an approval whose `expiresAt` equals `--now` is expired. The
 * README row said the approval "passed its `expiresAt` before `--now`", which is
 * one instant looser than the tool behaves. An understatement drifts from the
 * code exactly as an overclaim does; it just reads as modesty.
 */
test('the documented expiry boundary is the inclusive one the code applies', () => {
  const row = readme.split('\n').find((line) => line.startsWith('| `approval-expired` |'))
  assert.ok(row !== undefined, 'the approval-expired row was not found, so this test proves nothing')
  assert.match(row, /at or before `--now`/)
  assert.ok(!/passed its `expiresAt` before/.test(readme), 'the looser sentence must not come back')
})

test('every severity is one of the three the contract allows', () => {
  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.ok(['error', 'warning', 'info'].includes(severity), `${ruleId} has severity ${severity}`)
  }
})

test('the documented limits are the limits the code has', async () => {
  const help = (await runCli(['--help'])).stdout
  const flags = {
    maxActions: '--max-actions', maxActionsBytes: '--max-actions-bytes',
    maxPolicyBytes: '--max-policy-bytes', maxRules: '--max-rules', timeoutMs: '--timeout-ms',
  }
  assert.deepEqual(Object.keys(flags).sort(), Object.keys(DEFAULT_LIMITS).sort(), 'a limit with no flag is a limit nobody can set')
  for (const [key, flag] of Object.entries(flags)) {
    assert.ok(help.includes(flag), `${flag} is missing from --help`)
    assert.ok(
      readme.includes(`| \`${flag}\` | ${DEFAULT_LIMITS[key]} |`),
      `the README must document ${flag} as ${DEFAULT_LIMITS[key]}`,
    )
  }
})

test('the documented vocabularies are the vocabularies the code enforces', () => {
  assert.deepEqual(EFFECTS, ['delete', 'execute', 'read', 'send', 'write'])
  assert.deepEqual(SCOPES, ['external', 'local', 'workspace'])
  assert.deepEqual(DATA_CLASSES, ['confidential', 'internal', 'personal', 'public', 'secret'])
  assert.deepEqual(RULE_DECISIONS, ['allowed', 'denied', 'requires-approval'])
  assert.deepEqual(DEFAULT_DECISIONS, ['denied', 'requires-approval'])
  assert.ok(!DEFAULT_DECISIONS.includes('allowed'), 'the README says allowed is not offered as a default')
  for (const value of [...EFFECTS, ...SCOPES, ...DATA_CLASSES]) {
    assert.ok(readme.includes(`\`${value}\``), `the README must document the value ${value}`)
  }
})

test('the README does not promise a confinement the code does not perform', () => {
  assert.match(readme, /The destination is not confined to any root/i)
  assert.match(readme, /symbolically linked \*\*parent\*\* directory is followed/)
  assert.ok(
    !/refuses? (every |a )?symlinked (parent|ancestor)/i.test(readme),
    'the tool follows a symlinked parent; claiming otherwise reads as coverage that does not exist',
  )
})

test('the README quick start is a command that actually runs', async () => {
  const commands = [...readme.matchAll(/node bin\/approval-boundary-checker\.mjs \\\n((?:\s+--[^\n]*\n)+)/g)]
  assert.equal(commands.length, 2, 'both quick-start commands must be found')
  for (const [, block] of commands) {
    const args = block.trim().split(/\s+/).filter((token) => token !== '\\')
    const run = await runCli(args)
    assert.ok([0, 1].includes(run.code), `the quick start exited ${run.code}: ${run.stderr}`)
  }
})
