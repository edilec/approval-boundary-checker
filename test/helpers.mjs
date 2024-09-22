/**
 * Test scaffolding.
 *
 * `node:child_process` is imported HERE and nowhere in `src/` or `bin/`: the
 * tests have to start the CLI as a real process to observe an exit code, while
 * the tool itself must never be able to start anything at all.
 * `test/no-execution.test.mjs` asserts that separation over the shipped source.
 */

import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
export const CLI = join(PACKAGE_ROOT, 'bin', 'approval-boundary-checker.mjs')

/** A scratch directory removed when the test finishes, however it finishes. */
export async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), 'approval-boundary-checker-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  return directory
}

export async function writeFixture(directory, name, contents) {
  const path = join(directory, name)
  await mkdir(dirname(path), { recursive: true })
  const body = typeof contents === 'string' || Buffer.isBuffer(contents)
    ? contents
    : `${JSON.stringify(contents, null, 2)}\n`
  await writeFile(path, body)
  return path
}

/** Run the CLI as a child process and capture the exit code and both streams. */
export function runCli(args, options = {}) {
  return new Promise((settle) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      { cwd: options.cwd ?? PACKAGE_ROOT, maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => settle({ code: error === null ? 0 : error.code, stdout, stderr }),
    )
  })
}

export const FIXED_NOW = '2026-09-14T09:00:00Z'
export const FIXED_NOW_MS = Date.parse(FIXED_NOW)

/** A policy that exercises every decision the vocabulary offers. */
export function policyDocument(overrides = {}) {
  return {
    schemaVersion: '1',
    defaultDecision: 'requires-approval',
    rules: [
      { id: 'workspace-read', effects: ['read'], scopes: ['local', 'workspace'], decision: 'allowed' },
      { id: 'workspace-write', effects: ['write'], scopes: ['workspace'], decision: 'allowed' },
      { id: 'external-side-effect', effects: ['delete', 'send', 'write'], scopes: ['external'], decision: 'requires-approval' },
      { id: 'secret-egress', scopes: ['external'], dataClasses: ['secret'], decision: 'denied' },
    ],
    ...overrides,
  }
}

export function actionsDocument(actions, overrides = {}) {
  return { schemaVersion: '1', actions, ...overrides }
}

export function externalWrite(overrides = {}) {
  return {
    id: 'publish-notes',
    tool: 'http.post',
    effect: 'write',
    scope: 'external',
    dataClasses: ['public'],
    ...overrides,
  }
}

export function workspaceRead(overrides = {}) {
  return {
    id: 'read-brief',
    tool: 'fs.readFile',
    effect: 'read',
    scope: 'workspace',
    dataClasses: ['internal'],
    ...overrides,
  }
}

export function validApproval(overrides = {}) {
  return { approvedBy: 'release-manager', approvedAt: '2026-09-14T08:30:00Z', ...overrides }
}

/** Write an actions/policy pair and return the argument list that checks them. */
export async function prepare(directory, actions, policy = policyDocument()) {
  const actionsPath = await writeFixture(directory, 'actions.json', actions)
  const policyPath = await writeFixture(directory, 'policy.json', policy)
  return { actionsPath, policyPath, args: ['--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW] }
}
