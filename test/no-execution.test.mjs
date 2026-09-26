/**
 * Acceptance: "no action is executed by the checker."
 *
 * Two independent halves, because either one alone is weak:
 *
 * - The OBSERVABLE half runs the real CLI over a plan of destructive actions
 *   inside a scratch workspace and asserts the workspace is byte-identical
 *   afterwards, down to the file list. This is what would fail if a future edit
 *   made the tool touch anything.
 * - The STRUCTURAL half asserts the shipped source imports no module capable of
 *   executing anything or reaching a network, and contains no dynamic-evaluation
 *   construct. This is what catches a capability that exists but that this
 *   particular fixture happened not to trigger.
 *
 * The plan's actions also name targets that CANNOT be opened -- a directory, a
 * dangling symbolic link, an unreadable file. If the checker resolved a target
 * it would fail on them; instead it reaches an ordinary verdict, which is the
 * observable difference between reading a declaration and acting on it.
 */

import assert from 'node:assert/strict'
import { chmod, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import test from 'node:test'

import { FIXED_NOW, PACKAGE_ROOT, policyDocument, runCli, workspace, writeFixture } from './helpers.mjs'

/** Every file under `directory`, with its bytes, as a sorted comparable map. */
async function snapshot(directory) {
  const entries = {}
  const walk = async (current) => {
    for (const item of (await readdir(current, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const path = join(current, item.name)
      const key = relative(directory, path)
      if (item.isDirectory()) {
        entries[key] = 'dir'
        await walk(path)
      } else if (item.isSymbolicLink()) {
        entries[key] = 'symlink'
      } else {
        entries[key] = (await readFile(path)).toString('base64')
      }
    }
  }
  await walk(directory)
  return entries
}

test('a plan of destructive actions leaves the workspace byte-identical', async (t) => {
  const directory = await workspace(t)
  await writeFixture(directory, 'sentinel.txt', 'this file is named by three actions and touched by none of them\n')
  await mkdir(join(directory, 'scripts'), { recursive: true })
  await writeFile(join(directory, 'scripts', 'migrate.sh'), '#!/bin/sh\necho this must never run\n')
  await symlink(join(directory, 'nowhere-at-all'), join(directory, 'dangling'))

  const actions = {
    schemaVersion: '1',
    actions: [
      { id: 'delete-sentinel', tool: 'fs.unlink', effect: 'delete', scope: 'workspace', dataClasses: ['internal'], target: join(directory, 'sentinel.txt') },
      { id: 'overwrite-sentinel', tool: 'fs.writeFile', effect: 'write', scope: 'workspace', dataClasses: ['internal'], target: join(directory, 'sentinel.txt') },
      { id: 'run-migration', tool: 'shell.exec', effect: 'execute', scope: 'local', dataClasses: ['internal'], target: join(directory, 'scripts', 'migrate.sh') },
      { id: 'read-a-directory', tool: 'fs.readFile', effect: 'read', scope: 'workspace', dataClasses: ['internal'], target: join(directory, 'scripts') },
      { id: 'read-a-dangling-link', tool: 'fs.readFile', effect: 'read', scope: 'workspace', dataClasses: ['internal'], target: join(directory, 'dangling') },
      { id: 'post-to-vendor', tool: 'http.post', effect: 'send', scope: 'external', dataClasses: ['secret'], target: 'https://example.invalid/collect' },
    ],
  }
  const actionsPath = await writeFixture(directory, 'plan/actions.json', actions)
  const policyPath = await writeFixture(directory, 'plan/policy.json', policyDocument())

  const before = await snapshot(directory)
  const run = await runCli(['--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW], { cwd: directory })
  const after = await snapshot(directory)

  assert.equal(run.code, 1, 'the run reaches an ordinary verdict; it did not choke on a target it should never have opened')
  assert.deepEqual(after, before, 'the checker must not create, modify or remove anything')
  assert.match(run.stdout, /No action was executed/)
  assert.ok(!run.stderr.includes('EISDIR') && !run.stderr.includes('ENOENT'), run.stderr)
})

test('a target the process cannot read does not disturb the verdict', async (t) => {
  if (process.getuid?.() === 0) return
  const directory = await workspace(t)
  const secret = join(directory, 'unreadable.txt')
  await writeFile(secret, 'if this is opened the run fails differently\n')
  await chmod(secret, 0o000)
  t.after(() => chmod(secret, 0o600).catch(() => {}))

  const actionsPath = await writeFixture(directory, 'actions.json', {
    schemaVersion: '1',
    actions: [{ id: 'exfiltrate', tool: 'http.post', effect: 'send', scope: 'external', dataClasses: ['secret'], target: secret }],
  })
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())

  const run = await runCli(['--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW, '--json'])
  assert.equal(run.code, 1)
  const report = JSON.parse(run.stdout)
  assert.equal(report.decisions[0].decision, 'denied')
  assert.ok(!run.stdout.includes('EACCES') && !run.stderr.includes('EACCES'))
})

test('running the CLI creates no file when --decisions-out is not given', async (t) => {
  const directory = await workspace(t)
  const actionsPath = await writeFixture(directory, 'actions.json', {
    schemaVersion: '1',
    actions: [{ id: 'read-brief', tool: 'fs.readFile', effect: 'read', scope: 'workspace', dataClasses: ['internal'] }],
  })
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())
  const before = await snapshot(directory)
  const run = await runCli(['--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW], { cwd: directory })
  assert.equal(run.code, 0)
  assert.deepEqual(await snapshot(directory), before)
})

/**
 * The capability audit.
 *
 * A fixture proves that this plan was not executed. This proves the tool has no
 * way to execute any plan: the modules that could start a process, evaluate a
 * string or open a socket are not imported anywhere in what ships.
 */
test('the shipped source imports nothing that can execute or reach a network', async () => {
  const forbiddenModules = [
    'child_process', 'cluster', 'dgram', 'http', 'http2', 'https', 'inspector',
    'net', 'perf_hooks', 'repl', 'tls', 'vm', 'worker_threads',
  ]
  const forbiddenConstructs = [
    { name: 'eval', pattern: /(^|[^.\w])eval\s*\(/ },
    { name: 'new Function', pattern: /new\s+Function\s*\(/ },
    { name: 'require', pattern: /(^|[^.\w])require\s*\(/ },
    { name: 'process.binding', pattern: /process\s*\.\s*binding/ },
    { name: 'dynamic import', pattern: /(^|[^.\w])import\s*\(/ },
    { name: 'fetch', pattern: /(^|[^.\w])fetch\s*\(/ },
  ]
  const files = []
  for (const directory of ['src', 'bin']) {
    for (const name of await readdir(join(PACKAGE_ROOT, directory))) {
      if (name.endsWith('.mjs')) files.push(join(directory, name))
    }
  }
  assert.ok(files.length >= 4, 'the audit must actually have found the shipped modules')

  for (const file of files) {
    const source = await readFile(join(PACKAGE_ROOT, file), 'utf8')
    for (const module of forbiddenModules) {
      assert.ok(
        !new RegExp(`['"]node:${module}['"]`).test(source) && !new RegExp(`from\\s+['"]${module}['"]`).test(source),
        `${file} must not import ${module}`,
      )
    }
    for (const construct of forbiddenConstructs) {
      assert.ok(!construct.pattern.test(source), `${file} must not use ${construct.name}`)
    }
  }
})
