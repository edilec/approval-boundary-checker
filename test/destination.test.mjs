/**
 * `--decisions-out` must never destroy a file nobody named.
 *
 * Three independent holes, each with its own check, because guarding one or two
 * is what every tool in this catalog that destroyed a file had already done:
 *
 *   1. A SYMLINK AT THE DESTINATION -- `realpath` RESOLVES it, and resolving is
 *      the dangerous act, so it is refused on sight with `lstat`.
 *   2. A SYMLINKED PARENT -- this tool has NO root. It reads exactly the two
 *      files named on its command line and walks no tree, so there is nothing
 *      for a destination to escape from, and a symbolically linked parent is
 *      followed here exactly as it is by `cp`. That is tested as an ALLOWED
 *      case below, and the help text and README say so, because documenting a
 *      confinement the code does not perform is worse than saying nothing.
 *   3. A HARD LINK TO AN INPUT -- no target to resolve and no shared path, so
 *      `realpath` and string comparison both call it a different file. Only
 *      device plus inode sees it.
 *
 * The allowed cases matter as much as the refusals: a guard that refuses
 * everything passes every data-loss test while making the tool useless.
 */

import assert from 'node:assert/strict'
import { link, lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import {
  FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, runCli, workspace, workspaceRead, writeFixture,
} from './helpers.mjs'

const PRECIOUS = 'a file this run was never asked to touch\n'

async function fixture(t) {
  const directory = await workspace(t)
  const { args, actionsPath, policyPath } = await prepare(directory, actionsDocument([workspaceRead()]))
  return { directory, args, actionsPath, policyPath }
}

test('a plain destination in an existing directory is written', async (t) => {
  const { directory, args } = await fixture(t)
  const out = join(directory, 'decisions.json')
  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 0)
  const written = JSON.parse(await readFile(out, 'utf8'))
  assert.equal(written.tool, 'approval-boundary-checker')
  assert.equal(written.status, 'pass')
  assert.deepEqual(written.decisions.map((entry) => entry.id), ['read-brief'])
})

test('an existing unrelated regular file is overwritten, because that is what naming it means', async (t) => {
  const { directory, args } = await fixture(t)
  const out = join(directory, 'decisions.json')
  await writeFile(out, 'stale output from the last run\n')
  assert.equal((await runCli([...args, '--decisions-out', out])).code, 0)
  assert.match(await readFile(out, 'utf8'), /"tool": "approval-boundary-checker"/)
})

test('a destination reached through a symbolically linked PARENT is written, and is documented as unconfined', async (t) => {
  const { directory, args } = await fixture(t)
  const real = join(directory, 'elsewhere')
  await mkdir(real, { recursive: true })
  await symlink(real, join(directory, 'via-link'))
  const run = await runCli([...args, '--decisions-out', join(directory, 'via-link', 'decisions.json')])
  assert.equal(run.code, 0, 'this tool has no root, so there is nothing to escape from')
  assert.match(await readFile(join(real, 'decisions.json'), 'utf8'), /"decisions"/)

  const help = await runCli(['--help'])
  assert.match(help.stdout, /NOT CONFINED TO ANY ROOT/)
  assert.match(help.stdout, /symbolically linked PARENT directory is followed/)
})

test('hole 1: a destination that is a symbolic link is refused, and its target survives', async (t) => {
  const { directory, args } = await fixture(t)
  const precious = join(directory, 'precious.txt')
  await writeFile(precious, PRECIOUS)
  const out = join(directory, 'decisions.json')
  await symlink(precious, out)

  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '', 'a refused destination is a configuration error: exit 2 with empty stdout')
  assert.match(run.stderr, /symbolic link/)
  assert.equal(await readFile(precious, 'utf8'), PRECIOUS)
  assert.ok((await lstat(out)).isSymbolicLink(), 'the link itself is left alone too')
})

test('hole 1: a DANGLING symbolic link is refused rather than creating a file outside', async (t) => {
  const { directory, args } = await fixture(t)
  const outside = join(directory, 'not-yet-created.txt')
  const out = join(directory, 'decisions.json')
  await symlink(outside, out)

  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '')
  await assert.rejects(() => readFile(outside), { code: 'ENOENT' }, 'writing through the link would have created it')
})

test('hole 3: a HARD LINK to an input is refused, and the input survives', async (t) => {
  const { directory, args, actionsPath } = await fixture(t)
  const before = await readFile(actionsPath, 'utf8')
  const out = join(directory, 'decisions.json')
  await link(actionsPath, out)

  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  assert.equal(run.stdout, '')
  assert.match(run.stderr, /same file as an input/)
  assert.match(run.stderr, /device \d+ and inode \d+/)
  assert.equal(await readFile(actionsPath, 'utf8'), before, 'the actions document must be untouched')
})

test('hole 3: EVERY file the run opened is protected, not only the first one', async (t) => {
  const { directory, args, policyPath } = await fixture(t)
  const before = await readFile(policyPath, 'utf8')
  const out = join(directory, 'decisions.json')
  await link(policyPath, out)

  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  assert.equal(await readFile(policyPath, 'utf8'), before)
})

test('naming an input directly as the destination is refused', async (t) => {
  const { args, actionsPath, policyPath } = await fixture(t)
  for (const input of [actionsPath, policyPath]) {
    const before = await readFile(input, 'utf8')
    const run = await runCli([...args, '--decisions-out', input])
    assert.equal(run.code, 2)
    assert.equal(await readFile(input, 'utf8'), before)
  }
})

test('a destination that is a directory is refused', async (t) => {
  const { directory, args } = await fixture(t)
  const out = join(directory, 'somewhere')
  await mkdir(out, { recursive: true })
  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  assert.match(run.stderr, /not a regular file/)
})

test('a destination in a directory that does not exist is refused rather than created', async (t) => {
  const { directory, args } = await fixture(t)
  const run = await runCli([...args, '--decisions-out', join(directory, 'absent', 'decisions.json')])
  assert.equal(run.code, 2)
  assert.match(run.stderr, /names a directory that does not exist/)
  await assert.rejects(() => lstat(join(directory, 'absent')), { code: 'ENOENT' }, 'no directory may be created on the way')
})

test('an incomplete run writes nothing at all', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([]))
  const out = join(directory, 'decisions.json')
  const run = await runCli([...args, '--decisions-out', out])
  assert.equal(run.code, 2)
  await assert.rejects(() => readFile(out), { code: 'ENOENT' })
  assert.match(run.stderr, /produced no verdicts and nothing was written/)
})

test('a refused destination stops the run before any report is emitted', async (t) => {
  const directory = await workspace(t)
  // A plan that would otherwise fail with exit 1 and a full report.
  const { args, actionsPath } = await prepare(directory, actionsDocument([externalWrite()]))
  const out = join(directory, 'decisions.json')
  await link(actionsPath, out)
  const run = await runCli([...args, '--decisions-out', out, '--json'])
  assert.equal(run.code, 2, 'a configuration that would destroy an input is not one to carry on with')
  assert.equal(run.stdout, '')
})

test('the written decisions document is byte-identical between runs', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([workspaceRead(), externalWrite()]))
  const first = join(directory, 'first.json')
  const second = join(directory, 'second.json')
  await runCli([...args, '--decisions-out', first])
  await runCli([...args, '--decisions-out', second])
  assert.equal(await readFile(first, 'utf8'), await readFile(second, 'utf8'))
})

test('the decisions document carries the same verdicts as the report', async (t) => {
  const directory = await workspace(t)
  const { args } = await prepare(directory, actionsDocument([
    workspaceRead(), externalWrite(), externalWrite({ id: 'leak', effect: 'send', dataClasses: ['secret'] }),
  ]))
  const out = join(directory, 'decisions.json')
  const run = await runCli([...args, '--decisions-out', out, '--json'])
  assert.equal(run.code, 1)
  const report = JSON.parse(run.stdout)
  const written = JSON.parse(await readFile(out, 'utf8'))
  assert.deepEqual(written.decisions, report.decisions)
  assert.equal(written.status, report.status)
})

test('a policy document that is itself the destination is refused even when it is a hard link in another directory', async (t) => {
  const directory = await workspace(t)
  const policyPath = await writeFixture(directory, 'policies/strict.json', policyDocument())
  const actionsPath = await writeFixture(directory, 'plans/actions.json', actionsDocument([workspaceRead()]))
  await mkdir(join(directory, 'out'), { recursive: true })
  const out = join(directory, 'out', 'unrelated-name.json')
  await link(policyPath, out)

  const run = await runCli([
    '--actions', actionsPath, '--policy', policyPath, '--now', FIXED_NOW, '--decisions-out', out,
  ])
  assert.equal(run.code, 2)
  assert.match(await readFile(policyPath, 'utf8'), /"defaultDecision"/)
})
