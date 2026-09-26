/**
 * A parse failure must not reproduce the document.
 *
 * V8 embeds the offending input in its own message:
 *
 *   safe   Expected ',' or '}' after property value in JSON at position 37 (line 1 column 38)
 *   LEAKS  Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON
 *
 * Interpolating `error.message` therefore walks file contents onto stdout past
 * every redactor. `parseFailureDetail` describes the failure without the
 * document, and the ORDER of its branches is the whole guard: a helper that
 * looks for `at position \\d+` first finds that phrase INSIDE the quoted span
 * whenever the document itself contains it, and slices the document back out.
 *
 * Every case below is one this catalog has measured a tool failing.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { parseFailureDetail } from '../src/index.mjs'
import { policyDocument, runCli, workspace, writeFixture } from './helpers.mjs'

const UNPARSEABLE = 'the document could not be parsed as JSON'

function failureFor(document) {
  try {
    JSON.parse(document)
  } catch (error) {
    return { message: error.message, detail: parseFailureDetail(error) }
  }
  throw new Error('that document parsed, so it proves nothing')
}

test('a document whose own text reads "at position 1" is not sliced back out', () => {
  const { message, detail } = failureFor('at position 1')
  assert.equal(message, 'Unexpected token \'a\', "at position 1" is not valid JSON')
  assert.equal(detail, "unexpected token 'a' at the start of the document")
  assert.ok(!detail.includes('at position 1'), 'the position branch must not run before the quoting branch')
})

test('a document that is nothing but a credential is not reproduced', () => {
  const { detail } = failureFor('AKIAIOSFODNN7EXAMPLE')
  assert.equal(detail, "unexpected token 'A' at the start of the document")
  assert.ok(!detail.includes('AKIAIOSFODNN7EXAMPLE'))
})

test('a long document with a sensitive prefix is not reproduced ten characters at a time', () => {
  const { message, detail } = failureFor(`password=hunter2 ${'x'.repeat(4000)}`)
  assert.match(message, /"password=h"\.\.\./, 'V8 really does quote the prefix')
  assert.equal(detail, "unexpected token 'p' at the start of the document")
  assert.ok(!detail.includes('password'))
})

test('a quoted window taken from the MIDDLE of a document is not reproduced either', () => {
  // The window V8 quotes is taken from wherever the offence is, not from the
  // front, so "truncate the front" is not a fix. Here it is surrounded by
  // ellipses on both sides.
  const { message, detail } = failureFor(`[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ZQXJVBMP7W${'y'.repeat(60)}]`)
  assert.equal(message, 'Unexpected token \'Z\', ..."8, 9, 10, ZQXJVBMP7W"... is not valid JSON')
  assert.equal(detail, "unexpected token 'Z' inside the document")
  assert.ok(!detail.includes('ZQXJVBMP7W'))
})

test('a quoted span containing a newline is still recognised as a quoted span', () => {
  const { message, detail } = failureFor('ZQXJ\nVBMP\n7W')
  assert.ok(message.includes('\n'), 'the message itself carries the newline, which a non-dotAll pattern would miss')
  assert.equal(detail, "unexpected token 'Z' at the start of the document")
  assert.ok(!detail.includes('ZQXJ'))
})

test('the safe positional form keeps its position, line and column', () => {
  const { detail } = failureFor('{"alpha": 1,}')
  assert.equal(detail, 'Expected double-quoted property name in JSON at position 12 (line 1 column 13)')
  const truncated = failureFor('{"alpha": 1')
  assert.equal(truncated.detail, "Expected ',' or '}' after property value in JSON at position 11 (line 1 column 12)")
})

test('an empty document keeps its own plain sentence', () => {
  assert.equal(failureFor('').detail, 'Unexpected end of JSON input')
})

test('the backstop refuses any message that still carries a double quote', () => {
  /**
   * The case the backstop exists for: a wording that reaches the SAFE
   * positional branch while still carrying a quoted span in front of the
   * position. The branch logic happily returns the prefix, and the prefix holds
   * the document. Across 500,206 distinct V8 parse messages every message with
   * no quoted snippet also carried no double quote at all -- V8 quotes JSON
   * punctuation with apostrophes -- so a surviving double quote means a snippet
   * survived, whatever the branches above concluded.
   */
  assert.equal(
    parseFailureDetail(new Error('Bad escaped character "AKIAIOSFODNN7EXAMPLE" in JSON at position 12 (line 1 column 13)')),
    UNPARSEABLE,
  )
  assert.equal(
    parseFailureDetail(new Error('Unexpected token \'"\', "a" is not valid JSON')),
    UNPARSEABLE,
    'even the offending token itself may be a double quote',
  )
  assert.equal(
    parseFailureDetail(new Error('A wording no future V8 has invented yet: "SECRETVALUE" is bad')),
    UNPARSEABLE,
  )
  assert.equal(parseFailureDetail(new Error('')), UNPARSEABLE)
  assert.equal(parseFailureDetail(undefined), UNPARSEABLE)
  assert.equal(parseFailureDetail({ message: null }), UNPARSEABLE)
})

test('a credential in an unparseable actions document never reaches stdout', async (t) => {
  const directory = await workspace(t)
  const credential = 'AKIAIOSFODNN7EXAMPLE'
  const actionsPath = await writeFixture(directory, 'actions.json', credential)
  const policyPath = await writeFixture(directory, 'policy.json', policyDocument())
  for (const mode of [[], ['--json']]) {
    const run = await runCli(['--actions', actionsPath, '--policy', policyPath, ...mode])
    assert.equal(run.code, 2)
    assert.ok(!run.stdout.includes(credential), 'the document walked onto stdout through its own error message')
    assert.ok(!run.stderr.includes(credential))
    assert.match(run.stdout, /actions-not-json/)
  }
})
