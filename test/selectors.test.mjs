/**
 * What a rule selector actually selects.
 *
 * `tools` is the selector with no closed vocabulary behind it: `effects`,
 * `scopes` and `dataClasses` are checked against frozen lists, so a mistake in
 * how they are compared is caught by the vocabulary. A tool name is any string
 * the document cares to write, and the README says twice what that means --
 * "`effects`, `scopes` and `tools` by exact membership", and the non-goal "No
 * globbing in `tools`. Selectors are exact strings. `http.*` matches nothing."
 *
 * Nothing defended either sentence. Replacing `rule.tools.includes(action.tool)`
 * with a prefix test turns a rule written for the tool `http` into a rule that
 * also clears `http.post`, and the whole suite stayed green: a credential upload
 * came back `allowed`, status `pass`, exit 0.
 *
 * So the cases below are the ones a wrong comparison gets wrong -- a prefix, a
 * suffix, a substring, a different case, a glob -- and each is driven through
 * the real entry point. The allowed case is pinned beside them on purpose: a
 * selector that matched nothing at all would pass every refusal test here while
 * making the selector useless.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { checkApprovalBoundary, ruleMatches } from '../src/index.mjs'
import { FIXED_NOW, actionsDocument, externalWrite, policyDocument, prepare, runCli, workspace } from './helpers.mjs'

/** A policy whose only rule clears one exactly-named tool. Everything else defaults to denied. */
function toolPolicy(tools) {
  return policyDocument({ defaultDecision: 'denied', rules: [{ id: 'exact-tool', tools, decision: 'allowed' }] })
}

async function verdictFor(t, tool, policy) {
  const directory = await workspace(t)
  const { actionsPath, policyPath } = await prepare(
    directory, actionsDocument([externalWrite({ id: 'candidate', tool })]), policy,
  )
  const report = await checkApprovalBoundary({
    actions: actionsPath, policy: policyPath, now: () => Date.parse(FIXED_NOW),
  })
  return report.decisions[0]
}

test('a tools selector matches the tool name exactly', async (t) => {
  const verdict = await verdictFor(t, 'http.post', toolPolicy(['http.post']))
  assert.deepEqual(verdict.matchedRules, ['exact-tool'], 'the exact name must select, or this file only proves refusals')
  assert.equal(verdict.decision, 'allowed')
  assert.equal(verdict.outcome, 'allowed')
})

for (const [shape, tool] of [
  ['a longer name starting with the selector', 'http.post.v2'],
  ['a name the selector is a prefix of', 'http.postMessage'],
  ['a name that contains the selector', 'proxy.http.post.wrapper'],
  ['a name that is a prefix of the selector', 'http'],
  ['the same name in another case', 'HTTP.POST'],
  ['the same name with surrounding space', ' http.post '],
]) {
  test(`${shape} is not selected: "${tool}" is not "http.post"`, async (t) => {
    const verdict = await verdictFor(t, tool, toolPolicy(['http.post']))
    assert.deepEqual(verdict.matchedRules, [], `"${tool}" must select no rule`)
    assert.equal(verdict.decision, 'denied', 'it falls through to the policy default instead')
    assert.equal(verdict.outcome, 'stopped')
  })
}

test('a selector that is a prefix of the tool name selects nothing', async (t) => {
  // The exact mutation that stayed green: rule.tools.some(x => action.tool.startsWith(x)).
  const verdict = await verdictFor(t, 'http.post', toolPolicy(['http']))
  assert.deepEqual(verdict.matchedRules, [])
  assert.equal(verdict.decision, 'denied')
})

test('"http.*" in a tools selector matches nothing -- there is no globbing', async (t) => {
  const globbed = await verdictFor(t, 'http.post', toolPolicy(['http.*']))
  assert.deepEqual(globbed.matchedRules, [], 'the README states this as a non-goal')
  assert.equal(globbed.decision, 'denied')

  // And the glob is a literal string, not a rejected one: a tool actually named
  // "http.*" is selected by it.
  const literal = await verdictFor(t, 'http.*', toolPolicy(['http.*']))
  assert.deepEqual(literal.matchedRules, ['exact-tool'])
  assert.equal(literal.decision, 'allowed')
})

test('a tools selector listing several names selects each of them and nothing between', async (t) => {
  const policy = toolPolicy(['fs.readFile', 'http.post'])
  for (const tool of ['fs.readFile', 'http.post']) {
    assert.deepEqual((await verdictFor(t, tool, policy)).matchedRules, ['exact-tool'], `${tool} is listed`)
  }
  for (const tool of ['fs.read', 'fs.readFileSync', 'http.pos']) {
    assert.deepEqual((await verdictFor(t, tool, policy)).matchedRules, [], `${tool} is not listed`)
  }
})

test('a prefix match would clear a secret upload, and the exit code says it does not', async (t) => {
  const directory = await workspace(t)
  // A policy written for the tool "http": under exact membership it selects
  // nothing here and the secret egress takes the "denied" default. Under a
  // prefix comparison it selects "http.post" and clears it.
  const { args } = await prepare(
    directory,
    actionsDocument([externalWrite({ id: 'upload-credentials', tool: 'http.post', dataClasses: ['secret'] })]),
    toolPolicy(['http']),
  )
  const run = await runCli([...args, '--json'])
  const report = JSON.parse(run.stdout)

  assert.equal(run.code, 1, 'a denied secret egress fails the run')
  assert.equal(report.status, 'fail')
  assert.equal(report.decisions[0].decision, 'denied')
  assert.equal(report.decisions[0].outcome, 'stopped')
  assert.deepEqual(report.decisions[0].matchedRules, [])
  assert.ok(
    report.findings.some((finding) => finding.ruleId === 'action-denied'),
    'and the report says why, rather than only exiting non-zero',
  )
})

test('every declared selector must be satisfied, so tools narrows rather than widens', async (t) => {
  const policy = policyDocument({
    defaultDecision: 'denied',
    rules: [{ id: 'narrow', tools: ['http.post'], effects: ['read'], decision: 'allowed' }],
  })
  const matching = await verdictFor(t, 'http.post', policy)
  assert.deepEqual(matching.matchedRules, [], 'the effect does not match, so the rule does not select')
  assert.equal(matching.decision, 'denied')
})

test('ruleMatches compares tool names by identity, with no selector meaning no constraint', () => {
  const action = { tool: 'http.post', effect: 'write', scope: 'external', dataClasses: ['public'] }
  assert.equal(ruleMatches({ tools: ['http.post'] }, action), true)
  assert.equal(ruleMatches({ tools: ['http'] }, action), false)
  assert.equal(ruleMatches({ tools: ['http.post.v2'] }, action), false)
  assert.equal(ruleMatches({ tools: ['http.*'] }, action), false)
  assert.equal(ruleMatches({ tools: ['a', 'http.post', 'z'] }, action), true)
  assert.equal(ruleMatches({ effects: ['write'] }, action), true, 'an undeclared tools selector constrains nothing')
})

test('a tools selector must be a non-empty array of non-empty strings', async (t) => {
  for (const tools of [[], ['  '], [42], 'http.post', [null]]) {
    const directory = await workspace(t)
    const { args } = await prepare(
      directory, actionsDocument([externalWrite()]),
      policyDocument({ rules: [{ id: 'bad-tools', tools, decision: 'allowed' }] }),
    )
    const run = await runCli([...args, '--json'])
    const report = JSON.parse(run.stdout)
    assert.equal(run.code, 2, `${JSON.stringify(tools)} must be refused, not quietly ignored`)
    assert.equal(report.status, 'incomplete')
    assert.ok(report.findings.some((finding) => finding.ruleId === 'policy-rule-malformed'))
  }
})
