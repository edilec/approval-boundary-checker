/**
 * The vocabulary, the document validators and the classification rule.
 *
 * Everything in this module is a pure function of its arguments. It reads no
 * file, opens no socket, spawns no process and performs none of the actions it
 * classifies -- an action is a record in a document here, never a thing to do.
 */

import { byCodeUnit, escapePointerSegment, sanitize } from './text.mjs'

/**
 * The closed vocabularies.
 *
 * Closed on purpose. An open vocabulary means a typo -- `externel`, `wirte` --
 * produces an action no rule selects, which then falls through to the default
 * decision and looks like a deliberate policy gap rather than the misspelling
 * it is. Every unknown token is a malformed document instead.
 */
export const EFFECTS = Object.freeze(['delete', 'execute', 'read', 'send', 'write'])
export const SCOPES = Object.freeze(['external', 'local', 'workspace'])
export const DATA_CLASSES = Object.freeze(['confidential', 'internal', 'personal', 'public', 'secret'])
export const RULE_DECISIONS = Object.freeze(['allowed', 'denied', 'requires-approval'])

/**
 * What an action with no matching rule becomes.
 *
 * `allowed` is deliberately absent, and its absence is the point. A policy
 * whose default is "allow" turns every action nobody thought about into a pass,
 * which is the exact defect this catalog keeps finding: unknown reported as a
 * pass. A document asking for it is refused as malformed rather than honoured.
 */
export const DEFAULT_DECISIONS = Object.freeze(['denied', 'requires-approval'])

/**
 * How several matching rules combine.
 *
 * The strictest matching decision wins, so rule order in the document does not
 * affect the outcome and a permissive rule can never cancel a restrictive one.
 * That is what makes the classification deterministic without the document
 * having to declare a precedence, and it means adding a rule can only ever
 * tighten a policy.
 */
export const STRICTNESS = Object.freeze({ allowed: 0, 'requires-approval': 1, denied: 2 })

export const ACTIONS_SCHEMA_VERSION = '1'
export const POLICY_SCHEMA_VERSION = '1'

export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/**
 * Timestamps are accepted only in strict ISO 8601 UTC form.
 *
 * `Date.parse` on anything else is implementation-defined, so `03/04/2026`
 * means two different days on two correct engines and the same approval is
 * expired on one machine and live on the other. A timestamp that decides
 * whether a side effect is permitted may not be ambiguous.
 */
export const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/

const ACTION_KEYS = Object.freeze([
  'approval', 'dataClasses', 'description', 'effect', 'id', 'reversible', 'scope', 'target', 'tool',
])
const APPROVAL_KEYS = Object.freeze(['actionId', 'approvedAt', 'approvedBy', 'expiresAt', 'note'])
const RULE_KEYS = Object.freeze(['dataClasses', 'decision', 'description', 'effects', 'id', 'scopes', 'tools'])
const SELECTOR_KEYS = Object.freeze(['dataClasses', 'effects', 'scopes', 'tools'])

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function problem(ruleId, pointer, message, extra = {}) {
  return { ruleId, pointer, message, ...extra }
}

/** Parse a strict ISO 8601 UTC instant, or return null. Never throws. */
export function parseTimestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) return null
  const millis = Date.parse(value)
  return Number.isFinite(millis) ? millis : null
}

function readStringList(container, key, allowed, pointer, ruleIdForProblem, problems, { required }) {
  const raw = container[key]
  if (raw === undefined) {
    if (required) {
      problems.push(problem(ruleIdForProblem, pointer, `"${key}" is required and was not declared.`))
    }
    return null
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    problems.push(problem(ruleIdForProblem, `${pointer}/${key}`, `"${key}" must be a non-empty array.`))
    return null
  }
  const seen = new Set()
  const values = []
  let ok = true
  for (const entry of raw) {
    if (typeof entry !== 'string' || !allowed.includes(entry)) {
      problems.push(problem(
        ruleIdForProblem,
        `${pointer}/${key}`,
        `"${key}" contains ${typeof entry === 'string' ? `"${sanitize(entry, 40)}"` : 'a non-string entry'}, `
        + `which is not one of: ${allowed.join(', ')}.`,
      ))
      ok = false
      continue
    }
    if (seen.has(entry)) {
      problems.push(problem(ruleIdForProblem, `${pointer}/${key}`, `"${key}" lists "${sanitize(entry, 40)}" twice.`))
      ok = false
      continue
    }
    seen.add(entry)
    values.push(entry)
  }
  if (!ok) return null
  values.sort(byCodeUnit)
  return values
}

/**
 * Validate one approval record.
 *
 * The distinction this function exists to preserve: an approval record that is
 * present but unreadable is NOT the same as no approval record. Reporting the
 * second when the first happened tells an operator to go and get an approval
 * that already exists, and hides the real problem, which is that the one they
 * have is malformed. The caller gets `state: 'malformed'` with a reason, and
 * `state: 'absent'` only when the action really declared nothing.
 */
export function validateApproval(action, pointer) {
  const raw = action.approval
  if (raw === undefined) return { state: 'absent' }
  if (!isPlainObject(raw)) {
    return { state: 'malformed', reason: 'the "approval" field is not an object' }
  }
  for (const key of Object.keys(raw)) {
    if (!APPROVAL_KEYS.includes(key)) {
      return { state: 'malformed', reason: `"approval" declares the unknown key "${sanitize(key, 40)}"` }
    }
  }
  if (typeof raw.approvedBy !== 'string' || raw.approvedBy.trim() === '') {
    return { state: 'malformed', reason: '"approval.approvedBy" is missing or not a non-empty string' }
  }
  const approvedAt = parseTimestamp(raw.approvedAt)
  if (approvedAt === null) {
    return {
      state: 'malformed',
      reason: '"approval.approvedAt" is not an ISO 8601 UTC instant such as 2026-09-14T08:30:00Z',
    }
  }
  let expiresAt = null
  if (raw.expiresAt !== undefined) {
    expiresAt = parseTimestamp(raw.expiresAt)
    if (expiresAt === null) {
      return {
        state: 'malformed',
        reason: '"approval.expiresAt" is not an ISO 8601 UTC instant such as 2026-09-14T08:30:00Z',
      }
    }
    if (expiresAt < approvedAt) {
      return { state: 'malformed', reason: '"approval.expiresAt" is earlier than "approval.approvedAt"' }
    }
  }
  if (raw.actionId !== undefined && raw.actionId !== action.id) {
    return {
      state: 'mismatched',
      reason: `the approval names action "${sanitize(raw.actionId, 64)}" but is attached to "${sanitize(action.id, 64)}"`,
    }
  }
  if (raw.note !== undefined && typeof raw.note !== 'string') {
    return { state: 'malformed', reason: '"approval.note" is not a string' }
  }
  void pointer
  return { state: 'present', approvedBy: raw.approvedBy, approvedAt, expiresAt }
}

/**
 * Validate the actions document.
 *
 * `dataClasses` is required and non-empty on every action, which looks strict
 * until you consider the alternative: an action that declares no data classes
 * cannot be selected by any data-class rule, so a policy denying secret egress
 * silently fails to apply to the one action that forgot to say what it carries.
 * "I did not say" must not be a way to slip past a data rule, so the document
 * has to say `["public"]` out loud.
 */
export function validateActionsDocument(document) {
  const problems = []
  if (!isPlainObject(document)) {
    problems.push(problem('actions-malformed', '', 'The actions document is not a JSON object.'))
    return { actions: [], problems }
  }
  for (const key of Object.keys(document)) {
    if (key !== 'schemaVersion' && key !== 'actions') {
      problems.push(problem('actions-malformed', '', `The actions document declares the unknown key "${sanitize(key, 40)}".`))
    }
  }
  if (document.schemaVersion !== ACTIONS_SCHEMA_VERSION) {
    problems.push(problem(
      'actions-schema-unsupported',
      '/schemaVersion',
      `This tool reads actions schemaVersion "${ACTIONS_SCHEMA_VERSION}"; the document declares `
      + `${document.schemaVersion === undefined ? 'none' : `"${sanitize(document.schemaVersion, 40)}"`}.`,
    ))
    return { actions: [], problems }
  }
  if (!Array.isArray(document.actions)) {
    problems.push(problem('actions-malformed', '/actions', '"actions" must be an array.'))
    return { actions: [], problems }
  }

  const actions = []
  const seenIds = new Set()
  for (let index = 0; index < document.actions.length; index += 1) {
    const raw = document.actions[index]
    const indexPointer = `/actions/${index}`
    if (!isPlainObject(raw)) {
      problems.push(problem('action-malformed', indexPointer, 'An action entry is not a JSON object.'))
      continue
    }
    const hasUsableId = typeof raw.id === 'string' && ID_PATTERN.test(raw.id)
    const pointer = hasUsableId ? `/actions/${escapePointerSegment(raw.id)}` : indexPointer
    let ok = true
    if (!hasUsableId) {
      problems.push(problem(
        'action-malformed',
        `${indexPointer}/id`,
        `"id" must match ${ID_PATTERN.source}; the entry declares `
        + `${raw.id === undefined ? 'none' : `"${sanitize(raw.id, 64)}"`}.`,
      ))
      ok = false
    } else if (seenIds.has(raw.id)) {
      problems.push(problem('action-duplicate-id', pointer, `Two actions share the id "${sanitize(raw.id, 64)}".`))
      ok = false
    }
    for (const key of Object.keys(raw)) {
      if (!ACTION_KEYS.includes(key)) {
        problems.push(problem('action-unknown-key', pointer, `The action declares the unknown key "${sanitize(key, 40)}".`))
        ok = false
      }
    }
    if (typeof raw.tool !== 'string' || raw.tool.trim() === '') {
      problems.push(problem('action-malformed', `${pointer}/tool`, '"tool" is required and must be a non-empty string.'))
      ok = false
    }
    if (typeof raw.effect !== 'string' || !EFFECTS.includes(raw.effect)) {
      problems.push(problem(
        'action-malformed',
        `${pointer}/effect`,
        `"effect" must be one of: ${EFFECTS.join(', ')}.`,
      ))
      ok = false
    }
    if (typeof raw.scope !== 'string' || !SCOPES.includes(raw.scope)) {
      problems.push(problem('action-malformed', `${pointer}/scope`, `"scope" must be one of: ${SCOPES.join(', ')}.`))
      ok = false
    }
    const dataClasses = readStringList(raw, 'dataClasses', DATA_CLASSES, pointer, 'action-malformed', problems, { required: true })
    if (dataClasses === null) ok = false
    if (raw.reversible !== undefined && typeof raw.reversible !== 'boolean') {
      problems.push(problem('action-malformed', `${pointer}/reversible`, '"reversible" must be a boolean.'))
      ok = false
    }
    for (const key of ['description', 'target']) {
      if (raw[key] !== undefined && typeof raw[key] !== 'string') {
        problems.push(problem('action-malformed', `${pointer}/${key}`, `"${key}" must be a string.`))
        ok = false
      }
    }
    if (hasUsableId) seenIds.add(raw.id)
    if (!ok) continue
    actions.push({
      id: raw.id,
      tool: raw.tool,
      effect: raw.effect,
      scope: raw.scope,
      dataClasses,
      reversible: raw.reversible,
      target: raw.target,
      approval: raw.approval,
      pointer,
    })
  }
  return { actions, problems }
}

/**
 * Validate the policy document.
 *
 * A rule with no selector at all is refused. It would match every action, so a
 * single `{"decision": "allowed"}` entry silently turns the whole policy into a
 * rubber stamp, and nothing else in the document would look wrong.
 */
export function validatePolicyDocument(document) {
  const problems = []
  if (!isPlainObject(document)) {
    problems.push(problem('policy-malformed', '', 'The policy document is not a JSON object.'))
    return { rules: [], defaultDecision: null, problems }
  }
  for (const key of Object.keys(document)) {
    if (key !== 'schemaVersion' && key !== 'defaultDecision' && key !== 'rules') {
      problems.push(problem('policy-malformed', '', `The policy document declares the unknown key "${sanitize(key, 40)}".`))
    }
  }
  if (document.schemaVersion !== POLICY_SCHEMA_VERSION) {
    problems.push(problem(
      'policy-schema-unsupported',
      '/schemaVersion',
      `This tool reads policy schemaVersion "${POLICY_SCHEMA_VERSION}"; the document declares `
      + `${document.schemaVersion === undefined ? 'none' : `"${sanitize(document.schemaVersion, 40)}"`}.`,
    ))
    return { rules: [], defaultDecision: null, problems }
  }
  let defaultDecision = null
  if (typeof document.defaultDecision !== 'string' || !DEFAULT_DECISIONS.includes(document.defaultDecision)) {
    problems.push(problem(
      'policy-malformed',
      '/defaultDecision',
      `"defaultDecision" must be one of: ${DEFAULT_DECISIONS.join(', ')}. `
      + '"allowed" is not offered: a default that allows every action nobody wrote a rule for reports '
      + 'unknown as a pass, which is what this check exists to prevent.',
    ))
  } else defaultDecision = document.defaultDecision
  if (!Array.isArray(document.rules)) {
    problems.push(problem('policy-malformed', '/rules', '"rules" must be an array.'))
    return { rules: [], defaultDecision, problems }
  }

  const rules = []
  const seenIds = new Set()
  for (let index = 0; index < document.rules.length; index += 1) {
    const raw = document.rules[index]
    const indexPointer = `/rules/${index}`
    if (!isPlainObject(raw)) {
      problems.push(problem('policy-rule-malformed', indexPointer, 'A rule entry is not a JSON object.'))
      continue
    }
    const hasUsableId = typeof raw.id === 'string' && ID_PATTERN.test(raw.id)
    const pointer = hasUsableId ? `/rules/${escapePointerSegment(raw.id)}` : indexPointer
    let ok = true
    if (!hasUsableId) {
      problems.push(problem(
        'policy-rule-malformed',
        `${indexPointer}/id`,
        `"id" must match ${ID_PATTERN.source}; the entry declares `
        + `${raw.id === undefined ? 'none' : `"${sanitize(raw.id, 64)}"`}.`,
      ))
      ok = false
    } else if (seenIds.has(raw.id)) {
      problems.push(problem('policy-rule-duplicate-id', pointer, `Two rules share the id "${sanitize(raw.id, 64)}".`))
      ok = false
    }
    for (const key of Object.keys(raw)) {
      if (!RULE_KEYS.includes(key)) {
        problems.push(problem('policy-rule-malformed', pointer, `The rule declares the unknown key "${sanitize(key, 40)}".`))
        ok = false
      }
    }
    if (typeof raw.decision !== 'string' || !RULE_DECISIONS.includes(raw.decision)) {
      problems.push(problem('policy-rule-malformed', `${pointer}/decision`, `"decision" must be one of: ${RULE_DECISIONS.join(', ')}.`))
      ok = false
    }
    const effects = raw.effects === undefined ? undefined
      : readStringList(raw, 'effects', EFFECTS, pointer, 'policy-rule-malformed', problems, { required: false })
    const scopes = raw.scopes === undefined ? undefined
      : readStringList(raw, 'scopes', SCOPES, pointer, 'policy-rule-malformed', problems, { required: false })
    const dataClasses = raw.dataClasses === undefined ? undefined
      : readStringList(raw, 'dataClasses', DATA_CLASSES, pointer, 'policy-rule-malformed', problems, { required: false })
    if (effects === null || scopes === null || dataClasses === null) ok = false
    let tools
    if (raw.tools !== undefined) {
      if (!Array.isArray(raw.tools) || raw.tools.length === 0
        || raw.tools.some((entry) => typeof entry !== 'string' || entry.trim() === '')) {
        problems.push(problem('policy-rule-malformed', `${pointer}/tools`, '"tools" must be a non-empty array of non-empty strings.'))
        ok = false
      } else tools = [...raw.tools].sort(byCodeUnit)
    }
    if (raw.description !== undefined && typeof raw.description !== 'string') {
      problems.push(problem('policy-rule-malformed', `${pointer}/description`, '"description" must be a string.'))
      ok = false
    }
    const declaredSelectors = SELECTOR_KEYS.filter((key) => raw[key] !== undefined)
    if (declaredSelectors.length === 0) {
      problems.push(problem(
        'policy-rule-unselective',
        pointer,
        `The rule declares none of ${SELECTOR_KEYS.join(', ')}, so it matches every action. `
        + 'A catch-all rule makes the rest of the policy unreachable and is refused.',
      ))
      ok = false
    }
    if (hasUsableId) seenIds.add(raw.id)
    if (!ok) continue
    rules.push({ id: raw.id, decision: raw.decision, effects, scopes, dataClasses, tools, pointer })
  }
  return { rules, defaultDecision, problems }
}

/** Does one rule select this action? Every declared selector must be satisfied. */
export function ruleMatches(rule, action) {
  if (rule.effects !== undefined && !rule.effects.includes(action.effect)) return false
  if (rule.scopes !== undefined && !rule.scopes.includes(action.scope)) return false
  if (rule.tools !== undefined && !rule.tools.includes(action.tool)) return false
  if (rule.dataClasses !== undefined && !action.dataClasses.some((entry) => rule.dataClasses.includes(entry))) return false
  return true
}

/**
 * Classify one action against the whole rule set.
 *
 * Returns the matched rule ids as well as the decision, because "why" is the
 * product here. An approval queue that says `requires-approval` without naming
 * the rule that said so cannot be reviewed, only obeyed.
 */
export function classifyAction(action, rules, defaultDecision) {
  const matchedRules = []
  let decision = null
  for (const rule of rules) {
    if (!ruleMatches(rule, action)) continue
    matchedRules.push(rule.id)
    if (decision === null || STRICTNESS[rule.decision] > STRICTNESS[decision]) decision = rule.decision
  }
  matchedRules.sort(byCodeUnit)
  if (decision === null) return { decision: defaultDecision, matchedRules, unmatched: true }
  return { decision, matchedRules, unmatched: false }
}
