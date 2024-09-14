/**
 * approval-boundary-checker
 *
 * Reads a document of DECLARED actions and a document of policy rules, and says
 * for each action whether it is allowed outright, needs a human approval, is
 * denied, or matched no rule at all. It is static analysis of configuration:
 * the only files it ever opens are the ones named on its own command line.
 *
 * Four properties are structural rather than incidental:
 *
 * 1. **Nothing is executed.** An action is a record, never a thing to do. This
 *    tool opens no path an action names, spawns no process, and reaches no
 *    network -- `node:child_process`, `node:vm`, the network modules, `eval`
 *    and `new Function` appear nowhere in its source, and `test/no-execution.
 *    test.mjs` proves the observable half of that by running the CLI over a plan
 *    of destructive actions inside a workspace and asserting the workspace is
 *    byte-identical afterwards.
 * 2. **An unmatched action is never allowed.** An action no rule selects takes
 *    the policy's `defaultDecision`, and the only values that field accepts are
 *    `requires-approval` and `denied`. A policy asking to default to `allowed`
 *    is refused as malformed, so there is no arrangement of inputs in which an
 *    action nobody wrote a rule for comes back cleared.
 * 3. **An approval cannot lift a denial, and unknown approval evidence is not
 *    an approval.** A denied action stays denied however many approvals it
 *    carries. An approval record that is present but unreadable reports
 *    `approval-malformed`, never `approval-missing`: telling an operator to go
 *    and get an approval that already exists hides the real defect.
 * 4. **Unknown evidence is never a pass.** A document that could not be read,
 *    decoded, parsed or interpreted, a limit reached, or a time budget expired
 *    makes the run `incomplete`, emits NO per-action verdicts at all, and exits
 *    2. A boundary check is a verdict on a whole plan; half a verdict is not a
 *    smaller answer, it is a wrong one.
 */

import { readFile } from 'node:fs/promises'
import { basename } from 'node:path'

import {
  ACTIONS_SCHEMA_VERSION, DATA_CLASSES, DEFAULT_DECISIONS, EFFECTS, ID_PATTERN, POLICY_SCHEMA_VERSION,
  RULE_DECISIONS, SCOPES, STRICTNESS, TIMESTAMP_PATTERN, classifyAction, parseTimestamp, ruleMatches,
  validateActionsDocument, validateApproval, validatePolicyDocument,
} from './policy.mjs'
import { byCodeUnit, decodeUtf8, escapePointerSegment, parseFailureDetail, sanitize } from './text.mjs'

export {
  ACTIONS_SCHEMA_VERSION, DATA_CLASSES, DEFAULT_DECISIONS, EFFECTS, ID_PATTERN, POLICY_SCHEMA_VERSION,
  RULE_DECISIONS, SCOPES, STRICTNESS, TIMESTAMP_PATTERN, classifyAction, parseTimestamp, ruleMatches,
  validateActionsDocument, validateApproval, validatePolicyDocument,
} from './policy.mjs'
export { CONTROL_CLASSES, byCodeUnit, decodeUtf8, escapePointerSegment, parseFailureDetail, sanitize } from './text.mjs'
export { DestinationError, assertWritableDestination } from './destination.mjs'

export const TOOL_ID = 'approval-boundary-checker'
export const REPORT_SCHEMA_VERSION = '1'
export const DECISIONS_SCHEMA_VERSION = '1'

/**
 * Bounds are part of the contract, not a safety net.
 *
 * An actions document is ordinary untrusted input: it can declare a hundred
 * thousand actions or arrive as a 40 MB generated file. Every limit is
 * explicit, overridable from the command line, and named in the finding when it
 * is reached. Exceeding one produces an `incomplete` report with no verdicts --
 * never a quietly shorter check, and never a pass.
 *
 * `timeoutMs` accepts 0, and 0 means "no time at all": the first check fires.
 * That is the only way to prove from the outside that the flag is wired through
 * to the classification loop at all, and a documented limit the command line
 * never reaches is a defect this catalog has already shipped once.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxActions: 2000,
  maxActionsBytes: 2097152,
  maxPolicyBytes: 1048576,
  maxRules: 500,
  timeoutMs: 10000,
})

/**
 * The authoritative rule severity table.
 *
 * Severity decides whether a run refuses. Spread across construction sites as a
 * literal it drifts silently, so every finding takes its severity from here and
 * an unknown rule id throws.
 *
 * This table is the source of truth. It is **not** the guard. Three
 * declarations agreeing with each other -- this table, the README's rule table,
 * and an expected-value map written out again in a test -- are all satisfied by
 * one coordinated edit. The guard is `test/severity-outcomes.test.mjs`, which
 * drives each rule through the real entry point and asserts the observable
 * outcome (`'fail'`, `'incomplete'`, exit `1`, exit `2`) as a literal at the
 * assertion site. An edit here has nothing there to agree with.
 */
export const RULE_SEVERITY = Object.freeze({
  'action-denied': 'error',
  'action-duplicate-id': 'error',
  'action-malformed': 'error',
  'action-unknown-key': 'error',
  'action-unmatched': 'warning',
  'actions-malformed': 'error',
  'actions-not-json': 'error',
  'actions-not-utf8': 'error',
  'actions-schema-unsupported': 'error',
  'actions-too-large': 'error',
  'actions-unreadable': 'error',
  'approval-expired': 'error',
  'approval-malformed': 'error',
  'approval-missing': 'error',
  'approval-scope-mismatch': 'error',
  'approval-superfluous': 'info',
  'no-actions': 'warning',
  'policy-malformed': 'error',
  'policy-not-json': 'error',
  'policy-not-utf8': 'error',
  'policy-rule-duplicate-id': 'error',
  'policy-rule-malformed': 'error',
  'policy-rule-unselective': 'error',
  'policy-schema-unsupported': 'error',
  'policy-too-large': 'error',
  'policy-unreadable': 'error',
  'time-budget-exceeded': 'error',
  'too-many-actions': 'error',
  'too-many-rules': 'error',
})

/** The logical input names that appear in `location.file`. */
export const INPUT_NAMES = Object.freeze(['actions', 'policy'])

class Findings {
  constructor() {
    this.entries = []
  }

  add(ruleId, file, pointer, message, extra = {}) {
    const severity = RULE_SEVERITY[ruleId]
    if (severity === undefined) throw new Error(`No severity is declared for rule "${ruleId}"`)
    if (!INPUT_NAMES.includes(file)) throw new Error(`No such logical input "${file}"`)
    const finding = {
      ruleId,
      severity,
      message: sanitize(message, 400),
      location: { file, ...(pointer === '' ? {} : { pointer: sanitize(pointer, 200) }) },
    }
    if (extra.evidence !== undefined) finding.evidence = sanitize(extra.evidence, 160)
    if (extra.suggestion !== undefined) finding.suggestion = sanitize(extra.suggestion, 240)
    this.entries.push(finding)
    return finding
  }

  /**
   * Sorted by `(location.file, location.pointer, ruleId, message)`.
   *
   * The message is the last tiebreak so that two findings differing only in
   * their message still have one fixed order; without it the pre-sort order,
   * which is emission order, would decide, and emission order is an
   * implementation detail nobody documented.
   */
  sorted() {
    return [...this.entries].sort((left, right) =>
      byCodeUnit(left.location.file, right.location.file)
      || byCodeUnit(left.location.pointer ?? '', right.location.pointer ?? '')
      || byCodeUnit(left.ruleId, right.ruleId)
      || byCodeUnit(left.message, right.message))
  }
}

function validateLimits(overrides) {
  const limits = { ...DEFAULT_LIMITS }
  for (const [key, value] of Object.entries(overrides)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) throw new TypeError(`Unknown limit "${key}"`)
    const minimum = key === 'timeoutMs' ? 0 : 1
    if (!Number.isInteger(value) || value < minimum) {
      throw new TypeError(`Limit "${key}" must be an integer of ${minimum} or more`)
    }
    limits[key] = value
  }
  return Object.freeze(limits)
}

/**
 * Read one JSON document, recording the path as a source BEFORE opening it.
 *
 * The recording happens first on purpose. The list of files this run read is
 * what `--decisions-out` is checked against, and a file recorded only after a
 * successful read leaves every file that threw off that list -- which is
 * exactly the file a destination is most likely to collide with when something
 * has already gone wrong.
 */
async function readJsonDocument(path, file, maxBytes, findings, sources) {
  sources.push(path)
  let bytes
  try {
    bytes = await readFile(path)
  } catch (error) {
    findings.add(`${file}-unreadable`, file, '', `The ${file} document could not be read: ${error.code ?? 'unknown error'}.`)
    return { ok: false }
  }
  if (bytes.byteLength > maxBytes) {
    findings.add(
      `${file}-too-large`, file, '',
      `The ${file} document is ${bytes.byteLength} bytes, over the ${maxBytes} byte limit.`,
      { suggestion: `Raise --max-${file}-bytes, or split the document.` },
    )
    return { ok: false }
  }
  const decoded = decodeUtf8(bytes)
  if (!decoded.ok) {
    findings.add(`${file}-not-utf8`, file, '', `The ${file} document is not valid UTF-8, so it was not decoded.`)
    return { ok: false }
  }
  try {
    return { ok: true, document: JSON.parse(decoded.text) }
  } catch (error) {
    findings.add(`${file}-not-json`, file, '', `The ${file} document is not valid JSON: ${parseFailureDetail(error)}.`)
    return { ok: false }
  }
}

/**
 * Invariants re-checked on every report before it leaves the library.
 *
 * These are not tests; they run in production. They exist because the defect
 * this catalog keeps finding is a `pass` that nobody defended, and an assertion
 * at the exit of the only function that builds a report is the one place that
 * sees every path into it at once.
 */
export function assertReportInvariants(report) {
  const violations = []
  if (report.status === 'pass' && report.summary.checked === 0) {
    violations.push('a pass was produced with nothing checked')
  }
  if (report.status === 'pass' && report.summary.errors > 0) {
    violations.push('a pass was produced with error findings')
  }
  if (report.status === 'incomplete' && report.decisions.length > 0) {
    violations.push('an incomplete run produced per-action verdicts')
  }
  if (report.status !== 'incomplete' && report.summary.unexamined > 0) {
    violations.push('a complete run left actions unexamined')
  }
  for (const finding of report.findings) {
    if (finding.severity !== RULE_SEVERITY[finding.ruleId]) {
      violations.push(`finding "${finding.ruleId}" carries a severity the table does not declare`)
    }
  }
  /**
   * The cross-check that matters: an action cleared as `allowed` must carry no
   * error finding of its own. Without it `outcome` is just a second opinion
   * computed beside the findings, and the two could drift apart -- which is how
   * a report ends up saying `stopped` in its summary and `allowed` in the row a
   * queue actually reads.
   */
  const faulted = new Set(
    report.findings
      .filter((finding) => finding.severity === 'error' && finding.location.file === 'actions')
      .map((finding) => finding.location.pointer ?? ''),
  )
  for (const entry of report.decisions) {
    if (entry.outcome === 'allowed' && faulted.has(`/actions/${entry.id}`)) {
      violations.push(`action "${entry.id}" was cleared while carrying an error finding`)
    }
    if (entry.decision === 'denied' && entry.outcome !== 'stopped') violations.push(`denied action "${entry.id}" was not stopped`)
  }
  return violations
}

/**
 * Check a declared plan against a policy, returning the report and the list of
 * files the run opened.
 *
 * `now` and `monotonic` are injected and separate on purpose. `now` is the wall
 * clock, and it decides one thing only: whether an approval has passed its
 * `expiresAt`. `monotonic` measures elapsed time for the budget. They cannot be
 * the same injected value in a test, because pinning the wall clock to a fixed
 * instant to make an expiry reproducible would also freeze elapsed time at zero
 * and quietly disable the budget -- which is precisely the shape of "a
 * documented limit the CLI never wired through" that this catalog has shipped
 * before.
 */
export async function checkApprovalBoundaryWithSources(options = {}) {
  const {
    actions: actionsPath, policy: policyPath, limits: limitOverrides = {},
    now = Date.now, monotonic = Date.now,
  } = options
  if (typeof actionsPath !== 'string' || actionsPath === '') throw new TypeError('An actions document path is required')
  if (typeof policyPath !== 'string' || policyPath === '') throw new TypeError('A policy document path is required')
  if (typeof now !== 'function') throw new TypeError('"now" must be a function returning milliseconds')
  if (typeof monotonic !== 'function') throw new TypeError('"monotonic" must be a function returning milliseconds')
  const limits = validateLimits(limitOverrides)

  const findings = new Findings()
  const sources = []
  const started = monotonic()
  const outOfTime = () => monotonic() - started >= limits.timeoutMs

  const inputs = { actions: sanitize(basename(actionsPath), 120), policy: sanitize(basename(policyPath), 120) }
  const finish = (summary, decisions) => {
    const emitted = findings.sorted()
    const counts = { errors: 0, warnings: 0, info: 0 }
    for (const finding of emitted) {
      if (finding.severity === 'error') counts.errors += 1
      else if (finding.severity === 'warning') counts.warnings += 1
      else counts.info += 1
    }
    const incomplete = summary.incomplete
    const status = incomplete ? 'incomplete' : (counts.errors > 0 ? 'fail' : 'pass')
    const report = {
      schemaVersion: REPORT_SCHEMA_VERSION,
      tool: TOOL_ID,
      status,
      inputs,
      summary: {
        declared: summary.declared,
        checked: incomplete ? 0 : decisions.length,
        allowed: incomplete ? 0 : decisions.filter((entry) => entry.outcome === 'allowed').length,
        stopped: incomplete ? 0 : decisions.filter((entry) => entry.outcome === 'stopped').length,
        denied: incomplete ? 0 : decisions.filter((entry) => entry.decision === 'denied').length,
        requiresApproval: incomplete ? 0 : decisions.filter((entry) => entry.decision === 'requires-approval').length,
        unmatched: incomplete ? 0 : decisions.filter((entry) => entry.matchedRules.length === 0).length,
        unexamined: incomplete ? summary.declared : 0,
        errors: counts.errors,
        warnings: counts.warnings,
        info: counts.info,
      },
      decisions: incomplete ? [] : decisions,
      findings: emitted,
    }
    const violations = assertReportInvariants(report)
    if (violations.length > 0) throw new Error(`Report invariant violated: ${violations.join('; ')}`)
    return { report, sources }
  }

  const actionsRead = await readJsonDocument(actionsPath, 'actions', limits.maxActionsBytes, findings, sources)
  const policyRead = await readJsonDocument(policyPath, 'policy', limits.maxPolicyBytes, findings, sources)
  if (!actionsRead.ok || !policyRead.ok) return finish({ declared: 0, incomplete: true }, [])

  const actionsDocument = validateActionsDocument(actionsRead.document)
  for (const entry of actionsDocument.problems) findings.add(entry.ruleId, 'actions', entry.pointer, entry.message)
  const policyDocument = validatePolicyDocument(policyRead.document)
  for (const entry of policyDocument.problems) findings.add(entry.ruleId, 'policy', entry.pointer, entry.message)

  const declared = Array.isArray(actionsRead.document?.actions) ? actionsRead.document.actions.length : 0
  if (actionsDocument.problems.length > 0 || policyDocument.problems.length > 0) {
    return finish({ declared, incomplete: true }, [])
  }
  if (declared > limits.maxActions) {
    findings.add('too-many-actions', 'actions', '/actions', `The document declares ${declared} actions, over the ${limits.maxActions} limit.`)
    return finish({ declared, incomplete: true }, [])
  }
  if (policyDocument.rules.length > limits.maxRules) {
    findings.add('too-many-rules', 'policy', '/rules', `The policy declares ${policyDocument.rules.length} rules, over the ${limits.maxRules} limit.`)
    return finish({ declared, incomplete: true }, [])
  }

  /**
   * A plan with no actions is not a clean plan, it is no evidence at all.
   *
   * `pass` with `checked: 0` is green on nothing, and the commonest way to
   * reach it is a `--actions` path that points at the wrong file. The finding
   * below is a warning, so the `incomplete: true` beside it is the only thing
   * standing between this branch and a green exit 0 -- which is why
   * `test/incomplete.test.mjs` removes it and watches the exit code change.
   */
  if (declared === 0) {
    findings.add(
      'no-actions', 'actions', '/actions',
      'The actions document declares no actions, so this run checked nothing and is reported incomplete rather than clear.',
      { suggestion: 'Check that --actions names the intended plan.' },
    )
    return finish({ declared, incomplete: true }, [])
  }

  const wallNow = now()
  if (!Number.isFinite(wallNow)) throw new TypeError('"now" must return a finite number of milliseconds')

  const decisions = []
  for (const action of actionsDocument.actions) {
    /**
     * Checked BEFORE the action is classified, not after.
     *
     * An expiry noticed after the verdict was appended would leave a decision
     * of record in a run that ran out of time, and `finish` would then have to
     * be trusted to throw it away. It is thrown away here instead, and the
     * whole run is abandoned: every verdict already made is discarded by
     * `incomplete`, so no half-checked plan can be read as a checked one.
     */
    if (outOfTime()) {
      findings.add(
        'time-budget-exceeded', 'actions', '/actions',
        `The ${limits.timeoutMs} ms time budget expired after classifying ${decisions.length} of ${actionsDocument.actions.length} actions, `
        + 'so no verdicts were produced.',
        { suggestion: 'Raise --timeout-ms, or split the plan.' },
      )
      return finish({ declared, incomplete: true }, [])
    }

    const { decision, matchedRules } = classifyAction(action, policyDocument.rules, policyDocument.defaultDecision)
    let errorsHere = 0
    const fail = (ruleId, message, extra) => {
      findings.add(ruleId, 'actions', action.pointer, message, extra)
      errorsHere += 1
    }

    const approval = validateApproval(action, action.pointer)
    let approvalState = 'none'
    if (approval.state === 'malformed') {
      approvalState = 'malformed'
      fail(
        'approval-malformed',
        `Action "${sanitize(action.id, 64)}" carries an approval record that could not be read: ${approval.reason}. `
        + 'An approval nobody can read is not an approval, and this is not the same as no approval being supplied.',
        { suggestion: 'Repair the approval record; do not remove it and re-approve blind.' },
      )
    } else if (approval.state === 'mismatched') {
      approvalState = 'mismatched'
      fail(
        'approval-scope-mismatch',
        `Action "${sanitize(action.id, 64)}" carries an approval scoped to another action: ${approval.reason}.`,
        { suggestion: 'An approval applies only to the action it names.' },
      )
    } else if (approval.state === 'present') {
      approvalState = approval.expiresAt !== null && approval.expiresAt <= wallNow ? 'expired' : 'valid'
    }

    if (matchedRules.length === 0) {
      findings.add(
        'action-unmatched', 'actions', action.pointer,
        `No policy rule selects action "${sanitize(action.id, 64)}" (${sanitize(action.effect, 16)} / ${sanitize(action.scope, 16)} `
        + `via ${sanitize(action.tool, 64)}), so it takes the policy default "${policyDocument.defaultDecision}".`,
        { suggestion: 'Write a rule that says what this action is, rather than leaving it to the default.' },
      )
    }

    if (decision === 'denied') {
      fail(
        'action-denied',
        `Action "${sanitize(action.id, 64)}" is denied by policy (${sanitize(action.effect, 16)} / ${sanitize(action.scope, 16)}, `
        + `data ${action.dataClasses.map((entry) => sanitize(entry, 20)).join('+')}). `
        + (approvalState === 'valid'
          ? 'It carries a valid approval, which does not lift a denial.'
          : 'A denial is not something an approval can lift.'),
        { evidence: matchedRules.length === 0 ? `policy default ${policyDocument.defaultDecision}` : `matched ${matchedRules.join(', ')}` },
      )
    } else if (decision === 'requires-approval') {
      if (approvalState === 'none') {
        fail(
          'approval-missing',
          `Action "${sanitize(action.id, 64)}" requires approval and none was supplied (${sanitize(action.effect, 16)} / `
          + `${sanitize(action.scope, 16)} via ${sanitize(action.tool, 64)}), so it is stopped.`,
          {
            evidence: matchedRules.length === 0 ? `policy default ${policyDocument.defaultDecision}` : `matched ${matchedRules.join(', ')}`,
            suggestion: 'Record an approval on the action, or narrow the action until a rule allows it.',
          },
        )
      } else if (approvalState === 'expired') {
        fail(
          'approval-expired',
          `Action "${sanitize(action.id, 64)}" requires approval and the approval on record has passed its expiry, so it is stopped.`,
          { suggestion: 'Renew the approval.' },
        )
      }
    } else if (approvalState === 'valid' || approvalState === 'expired') {
      findings.add(
        'approval-superfluous', 'actions', action.pointer,
        `Action "${sanitize(action.id, 64)}" is allowed outright, so the approval recorded on it was not needed.`,
        { suggestion: 'Either the policy is wider than intended, or the approval belongs to a different action.' },
      )
    }

    decisions.push({
      id: sanitize(action.id, 64),
      tool: sanitize(action.tool, 64),
      effect: action.effect,
      scope: action.scope,
      dataClasses: action.dataClasses,
      decision,
      matchedRules: matchedRules.map((entry) => sanitize(entry, 64)),
      approval: approvalState,
      outcome: errorsHere > 0 ? 'stopped' : 'allowed',
    })
  }

  decisions.sort((left, right) => byCodeUnit(left.id, right.id))
  return finish({ declared, incomplete: false }, decisions)
}

/** The report alone, for the caller who does not need the list of files read. */
export async function checkApprovalBoundary(options = {}) {
  const { report } = await checkApprovalBoundaryWithSources(options)
  return report
}

/** The per-action verdicts as a standalone document, for `--decisions-out`. */
export function assembleDecisions(report) {
  if (report.status === 'incomplete') return null
  return {
    schemaVersion: DECISIONS_SCHEMA_VERSION,
    tool: TOOL_ID,
    status: report.status,
    decisions: report.decisions,
  }
}

export function formatReport(report) {
  const lines = report.findings.map((finding) =>
    `${finding.severity.toUpperCase().padEnd(7)} ${finding.location.file} ${finding.location.pointer ?? '(document)'} ${finding.ruleId} ${finding.message}`)
  lines.push('')
  for (const entry of report.decisions) {
    lines.push(`${entry.outcome.toUpperCase().padEnd(7)} ${entry.id} ${entry.decision} `
      + `(${entry.effect}/${entry.scope}, approval ${entry.approval}, rules ${entry.matchedRules.join(', ') || 'none'})`)
  }
  if (report.decisions.length > 0) lines.push('')
  lines.push(
    `${report.summary.checked} of ${report.summary.declared} declared action(s) checked: `
    + `${report.summary.allowed} allowed, ${report.summary.stopped} stopped `
    + `(${report.summary.denied} denied, ${report.summary.requiresApproval} needing approval, `
    + `${report.summary.unmatched} matched by no rule). `
    + `${report.summary.errors} error, ${report.summary.warnings} warning, ${report.summary.info} info, status ${report.status}.`,
  )
  if (report.status === 'incomplete') {
    lines.push(
      `This run is incomplete, so it produced no verdicts: ${report.summary.unexamined} declared action(s) were not checked. `
      + 'An incomplete boundary check is not an approval.',
    )
  }
  lines.push('No action was executed. This tool classifies declared actions and performs none of them.')
  return `${lines.join('\n')}\n`
}
