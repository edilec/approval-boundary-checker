#!/usr/bin/env node

import { writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import { WRITE_NO_FOLLOW, assertWritableDestination } from '../src/destination.mjs'
import {
  TIMESTAMP_PATTERN, assembleDecisions, checkApprovalBoundaryWithSources, formatReport, parseTimestamp,
} from '../src/index.mjs'

const HELP = `approval-boundary-checker

Classify the actions a plan DECLARES against a permission, data and side-effect
policy: allowed, requires-approval, denied, or matched by no rule at all.

This tool executes nothing. An action is a record in a document; the checker
never opens a path an action names, never spawns a process and never reaches a
network. The only files it opens are the ones named below.

Usage:
  approval-boundary-checker --actions FILE --policy FILE
                            [--now INSTANT] [--decisions-out FILE]
                            [--json] [limits]

Options:
  --actions FILE         Declared action plan to classify (required)
  --policy FILE          Policy rules to classify it against (required)
  --now INSTANT          ISO 8601 UTC instant used to judge approval expiry,
                         for example 2026-09-14T08:30:00Z. Without it the
                         system clock is read, and the verdict then depends on
                         when you ran it -- pass this for a reproducible run
  --decisions-out FILE   Write the per-action verdicts as JSON. Nothing is
                         written when the run is incomplete, because an
                         incomplete run produces no verdicts.

                         THIS DESTINATION IS NOT CONFINED TO ANY ROOT. This
                         tool reads two files you name and walks no tree, so it
                         has no root for a destination to escape from, and a
                         symbolically linked PARENT directory is followed here
                         exactly as it is by cp or a shell redirect. What is
                         refused: a destination that is itself a symbolic link,
                         a destination that is not a regular file, and a
                         destination that is the same file as an input --
                         including a hard link to one, which shares no path
                         with it and is caught by device and inode. The parent
                         directory must already exist: this tool creates no
                         directories, because creating one is how a guard that
                         runs after mkdir -p leaves a trail somewhere nobody
                         named
  --json                 Emit the machine-readable report on stdout
  --max-actions N        Maximum actions in a plan (default 2000)
  --max-actions-bytes N  Maximum actions document size (default 2097152)
  --max-policy-bytes N   Maximum policy document size (default 1048576)
  --max-rules N          Maximum rules in a policy (default 500)
  --timeout-ms N         Time budget for the whole run (default 10000; 0 leaves
                         no time at all and is only useful for proving the
                         budget is enforced)
  -h, --help             Show this help

How a decision is reached:

  Every rule whose declared selectors all match the action is collected, and
  the STRICTEST of their decisions wins: denied beats requires-approval beats
  allowed. Rule order in the document therefore changes nothing, and adding a
  rule can only tighten a policy.

  An action no rule selects takes the policy's "defaultDecision", which accepts
  only "requires-approval" or "denied". A policy asking to default to "allowed"
  is refused as malformed.

What cannot happen:

  - An unmatched action is never cleared. It defaults to review or denial, and
    "allowed" is not a value the default field accepts.
  - An approval never lifts a denial. A denied action stays denied.
  - An approval record that exists but cannot be read reports
    approval-malformed, never approval-missing. They are different problems and
    the second sends an operator to fetch something they already have.
  - Unknown evidence is never a pass. An unreadable, undecodable, unparseable
    or uninterpretable document, a limit reached, a time budget expired, or a
    plan declaring no actions at all, each produce an "incomplete" report with
    NO per-action verdicts, and exit 2.

Every option is accepted once; a repeated flag is a configuration error rather
than a silent last-wins. An unknown option is refused rather than ignored.

Exit codes:
  0  every declared action is cleared by the policy
  1  at least one action is stopped: denied, or needing an approval it does not
     have
  2  invalid usage (no report on stdout), or evidence that was missing,
     undecodable or bounded out (an "incomplete" report on stdout)
`

const LIMIT_FLAGS = new Map([
  ['--max-actions', 'maxActions'],
  ['--max-actions-bytes', 'maxActionsBytes'],
  ['--max-policy-bytes', 'maxPolicyBytes'],
  ['--max-rules', 'maxRules'],
  ['--timeout-ms', 'timeoutMs'],
])

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  const options = { actions: null, policy: null, now: null, decisionsOut: null, json: false, limits: {} }
  const given = new Set()

  /**
   * A flag that carries a value is accepted once.
   *
   * Letting it repeat discards the earlier value with no diagnostic, so
   * `--policy strict.json --policy scratch.json` checks against a policy nobody
   * asked for. That is the same defect as an ignored typo, which this tool
   * already refuses.
   */
  const once = (name) => {
    if (given.has(name)) throw new Error(`${name} was given more than once`)
    given.add(name)
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }

    if (argument === '--json') {
      once('--json')
      options.json = true
    } else if (argument === '--actions') {
      once('--actions')
      options.actions = takeValue('--actions')
    } else if (argument === '--policy') {
      once('--policy')
      options.policy = takeValue('--policy')
    } else if (argument === '--decisions-out') {
      once('--decisions-out')
      options.decisionsOut = takeValue('--decisions-out')
    } else if (argument === '--now') {
      once('--now')
      const raw = takeValue('--now')
      if (parseTimestamp(raw) === null) {
        throw new Error(`--now must be an ISO 8601 UTC instant matching ${TIMESTAMP_PATTERN.source}`)
      }
      options.now = parseTimestamp(raw)
    } else if (LIMIT_FLAGS.has(argument)) {
      once(argument)
      const raw = takeValue(argument)
      const minimum = argument === '--timeout-ms' ? 0 : 1
      if (!/^\d+$/.test(raw) || Number(raw) < minimum) {
        throw new Error(`${argument} requires an integer of ${minimum} or more`)
      }
      options.limits[LIMIT_FLAGS.get(argument)] = Number(raw)
    } else throw new Error(`Unknown option "${argument}"`)
  }

  if (options.actions === null) throw new Error('--actions is required')
  if (options.policy === null) throw new Error('--policy is required')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }

  // Which clock decided expiry is a diagnostic, not data: it goes to stderr so
  // stdout stays parseable, but it is never left unsaid, because a run whose
  // approvals expired against a clock the operator forgot about is exactly the
  // run that reports the wrong verdict.
  process.stderr.write(
    options.now === null
      ? 'approval expiry judged against the system clock; pass --now for a reproducible verdict\n'
      : `approval expiry judged against --now ${new Date(options.now).toISOString()}\n`,
  )

  let report
  let sources
  try {
    ;({ report, sources } = await checkApprovalBoundaryWithSources({
      actions: options.actions,
      policy: options.policy,
      limits: options.limits,
      ...(options.now === null ? {} : { now: () => options.now }),
    }))
  } catch (error) {
    process.stderr.write(`${error.message}\n`)
    return 2
  }

  if (options.decisionsOut !== null) {
    const assembled = assembleDecisions(report)
    if (assembled === null) {
      process.stderr.write('The run is incomplete, so it produced no verdicts and nothing was written to --decisions-out.\n')
    } else {
      /**
       * The destination is checked here, with the run finished, because only
       * now is the list of files this run read complete. A destination that
       * turns out to be one of them -- by name, through a symbolic link, or as
       * a hard link that shares no name with it at all -- is refused, and
       * refusing means nothing is written and no report reaches stdout. A
       * configuration that would destroy an input is not a configuration to
       * carry on with.
       *
       * `root` is null and that is a real answer, not a shortcut: this tool
       * reads exactly the files named on its command line and walks no tree, so
       * there is no root for a destination to escape from. Inventing one would
       * refuse legitimate absolute destinations, and refusing every symbolically
       * linked ancestor would refuse every run under the macOS temp directory,
       * where /var is itself a link. The help text and the README say so.
       */
      const destination = resolve(options.decisionsOut)
      let target
      try {
        target = await assertWritableDestination(destination, {
          inputs: sources,
          root: null,
          label: '--decisions-out',
        })
      } catch (error) {
        process.stderr.write(`${error.message}\n`)
        return 2
      }
      try {
        await writeFile(target, `${JSON.stringify(assembled, null, 2)}\n`, { encoding: 'utf8', flag: WRITE_NO_FOLLOW })
      } catch (error) {
        process.stderr.write(`--decisions-out could not be written: ${error.code ?? error.message}\n`)
        return 2
      }
      process.stderr.write(`wrote ${assembled.decisions.length} verdict(s) to the decisions destination\n`)
    }
  }

  process.stdout.write(options.json ? `${JSON.stringify(report, null, 2)}\n` : formatReport(report))

  if (report.status === 'incomplete') {
    process.stderr.write(
      `incomplete: ${report.summary.unexamined} declared action(s) were not checked, so no verdict was produced.\n`,
    )
    return 2
  }
  return report.status === 'fail' ? 1 : 0
}

process.exitCode = await main(process.argv.slice(2))
