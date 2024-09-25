# approval-boundary-checker

Classify the actions an agent plan **declares** against a permission, data and
side-effect policy: allowed, requires-approval, denied, or matched by no rule at
all — with the rules that decided it attached to every verdict.

This is static analysis of configuration. **It executes nothing.** An action is a
record in a JSON document, never a thing to do: the checker opens no path an
action names, spawns no process and reaches no network. The only files it ever
opens are the two you name on the command line, plus `--decisions-out` if you
ask for one.

- **Repository:** [edilec/approval-boundary-checker](https://github.com/edilec/approval-boundary-checker)
- **Area:** Prompt & Agent Workflows
- **License:** MIT

## Why it exists

An agent that can write outside its workspace, delete things, or send data
somewhere is gated by a review step that lives in a document — a tool manifest,
a plan, a runbook — and by a policy that lives in another one. Nothing checks
that the two agree. The failure is quiet in both directions: an external write
slips through because nobody wrote a rule naming it, or a rule exists and the
plan spells the effect slightly differently so no rule ever matched.

This tool reads both documents and produces one verdict per action, so the gap
is a build failure rather than a surprise.

## Quick start

```sh
# A plan whose every action is cleared by the policy. Exits 0.
node bin/approval-boundary-checker.mjs \
  --actions examples/allowed/actions.json \
  --policy  examples/policy.json \
  --now     2026-09-14T09:00:00Z

# A plan with an unapproved external write, a denied credential upload, and an
# action no rule covers. Exits 1.
node bin/approval-boundary-checker.mjs \
  --actions examples/blocked/actions.json \
  --policy  examples/policy.json \
  --now     2026-09-14T09:00:00Z --json
```

## The actions document

```json
{
  "schemaVersion": "1",
  "actions": [
    {
      "id": "publish-release-notes",
      "tool": "http.post",
      "effect": "write",
      "scope": "external",
      "dataClasses": ["public"],
      "target": "https://example.invalid/releases",
      "reversible": false,
      "description": "free text, never echoed into the report",
      "approval": {
        "actionId": "publish-release-notes",
        "approvedBy": "release-manager",
        "approvedAt": "2026-09-14T08:30:00Z",
        "expiresAt": "2026-09-14T20:30:00Z",
        "note": "free text"
      }
    }
  ]
}
```

| Field | Required | Values |
| --- | --- | --- |
| `id` | yes | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, unique in the document |
| `tool` | yes | any non-empty string |
| `effect` | yes | `delete`, `execute`, `read`, `send`, `write` |
| `scope` | yes | `external`, `local`, `workspace` |
| `dataClasses` | yes | one or more of `confidential`, `internal`, `personal`, `public`, `secret` |
| `target` | no | a **label**. The checker never resolves or opens it |
| `reversible` | no | boolean, reported but not yet used by any rule |
| `description` | no | free text, never echoed into the report |
| `approval` | no | the record below |

`dataClasses` is required and must be non-empty, which looks strict until you
consider the alternative: an action declaring no data classes cannot be selected
by any data-class rule, so a policy denying secret egress silently fails to apply
to the one action that forgot to say what it carries. "I did not say" is not a
way past a data rule.

`approval.approvedAt` and `approval.expiresAt` are strict ISO 8601 UTC instants
(`2026-09-14T08:30:00Z`). Anything else is refused: `Date.parse` on other forms
is implementation-defined, so `03/04/2026` means two different days on two
correct engines, and a timestamp that decides whether a side effect is permitted
may not be ambiguous.

## The policy document

```json
{
  "schemaVersion": "1",
  "defaultDecision": "requires-approval",
  "rules": [
    { "id": "workspace-read", "effects": ["read"], "scopes": ["local", "workspace"], "decision": "allowed" },
    { "id": "external-side-effect", "effects": ["delete", "send", "write"], "scopes": ["external"], "decision": "requires-approval" },
    { "id": "secret-egress", "scopes": ["external"], "dataClasses": ["secret"], "decision": "denied" }
  ]
}
```

A rule selects an action when **every** selector it declares is satisfied:
`effects`, `scopes` and `tools` by exact membership, `dataClasses` by any
overlap. A rule declaring **no** selector would match everything, so it is
refused — a single `{"decision": "allowed"}` entry would otherwise turn the whole
policy into a rubber stamp and nothing else in the document would look wrong.

`decision` is `allowed`, `requires-approval` or `denied`.

### How several matching rules combine

The **strictest** matching decision wins: `denied` beats `requires-approval`
beats `allowed`. Rule order in the document therefore changes nothing, and adding
a rule can only ever tighten a policy. Every matching rule id is listed on the
verdict, including the ones that were overruled, because "why" is the product
here.

### The default

`defaultDecision` accepts `requires-approval` or `denied`. **`allowed` is
deliberately not offered.** A policy whose default is "allow" turns every action
nobody thought about into a pass, which is the exact failure this check exists to
prevent. A document asking for it is refused as malformed.

## What the tool guarantees

Each of these has a test that fails when the guarantee is removed from the code.

1. **An external write lacking approval is stopped.** It reports
   `approval-missing`, the verdict row reads `stopped`, the status is `fail` and
   the CLI exits `1`.
2. **An unmatched action is never cleared.** It takes the policy default, and
   `allowed` is not a value that field accepts.
3. **An approval never lifts a denial.** A denied action carrying a perfectly
   valid approval is still stopped.
4. **An approval that exists but cannot be read is not a missing approval.** It
   reports `approval-malformed`, with a message that does not say none was
   supplied. Sending an operator to fetch an approval they already have hides
   the real defect.
5. **Unknown evidence is never a pass.** An unreadable, undecodable, unparseable
   or uninterpretable document, a limit reached, a time budget expired, or a plan
   declaring no actions at all, each produce an `incomplete` report with **no
   per-action verdicts at all** and exit `2`. A boundary check is a verdict on a
   whole plan; half a verdict is not a smaller answer.
6. **Nothing is executed.** No path an action names is opened, no process is
   started, no socket is opened. The shipped source imports none of
   `node:child_process`, `node:vm`, `node:worker_threads` or any network module,
   and uses no `eval`, `new Function` or dynamic `import`.
7. **Output is stable.** Findings and verdicts are ordered by UTF-16 code unit,
   never by locale collation. No clock reading, absolute path or input key order
   reaches stdout.

## Rules

| Rule id | Severity | Meaning |
| --- | --- | --- |
| `action-denied` | error | Policy denies this action. An approval does not lift it. |
| `action-duplicate-id` | error | Two actions share an id, so a verdict could not be addressed to either. |
| `action-malformed` | error | An action is missing a required field or declares a value outside the vocabulary. |
| `action-unknown-key` | error | An action declares a key this schema does not define — usually a typo that would otherwise be ignored. |
| `action-unmatched` | warning | No rule selects this action, so it fell to the policy default. The policy has a gap. |
| `actions-malformed` | error | The actions document is not an object, or `actions` is not an array. |
| `actions-not-json` | error | The actions document is not valid JSON. |
| `actions-not-utf8` | error | The actions document is not valid UTF-8. |
| `actions-schema-unsupported` | error | The actions document declares a `schemaVersion` this release does not read. |
| `actions-too-large` | error | The actions document is over `--max-actions-bytes`. |
| `actions-unreadable` | error | The actions document could not be opened. |
| `approval-expired` | error | The approval on record passed its `expiresAt` before `--now`. |
| `approval-malformed` | error | An approval record is present and could not be read. This is not the same as none being supplied. |
| `approval-missing` | error | The action requires approval and no approval record was supplied. |
| `approval-scope-mismatch` | error | The approval names a different action than the one it is attached to. |
| `approval-superfluous` | info | The policy allows this action outright, so the approval recorded on it was not needed. |
| `no-actions` | warning | The document declares no actions, so nothing was checked. The run is `incomplete`. |
| `policy-malformed` | error | The policy document is not an object, or `defaultDecision` / `rules` is wrong. |
| `policy-not-json` | error | The policy document is not valid JSON. |
| `policy-not-utf8` | error | The policy document is not valid UTF-8. |
| `policy-rule-duplicate-id` | error | Two rules share an id, so a verdict could not cite either unambiguously. |
| `policy-rule-malformed` | error | A rule is missing a required field or declares a value outside the vocabulary. |
| `policy-rule-unselective` | error | A rule declares no selector, so it would match every action. |
| `policy-schema-unsupported` | error | The policy document declares a `schemaVersion` this release does not read. |
| `policy-too-large` | error | The policy document is over `--max-policy-bytes`. |
| `policy-unreadable` | error | The policy document could not be opened. |
| `time-budget-exceeded` | error | `--timeout-ms` expired. No verdicts are produced. |
| `too-many-actions` | error | The plan declares more actions than `--max-actions`. |
| `too-many-rules` | error | The policy declares more rules than `--max-rules`. |

Rule ids are stable across releases; renaming one is a breaking change recorded
in [CHANGELOG.md](./CHANGELOG.md).

## Exit codes

| Code | Meaning | stdout |
| ---: | --- | --- |
| `0` | every declared action is cleared | the report |
| `1` | at least one action is stopped | the report |
| `2` | invalid usage or a refused `--decisions-out` | **empty** |
| `2` | evidence missing, undecodable or bounded out | an `incomplete` report |

Exit 2 has two shapes on purpose. A usage error means the run never had a
subject, so there is nothing to report about. An unreadable input means the run
had a subject and failed to obtain evidence about it — which is what
`incomplete` exists to say, and a consumer needs that report to know *which*
input was not read. A consumer piping stdout must handle an empty stdout on
exit 2.

## Writing `--decisions-out`

Optional. It writes the per-action verdicts as JSON, and writes nothing at all
when the run is incomplete, because an incomplete run produced no verdicts.

**The destination is not confined to any root.** This tool reads exactly the two
files you name and walks no tree, so it has no root for a destination to escape
from, and a symbolically linked **parent** directory is followed here exactly as
it is by `cp` or a shell redirect. Inventing a root to say otherwise would refuse
legitimate absolute destinations — and every run under the macOS temp directory,
where `/var` is itself a link.

What is refused, each with its own check because no one of them catches the
others:

- **A destination that is itself a symbolic link.** `realpath` would *resolve*
  it, and resolving is the dangerous act, so it is refused on sight with `lstat`
  — including a link to a path that does not exist yet, which would otherwise
  create a file somewhere nobody named.
- **A destination that is not a regular file**, and a destination whose parent
  directory does not exist. No directory is created: a guard that runs after
  `mkdir -p` has already left a trail.
- **A destination that is the same file as an input**, including a hard link to
  one. A hard link has no target to resolve and shares no path with its twin, so
  `realpath` and string comparison both call it a different file. Only device
  plus inode sees it. Every file the run opened is protected, not only the first.

A refused destination is a configuration error: exit `2`, empty stdout, nothing
written.

## Determinism

Running the tool twice over identical inputs produces byte-identical stdout.

- Findings sort by `(location.file, location.pointer, ruleId, message)`, verdicts
  by action id, and matched rule ids within a verdict — all by **UTF-16 code
  unit**. `localeCompare` and `Intl.Collator` consult ICU data that differs
  between Node builds, so two correct machines would disagree about the same
  report.
- `location.file` is the **logical input name**, `actions` or `policy` — never a
  host path. `location.pointer` addresses the item by id where one is usable
  (`/actions/publish-release-notes`) and by index otherwise (`/actions/2/effect`).
- The wall clock reaches exactly one decision — whether an approval passed its
  `expiresAt` — and it is injected, not read. Pass `--now` for a reproducible
  verdict; without it the system clock is used and stderr says so.

## Limits

Every limit is enforced and overridable. Exceeding one is an `incomplete` result
naming the limit, never a silent truncation and never a pass.

| Flag | Default |
| --- | ---: |
| `--max-actions` | 2000 |
| `--max-actions-bytes` | 2097152 |
| `--max-policy-bytes` | 1048576 |
| `--max-rules` | 500 |
| `--timeout-ms` | 10000 |

`--timeout-ms 0` leaves no time at all and the first check fires. That is the
only way to prove from outside that the flag reaches the classification loop.

## Non-goals

- **It does not execute, simulate, sandbox or dry-run anything.** It reads two
  documents and reports.
- **It does not verify that a plan is what an agent will actually do.** It checks
  the declaration. A tool that declares `read` and writes is outside what any
  static check can see.
- **It does not authenticate an approval.** `approvedBy` is a string in a
  document. There is no signature check, no identity provider and no approval
  ledger; an approval is scoped to the action it is attached to and nothing else.
- **No globbing in `tools`.** Selectors are exact strings. `http.*` matches
  nothing.
- **No rule inheritance, no rule priorities, no exceptions.** Strictest wins, and
  that is the whole combination model.
- **No network access, ever, including in tests.**
- **It does not modify a permission, an account or a record of any kind.**

## Verification

```sh
npm run check   # lint + tests + both examples + npm pack --dry-run
```

## License

MIT. See [LICENSE](./LICENSE).
