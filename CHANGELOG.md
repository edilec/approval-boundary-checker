# Changelog

All notable changes to this project are documented here. Rule ids are part of
the public surface: renaming one is a breaking change and is recorded here.

## 0.1.0

First implementation.

- Classifies declared actions against a policy as `allowed`,
  `requires-approval`, `denied`, or matched by no rule at all, and attaches the
  matching rule ids to every verdict.
- The strictest matching rule decides, so rule order in the policy document
  changes nothing.
- `defaultDecision` accepts only `requires-approval` or `denied`; a policy
  asking to default to `allowed` is refused as malformed.
- An approval that is present but unreadable reports `approval-malformed`, never
  `approval-missing`.
- An incomplete run — unreadable, undecodable, unparseable or uninterpretable
  input, a limit reached, a time budget expired, or a plan declaring no actions
  — produces no per-action verdicts at all and exits 2.
- Optional `--decisions-out`, guarded against a symbolic-link destination, a
  non-regular-file destination, and a destination that is the same file as an
  input including through a hard link. The destination is not confined to a
  root, and the help text and README say so.
- The wall clock is injected and reaches exactly one decision, approval expiry;
  `--now` makes a run reproducible.
- 29 rule ids, listed in [README.md](./README.md).
