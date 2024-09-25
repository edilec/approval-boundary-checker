# Design notes

## An action is a record, not a thing to do

Everything in this tool follows from that. The actions document is untrusted
input in the ordinary sense — it can be malformed, enormous, or full of control
characters — but it is also untrusted in a second sense: it *describes* things
that would be dangerous to do. So the tool is built so that doing them is not
possible, rather than so that doing them is avoided.

`target` is a label. It is reported and never resolved, never `stat`ed, never
opened. `test/no-execution.test.mjs` points three actions at a file, a
directory, a dangling symbolic link and an unreadable file, runs the real CLI,
and asserts the workspace is byte-identical afterwards and the run reached an
ordinary verdict — if the tool had opened any of those targets it would have
failed differently. The same file asserts the shipped source imports no module
capable of starting a process or opening a socket.

## Strictest-wins, rather than first-match or last-match

Ordered rule evaluation makes a policy's meaning depend on where a line sits in
a file. Somebody adds a broad `allowed` rule at the top for a local experiment,
and every deny below it stops applying, with nothing in the diff that looks
wrong.

Collecting every matching rule and taking the strictest decision removes the
ordering question entirely: a policy means the same thing however it is sorted,
adding a rule can only tighten it, and every matching rule id is reported —
including the ones that were overruled — so a reviewer can see the rule that
*would* have allowed the action and the one that did not.

The cost is that there is no way to express an exception ("deny external writes,
except this one tool"). That is deliberate. An exception is what an approval
record is for, and an approval names a person and an instant, which a policy
line does not.

## Why the default cannot be "allowed"

Two of the eight defect classes in the house contract are the same mistake:
unknown reported as a pass, and a vacuous pass. A policy defaulting to `allowed`
is both at once — every action nobody wrote a rule for comes back cleared, and
the emptier the policy the greener the build.

Refusing the value outright, rather than warning about it, is the difference
between a guard and a note. `DEFAULT_DECISIONS` contains two strings and
`allowed` is not one of them, so the document is malformed and the run is
incomplete.

## Why an incomplete run discards the verdicts it already made

A boundary check is a verdict on a plan, not a scatter of independent verdicts.
When the tool cannot interpret one action, or runs out of its time budget
halfway through, the actions it did classify are correct as far as they go — and
that is exactly the problem. They would sit in an approval queue looking
cleared, next to a count that nobody reads, while the action that could not be
interpreted is the one worth looking at.

So `finish` empties the verdict list whenever the run is incomplete, and
`assertReportInvariants` — which runs in production, not only in the tests —
refuses to build a report that has both. The same invariant refuses a `pass`
with nothing checked, and a verdict cleared while carrying an error finding.

## Two clocks, not one

`now` is the wall clock and decides one thing: whether an approval has passed
its `expiresAt`. `monotonic` measures elapsed time against the budget. They are
separate injected parameters because a test that pins the wall clock to a fixed
instant — which is what `--now` is for — would otherwise freeze elapsed time at
zero and quietly disable the time budget. A documented limit the command line
never reaches is a defect this catalog has already shipped.

## What was left out

- **Approval authenticity.** `approvedBy` is a string. There is no signature, no
  identity provider, no revocation list. Pretending otherwise would be worse
  than the gap, because a reviewer would stop looking.
- **Tool globbing.** `http.*` is tempting and would immediately raise the
  question of what `*` matches in a name containing dots. Exact strings, and the
  README says so.
- **Inference.** Nothing is guessed from a tool name: a tool called
  `fs.deleteEverything` declaring `effect: "read"` is classified as a read. The
  tool checks a declaration against a policy; catching a declaration that lies
  is a different tool, and it is not a static one.
