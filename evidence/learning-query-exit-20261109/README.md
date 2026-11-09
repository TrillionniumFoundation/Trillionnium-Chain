# Learning query process completion — 2026-11-09

Scope: a development-driver repair on PR #820, based on exact commit
`c247d623704b1cce2307fa31b21cab045063e0f6`, tree
`098f1aaa991ac04c70177982929b3cc39d9f8009`. PR #821 does not contain this driver.

## Boundary and result

The provider CLI can print a successful JSON reply before process cleanup
finishes. The driver previously reused that reply even when the query process
exited nonzero. The same omission affected native paid readback, candidate
service readback and retained-parent next-input readback.

The driver now requires an observed integer zero exit before accepting successful
provider/native observations as completed effects. A complete NoUpdate comparison
also requires a confirmed candidate query before the combined operation can be
reported complete. Missing, boolean and textual exit codes are unconfirmed.
Initial execution and query-only reconciliation share this rule.

Raw stage exits, stdout and stderr remain available. Provider UNKNOWN/FAILED
observations retain their original exit codes and reservations. Readback does not
authorize replay. A later successful original-owner query may confirm an earlier
uncertain effect. Independent numerical Candidate/NoUpdate findings remain
separate from service completion: Candidate pending still means that the original
owner has not selected or installed it.

## Preserved observations

[The source verification](source-worktree-before.json) checks all **23,652 tracked
entries / 2,383,742,542 bytes**, including executable modes, against the original
commit before edits. This is a complete current checkout with explicit shallow
history boundaries. It does not transfer any #821 test result.

The original driver passed its [16 existing tests](baseline-driver-16.stderr.log).
With only the new regression tests added, [five focused boundary cases failed
against the original driver](original-driver-red-5.stderr.log). Their processes
really ran and exited nonzero; model, evaluation and ledger responses are
synthetic fixtures. They do not demonstrate model training or native payment.

The modified candidate then passed all **84 tests**, with no skips:

| Complete suite | Tests | Raw stderr |
| --- | ---: | --- |
| Development driver | 24 | [driver](green-driver-24.stderr.log) |
| Inherited runtime | 6 | [runtime](green-inherited-runtime.stderr.log) |
| Parent material | 11 | [parent](green-parent-material.stderr.log) |
| Once-only operation | 17 | [operation](green-inherited-operation.stderr.log) |
| Frozen evaluation | 26 | [evaluation](green-frozen-evaluation.stderr.log) |

Each named command retains complete stdout/stderr and a JSON command record.
These are pre-commit observations of the recorded candidate file bytes; committed
source checks and repeated qualification are recorded separately. Repeated runs
are not additional distinct test coverage. [The changed source pins](source-pin-updates.json)
are limited to the driver, its tests and the sole development plan.

## Candidate source checks

The [43 source-integrity negative controls](candidate-source-negative-43.stderr.log)
and [57 source-integration negative controls](candidate-pq-source-negative-57-attempt2.stderr.log)
passed. The candidate also passed repository/Markdown checking, all 883 source
pins with HOLD_NO_GO preserved, distributed inventory, the complete offline and
locked all-features Cargo metadata command, and workspace formatting. Their
complete stdout/stderr and command records are adjacent to these logs.

The first source-integration attempt exceeded a 90-second preparation-runner
limit. Its [timeout record](pq-source-first-timeout.json) and [outer supervisor
trace](pq-source-first-supervisor.stderr.log) are retained. The first helper did
not persist the exception's partial child output; that evidence gap is explicit.
The second attempt used persistent output files and completed in 211.090 seconds.
No product budget, pressure contract or protocol deadline was changed.

## Remaining scope

These Python controls do not run the real model experiment, native Rust service
tests, WAN/cold custody or an independent final-use confirmation. Strict workspace
Clippy is required on the frozen commit and is recorded separately. This repair does
not alter the existing budgets, deadlines, original owner, journal schemas or
signed domains. No new training, settlement, installation or model quality claim
follows from the regression fixtures.

The [original service observations](../learning-service-20261108/README.md),
including the real next-output mismatch, remain unchanged. The real four-arm
no-change / cell-only / routing-only / joint comparison, complete production
owner chain, independent custody, real-asset funding, FinalUse, work hardness and
whole-chain qualifications remain HOLD / NO-GO.
