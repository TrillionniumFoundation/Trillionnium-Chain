# Exact code-source qualification and original-owner query

This directory delivers previously observed evidence for **code-source commit
`0f71bd817164feef370f75ee2ab881227693573d`**, tree
`4d567fb9a4ff9e3ae9e957e9e706443ac241dbbb`.

The enclosing evidence-delivery commit is an evidence-only descendant of
that code-source commit. Its identity is the Git commit containing this file and
is recorded in PR #829. No driver, test, Rust, plan, configuration, signed domain,
stored schema, budget or deadline changes are introduced by the delivery commit.
The 84 Python tests, 43 source-integrity negatives, 57 source-integration negatives
and strict Clippy below **executed on the code-source commit**, not on the later
evidence-delivery head. Copying their original receipts does not relabel them as
new test executions.

## Exact code-source records

[Qualification](qualification/frozen-qualification.json) retains the exact command,
cwd, tested commit/tree, actual exit, timeout outcome, counts and stdout/stderr
hashes for every gate. The full stdout and stderr are adjacent to each command
record, including empty output files. [Source before](qualification/frozen-source-before-report.json)
and [source after](qualification/frozen-source-after-report.json) verify all
23,701 tracked entries / 2,384,661,017 bytes, including modes, against that same
committed tree.

The independent source-before command is also retained with its [actual exit](qualification/frozen-source-before.json), [full stdout](qualification/frozen-source-before.stdout) and [full stderr](qualification/frozen-source-before.stderr).

| Observation on code-source 0f71 | Retained record |
| --- | --- |
| Driver 24/24, zero skips | [command](qualification/frozen-driver-24.json), [raw stderr](qualification/frozen-driver-24.stderr) |
| Runtime 6, parent 11, operation 17, frozen evaluation 26 | [qualification](qualification/frozen-qualification.json) |
| Source-integrity negatives 43/43 | [command](qualification/frozen-source-negative-43.json), [raw stderr](qualification/frozen-source-negative-43.stderr) |
| PQ source-integration negatives 57/57 | [command](qualification/frozen-pq-source-negative-57.json), [raw stderr](qualification/frozen-pq-source-negative-57.stderr) |
| Strict whole-workspace / all-targets / all-features Clippy, exit 0 | [command](qualification/frozen-strict-clippy.json), [raw stderr](qualification/frozen-strict-clippy.stderr), [pinned environment](qualification/frozen-clippy-environment.json) |
| Complete offline locked all-features Cargo metadata | [command](qualification/frozen-cargo-metadata.json), [full stdout](qualification/frozen-cargo-metadata.stdout) |
| Formatting, links, source pins, inventory, preflight | [qualification](qualification/frozen-qualification.json) |

The [prior baseline/red/green package](../README.md) still records the original
16 passing tests and five expected red failures. Repeated qualification does not
increase the number of distinct tests. These Python fixtures do not establish
model efficacy, native runtime behavior or production acceptance.

## One fresh original-owner query

[The command record](original-owner/query.command.json) identifies the fixed
reader, unchanged original owner and sealed native binary. [Complete stdout](original-owner/query.stdout)
and [complete stderr](original-owner/query.stderr) preserve the actual result.

The original owner was
`/home/qq/chain-real-iteration-20261108-8b4f0eedf006/artifacts/development-iteration-v1`
on ai395. The [reader capsule manifest](original-owner/reader-capsule.json)
identifies the exact driver and unchanged helpers. This was a separately
identified 16-file query capsule, not a whole-repository model execution.
The native ELF and the historical owner manifest were not replaced.

All four query children exited 0. Their original invocation, started record, exit
receipt, stdout and stderr are under:

- [Candidate query](original-owner/query-stages/01-candidate-query/exit.json)
- [Evaluation query](original-owner/query-stages/02-evaluation-query/exit.json)
- [Native query](original-owner/query-stages/03-native-query/exit.json)
- [Next-input query](original-owner/query-stages/04-next-input-query/exit.json)

The driver actually exited **2**, with
`NO_UPDATE_NEXT_INPUT_OUTPUT_MISMATCH`. Numerical NoUpdate is complete; candidate
selection, installation and native iteration remain false. Current native
readback retains 2,000 local-development units, `locally_revoked=true` and
`dispatch_allowed=false`. All six authority flags, including FinalUse and
independent acceptance, remain false.

[Before-query hashes](original-owner/before-query.json) and the
[original audit](original-owner/readback-audit.json) show both terminal provider
rows unchanged and identical SHA256 for 13 sampled original files, including
the provider, trial and native SQLite files. One query audit directory was added.
The native query path can append observed reconciliation facts; no new training,
inference, settlement, revocation, installation or paid work was requested.

The first audit aggregation looked for child exit codes at the wrong nesting
level and therefore contains null values in its convenience `stages` fields.
It is preserved unmodified. The original `receipt.exit_code` values, linked raw
stage exit files, and [corrected derived summary](original-owner/readback-summary.json)
all establish four zero child exits. Those null aggregate fields are not
observations of unknown process exits.

## Evidence scope and acceptance

[The delivery manifest](delivery-manifest.json) lists every included file's bytes
and SHA256. [Qualification review](qualification/publication-review.json) and
[owner-query review](original-owner/publication-review.json) record the explicit
file allowlists and credential-pattern review. Only this task's command receipts,
toolchain/source reports and query audit were selected. Private native identities,
keys, databases, model artifacts, general environment dumps and unrelated
runtime records are excluded. Original output bytes were not redacted or rewritten.

The historical real experiment has six roles, eight held-out rows and tied
candidate/strongest-control scores of 4/8. It does not establish the requested
encoder/router no-change / cell-only / routing-only / joint four-arm production
comparison. Complete work-family qualification, real user FinalUse, independent
confirmation and the full A-G joint acceptance remain **HOLD / NO-GO**.
