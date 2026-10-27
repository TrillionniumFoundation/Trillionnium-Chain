# Merged research candidate: 9e05 and c86

This source increment preserves upstream `9e05ad5d237660fb0ea8b40dd5c29af4225551d3`
and frozen local candidate `c86d6e50424bf3871d3bffca72b0bc2e6b9b87c8`.
It has not generated a complete W1 receipt. The original 5,400-second hosted
failure and upstream's separate local failure remain unchanged. The existing
9e05 hosted proof run was still running when these small controls were taken;
no second expensive proof was started by these controls.

## Semantic merge

The upstream single-result log parser, actual unmodified Rust f32 soundness
calculator, candidate-retention behavior, and conservative process observer
remain the owners of those operations. The duplicate active two-second sampler
and float64 formula were removed. Original sampler RED/GREEN snapshots are
historical evidence under their original source hashes, not evidence of the
merged observer. The factored complete-receipt parser keeps its original size,
segment, seal, cycle and empty-assumption limits. Its exact new source hash is
pinned by the calculator. The guest, full relation, Cargo lock, compiler/profile
manifest and pinned raw ELF/program/image identities are unchanged from 9e05.

The new source still uses exactly two independent workers, each with two Rayon
threads. One future attempt has a 3,600-second child timeout, a 300-second worker
limit and bounded owned-group cleanup; real elapsed wall time includes that
cleanup. The 8 GiB / four-effective-CPU resource precondition has no smaller
fallback. An unreadable non-root controller ancestor now fails instead of
hiding a potential finite cap. An absent limit file at the hierarchy root alone
cannot establish sufficient controller observations.

## Actual small controls

`controls-003/source-inputs.json` and `controls-004/source-inputs.json` pin the
exact working source bytes used. These were uncommitted merged bytes when run;
`source_sha: null` in their process records deliberately avoids falsely calling
them executions of either parent commit. The publication manifest binds their
unchanged file hashes to the final candidate tree.

| Control | Actual result | Scope |
| --- | --- | --- |
| Owned subprocess terminal/log retention | 5 PASS | Real success, failure, TERM, KILL, spawn error and orphan collection |
| Exact-image receipt reuse policy | 6 PASS | Reuse metadata/byte controls; no successful proof was simulated |
| Upstream single-result log parser | 5 PASS | Raw logs and duplicate/wrong-operation rejection |
| Upstream process sampler | 7 PASS | Identity/parser controls and real normal/timeout child families |
| First merged scheduler controls | 3 PASS / 1 FAIL | Original RED raw wrapper result and exact fixture source retained |
| Follow-up scheduler controls | 4 PASS | Real worker exit/cancel/deadline and controller-limit checks |
| Rust backend formatting | PASS | Rust 1.95 cargo fmt check only; no host build or cryptographic proof |

The initial scheduler fixture inferred independent worker A's exit from worker
B's ready output. The new fixture waits for A's actual terminal code before
asserting rejection, and retains the nested raw controller and worker files.
The first RED did not preserve its nested stderr; its exact causal path is
therefore not established by that observation alone. Nothing rewrites the RED.
Only the affected four-control suite was rerun after this fixture correction.

On this actual host `/proc/self/stat` and local process identities differ. The
merged sampler reported `proc_self_identity_mismatch`, null sampled RSS/CPU and
no observed identities. Those are UNKNOWN resource observations, not zero use
or a successful same-namespace measurement. The independent Linux wait/reap
records confirm that the real child groups were closed. Same-namespace sampling
on the future hosted runner still requires that runner's own evidence.

The first direct cargo invocation could not resolve its `fmt` subcommand from
the caller's PATH (exit 101). The explicit pinned toolchain PATH then ran the
format check successfully; this was a tool-resolution error, not a Rust compile
failure. Both observations are kept. Host compilation, strict Clippy, real late
invalid guest executions, a complete non-dev Composite receipt, strict positive
verification and receipt attacks remain pending on this new source. Formatting
and Python controls establish none of those results. All qualification and
consensus-authority flags remain false.
