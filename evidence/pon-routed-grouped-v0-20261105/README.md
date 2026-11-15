# Routed grouped integer research: implementation and observed costs

Date: 2026-11-05. Profile: `pon-routed-int257-grouped-research-v0`.

**The relation is implemented and independently recomputed. The direct selected
producer has a lower observed hot median than the packed producer for all four
measured shapes. It still costs more than the ordinary control, and the complete
commitment/verification path costs substantially more than either hot kernel.**
This is a research result. PoW/consensus qualification, production activation,
real-demand credit and model reward remain false or zero. The retained model
remains `not_adopted`.

## Exact source and records

- [Implementation commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/abf7986fe338e09fef9729a1738b9b5127700d8f).
- [Published composition actually validated and measured](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e0fc4df37bed96050db2a07d91d427829921e5fa), tree `7f1b7af0351d87032950e01858ea767074c0d032`.
- [Operator contract and existing owner boundaries](../../docs/development/specs/pon/GROUPED_CELL_OPERATOR_V0.md).
- [Complete reproduction recipe](REPRODUCE.md).
- [All three observations, compacted without raw timing arrays](summary.json).
- [Actual validation commands, counts, costs and log hashes](validation.json).
- [Later integration compatibility, with its separate source and binary](composition-validation.json).
- [Source, native binary, toolchain and frozen-input identities](source-manifest.json).
- [Local raw-material hash and byte-size index](raw-artifacts-index.json).

Work continues existing [PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688).
The composed source preserves concurrent owner/mining/runtime controls and their
current registrations. Historical execution records have not been repinned or
relabelled. The final source receipt is `e0fc4df`, not an assertion about every
later descendant or about remote CI execution.

## What was implemented

1. Exact signed integer router and selected-expert computation for every batch
   size 1 through 64, stable lowest-index ties, empty-group skipping and scatter
   to original request order. The packed producer gathers real `257 x b_e`
   activation matrices; the direct producer avoids that copy and produces the
   identical complete Product.
2. Fresh model/input/statement domains bind the original model, context, ordered
   request identities and scopes, original times, all features, routing, groups,
   logits, predictions and arithmetic counts. A full scalar verifier uses
   original base and delta coefficients separately and alone constructs the
   typed verified result. These commitments are not succinct proofs.
3. A bounded persistent native NDJSON process prepares the model once, rejects
   malformed/noncanonical messages and identity rebinding, and checks completion
   time after work and before returning a response. It reports the three kernel
   arms, independent verification and process costs in separate scopes.
4. An immutable bounded research batch planner flushes partial batches on
   capacity, maximum wait or original deadline minus service allowance, and on
   scope/model changes. Late wake-up cannot backdate dispatch. Cancellation
   remains terminal; late completion cannot earn acceptance. Caller observations
   are not authenticated demand or a durable payment owner.
5. Factor-preserving adapter execution reuses the existing adapter normalizer
   and computes `B (A x)`. Admission validation and any dense comparison are
   charged separately. Valid rank-4 through rank-8 forms remain representable;
   factors need not be cheaper for a three-output matrix. No expanded dense work
   is credited as necessary inference.
6. Tests, the protocol-contract CI hook, the generated Rust inventory, current
   source pins, M01 documentation and the sole development plan were updated.
   The existing W1 work relation and Hepta installation/FinalUse owners retain
   their boundaries.

## Frozen inputs and useful arithmetic

The existing deterministic producer recovered exactly the previous model,
consumer corpus and evaluation bundle bytes. Their full file and domain hashes
are in the source manifest and reproduction recipe. The benchmark then performs
no training and creates no new candidate. Source replay uses historical public
commit `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`.

The four shapes are overlapping prefixes of the same 64 consumer rows: **85 row
occurrences, 64 unique rows, zero added rows**. Benchmark repetitions do not
increase demand or credit. At size 64 the expert groups contain `[16,17,31]`
requests. Both producers match the original scalar, NumPy and `predict_rows`
outputs and independently reconstructed commitments. Their predictions retain
25 correct labels out of 64; this is arithmetic preservation, not an improvement
in model quality or a renewed adoption trial.

Forward dense arithmetic is `6 * 257 * n`: **98,688 multiply-add positions at
n=64, zero padding, no unselected expert output**. The independent verifier
recomputes router, base and selected delta using `9 * 257 * n`, or 148,032
positions at n=64. Model preparation caches base-plus-delta once. These counts
are implementation algebraic counts, not a proved minimum attacker cost.

## Published-source hot measurements

Host: shared AMD EPYC 9V74 Linux environment; Rust 1.95.0 release; Python 3.12.14;
NumPy 1.26.4 and cryptography 50.0.2; BLAS/OpenMP thread settings both 1. This was
not the original `dot` host and there was no isolated-service hardware or cgroup
quota qualification. Hardware and observed affinity are recorded explicitly.

Each shape used **12 warmups and 120 measured samples per arm**. All six
execution orders repeat in 20 complete cycles, with no partial cycle. Ordinary
returns routes/logits/predictions. Selected and packed retain the same complete
Product. Packed also contains three phase-clock probes absent from the other
two kernels. Hot ratios exclude commitments, verification, transport and model
preparation; they cannot isolate pure activation-packing cost.

All times below are microseconds. The last column is one separately observed
full selected call, not a median or an end-to-end service latency.

| Rows | Ordinary hot median | Selected hot median | Packed hot median | Selected / ordinary | Packed / ordinary | Full selected call, one observation |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.681 | 0.761 | 2.173 | 1.1175x | 3.1909x | 7.772 |
| 4 | 2.694 | 2.834 | 7.011 | 1.0520x | 2.6024x | 22.184 |
| 16 | 10.636 | 11.136 | 17.085 | 1.0471x | 1.6064x | 78.719 |
| 64 | 42.404 | 44.316 | 59.164 | 1.0451x | 1.3952x | 334.104 |

The observed direct overhead over ordinary is about 4.5% to 11.7%. The packed
path remains slower on these narrow three-output matrices. A per-shape candidate
based on the lower selected/packed median is only a recorded observation; it
changes no runtime policy and proves no general speedup.

Shared-host tail variation is material. Preserve the hot-kernel p95 values as
well; the size-64 tail ranking differs from the median ranking:

| Rows | Ordinary hot p95, us | Selected hot p95, us | Packed hot p95, us |
|---:|---:|---:|---:|
| 1 | 0.792 | 0.851 | 3.135 |
| 4 | 2.714 | 2.845 | 11.898 |
| 16 | 13.931 | 29.545 | 69.384 |
| 64 | 121.443 | 126.621 | 91.228 |

These are kernel sample percentiles, not request/queue/service percentiles.
There is no demonstrated deadline, tail-latency or throughput advantage.

## Full cost boundaries

At size 64, the selected full-call wall observation is **334.104 us**, with
333.166 us thread CPU. It includes fresh batch validation/copy, input commitment,
selected Product, statement commitment, full independent verification and the
completion deadline check. Its instrumented components were:

| Component | Wall time, us |
|---|---:|
| Batch validation | 7.562 |
| Input commitment | 85.428 |
| Selected execution | 45.178 |
| Statement commitment | 3.695 |
| Independent full verification | 188.494 |

The enclosing wall timer also includes bookkeeping and clock checks; component
numbers need not add to the enclosing total. The call has **one observation per
shape** and excludes model preparation and transport. Model preparation was
74.612 us once for the process. This does not establish a 4.5% total proof cost.

The complete persistent process exchange was **39.956 ms wall** and 39.547 ms
child CPU. It includes one OS-process launch, model init, all four shape commands,
all three arms' repeated samples, both full verification paths, pipes, output
drain and child cleanup. It is not the latency of one inference. Separate
startup-only and IPC-only costs are unknown; their fields remain null.
The complete Python experiment before report writing was about 1.509 s, including
source replay, input decode, Python/NumPy controls and independent comparisons.

## Earlier observations remain visible

The first packed-only experiment was a **dirty-tree development diagnostic** on
HEAD `dda4cc47...`, before the direct Product producer and final three-arm
harness. Its own source and binary hashes are retained, without claiming it is a
clean published-source measurement or exactly reproducible from final code:

| Rows | Initial packed / ordinary hot median |
|---:|---:|
| 1 | 3.3757x |
| 4 | 2.8682x |
| 16 | 1.7860x |
| 64 | 1.4672x |

That negative result motivated measuring the lawful direct producer. A later
clean local checkpoint `d95f8c5...` observed selected/ordinary ratios of
1.0447–1.1175 and packed/ordinary ratios of 1.3843–3.1615. Its declared runtime
source files and release binary are byte-identical to the final observation.
Both earlier observations remain in the compact summary and raw-material index.
The primary observation is the subsequent published-source run, selected by
source status rather than by faster timings.

The [older padded W1 experiment](../pon-shared-material-v1-20261105/README.md)
includes a different proof/search workload. Its 373–611x child-path result is
neither overwritten nor directly divided by these kernel timings to manufacture
a PoUW speedup. This grouped relation does not implement its lottery or proof.

## Validation on the actual published source

All checks below ran at clean `e0fc4df`, with the same head/tree before and after:

| Executed suite | Passed tests |
|---|---:|
| M01 default-feature native tests, all targets | 202 |
| Grouped Python, including two actual native integration tests | 32 |
| Retained W1 consumer | 9 |
| CI source-integrity negatives | 43 |
| PQ source-registration negatives | 35 |
| CI command-contract tests | 98 |

There were no failed or skipped tests in those suites. Native arithmetic tests
cover all batch sizes 1–64 and deterministic ties, and reject changed inputs,
routes/groups, outputs, statements, contexts, counts and deadlines. Planner and
factor tests include late wake-up/completion, cancellation, immutable history,
identity binding, cheap factor execution and valid higher-rank forms.

Strict release all-target Clippy with `-D warnings`, workspace formatting,
locked/offline Cargo graph, generated inventory, source identity, whitespace
and repository link/ownership checks passed. The locked graph has 175 packages
and 26 workspace members. Current registration checks **502** exact blobs and
still reports `HOLD_NO_GO`; pin agreement is not cryptographic acceptance.
This validation scope is M01 default-feature native targets plus the listed
Python/source/CI/static checks. It is not a full-workspace native build, a remote
CI success claim or public-service qualification.

## Later integration compatibility, with no new timing claim

Concurrent W1 cost instrumentation and source-registration work subsequently
advanced the branch. A separate clean-source compatibility run at
[`32c3d63c907d0060a5b02cd678c74b01e54ec0f9`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/32c3d63c907d0060a5b02cd678c74b01e54ec0f9)
rebuilt the grouped example and passed all 14 recorded checks. The native suite
now contains 208 passing tests, grouped Python 32, retained W1 consumer 12,
source-integrity negatives 43, source-registration negatives 37, and CI contracts
98: **430 passing tests** in this explicitly bounded scope. Source registration
checks 505 blobs and still reports `HOLD_NO_GO`.

All eight grouped implementation/test files are unchanged. Among declared
measurement source inputs, the shared W1 Python module changed: its optional cost
instrumentation updates `baseline`, while the imported input loader, NumPy
operator/preparation, identity, host snapshot and JSON helper function ASTs are
unchanged. This compatibility run exercises the composed imports and a rebuilt
native binary. The release binary hash changed with the crate composition;
**no new performance observation was made at this later source**. All timing
tables above remain observations of `e0fc4df` and its original binary.
[composition-validation.json](composition-validation.json) records the actual
head/tree, build, tests, source differences and new binary identity. Neither the
502-blob receipt nor the earlier timing records are rewritten as 505-blob or
later-source receipts.

## Boundaries and remaining work

There is no authenticated arrival trace. Original arrival/deadline observations,
queue p95/p99, batch-fill delay and deadline benefit remain null. Logical times
exercise transport semantics only. Shared encoder weights reduce residency;
reusing an encoded result additionally requires identical input/representation,
model generation and compatible authorized scope. No encoder cache was installed.

Remaining gates include a registered challenge/lottery and minimum lawful-cost
analysis, proof/verification/availability/propagation budgets, authenticated real
requests and deadlines, independent prospective model benefit, ordinary Hepta
installation and consumption, original hostile-service budgets, and original
CURRENT/FinalUse/funded-effect owners. The implementation closes the research
arithmetic/batching/code-verification gap while keeping those gates open.

Only source, tests, configuration, reproducible commands and these compact
records are added by this work. Generated model files, corpus rows, raw streams,
raw timing arrays and large log archives are not added. Their local hashes are
indexed; reproduction regenerates outputs, with host-dependent timing bytes.
