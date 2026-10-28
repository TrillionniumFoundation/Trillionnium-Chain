# Strict legacy evidence reader: actual Layout source compatibility

## Observed required-job failure

The numerical model replay passed independently, but the required
`external-evidence-contract` job failed on its exact published source
`c3a13bcf50a46826974681f4b837f291278bcaf5`. In
[run 40607357155](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40607357155),
job `122550076324`, the inherited reader still required the older direct DDL
selection expression. The actual node already selected its DDL through the
versioned `shared_snapshot::Layout` path. The reader refused the legacy fixture
before its intended positive and negative checks could complete.

The [original outcome](hosted-original-failure.json) records 48 test methods,
40 failed subcases and 19 errors. The complete 219,639-byte original job log is
preserved as [gzip](hosted-original-failure.log.gz), with its uncompressed
SHA-256 recorded in that outcome. No original failure receives passing credit.

## Narrow source compatibility repair

The two reader files are transferred byte-for-byte from the already reviewed
integration candidate. The [source transfer record](source-transfer.json)
binds their original Git blobs and before/after SHA-256 values. The destination's
`store.rs`, `shared_snapshot.rs` and `ancestry_index.rs` are byte-identical to
the corresponding source inspected by that integration reader.

The reader now recognizes the actual module attributes, visibility, Layout
variants, method selection and complete DDL/schema binding. It continues to
qualify only the existing legacy evidence schema. PQ, shared-snapshot and growth
schemas, changed source selection, mutable or shadowed owners, added tables and
metadata resealing remain rejected. This change grants no new runtime, SQL,
packet or migration authority. No Rust runtime source, model assumption,
signature domain, stored schema or numerical result is changed.

## First complete regression and subsequent lexical counterexamples

On frozen source `a2da85012afac22c46412aa9a4e0e6b79f2ac57b`, the original full
reader suite plus its five retained Layout controls executed as
`python3 -B scripts/ci/test_public_readiness_evidence.py` within the declared
600-second outer limit. **All 53 methods passed, with no skips**. The process
exited zero and was reaped after 581.168633045 seconds; recorded child CPU was
557.507773 seconds and maximum waited descendant RSS was 48,740 KiB. The five
reader/runtime source hashes were identical before and after execution.

The [execution receipt](final-tests.json), [stdout](final-tests.stdout.log) and
[complete stderr](final-tests.stderr.log) retain the actual observations.
This is one complete regression, not an accumulation of partial passing runs.
The test's measured duration is close to its local outer limit; no limit was
increased and no assertion or method was removed to obtain the result.

That 53-test observation did not cover joint Rust token boundaries. Independent
review then demonstrated that the inherited structural comparator erased
whitespace inside `&&` and between a byte-string prefix and its quote. The
[source review](prior-layout-token-review.json) and the actual
[two-method RED run](token-red.json), with [complete output](token-red.stderr.log.gz),
retain five failed subcases. The reader accepted those changed source forms
and returned the legacy DDL. This is a source-grammar acceptance defect, not
evidence of a compiled runtime exploit; a split byte-string prefix is invalid
Rust. Publication of the first reader candidate was paused.

## Token-preserving correction and complete final regression

The structural comparison now reads literal-aware tokens from the original
text, preserving joint punctuation, byte/C/raw/string/character literal kinds
and lifetimes. Schema-affecting literal payloads retain their independent
exact-byte checks. Comments and whitespace between tokens remain accepted.
Pure lexical transforms are cached only by complete current text inside one
reader invocation. No file path, SQL observation, previous invocation or
acceptance verdict is cached.

On frozen corrected source `7887b2efbbed0613640b2c1be6019bd31ca5651c`, the same
full CI entry point executed **60 tests, all passing, with no skips**, within
the unchanged 600-second outer limit. All original 53 method ASTs are identical;
two actual source-mutation methods and five lexical methods were added. The
lexical controls include 24 joint operators, split literal prefixes, raw
literals, nested comments and lifetimes. The real full run took
125.765331364 seconds with 124.268403 seconds of child CPU. Its eight bound
reader/helper/runtime input hashes were identical before and after execution.

The [final execution receipt](token-final-tests.json),
[stdout](token-final-tests.stdout.log) and
[complete stderr](token-final-tests.stderr.log) preserve this separate result.
The earlier 53-test pass and later RED failures remain unchanged. The reduction
in repeated lexical work is an observation on this host, not a general runtime
performance guarantee.

The separate [repository controls](repository-controls.json) retain all
34 source-integrity negative tests, 95 CI-contract tests, the current CI
contract check and distributed-source inventory check, all passing. A second
execution of the two short suites preserves complete local logs; it does not
increase the distinct test count. All added local Markdown links resolve.
The [full repository check](full-repository.json) still refuses this local
sparse checkout's pre-existing missing `evidence/pon-v1/README.md` link.
The missing historical evidence was neither fabricated nor removed from the
committed tree. Full repository qualification is not claimed locally.

On the token-corrected source, the separate
[final repository controls](token-repository-controls.json) again passed all
34 source-integrity, 38 evidence-source and 95 CI-contract methods, plus the
CI contract and distributed inventory checks. Their complete logs remain
separate from the earlier checks and do not add distinct-method credit.

This repair closes the reproduced source-reader mismatch and token-boundary
counterexamples locally. Its new
published source still requires its own hosted required-job result. It does
not qualify the complete Cargo workspace, PQ schemas, native proof performance,
physical quantum resources, minimum oracle cost or production activation.
