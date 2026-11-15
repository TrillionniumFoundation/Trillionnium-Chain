# Cold observer and cumulative mutation CPU component

Status: source-specific component continuation. Full public pressure and
complete observer CPU qualification remain **HOLD / NO-GO**.

## Candidate and provenance

This branch starts at integration commit
`8d5389748873dad6e296d17f2ff20483b5afa5bc`. It targets the original
`TrillionniumFoundation/Trillionnium-Chain` owner. The cold native observation
implementation and tests are selectively ported from PR #791 head
`9f54b05c643185a5041fc1f78cef77e95877f52a`; no unrelated Cell patches or merge
are included. The actual mutation CPU owner remains the existing #782-era
`ServiceMutationCpuDomain` and `PaidMutationCpuBudget`.

The change adds a local Linux process CPU/wall/output envelope, exact source
preservation and accepted-task cold observation controls, and the continuously
distinct invalid W1 regression. It changes no signed domain or stored schema.
See [the observer specification](../../docs/development/specs/pon/NATIVE_PACKET_STATUS_OBSERVATION_V1.md).

## What is measured

The changing-W1 test uses real native dispatch, matrix replay, original cache,
owner CPU and every scoped-worker CPU clock. Only refill is frozen in the
fixture; no measured CPU value or acceptance is fabricated. Every attempt
changes a different canonical C word while retaining original A/B, trace and
ticket. All completed refusals pay exactly their observed total debit, and
none is recorded as verified work. Clones share the original Node-bound
budget. Once less than a new original principal remains, new identities must
refuse before further replay or state mutation. This is a component invariant,
not the original multi-peer pressure acceptance run.

The envelope test actually runs four native infinite CPU workers without
cooperative checkpoints. The kernel terminates their common process under
one absolute one-second CPU limit. A later request for thirty seconds cannot
raise the installed one-second hard limit. Separate native subprocesses test
wall expiry and output capture refusal. Parent-owned directories are removed
after child termination. No result interprets a killed process as proof of
absence, safe retry or completed business effect.

Cold API and actual CLI tests compare source contents and metadata (excluding
read atime) for both native backends, including admission before activation,
an unfinished real reorg, already-completed corrupt journal fields, live
writer and recovery-marker refusals, and real task reserve/receipt/accept
transactions. The ordinary writer is subsequently shown to retain its prior
recovery behavior.

## Development observations retained

- `development/observer-envelope-1.log`: four tests passed, but the SQLite
  optional build witness reported a missing actual toolchain top-level `lib`
  path. This early run is not promoted to build qualification.
- `development/distinct-w1-1.log`: optimized Node lib-test compilation exited
  via SIGKILL before any test ran. The observed signal does not establish its
  underlying cause.
- `development/distinct-w1-2.log`: explicit Node test opt-level-zero compile;
  the original W1 primitive remains optimized with debug/overflow checks.
  The changing-input regression ran and passed. This is not a performance
  comparison with the original optimized test build.
- `development/source-inputs-1.json`: early working-tree snapshot. Development
  records predate the final frozen source and are not final-source receipts.

The corrected toolchain uses an absolute `RUSTC`, absolute `RUSTDOC`, and the
existing top-level toolchain `lib` in `LD_LIBRARY_PATH` alongside Cargo's
normal added loader paths. No checker is bypassed. The component observations are current working-tree runs on the stated
integration base, not reused PR #791 measurements. Their early raw logs do not
embed a full invocation transcript; the record index does not invent one.
A later source freeze identifies the delivered candidate separately.

## Remaining boundaries

The CLI limit is for one reader process. Its Linux enforcement granularity and
bounded parent work do not constitute a nanosecond-exact full-host charge.
Direct internal-worker invocation still installs the CPU hard cap, but only
ordinary supervisor invocation provides the parent wall/output/cleanup
contract. Abrupt supervisor or host loss has no durable cleanup receipt.
Direct library calls, Growth readers and public reads are not newly admitted
through a durable common credit owner. Repeated or concurrent CLI launches
still need a separately retained global/owner budget before any full aggregate
observer-CPU claim. The original r14 read-not-charged signed policy is unchanged.

Full pressure failures, original resource limits, rollback/revocation anchors,
external-provider idempotency and authority, loaded-image identity and
administrative/fault/funding/key-custody independence keep their original gates.
No production activation or release acceptance is asserted.

## Component results and handoff gates

The [development record index](development-records.json) hashes every raw log
in [the retained archive](development-logs.tar.gz), including both failed
observations. The exact Cargo graph is retained in
[the metadata record](development/cargo-metadata.json). The original optimized
Node package test profile and repository Cargo configuration remain unchanged;
the successful W1 and native observer invocations explicitly selected Node
test opt-level zero. CPU totals from those invocations are not an optimized
pressure qualification.

| Component | Observed result | Scope |
| --- | --- | --- |
| Continuously distinct bad W1 | 1 passed; 19 attempts, 308843879 actual CPU ns, zero fact-cache hits | Cumulative debit and pre-replay refusal; explicit Node opt-level zero |
| Native cold observer | 10 passed | Actual CLI and two original complete-State backends |
| Accepted-task observation | 4 passed | Actual task transitions and cold readback/source preservation |
| Kernel CPU/wall/output envelope | 4 passed | Native subprocess component; early SQLite build witness warning retained |
| CI source-integrity controls | 43 passed | Positive/negative source verification |
| Formatting, locked graph, repository boundary | Passed on working candidate | 26 packages; source pins refreshed with unchanged guards |
| Original optimized Node lib tests | No test ran; compile terminated by SIGKILL | No passing runtime receipt |
| Candidate strict workspace/all-target/all-feature Clippy | Not run | Requires the serialized integration gate |

The kernel envelope module's bytes are unchanged from its early test input.
That observation is explicitly a component test, not qualification of the
SQLite build image. The exact-source native rerun and strict Clippy must happen
in the serialized build window after integration; other branches' baseline
passes cannot satisfy those gates. No new heavy compilation is left running.

The changed `lib.rs`, `main.rs` and `store.rs` current candidate corpus pins,
and the workflow's literal `store.rs` pin, were refreshed after the source
change. The original stale-pin refusal remains in the archive. Integration
must refresh the pins again if sibling changes alter those files. Historical
receipt identities, pressure limits and acceptance assertions are untouched.

Reproduction targets, after configuring the qualified local toolchain and an
isolated `CARGO_TARGET_DIR`, are:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib continuously_distinct_bad_products_exhaust_one_original_prepaid_domain -- --nocapture
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bin trnm-pon-node packet_observer_cli::tests -- --nocapture
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_packet_observer --test accepted_task_observation -- --nocapture
```

Those recipes use the unchanged original package test profile. For a deliberately
limited component rerun, add
`--config 'profile.test.package.trnm-pon-node.opt-level=0'` and retain that
explicit distinction in its receipt. The recipes above are future rerun
instructions, not fabricated transcripts of the early invocations.

## Frozen source-only receipts

The delivered source was frozen as
`d5b7c1726b7351400a46c27c836d382b43399ca5`, tree
`3c02074f42bced7417e51d56cc6e7a74d6fe2a6c`. The subsequent evidence commit
adds this record and does not change its code, tests, Cargo files or source pins.

[The frozen-source index](frozen-source.json) records exact arguments, start/end
times, return codes, source identities and each stdout/stderr digest for
checks executed on that clean committed source. [Its raw archive](frozen-source-checks.tar.gz)
also retains the actual runner. The source verifier passed before and after
the checks. The repository boundary, 43 source-integrity tests, all-package
formatting and locked/offline 26-package graph passed. None of those commands
compiled or ran Node or supplied strict Clippy qualification; the native gates
listed above remain pending.
