# Bounded Cell transport retry for transient capacity refusal

Status: **local component tested; no production or public-network acceptance**.

The [real model replica experiment](SMOLLM_CELL_REPLICA_RESEARCH_V1.md) exposed
an optimized-build acquisition failure: the original native client received a
connection reset during the response header after 2.05 seconds. The full model
had already been packed and its complete release prepared. The failed run is
retained; it is not counted as a successful transfer.

## Failure and repair

The configured-peer server owns a finite number of readers and worker slots.
It immediately drops an excess connection, without adding an application queue.
A client can receive a complete reply and begin its next request before the
server's previous worker has been reaped. Matching client parallelism and server
worker count therefore does not prevent every transient capacity refusal. The
old client attempted each configured peer once and aborted on that refusal.

Two real TCP regressions now hold both server slots, cause an actual third
connection to be refused, then release the occupied slots. Both manifest and
chunk retrieval fail on the original client and succeed with the repair. The
server, admission limit and worker count remain unchanged.

The client permits **at most one additional attempt** for a reset, abort,
broken pipe or early EOF before the response header has completed. It waits
20 milliseconds, then uses the same shared connection counter, actual response
byte allowance and original absolute deadline. A short remaining deadline or
exhausted connection allowance prevents the retry. The second request rechecks
the original limits, including races with other client workers.

Complete malformed headers, missing-content responses, bad chunk digests,
response-body failures and timeouts do not trigger this retry. Partial header
bytes still consume the original byte budget. Existing fallback after a
truncated body retains its original byte and connection accounting. The retry
does not renew the release reservation or create another cache/output owner.
Persistent overload remains a bounded failure, and the ordinary verified cache
can still retain an unacknowledged prefix for an explicitly authorized later
attempt. `rejected_responses` includes failed transport attempts and is not a
finding of cryptographic fraud or a reward decision.

## Actual validation

The original-client regression log contains **two expected failures**, both
actual `ConnectionReset` observations. The repaired native library passes
**141 tests**, including the two capacity regressions and four new controls for
original connection/deadline bounds, partial-header accounting and the exact
one-byte-short cutoff, malformed frames/bad chunk digests, and persistent early
closure. Existing cache quotas, WAL/page bounds, source discovery, release
completeness, retention recovery and slow-response tests also pass. Strict
Clippy for all targets passes.

The first retry candidate also retried a truncated response body. An existing
test rejected that change in accounting. The implementation was narrowed; the
original test assertions were preserved. This development failure is retained
as `intermediate-observation.json`.

The optimized replay used the same real generation-3 adapter, full pinned base
model and eleven-cell release. Server workers stayed at two, client parallelism
at two, each connection allowance at 560, response bytes at 555,919,638, and the
original per-acquisition deadline at 180 seconds.

| Actual native operation | Result | Elapsed time |
| --- | --- | ---: |
| Publisher to fresh replica | All 272,190,131 payload bytes verified | 3.555 s |
| Original publisher after its actual process exit | Connection refused; no completion file | 0.008 s |
| Replica to fresh consumer, original publisher offline | All 269 chunks verified; zero initial cache hits | 2.728 s |
| Model-weight cache-only materialization | Original 269,060,552-byte weight file rehashed | 0.919 s |

Both provider processes were actually terminated and reaped before final
cache-only materialization. The original model-material and adapter validators
rechecked the consumer's exact bytes. This successful sample encountered no
transient refusal; the deterministic regressions exercise the actual retry.
It must not be described as a measured retry speedup. The times are single
observations on a shared host with filesystem caching, not sustainable WAN
throughput, independent-custody acceptance or chain TPS.

The ad-hoc replay wrapper subsequently attempted to append metadata by calling
the original create-only JSON writer on the already-complete transport report.
That raised `FileExistsError` after the native operations and preserved the
original report unchanged. A separate companion qualification file records this
wrapper return code of 1; a subsequent read-only invocation of the original
material/parent validators returned 0. No report was overwritten to turn that
wrapper failure into a clean run.

The previous model comparison remains **16/32 versus 16/32, no-update**. This
transport refinement performs no additional training or quality selection and
does not create a Hepta installation or FinalUse receipt. The native TCL4 path
does not become PQ-authenticated merely because the separate optional native
ML-DSA component exists.

## Evidence and reproduction

[The evidence directory](../../evidence/cell-transient-capacity-retry-v1/README.md)
retains exact commands, source blobs, actual outputs, original-client failures,
the later candidate failure and complete optimized replay logs. With the
repository toolchain, run:

```sh
bash scripts/project-preflight.sh
cargo test --manifest-path trillionnium/Cargo.toml --locked \
  -p trnm-data-availability --lib -- --test-threads=1
cargo clippy --manifest-path trillionnium/Cargo.toml --locked \
  -p trnm-data-availability --all-targets -- -D warnings
cargo build --manifest-path trillionnium/Cargo.toml --locked --release \
  -p trnm-data-availability --bin trnm-cell
```

Model transfer reproduction uses the original pinned inputs and research runner
documented in the preceding experiment. No consensus, signed wire domain,
activation gate, quality metric or sole development plan changed.
