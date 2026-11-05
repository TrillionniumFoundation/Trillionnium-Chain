# Cell delta owner cancellation and semantic audit — 2026-11-05

## Source scope and execution status

This review starts from Chain PR #688 source commit
`6ee529046d295e3175f09112492abee373f1f54c`. The local change is limited to
`cell/delta.rs`, `cell/delta_tests.rs` and `cell/delta_network_tests.rs` in
`trillionnium/crates/trnm-data-availability/src/`. No existing TCM1, TCR1,
TCD1, TMR1, TMT1, TMA1 or TCX1 wire encoding, digest domain or stored schema is
changed. This document is an audit record, not an additional development plan.

Project preflight and direct Rust formatting completed successfully. Native
execution is delegated to the integrating owner; this record does not mark the
new regression cases or the final combined source accepted. A build started
before source freeze is preparation and cannot establish final acceptance.

## Concrete defects and changes

The original delta entry computed its relative overall deadline after delta
and target digest computation and peer metadata validation. The controlled
entry now captures its start before that work, clamps it against the original
absolute release deadline, and uses that reservation throughout the operation.

`CellChunkDeltaV1::fetch_cancellable_to_file` adds caller cancellation using the
existing transport `RequestContext` and shared response reservation. The
existing `fetch_delta_to_file` remains available and delegates to the same
implementation without a flag. An already cancelled invocation exits before
manifest reads, target insertion, peer dialing or output publication. During
transfer the existing transport owns sticky cancellation, response charges
and retries; the delta wrapper does not create a replacement network session.

The wrapper also checks the original deadline and cancellation before reporting
success. If an event becomes observable after create-only target publication,
the operation returns an error and preserves the durable output for exact
readback. Cancellation supplies no rollback authority over that file.

Cancellation is cooperative. Local full-base validation and target
materialization retain their existing deadline-aware implementations; flag
checks surround these operations and occur throughout the transport path.
This patch does not add per-chunk cancellation to local reconstruction, a hard
filesystem interruption guarantee or a transaction that erases every immutable
cache write when cancellation happens during work.

## Added regression cases

| Test | Observation required by its assertions |
| --- | --- |
| `cancelled_delta_never_mutates_or_dials_and_new_attempt_keeps_original_pins` | A pre-cancelled call leaves cache usage, absent target manifest and absent output unchanged; a real listener sees no connection. A distinct fresh call with the same exact identities resumes from actual cached chunks. |
| `delta_cancellation_interrupts_partial_tcp_response_without_retry_or_publication` | A real TCP provider reads the request and returns only a partial header. Cancellation returns before the five-second request timeout, creates no retry connection, stores no incomplete new chunk and publishes no output. This is a local TCP composition check, not WAN evidence. |
| `delta_late_owner_event_preserves_published_target_but_refuses_success` | Both cancellation and expiry are injected only after the real target verifier/materializer has published and synced exact bytes. The returned result is an error; the output stays intact and readable. The hook never supplies data or a synthetic successful result. |
| `delta_reconstruction_requires_only_direct_base_even_after_many_version_steps` | After 32 version steps, a fresh consumer with only the immediate base manifest and actual base/target chunks reconstructs the exact final target. Thirty earlier manifests are absent; the call requires no network request or ancestor recipe. |

The partial-TCP integration case does not substitute server-written bytes for
an observed client byte counter. The existing transport cancellation tests
separately inspect the original response reservation and require charges for
actually received partial bytes, sticky cancellation after flag reset and no
extra retry/quarantine side effect.

## Semantic conclusions that remain separate

The [existing M09 contract](../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md)
defines the boundaries below. None is widened by this patch.

1. **TCX1 already has a fixed direct-base reconstruction depth.** Every recipe
   embeds the complete target TCM1 and commits one exact base TCM1. Indices
   select equal `(SHA256, length)` chunks from that base; they do not invoke
   older recipes. The new history test makes this existing property explicit.
   Full base and target hashing still costs real local I/O, and aggregate
   logical byte/chunk budgets do not measure physical read amplification,
   cache contention or performance on a representative model corpus.

2. **Cross-context raw CAS reuse is legal byte reuse.** Equal chunk bytes may
   be shared while independently pinned TCM1 identities, closure context,
   runtime, loader profile and generation remain separately checked. This
   audit did not find a path that converts byte reuse into loader authority.
   The physical retention arena still may reserve another manifest duty when
   a context changes. General cross-context physical retention aliases are
   unimplemented; that limitation must not be relabeled as a proven exploit.

3. **TMR1 is an identity and closure commitment.** It binds the existing
   complete closure, router roster and bounded direct parents. Its loader
   profile is an opaque owner pin. Equality of the digest does not parse an
   architecture, validate an expert call signature or prove model usability.
   The existing root tests already reject changed runtime/profile owner pins.

4. **TMT1 is a bounded dense-container contract.** It checks the declared
   tensor roster, F32/F16/BF16 dtype, shape, offsets, complete payload hash and
   Base/Adapter file coverage. Existing negative tests reject mismatched
   rosters, dtypes, shapes, malformed named tensor objects and unsupported wire
   profiles. They establish these declared container constraints, not full
   architecture semantics, adapter arithmetic compatibility or Expert ABI.
   TCD1 has no Expert role/ABI or expert activation policy. Adding those
   meanings requires an explicitly versioned loader/closure profile and its
   real runtime implementation; an extra generic admission shell would not
   close that gap.

Ordinary Hepta loading/use, device/VRAM ownership, independent WAN behavior,
public discovery fairness, independent administrators, real paid renewal and
long-term custody remain outside this source change and its test evidence.
