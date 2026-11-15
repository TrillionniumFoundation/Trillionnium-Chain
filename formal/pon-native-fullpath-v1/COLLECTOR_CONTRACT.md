# Full path collector contract v1

`fullpath_gate.py` now exposes `parse_packet(raw: bytes) -> dict` and `check_canonical(check, parsed_packet, evidence, context)`. No external dependencies. The body digest scope matches the Rust collector exactly: PNP2 bytes from offset `4 + 354`, including the u16 transaction count and every u16 length plus transaction, stopping before the u32 witness length. The witness digest excludes its length prefix. `parse_packet` does not replay FullLimb or validate signatures; invalid late C words remain parseable for rejected-work accounting.

## Stable parser output

`claim` equals the Rust collector five-field object (`header_hex`, `trace_hex`, `body_sha256`, `witness_sha256`, `packet_sha256`). Extra fields: `claim_sha256` = SHA256 of the five-field claim encoded as ASCII JSON with sorted keys and separators `,` / `:`; `block_hex`, `challenge_hex`, `parent_hex`, `task_hex`, `network_hex`, `parameters_hex`, `target_hex`, `height`, `timestamp`, `nonce`, `packet_bytes`, `transaction_count`.

## Canonical check

```json
{
  "at_ns": 1000000,
  "receipt": {"path": "valid/observe.stdout.jsonl", "sha256": "<64 lowercase hex>"},
  "canonical_path": [{"path": "valid/packet.bin", "sha256": "<64 lowercase hex>"}]
}
```

`receipt` is either the complete raw single `observe_complete` JSON line from the Rust collector (whose nested object is `native_observation`), or the exact native observation JSON object. `canonical_path` is the included PNP2 packet followed by each descendant through the observed tip. Depth zero therefore uses only the original packet; absent or no-longer-canonical checks use an empty list. The reader independently recomputes parent links, depths, TRNM-PON1 growth block IDs and target-derived descendant chainwork and checks these against the Node snapshot. This remains local recorded evidence, not authentication or finality.

## Manifest fields

- schema = `trnm-pon-fullpath-preregistration-v1`
- context = `{path, sha256}` for context JSON
- observation_end_ns, required_depth, minimum_reorg_window_ns
- maximum_total_cpu_ns, maximum_peak_rss_bytes, maximum_total_wire_bytes
- minimum_timely_ppm, minimum_samples_per_group
- schedule: each `{id, cohort, mode, scheduled_ns, deadline_ns, reorg_observe_until_ns, parent_hex, task_hex}`

Context requires schema = `trnm-pon-fullpath-context-v1`, scope = `same-host-component-observation` or `campaign`, clock_id, source_sha256, binary_sha256, resource_contract_sha256, workload_sha256, network_hex, parameters_hex, genesis_hex, and stage_semantics (all five phase names mapped to explicit nonempty boundary descriptions). Additional context metadata is retained by the file hash. The SHA256 source/resource/workload references are declarations, not authenticated by this reader. Source integrity and actual resource enforcement remain external gates.

## Observation report fields

- schema = `trnm-pon-fullpath-observations-v1`
- manifest_sha256, context_sha256, clock_id, observed_through_ns
- resources = `{cpu_ns, peak_rss_bytes, wire_bytes}` (an unavailable counter is null, which forces HOLD)
- attempts: each `{id, context_sha256, status, packet, claim, stages, cpu_ns, peak_rss_bytes, wire_bytes, canonical_checks}`

`packet` is `{path, sha256}` or null when no packet was produced. `claim` is the five-field parser output or null for a packet that cannot be structurally parsed.

Each stage is `{phase, started_ns, ended_ns, status, claim_sha256, receipt}`. Stage names are ordered `search`, `winner_prepare`, `propagation`, `verification`, `acceptance`; failed/reused attempts may retain an ordered subset. Completed accepted attempts require all five. Receipt is an original native process JSONL stream or one original line; complete stages require the corresponding native event `search_complete`, `produce_complete`, `packet_received`, `admission_complete`, `observe_complete` and exact claim. Verification additionally checks the actual native progress counts and return event; seeing BeforeVerifiedWork alone cannot count as success. Failed stages can refer to the original error receipt; missing native error receipts remain explicit unavailable evidence, never complete verification.

Attempt status: `accepted`, `rejected`, `timeout`, `cancelled`, `error`, `busy`, `stale`, `duplicate`, `send_failed`. Stage status: `complete`, `cancelled`, `error`, `partial`, `rejected`, `timeout`. Counters are nonnegative u64 integers or null (never booleans/floats). Campaign resources cover every attempt, including failures, and must dominate all known per-attempt CPU/wire totals and peak RSS.

All ns timestamps are read by the same parent monotonic clock. Native process-local ns values are only local callback-order checks, never subtracted across processes. `search` may be explicitly coalesced native generation; `winner_prepare` starts at the actual flushed boundary and includes only later packet serialization/roundtrip/fsync. Verification may include cold-open/full-W1/execution/SQL admission. Acceptance spans activation/close/independent cold-observation.

The frozen schedule is the denominator. Missing attempts, missing resources, cancellation, duplicates, lack of depth, late confirmations, reorg/absence during the frozen window, and insufficient terminal observation cannot pass. Root's four-start same-host example keeps depth 6 and the original 4 s deadline; depth 0 readback cannot replace them.

The current native process namespace is inherently a development component collector: even perfect recorded arithmetic yields `COMPONENT_OBSERVATION_ONLY`, with security and overall gate HOLD. No compressed collector or proof verifier is implemented; compressed rows cannot qualify through this native schema. The reader never manufactures a recorded-performance, quantum-cost, production or public-network qualification.

## Original collector lifecycle and normalization

`adapt_native.py` consumes the frozen four-start `collect_native.py` format. Original schedule rows include the actual pre-run `parent_hex` and `task_hex`; normalization preserves them and the original depth 6 / 4 s thresholds. The externally supplied original preregistration digest remains in the final readback. Normalized files are deterministic post-collection derivations, never described as a newly frozen plan.

Original process rows carry `process_started`, `process_reaped`, `pipes_resolved`, `process_group_resolved`, `owner_unresolved`, `dispatch_blocked_by`, `cleanup_attempted`, error lists and `resource_accounting_complete`. Launch/blocked failures may have null PID and exit code; unreaped processes may have null exit code. Such rows remain in the frozen denominator. Original stdout/stderr descriptors have `{path, sha256, complete}`. An unresolved stream has `sha256=null, complete=false`; normalization never invents a stable digest, a complete stage or an available resource counter for it. Only stable complete descriptors become the gate's `{path, sha256}` references.

Successful process use requires zero exit, no timeout, completed process/pipe/group ownership, no blocked dispatch, no cleanup intervention and no process/reader/feeder/cleanup/output errors. A timeout that later exits zero remains a timeout. Missing final source audit or incomplete ownership/accounting leaves campaign resource counters unavailable and the result HOLD.

The final collector also records `stderr_error_event`. The adapter re-reads stable raw stderr and independently detects JSON `event=error` or `status=error`; a false aggregate flag cannot conceal that evidence. Any such stdout record is likewise incompatible with complete process success. A normal stdout completion plus zero exit and a contradictory stderr error remains a failure.

Accepted rows require a nonempty first canonical snapshot bound to the exact acceptance receipt, with actual stored membership. Later absence/reorg stays in history and removes effective progress. A complete-stage receipt containing an error event is refused. Late-product rejection requires exact `WORK:Product` in addition to `[1,512,1,0]`; local errors with the same callback prefix cannot become mathematical rejection. Each measured mode needs both honest and hostile cohorts for recorded arithmetic completeness.

Phase intervals timestamp when the parent observes flushed native events, including reader scheduling. They are not exact child execution durations. The adapter never subtracts separate process clocks.
