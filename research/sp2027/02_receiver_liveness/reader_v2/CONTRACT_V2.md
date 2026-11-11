# SP27-02 native collector to SP27-06 analysis contract, revision 2

This revision binds an actual archived collector, a versioned SP27-02 reader,
and the retained SP27-06 analysis program. It grants no protocol, execution,
Host, or resource authority. The original four-second window, CPU allocation,
memory limit, permissions, and native final predicate remain unchanged.

## Version and acceptance scope

- Collector: `public_v3_from_zero.rs` at Chain
  `8ebcdb01016946a131f9067ebe1ace39b9c4f260`, as retained in Actions run
  `43052900246`, job `130634539770`, artifact `13871459353`.
- Reader: `sp27-02-native-reader-v2`; its exact source is bound by
  [CONTRACT_FREEZE.json](CONTRACT_FREEZE.json).
- Adapter: `sp27-02-collector-analysis-v2`, implemented by
  [consume_native_v2.py](consume_native_v2.py).
- Consumer: unchanged SP27-06 `analyzer.py` from Papers
  `c49c769fb3b08ee8f60c993c8ca6be2a4600246f`, retained as
  [analyzer_06_v1.py](frozen/analyzer_06_v1.py).
- Wire schema: `sp27-confirmed-goodput-contract-v1`; this adapter sets
  `window_end_rule="exclusive"` and `require_native_window_gate=true` explicitly.
  The separate adapter revision prevents an unnoticed reinterpretation of old
  archives. No stored ledger schema changes.

The current SP27-02 execution owner has accepted the strict predicate and exact
new-CI scope. The current measurement subagent has executed the real retained
SP27-06 consumer on the two-phase native sample. Root's independent consumption
is recorded separately after reading the freeze digest. Neither acknowledgment
is a reply from the earlier Agent 06 author or the portfolio coordinator. Those
external acknowledgments remain `NOT_OBSERVED` until an actual receipt arrives.

## Native endpoint rule

Let `T` be the **original traffic-window endpoint**, `t_recorded` the original
recorded independent confirmation end, and `g_native` the original final native
gate. A positive count requires all three:

1. The bound native independent observation satisfies the frozen policy.
2. `t_recorded < T`.
3. `g_native is true`.

The native source records the endpoint before sampling the final deadline gate.
Consequently, `t_recorded < T` and `g_native=false` is a valid failed-window
observation. V2 retains both values and grants zero timely credit. It never
reconstructs the later gate from the earlier endpoint. An asserted positive
gate with an endpoint at or after `T` is contradictory and is refused.

Missing final-gate evidence yields `UNKNOWN` and no credit in the endpoint
reader. The original complete-report adapters require the corresponding raw
field; missing required structural evidence is not silently filled. Malformed
boolean/float clocks are refused. Original resource spans remain half-open
intervals; their `ended == T` convention is unrelated to instantaneous
confirmation. The distinct per-operation SLO remains inclusive, subject to
the stricter window and native-gate requirements.

## Exact mapping for the minimal actual pair

All paths below are inside the SHA-256-pinned Actions ZIP. `p` denotes one
original `from-zero-native/confirmation/report.json` phase. Its order is
`attack-free-baseline`, then `from-zero-pressure`; this adapter preserves that
order and does not label it randomized.

| Consumer field | Source and rule |
| --- | --- |
| `run_id` | `ci-43052900246-13871459353/confirmation/` plus the original mode. |
| `chain_instance_id` | Phase identity plus `/fresh-ledger`; the raw pair's equal initial tip/state is verified. |
| `profile_id` | `original-four-second-pair`. |
| `window_start_ns` | `0`, in the original phase traffic epoch. |
| `window_end_ns` | `p.requested_window_ns`, required to equal `4000000000`. |
| `clock_id` | Phase-local traffic epoch, never joined to an unrelated host clock. |
| Source commit and tree | `from-zero-native/manifest.json` before/after tracked-source identities; both must match the pinned commit/tree. |
| `binary_sha256` | Rehashed `from-zero-native/public_v3_from_zero`; must equal both manifest digests. |
| `config_sha256` | `null`: a complete configuration digest was not retained; the observed subset hash is separately named. |
| Host/boot/process evidence | Complete `inside-before.json` and `inside-after.json`, plus child/controller Host error arrays. These do not establish resource exclusivity. |
| Transaction and expected block | Decode the original seven signed packets; exactly one contains the signed business transaction, six provide depth. Bind observation to the decoded transaction/block. |
| `scheduled_ns` | `null`: the historical pair did not record a prospective business-arrival timestamp. Do not substitute actual start or zero. |
| `request_start.at_ns` | `p.business_started_ns`, retained only as actual start. |
| `deadline_ns` | Original `p.requested_window_ns`. |
| `confirmation.at_ns` | `p.confirmation_ended_ns`, retained even when the later gate is false. |
| `native_window_gate` | `p.client_confirmed_before_original_window_end`, copied as a boolean. |
| Native observation | `p.independent_client_confirmation`, with transaction, block, policy, depth, required-work and authority checks. |
| Expected policy | `installed-depth-and-required-work`, depth at least 6, frozen required-work delta `0c`. |
| `flags` | Attestation of the pinned successful native confirming path; never inferred from ACK or Head, and not a new Python cryptographic check. |
| Provenance | Exact ZIP digest, report member and JSON pointer. |
| ACK/Head/History telemetry | Retained as telemetry. None can become a business confirmation. |
| Resource observations | The pinned 06 exporter retains inclusive/nested spans without adding them; complete missing owner costs remain null. |

The new pair remains a separate batch. It is not pooled with prior campaigns or
the unverified earlier local `PUBLIC_HOST_KERNEL_PARENT` failure. A health
readback without errors cannot certify an exclusive host or identify an attack
mechanism. No causal, saturation-capacity, independent-operator or production
qualification is added.

## Historical-reader compatibility

[legacy_reader_v1.py](frozen/legacy_reader_v1.py) is byte-identical to the old
SP27-02 reader. V1 can be loaded separately for replay. V2 reuses only its
unchanged decoding, binding and resource-audit functions; the native pair and
campaign endpoint readers are explicit versioned replacements. Input and output
versions are never silently rewritten.

`historical-corpus` first validates and replays the retained raw-report capsule
with V1, then with V2, compares their fully re-derived event streams and runs the
real 06 consumer. It separately audits raw endpoints for equality at `T` and for
positive observations below `T` with a false gate. A text-only event replay is
not labeled a raw-corpus recheck. Capsule verification does not claim that the
six original ZIPs, databases, or native binary bytes were re-downloaded.

## Minimum validation and actual consumption

The synthetic suite covers `T-1`, `T`, `T+1`, the earlier endpoint with a false
final gate, missing-gate Unknown, contradictory positive gates, malformed clocks,
existing identity checks, and the actual retained 06 consumer. These are reader
tests and are excluded from native experimental counts.

The minimum real sample is the two-phase new CI pair under
[results/ci_pair_43052900246](results/ci_pair_43052900246/CONSUMER_RECEIPT.json).
The contract, full planned schedule, events, operation ledger, source digests and
consumer result digest are retained. Read the receipt for the actual result;
the schema's existence alone is not evidence of successful consumption.
