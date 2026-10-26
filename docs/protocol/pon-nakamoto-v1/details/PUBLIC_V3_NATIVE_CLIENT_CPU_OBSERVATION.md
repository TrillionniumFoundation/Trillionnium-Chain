# P2: Original signed V3 client CPU measurement (additive only)

**Status:** implemented source and additional source tests, exact-head native
verification and independent cost qualification still pending. This page is
attached to the W1/P1/W2-C integration candidate, not a protocol release.
No existing V3 Cookie, signature, packet, profile ID, deadline, difficulty,
server resource account or W1 consensus semantics is changed.

## Original instrumentation deficiency

The existing `PublicClientMetrics` contains `solution_trials`,
`solution_search_ns` and `total_elapsed_ns`. The two latter fields use
wall-clock elapsed time, **not calling-thread CPU**. Comparing those values
to the receiver's native W1 thread CPU would produce an invalid economic
price ratio. The earlier `pon_v3_cookie_cpu_study.py` instead used synthetic
Cookie IDs and Python process CPU, *not* a full signed client negotiation.

## Implemented native research API

`ingress::public_v3::call_public_protected_v3_with_cpu_observation` is a
separate opt-in wrapper that calls the **original**
`call_public_protected_v3_with_metrics` without changing or reimplementing
any handshake. It adds one independently serialized
`PublicClientCpuObservation` with:

| Field | Semantics |
| --- | --- |
| `client_thread_cpu_ns: Option<u64>` | Original calling-thread CPU across canonical request creation, signed Cookie verification, SHA256 nonce search, caller signing, network protocol and signed reply checks. Unknown stays `None`, not zero or elapsed wall time |
| `client_wall_ns` | Entire wrapper call elapsed wall time, **not** a CPU cost or device energy measurement |
| `solution_trials`, `solution_found`, `solution_search_wall_ns` | Unchanged original client search observations, including incomplete attempts and bounded expirations |
| `solution_search_thread_cpu_ns: Option<u64>` | Actual calling-thread CPU for the original Cookie-ID calculation and SHA-256 search, including failed/expired/capped searches. An unavailable clock is `None`, not a wall-time estimate. Stored internally on the original metrics object with serialization explicitly skipped; exported only in the separate opt-in observation. |
| `failed_stage` | Unchanged typed client phase; denial, timeout and inability to solve are never interpreted as a successful paid request |
| `native_server_cpu_known = false` | This is a client-local caller measurement, not the server's W1/M06 CPU debit |
| `gpu_cpu_equivalence_assumed = false`, `work_profile_qualified = false` | Prevent interpretation as GPU/ASIC economic floor or public consensus activation |

The old client method, `PublicClientMetrics` fields/JSON, and signed
profile are retained unchanged. The actual costs of any separately spawned
caller child process or other network device are NOT included.

New tests live inside existing
`trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs`:
a before-socket policy rejection remains explicitly typed and carries no
fabricated ticket; the previously existing real signed Head/paid-mutation
cohort now also exercises the opt-in observer against a running V3 listener.

## Source-specific local reproduction

Run **inside an exact checked-out candidate** after its mandatory preflight:

    bash scripts/project-preflight.sh
    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib \
      ingress::public_v3::tests::client_cpu_observation_is_opt_in_does_not_mint_a_ticket_or_change_old_json \
      -- --exact --nocapture
    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib \
      ingress::public_v3::tests::paid_mutation_body_budget_preserves_signed_read_service_with_rotating_callers \
      -- --exact --nocapture

The existing real signed Head/mutation-queue test additionally prints
`public-v3-original-client-cpu-smoke-v1` with old client metrics and the
separate new actual CPU observation. For a retained raw write, select one
previously nonexistent path before running that second test:

    export TRNM_P2_V3_COST_REPORT=/unique/new/actual-v3-client-cost.json

The test uses `create_new` and `sync_all` and cannot overwrite a previous
experiment. One loopback Head request still lacks attacker GPU pricing,
receiver W1 cost, real WAN load and P4/A03 physical fairness evidence.

Keep the exact source/commit/tree, Rust binary/toolchain, CPU affinity,
real host/cgroup root and actual output with failures, including any
unknown CPU clocks. Running an existing previously retained binary cannot
validate this new source.

## Unclosed economic and security gates

This additive metric closes a *measurement API gap*, not the underlying W1
forgery amplification. P2 still needs identical task/target/client/server
profile and host bounds; independently measured attacker CPU, GPU and ASIC
worst-case ticket cost, full invalid-work receiver CPU **including** M05,
M06, message parsing/response signing and latency effects, honest Cookie
success/timeout burdens and actual public service mix.

Even a strongly paid signed Cookie can be forwarded through relay hosts;
independent receiver identity/epoch and a one-use resource receipt protect
the local service boundary, but no attack-cost bound can be inferred
without admitted-device and shared-resource assumptions.

P1 real unmetered-entry closure and physical host proof, P3 source/identity
churn and normal traffic, P4 the original full A03 3×3×3 campaign, W2
cryptographic proof soundness and third-party P6 review remain **OPEN**.
Status remains HOLD_NO_GO / production disabled.
