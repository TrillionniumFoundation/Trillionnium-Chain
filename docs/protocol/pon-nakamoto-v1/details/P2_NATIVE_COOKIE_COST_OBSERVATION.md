# P2: actual V3 Cookie search CPU is observable, not an attacker-cost proof

Status: candidate native observability only. Frozen parent
'db0dad68f0909460e8b1cf0c248d8bab4b59c129' of Chain #335.
No W1, signed Cookie, PublicPolicy::id, wire, challenge, target, fork,
chainwork, final-use or production activation change.

## Original measurement gap

Public V3's 'call_public_protected_v3_with_metrics' exposed actual bounded
hash trials, solution-stage **wall elapsed time** and whole request time.
The real CPU consumed by constructing the Cookie ID and hashing each
unsuccessful/successful nonce was not separately recorded. Wall time can
include preemption and blocked scheduling and cannot substitute for actual
CPU in honest-client versus false-W1 receiver economics.

## Changes

'PublicClientMetrics.solution_search_thread_cpu_ns: Option<u64>' is an
**optional local diagnostic**, omitted from serialized observations if
unavailable. A normal field value is actual, monotonic calling-thread
CPU time on Linux; non-Linux or failed thread clock stays None, **not zero**.
The measurement starts immediately before Cookie ID hashing, surrounds the
original, unchanged 0..1,048,576 nonce search with the original exact
2-second/outer deadlines and bits, and is finalized on both success **and
error**. It includes every unsuccessful SHA256 trial, never merely the
winning nonce. It does not include network I/O, server-side work, GPU time,
whole legitimate miner cost, or a guaranteed adversary CPU lower bound.
The old JSON fields retain their names, semantics and values; the new
field is optional and unsigned.

The existing *real signed V3 TCP* test
'public_v3::shared_cpu_domain_source_tests::process_cold_real_w1_cpu_depletion_preserves_read_and_recovers_honest_admission'
now requires actual client CPU observations on both a signed Head and
signed honest Submit. It emits a separate read-only
'trnm-p2-real-v3-cookie-client-cpu-v1' JSON report with those original
client metrics and receiver aggregate CPU as explicitly **separate**
denominators. The signed Cookie, its server MAC and caller signature still
follow the original V3 path. Optional 'TRNM_P2_REAL_V3_COOKIE_REPORT'
uses exclusive create-new file output to avoid replacing previous raw
observations.

The supplementary native W1 component research test
'public_v3::tests::native_v3_cookie_search_and_real_w1_costs_keep_disjoint_cpu_denominators'
runs the **actual Rust V3 winner predicate** on six fixed synthetic
Cookie IDs (8, 12, 16 bits, two samples each) and the actual native
W1 arithmetic for one honest zero-matrix proof and a transcript forged
without invoking the W1 producer. It records full hash trial counts
including target misses, fixed caps, thread CPU, wall time, real W1
generation/valid verification/invalid rejection, all 512 replay tiles,
and NO false VerifiedWork. Optional 'TRNM_P2_NATIVE_COOKIE_COST_REPORT'
writes a distinct exclusive JSON. This component experiment is not an
actual network or third-party source test.

## Reproduction, acceptance and negative interpretations

    bash scripts/project-preflight.sh
    cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib \
      public_v3::tests::native_v3_cookie_search_and_real_w1_costs_keep_disjoint_cpu_denominators \
      -- --exact --nocapture --test-threads=1

The signed TCP test is a separate existing test in
'public_v3::shared_cpu_domain_source_tests'. Its original process-cold
service budget and honest-recovery invariants must remain unchanged and
must actually pass. No aggregate CPU value may be added to a nested
'full_work_cpu' sample or to the client Cookie search.

**Not accepted as P2** without a new physical campaign on exact source,
full binary/compiler profile and signed policy id, honest and hostile
native TCP requests with all failures/Busy/expiry/timeout denominators,
GPU/ASIC and CPU attacker alternative SHA256 rates, verified Host
cgroup sharing, representative legal/invalid W1 task materials, cold
and warmed clocks and packet/body/network byte costs. Both client
and server actual CPU need a single preregistered resource model.
Only these measurements can price V3 bits; no fixed bit-count should be
promoted by a component ratio or synthetic proof.

The 3-mode × 3-run × 3-on-time client-confirmed A03 campaign (P4), real
P1 Host ownership across all ingress/relay/sync paths, full mathematical
W2 proof and independent external P6 review remain OPEN.
Production consensus activation stays false.
