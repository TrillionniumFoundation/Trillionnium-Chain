# PoN P1/P2 single-tree integration and evidence boundary

**Integration candidate only. Exact parent:**
'db0dad68f0909460e8b1cf0c248d8bab4b59c129' (Chain #335).
This revision merges **file blobs**, not independent test verdicts, from:

| Component | Frozen child commit | Files |
| --- | --- | --- |
| W2-C receiver-local ticket research | f06ccc809ebd7f553a55d5a54af1ba80e6523126 (#339) | Python issuer, attacker-cost prototype, eight test scenarios and study docs |
| Original-domain pinned-peer W1 | 563a8c982106dc38880f4a8cbaf37f4f89fa9cb4 (#340) | peer_polling.rs, P1 peer study docs |
| Native/CLI remote Sync fixed-host parent | e55107450eb1a1f051a6c98101f3f88b7afa8f91 (#342) | ingress.rs, main.rs, remote-source docs |
| Actual V3 Cookie client search CPU | 55e4a75f91c783e7bdd8c9f698f8699df7080c02 (#357) | public_v3.rs, P2 CPU docs |

All source files were selected **by their existing Git blob SHA** from the
exact child PR head, and placed on the original #335 Git tree using one new
commit. This tests the *combined* source dependency and avoids inferring
anything from separately observed old branches. The original child PRs are
retained. No merge into main or production activation.

## Owner/reachability graph to qualify

    remote signed History -> pinned peer polling
       -> Node.original public_service_cpu_domain()
       -> ServiceMutationCpuOperation
       -> W1 full replay
       -> M06 scoped execution
       -> CPU settlement and error reporting

    remote raw/authenticated/V3 History -> CLI/native sync
       -> original trnmponpublic.slice host cgroup check
       -> receive_page_from -> bounded Node::admit W1
       -> same host cgroup check on the actual calling thread

    inbound public V3 signed Submit
       -> one original Node-owned CPU domain
       -> same Original Host parent if reachable from WAN
       -> original W1 + M06 + signed outcome/settlement

    caller V3 Cookie client -> same signed V3 wire and solution hash predicate
       -> actual calling-thread CPU (or null)
       -> separate server full W1 and original CPU owner observations

    W2-C receiver-bound proof-of-cost -> research only
       -> receiver+epoch+proof MAC+finite one-use state
       -> never VerifiedWork, Chainwork, model deployment or final-use

The P1 resource fixes are intentionally heterogeneous: peer polling shares
the original *per-service* CPU budget while raw/authenticated Sync uses the
existing *kernel aggregate* parent check. The latter still lacks the same
fine-grained paid per-request CPU quota, so P1 is **NOT closed** by this tree.

## Source-complete commands for independent execution

    bash scripts/project-preflight.sh
    python3 formal/pon-nakamoto-v1/test_w2c_receiver_admission.py -v
    python3 formal/pon-nakamoto-v1/w2c_receiver_admission_cost.py --bits 8 12 --cap 65536 --out /new/path/w2c.json
    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --all-targets
    cargo test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib -- --test-threads=1
    cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-targets --all-features -- -D warnings

Exact raw-output controls:
'TRNM_P2_REAL_V3_COOKIE_REPORT' for real signed V3 client Head and Submit;
'TRNM_P2_NATIVE_COOKIE_COST_REPORT' for isolated actual V3 winner SHA256 and
W1 component; 'TRNM_W1_FOUR_NATIVE_REPORT' for P0 four forgeries. Always
use new regular files with source, compiler, binary and hardware provenance.
The commands above are *acceptance work*, not assertions that they ran.

## Critical unresolved attack vectors, no optimistic defaults

- **Loopback relay provenance:** native 'receive_page_from' accepts a
  caller-supplied source SocketAddr, so an application must not represent
  remote data through a forged loopback locator or relay. Destination IP
  alone is not sufficient to prove data origin. Secure deployment requires
  a mandatory original Host kernel parent for untrusted relay sources.
- **Operator outbound sync:** original host cgroup limits aggregate work but
  raw/native sync may still repeatedly consume W1 verification time without
  a signed per-request CPU price. Sharing kernel capacity is not caller
  fairness or infinite-flood immunity.
- **Pinned-peer CPU under contention:** the original local service budget
  covers its complete verification and scoped M06, but known bad complete
  W1, valid W1 with bad StateRoot, packet replays, budget depletion and
  legitimate Head/Submit must compete under one measured Host quota.
- **W2-C issuance/Sybil:** even receiver-local one-use tickets may cause
  finite grant-table exhaustion by unpaid senders; paid work is still
  cheaper than rejecting false transcripts on the same receiver.
- **W2-A/B/C proof soundness:** none is a verified economical replacement for
  current W1. W2-A admits an unsampled fraud, W2-B runs full arithmetic,
  W2-C remains a separately priced SHA256 search.
- **P4/A03 full public service:** three modes × three complete runs ×
  three timely real client-confirmed rounds, with all Busy/timeout/unknown
  denominators and multi-CPU/memory/process readbacks, has not been run on
  this newly integrated SHA.
- **P6 independent cryptanalysis:** a third Go program written in the same
  engineering effort is not independently operated or cryptographically
  reviewed. External reviewers, blinded vectors, signed reproducibility,
  fork-choice/work uniqueness and upgrade profile remain mandatory.

**Readiness: P0 regression source available; P1/P2/P3/P4/P5/P6 remain
research/development unqualified.** Exact full Rust compilation and an
actual administrator-provisioned host are unavailable in the assistant's
current container. This file must not promote production flags, merge a
protected branch or treat an unexecuted command as success.


## Additional integrated P0/P2 cost-evidence cross-check

The original actual TCP 'public_v3_from_zero' fixture already records *all*
unpaid/admitted attack and honest client bodies, responses and client-local
V3 metrics. On this integrated tree it now requires the real signed Cookie
search CPU to be present on every successful Head and honest Submit and
on every hostile call which completed in a late 'WORK:Transcript' refusal.
The Cookie CPU sample remains **nested** inside whole-client CPU, never
added to that interval or to server Work CPU. Early handshake, expired
Cookie, Busy and unsubmitted exhausted searches are preserved with no
fabricated Cookie CPU.

The existing independent 'scripts/ci/run_from_zero_native.py' report reader
recomputes this optional P2-on-P0 flag from **every retained original call**,
including trial counts 1..1,048,576, correctly typed real CPU, honest
response success, and Cookie CPU no larger than the same calling-thread
whole request CPU. Old historical P0 reports missing this opt-in flag keep
their original narrower meaning. Five new in-memory hostile report
mutations exercise missing/Boolean CPU, zero trials, false solution
completion and nested CPU overstatement. They are parser tests, not native
W1 or public-network evidence.

Still **not** a closed P2: real GPU/ASIC attacker cost, paid W1 negative
requests on a physically shared host, representative nontrivial legal
models, same resource budget and independent operators remain unmeasured.
The complete A03 P4 campaign is not run on the integrated SHA.
