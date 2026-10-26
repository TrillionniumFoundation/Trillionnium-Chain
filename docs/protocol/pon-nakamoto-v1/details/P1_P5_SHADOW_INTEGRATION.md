# P0–P6 adversarial integration preview: W1 verification-cost asymmetry

**SHADOW_ONLY / HOLD_NO_GO**: combined source, no production admission,
consensus, protocol, model reward, fork-choice or final-use activation. The
parent chain of changes starts with Chain #335 at
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'. This development tree
combines candidate material from #339, #340, #342 and #350, with additional
single-budget cross-path tests and the source-guard regression sentinel.

## One original proof owner, not four independent guest budgets

| Entry and threat | Current source target | What is enforceable in source | What remains unqualified |
| --- | --- | --- | --- |
| W1 four from-zero false traces | 'pon_work.rs' + independent Python oracle and native test in #335 | Exact ticket can pass; complete replay refuses TRANSCRIPT without VerifiedWork | Earlier user-supplied four raw transcripts/timings have not been provided to this patch; native exact-source receipts required |
| Public V3 untrusted Submit | 'ingress/public_v3.rs' | Original one-use server Cookie, paid lane, cooperative W1, genuine CPU domain, bounded worker count | Honest fairness under indefinite identity churn and GPU-accelerated Cookie solving |
| Legacy authenticated WAN and V2 | 'ingress.rs', 'public_v2.rs' | Legacy WAN requires signed protected admission + fixed cgroup; V2 unmetered proof listener remains loopback-only | Loopback tunnel/forwarder threat and actual host process/CPU measurement |
| Pinned Peer History | 'peer_polling.rs' (#340) | Original Node-bound shared CPU operation charges false W1 and M06; unknown accounting returns local failure, not completed sync | Real concurrent malicious peer, honest confirmed blocks and kernel total measurement |
| Native/CLI History sync | 'ingress.rs' / 'main.rs' (#342/#350) | Fixed Host parent for nonloopback; addressless public parser removed; original CPU domain charged per W1 and activation; standalone trusted Node binds only one zero-credit account | Caller-supplied loopback routing context, honest sync tail under contention, deep nonpreemptive activation |
| W2-C local cost trial | 'formal/pon-nakamoto-v1/w2c_receiver_admission.py' (#339) | One HMAC-bound proposal/receiver/epoch token consumes at most once, including 32-way replay challenge | Local cost asymmetry, token-slot exhaustion, GPU/ASIC costs, signed V3 integration and proof uniqueness |

An intermediate SHA-256 ticket, Hashcash Cookie, cache verdict, operator
document, committed source or pending CI job never constructs VerifiedWork or
actual Chainwork. All durable Node effects keep their original authority and
their existing recovery obligations.

## Native/source negative regression selectors

Run manually on a real isolated source checkout with exact source and hardware
receipts; the embedded commands do NOT grant correctness simply by being listed:

    bash scripts/project-preflight.sh --audit
    python3 scripts/ci/test_w1_public_cpu_paths.py
    python3 formal/pon-nakamoto-v1/test_work_precheck.py
    python3 formal/pon-nakamoto-v1/test_w2c_receiver_admission.py -v

    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib ingress::tests:: -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --lib peer_polling::tests:: -- --test-threads=1
    cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --test public_v3_from_zero \
      four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged -- --exact

The additive cross-owner selector
'peer_polling::tests::pinned_peer_and_history_page_charge_the_same_original_cpu_domain'
sends the **same late-failing proof** through pinned-peer and History import
against one Node and checks that the original settlement's
'settled_full_cpu_ns' increases twice, no in-flight operation survives and
state/active tip do not change. This is stronger than verifying merely
decreased credit, which could be confounded by refill.

The History tests cover a real new challenge-matched *valid W1 plus false
StateRoot* (late ROOT refusal), false C, valid activation, zero-credit
refusal/refill and forbidden second Node budget, and absence of paid owner
under a budgeted remote cgroup. Source test
'scripts/ci/test_w1_public_cpu_paths.py' checks exact known native sections
for original CPU and Host guards with in-memory negative edits. The checker
is a change sentinel, NOT exhaustive reachability, dataflow, code execution,
external security review, kernel budget measurement or deployment safety.

## Strict remaining gates

- **P0**: original four attacker raw byte/time/resources immutable and all
  native/third-language regressions actually executed under frozen SHA.
  Newly generated fixed vectors are not the same thing.
- **P1**: compile all integrated Rust; enumerate CLI, local/proxied-loopback,
  authenticated, V2, V3, pinned-polling and programmatic callers; confirm
  all actual Host CPUs and processes share finite original owners across
  crash/restart and observer faults. No unmetered PUBLIC W1 should remain.
- **P2**: actual V3 signed-Cookie cost on CPU and GPUs at same original
  target and task, independent hash rates, every miss and honest per-request
  burden; a synthetic Python Hashcash probe cannot set real price.
- **P3**: original same-CPU-domain attacks using key rotation, spent-cookie
  replay, distinct fake traces, valid-W1/wrong-StateRoot and honest read/submit
  arrival windows, with correct Busy/deferred/consensus-invalid distinctions.
- **P4**: original A03 three pressure modes, three complete repetitions per
  mode, each 3/3 independently confirmed timely honest rounds, all
  denied/timeout/unknown observations and before/after physical host totals.
  A local single-Host TEST PASS is not independent WAN qualification.
- **P5**: a separately versioned, uniquely lottery-bound efficient and
  cryptographically secure COMPLETE W2 relation; W2-A sampling demonstrably
  accepts wrong unsampled tiles, W2-B current witness is a full replay, and
  W2-C Hashcash remains non-neural useful work with replay/economic limits.
- **P6**: independent external cryptographic/security researchers implement
  an unrelated verifier with blind hidden vectors, verify challenge, task,
  ticket, fork rules, cost/security assumptions and signed receipts. Internal
  Go/Rust/Python parity cannot replace independent acceptance.

The current assistant execution sandbox cannot reach github.com over its
local network and has neither a complete mounted Chain checkout nor rustc,
cargo, physical target cgroup or actual external GPU. Source writes used the
authenticated GitHub tool; exact native execution and the repository-mandated
preflight are NOT reported as performed. All tests in this integration
beyond already observed Python research are source-authored, not counted
as runtime passes.

No CI status, documentation consistency or Git commit is used to close
a physical/economic/cryptographic blocker. Do not mark Ready or activate.
