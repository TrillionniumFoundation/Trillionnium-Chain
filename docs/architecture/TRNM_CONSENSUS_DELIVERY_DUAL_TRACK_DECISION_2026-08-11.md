# TRNM Consensus Delivery Dual-Track Decision — 2026-08-11

Status: **active delivery decision; no production-readiness claim**

This decision governs delivery sequencing. It does not silently amend the
PoCO-BFT v0 wire protocol, safety rules, or economic rules. Any such amendment
still requires a versioned protocol decision and conformance updates.

## 1. Decision

Trillionnium Chain will keep two deliberately separate consensus delivery
tracks until the custom PoCO-BFT node has production-parity evidence:

1. **CometBFT development-devnet track.** The existing CometBFT application
   adapter, deterministic runtime, JMT/ICS23 store, snapshots, and validator
   lifecycle fixtures remain the shortest deployable path for development and
   differential evidence. This track may produce explicitly labelled
   development-only devnet artifacts. It is not a public-testnet or mainnet
   readiness claim.
2. **PoCO-BFT incubator track.** The frozen PoCO-BFT protocol and deterministic
   Core remain the target custom consensus design. This track cannot be called
   a node candidate until a new, non-legacy `trnm-poco-node` owns the complete
   production lifecycle and passes the promotion gates in this decision.

The two tracks share the deterministic runtime, authenticated JMT state,
canonical transaction semantics, proof formats where compatible, and
differential vectors. They do not share validator safety state, signing
journals, node databases, chain IDs, readiness labels, or release artifacts.

## 2. Why this is required

The July CometBFT spike already has local four- and six-validator process
evidence, crash recovery, application replay, validator rotation, partitions,
JMT commitments, and snapshot state sync. The August PoCO-BFT branch has a
strong deterministic safety kernel, standalone SafetyState and signer
journals, a bounded inert G1c three-store recovery join, and a default-build
G1f host-owned timeout signing loop with exact persisted replay. P2 real-node
work has still not started: there is no production effect driver, authenticated
transport, production remote signer/external watermark, fork-aware execution
adapter, state sync, or deployable node artifact.

PoCO-derived validator power is not by itself evidence that a bespoke BFT
engine is required. CometBFT accepts deterministic application-supplied
validator-set and voting-power updates. A custom engine is justified only by a
documented requirement that cannot be implemented safely at that application
boundary, or by measured evidence that the custom engine provides a required
property while meeting the same safety, recovery, operations, and audit bar.

Continuing replacement-first development before that evidence would rebuild
P2P, WAL/replay, signer isolation, state sync, RPC, mempool, observability, and
operator tooling simultaneously. The dual-track boundary preserves a usable
integration oracle while making the replacement burden explicit.

## 3. Immediate engineering order

No new PoCO protocol carrier or typestate layer is added unless it directly
closes one of the frozen production contracts.

The PoCO-BFT incubator proceeds in this order:

1. correct legacy CLI, RPC, testnet, CI, and release labels that can imply
   production behavior when no production backend exists;
2. create the minimal fail-closed `trnm-poco-node` production host with unique
   ownership of Core, SafetyState store, signer, application/overlay store,
   pacemaker, network boundary, and recovery coordinator;
3. complete `CanonicalSignIntentV0`, an append-only sign journal, an
   independently monotonic signer watermark, exact signature replay, and real
   process kill-point tests;
4. implement authenticated validation-obligation takeover, BlockId-keyed
   speculative execution, a durable ordered finalization queue, and idempotent
   application acknowledgement;
5. close epoch transition, checkpoint/state sync, evidence persistence, and an
   independent light-client verifier;
6. only then add the real authenticated P2P node, remote signer, transaction
   ingress, operational controls, and multi-node campaigns.

PoCO voting power remains `shadow` throughout these steps.

The current G1c slice is evidence toward step 4, not completion of it. Ordinary
`Core::recover` still refuses an obligation-bearing head. A separate inert
session accepts exactly one reconciled deterministic-invalid obligation; the
schema-v8 application recovery owner opens existing data only and supports
`CallbackPending`, `Delivered`, and `Acked`. The inert node joins only
obligation + pending, obligation + delivered, completion + delivered, and
completion + acked across the application, SafetyState, and signer stores. A
concrete non-cloneable SafetyStore token proves exact native-invalid head
readback but grants no callback, Core, or general application transition
authority by itself. It is one required provenance input to the bounded
application recovery transition only when the pinned manifest and exact
existing `Delivered`/`Acked` row also match.

This slice has no fresh executor, BlockId speculative overlay, ordered
finalization queue, general effect driver/network, state sync, or complete
production crash matrix. G1e validation-recovery SIGKILL is archive-only. It is
non-buildable in the active Cargo graph. Its former feature-gated local Linux
design described sixteen checkpoints across `O+P`, `O+D`, `C+D`, and `C+K`,
both routes, and both supported deterministic-invalid reasons. The active
manifest now registers neither its legacy feature/dependency edge nor its
helper/integration-test targets, so it supplies zero current native-CI or
readiness evidence. The historical record was not power-loss, host-reboot,
device-write-cache, or hardware-fsync evidence and remains outside the
`--no-default-features` development-library artifact. `Reserved`, `Evaluated`,
`Applied`, `Valid`, and `Unavailable` recovery remain unsupported.
Whole-namespace rollback protection still needs a
production independent monotonic boundary. The application recovery facade now
uses ordinary-shared/recovery-exclusive sidecar locking, pins its process,
canonical parent, lock, and main-database identities, and audits all supported
and active rows before joining. That is still local Linux evidence: SQLite owns
the WAL/SHM inode lifecycle, hostile same-EUID bypass remains out of scope, and
neither sudden power loss nor the complete production kill-point campaign has
certified this ownership protocol.

G1f separately advances steps 2 and 3 without claiming either complete. The
ordinary host now uniquely owns Core, SafetyStore, signer journal, and an
injected producer for one host-derived local-timeout lane. It proves exact
persist/readback before `StorageAck`, canonical timeout intent journaling,
external-watermark confirmation before `SignatureReady`, fingerprint-bound
typed outbound release, exact restart replay without a second producer call,
and fail-stop when the signer maximum Safety revision is ahead of the
authenticated SafetyStore. Vote signing is explicitly refused. The producer is
still an injected adapter rather than a production HSM/KMS, the binary still
refuses activation. A required-feature local Linux matrix now proves direct
child SIGKILL/reap and two-fresh-process exact replay at six bounded points
from SafetyStore readback to verified typed Broadcast. It does not prove power
loss/hardware fsync, production HSM/KMS, network wire bytes, or
whole-namespace rollback. Pacemaker token ownership, transport, application
execution, and the general effect loop remain open.

## 4. PoCO-BFT promotion gates

The custom track may replace the CometBFT development candidate only after all
of the following are bound to an exact commit and reproducible artifact:

### G1 — single-node safety and recovery

- a production-reachable, non-legacy host owns exactly one Core, SafetyState
  store, signer journal, application store, and BlockId overlay namespace;
- every persisted vote, timeout, and handoff intent carries the complete
  canonical preimage, authorized SafetyState revision, and stable fingerprint;
- kill/restart at every persistence, signing, callback, finalization, and
  snapshot boundary produces no double-sign, skipped ancestor, lost durable
  obligation, or ambiguous restart state;
- whole-namespace rollback/clone is detected by an independent signer
  watermark or causes fail-stop before a signature can leave the boundary.

### G2 — protocol closure

- unequal-weight and adversarial-identity leader-selection evidence is reviewed
  before freezing proposer policy;
- epoch handoff/reset, evidence retention, checkpoint recovery, state sync, and
  same-epoch/cross-epoch light-client vectors are implemented;
- Rust traces, conformance vectors, bounded formal models, mutants, property
  tests, and decoder fuzzing agree on the frozen invariants.

### G3 — real-node parity

- authenticated and bounded transport, version negotiation, peer quotas,
  backpressure, WAL/replay, remote signer, transaction ingress, RPC, metrics,
  and runtime/JMT integration are production-reachable;
- reproducible four- and seven-validator campaigns cover process kill, disk
  full/read-only/corruption, stale state, OOM, clock skew, equivocation,
  partitions, healing, catch-up, and snapshot restore;
- the result has zero conflicting finalized blocks and zero double-signs, and
  all recovery evidence can be independently replayed.

### G4 — operational and review parity

- measured SLOs, resource bounds, disk growth, recovery time, and P50/P95/P99
  latency are enforced from real telemetry;
- a 72-hour campaign and then a seven-day multi-host soak pass;
- reproducible signed node artifacts, SBOM/provenance, upgrade compatibility,
  downgrade refusal, long fuzz campaigns, an external consensus review, and an
  independent light client pass.

Passing a Core unit-test or simulator gate cannot satisfy a real-node gate.

## 5. Decision and exit criteria

At each promotion review, one of three outcomes must be recorded:

- **continue dual-track** when the custom path is making bounded progress but
  has not reached parity;
- **promote PoCO-BFT** only when G1–G4 pass and the remaining custom-engine
  benefit is documented against the same CometBFT application workload;
- **retain CometBFT** when the required PoCO validator/economic semantics fit
  safely behind ABCI++ and the custom engine has no demonstrated compensating
  benefit, or when its recovery/operations burden misses a gate.

Any claim that CometBFT cannot carry the required validator semantics must name
the exact ABCI++ limitation, the affected invariant, the rejected adapter
designs, and a reproducible counterexample. Preference for Rust, message-count
reductions, or ownership of the stack is not sufficient by itself.

## 6. Claim boundary

Until a promotion decision is recorded:

- CometBFT artifacts are labelled `development_only` and must not claim PoCO
  production finality;
- PoCO-BFT artifacts are labelled `incubator` and must not claim node, testnet,
  or deployment readiness;
- legacy `trnm-node`, `trnm-cli`, `trnm-rpc`, and `trnm-sim` evidence cannot be
  used as PoCO-BFT P2 evidence;
- no PoCO economic weight is activated outside deterministic shadow output.

## 7. References

- `TRNM_CONSENSUS_ENGINE_DECISION_2026-07-27.md`
- `TRNM_COMETBFT_SPIKE_2026-07-27.md`
- `TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`
- `TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`
- `../development/TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md`
- `../protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md`
