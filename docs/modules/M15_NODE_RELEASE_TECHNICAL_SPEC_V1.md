# M15 Node Composition / Packaging / Release technical specification v1

Status: **implementation contract; no release authority**

## Authority

M15 composes reviewed ports into a process, validates configuration and owns
startup, shutdown, recovery orchestration and artifact packaging. Domain rules
remain in M00-M13. It cannot fabricate an authority receipt, set a finalized
root, lower a signer watermark or turn a candidate build into a production node.
The initial deliverable is a reproducible private-devnet process lifecycle.
That deliverable is distinct from production activation and external acceptance.

### Source map and executable status

| Source | Present capability | Boundary |
|---|---|---|
| `trillionnium/crates/trnm-poco-node/src/main.rs` | Fail-closed production entrypoint and bounded candidate preparation | Does not start an enabled production validator |
| `trillionnium/crates/trnm-poco-node-cli/src/lib.rs` | `status`, `start` commands | Current `start` is expected to refuse |
| `trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs` | `ProductionNodeCompositionV0`, verified authority ingress/facts/session | Generic ports are not a deployed service set |
| `trillionnium/crates/trnm-poco-node-production-v0/src/public_ingress.rs` | Transport-neutral `ProductionTxPublicIngressV0` dispatches a validated typed request into node-owned CheckTx and the durable M05 WAL | No socket, wire decoder, peer/HSM, proposal, or finality authority; production activation remains false |
| `trillionnium/crates/trnm-poco-node/src/authenticated_transport.rs` | Candidate-only bounded TCP framing around the authenticated P2P session; host callback is reached only after session/replay validation | Feature-gated; no TLS/static peer profile, peer lease, M05/M13 dispatcher, Core ACK, signer, proposal, finality or production listener |
| `trillionnium/crates/trnm-poco-node-host/src/lib.rs` | Persistent host lifecycle boundary | Recover actual module owners before serving |
| `trillionnium/crates/trnm-migration-v0::SqliteMigrationHandoffStoreV0` | Host-owned durable migration handoff ledger; atomic phase CAS and fsync/readback | Does not open production activation or manufacture M01/M02/M08 evidence |
| `trillionnium/crates/trnm-poco-lab-validator/src/candidate_devnet.rs` | Explicit bounded candidate CLI with external Unix peer lease | Single-LAN, local test keys; no HSM or public-testnet authority |
| `trillionnium/crates/trnm-release-bundle-v0/src/lib.rs` | Bundle validation, signatures and independent build comparison | Does not itself authorize publication |

## Interfaces

Existing closure names are `node-prod-v0`, `node-devnet-v0`, `ai-v1-candidate`
and `lab-and-evidence`. Resolve crates/features from `config/build-closures-v1.toml`;
never infer production eligibility from a crate name containing `production`.
AI-v1 candidate features remain explicit; lab/fixture dependencies cannot enter
the default production closure.

### Planned devnode configuration

`DevNodeConfigV1` is a proposed closed-world adapter configuration. Use TOML with
unknown-key rejection; normalize validated typed values into a deterministic
configuration digest, not the original whitespace. Every field below is required
unless its default is stated. It cannot contain a private key inline.

| Field | Meaning and validation |
|---|---|
| `schema`, `mode` | Exactly `trnm-devnode-v1`, `private-devnet`; other modes rejected |
| `chain_id`, `genesis_digest`, `protocol_digest`, `profile_digest` | Nonzero 32-byte digests; exact match with signed descriptor |
| `node_id`, `validator_id`, `validator_set_digest` | Exact descriptor identity/role; observer has no validator signing port |
| `data_root`, `config_descriptor` | Absolute canonical owner-controlled paths; no symlink escape or silent creation over existing data |
| `transport_profile`, `peer_descriptor` | Explicit M04 profile and authenticated static peers |
| `signer_endpoint`, `signer_policy_digest` | Separate service capability; local test signer allowed only in dev profile |
| `worker_count` | One of 1/2/4/8; recorded as local execution setting, never a different root rule |
| `rpc_bind`, `metrics_bind` | Loopback defaults; nonloopback requires TLS/explicit access policy |
| `control_plane_mode` | Exactly `observe`; application disabled by this initial target |
| `run_duration_seconds`, `max_blocks` | Finite positive dev bounds, independently checked against the chosen harness |
| `limits` | Named M04/M05/M14 resource profiles plus startup/drain ceilings |

`validate_config` reads and validates public descriptors before opening signing
keys or authority databases. Verify certificate/key roles, chain/profile and
feature closure. Then bind the digest to a process-instance ID and generation.
An environment variable may select the config path; it may not override a
signed chain, validator set, protocol or signer policy without revalidation.

### Current reproducible command entry points

These commands exercise existing entrypoints; a failed `start` is the expected
production boundary and is not a broken devnet bootstrap:

```bash
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-cli --locked -- status
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-cli --locked -- start
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-poco-lab-validator --bin trnm-poco-candidate-devnet-validator --locked -- --help
```

An actual bounded candidate run requires the manifest-bound private run root,
validator config, peer lease daemon and other validators prepared under the
existing `docs/runbooks/TRNM_POCO_G3_LAN_FLEET.md` contract. The following shows
the existing CLI invocation with operator-supplied absolute paths; placeholders
are not configuration generators or an assertion that this host is provisioned:

```bash
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-poco-lab-validator --bin trnm-poco-lab-validator --locked -- peer-lease-daemon --socket "$DEV_LEASE_SOCKET" --journal "$DEV_LEASE_JOURNAL"
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-poco-lab-validator --bin trnm-poco-candidate-devnet-validator --locked -- --acknowledge-candidate-only --run-root "$DEV_RUN_ROOT" --config "$DEV_VALIDATOR_CONFIG" --peer-lease-socket "$DEV_LEASE_SOCKET" --report "$DEV_REPORT_PATH" --duration-seconds 60 --max-blocks 30
```

Run the daemon in a separate supervised process. Existing candidate lease timeout
is 5000 ms by default, allowed 100..30000 ms; the harness allows at most seven
days and 10,000,000 blocks, with at least three blocks. A requested 60 s/30-block
run is a development example, not a completed soak. Preserve non-success and
special parked outcomes rather than translating every report into success.
The simplified `DevNodeConfigV1`/M04 TLS composition is planned, not this existing
lab CLI's accepted configuration schema.

### Reduced LAN placement (M15-LAN-PLACEMENT-V1)

The laboratory planner and material generator accept the closed
`--placement-profile` enum `canonical` (default) or `desktop4-rog3-mac-v1`.
`canonical` retains the exact existing schema-1 topology bytes for all
7/31/100-validator and equal/bounded-unequal combinations. The new explicit
profile accepts only seven equal-weight validators. It emits schema 2 with
`placement_profile` exactly `desktop4-rog3-mac-v1`: validator indices 0..3 on
the inventory's actual `desktop`, indices 4..6 on its actual `rog`, and the
actual `mac` as the sole nonvalidating observer. Participants are exactly those
three physical hosts in that order. The unchanged six-host inventory remains
the source of host identity, management alias, LAN address, OS, architecture
and roles; neither CLI accepts an arbitrary inventory override. Validator IDs
retain the existing fleet/index derivation, ports remain `31000 + index` and
`32000 + index`, and all seven validators retain six direct peers.

`plan_topology.py::build_topology` is the shared pure producer. Material and
connectivity admission regenerate and compare the complete exact typed topology
against the committed inventory, including participant order, host allocation,
management, addresses, indices, ports, weights, identities and peer order.
Rehashing a substituted topology or coherently rewriting its dependent configs
does not authorize another placement. Schema 1 cannot carry a placement field;
schema 2 requires the exact reduced profile. Unknown profiles, schema confusion,
31/100 validators, unequal weights or a substituted observer reject before
creating run material or opening network/signing authority. The existing
manifest version remains unchanged because its public-file inventory already
binds the exact topology bytes. Reports derive actual validator-host counts and
identify the reduced placement; they cannot report five validator hosts or all
six participants for this profile.

The reduced profile additionally admits the explicit native-client candidate
through the private transport below. This removes only the unsupported-placement
refusal; independent full-fleet, public-network and performance gates are unchanged.

### Candidate remote native request adapter (M15-NATIVE-REMOTE-REQUEST-V1)

The controller prefers the existing actual local Linux validator when present;
otherwise it deterministically selects the lowest validator ID among the actual
Linux validator processes. Selection must match the validated process, host stage
and per-host deployed `linux_paths` binary. The closed placement and existing
same-source/deployed-binary checks remain prerequisites. Mac remains the sole
application signer and independent inclusion-proof verifier. Linux receives only
canonical request bytes (including already signed outer bytes), never application
private keys. There is no TCP forwarding, tunnel, invented local validator or
remote signing authority.

Before output/staging/network effects, the runner checks selection and planned
namespace geometry. Each request executes the already deployed `native-client
request` binary on the selected host, against that validator's own private Unix
socket. SSH uses the validated management alias, batch mode, bounded connection
and absolute campaign deadline. Local placement uses the same adapter checks
without SSH. Paths must be canonical and confined to the owned stage; on-host
no-follow checks require owner-private directories, an owned regular executable,
an owned mode-0600 socket, and fresh mode-0600 request/response files. One fresh
request directory belongs only to this campaign; sequence reuse or preexisting
files reject. No node, key or unrelated stage is modified.

Requests retain the native CLI limit of 528384 bytes; responses retain
8 MiB + 16 KiB. The adapter bounds stderr to 64 KiB, at most 4096 exchanges,
64 MiB total request bytes and 256 MiB total response bytes. Request execution
has at most 12 seconds and never extends the one absolute campaign deadline;
SSH connection time is included. Only a specifically missing endpoint may retry
during startup. All other process, path, protocol and transport failures retain
the original diagnostic and abort; a consumed failure is not reported as success.
Controlled subprocess/SSH tests prove the adapter and rejection boundaries only;
a genuine same-source LAN native campaign remains a separate acceptance item.

The consensus runner passes this already validated placement to the capacity
gate. Canonical capacity reports retain their exact schema-1 bytes and require
one local validator host. The reduced profile additionally probes the actual
local coordinator, which hosts zero validators; it must not substitute a local
validator or skip the probe. Both validator hosts retain all existing CPU,
RSS, per-process file, UID-thread and system-capacity checks. The coordinator
uses the same bounded scalar observations and inherited-limit checks, including
the independent `7 * 2 + 128 = 142` capture-file-descriptor budget, UID/system
thread reserve and system file-handle headroom. All three observations share
the existing maximum 30-second epoch spread. The reduced capacity report uses
schema 2/profile `poco-g3-mesh-host-resource-preflight-desktop4-rog3-mac-v1`,
records `placement_profile`, keeps only desktop/rog in `hosts`, and records the
zero-validator `local-coordinator` separately in `coordinator`. This controller
observation adds no validating participant or full-fleet acceptance. Invalid
placement, missing coordinator facts or insufficient resources reject before
output creation, staging, signer launch or validator network authority.

The pure planned-P2P contract accepts the same independently supplied inventory
and uses the shared exact topology validator. Its existing canonical plan,
request/ack and report schema 1/profile
`planned-p2p-connectivity-admission-v1` remain unchanged. The reduced variants
use schema 2/profile
`planned-p2p-connectivity-admission-desktop4-rog3-mac-v1`, two source hosts,
seven destination endpoints, fourteen physical source-host/endpoint pairs
(including local pairs) and the same forty-two directed logical peer edges.
Helpers, cleanup and both sides of the report must cover that exact plan. The
existing message kinds/domains still bind the complete plan hash; schemas and
profiles cannot be mixed. This pure helper contract performs no network I/O
and does not imply that the controller invokes a connectivity admission stage.
Actual runtime reports independently record the selected placement, observed
validator-host count and truthful participant flags. Canonical runtime plans
and summaries retain their existing schema-1 keys. Reduced runtime plans and
summaries use schema 2 with `placement_profile` and `participant_host_count`;
the reduced summary also records `linux_validator_host_count`. A seven-process
success cannot set `all_six_hosts_participated` when only three physical hosts
participated. Existing completed full-fleet signed bundles may retain their
run-ID topology annotation, but the raw checker requires exact equality with
the signed summary before comparing the underlying canonical inventory plan.
That compatibility does not admit the annotation into material generation or
the topology planner and cannot admit reduced placement into external gates.

This profile allows bounded direct-LAN connectivity, process-fault, partition,
recovery and performance observations using fresh source-bound laboratory
binaries and fresh ephemeral keys. It supplies two validator failure domains
plus a real Mac observer. A physical-host loss removes three or four votes from
a seven-vote, quorum-five deployment, so it does not establish liveness under
one physical-host failure. Full-fleet/five-host, all-six-participant, geographic,
WAN, independent external acceptance and production gates retain their own
requirements. No reduced run may promote them or alter production activation.
Fake-material tests exercise configuration and rejection only; they are not
consensus, connectivity or performance evidence.

### Subordinate composition packages

These packages remain distinct owners of local interfaces; their existence does
not make the candidate node production-enabled. Paths below are under
`trillionnium/crates/`.

| Package / entrypoint | Exact responsibility and implementation rule |
|---|---|
| `trnm-poco-node-authority/src/facade.rs` | `NodeAuthorityCoordinatorV0` reports readiness and keeps `production_activation_gate` closed. Its feature-gated persistent candidate offers `open_candidate`, `recover`, `prepare_bound_ingress` and `advance_exact`; no I/O or telemetry callback may fabricate an advance. |
| `trnm-poco-node-authority/src/confirmed_application_safety.rs` | `ConfirmedApplicationSafetyAuthorityV0::from_checkpoint_candidate_v0` consumes the authenticated whole-node checkpoint, refuses zero application height/Safety revision, derives application/Safety stage digests and produces a one-use continuation. `OperationBindingV0` must match height/view/block and nonzero operation ID; mismatch returns `OperationBindingMismatch` or `InvalidOperationBinding`. Historic stage names remain observations under M08's two lifecycles. |
| `trnm-poco-node-io/src/lib.rs` | Default `NodeIoRuntimeV0::inert` enables zero surfaces. Candidate pacemaker identifies `(epoch,view,generation)`, requires nonzero view/generation and bounds delay at 60,000 ms. M15 supplies a monotonic clock; stale timer completion is discarded without advancing Core. Candidate authenticated P2P is explicitly feature-gated and obeys M04's replay/ack boundary. |
| `trnm-node-boundary-v0/src/{lib,production_ports}.rs` | Version 0 identity and budget contracts bind chain/validator/application/generation, `OperationBindingV0` and typed completions. `StepBudgetV0` rejects zero/over-ceiling counters: 4 MiB/frame, 256 ingress/outbound items, 32 MiB each direction, 32 authority advances per step. Production ports separate host attestation, monotonic anchor, remote signer and persistent pacemaker. `VerifiedProductionStartupV0` is issued only after actual port checks; an installed trait implementation is not verified startup. |
| `trnm-bridge-poc/src/{lib,relay_heartbeat,x2_settlement_loop}.rs` | Laboratory `SettlementRequest {chain_id:u32, tx_hash:String, status}` moves Pending to Finalized(height) or Reverted(reason), under local `CapabilityToken` and heartbeat checks. `drive_minimal_settlement` is an orchestration model, not native finality or remote bridge verification. Caller-constructible capability tokens must never authorize a production transfer. |

For the bridge PoC, reject malformed request/token, unauthorized action, zero or
invalid finalization height and illegal terminal transition without changing
status; retry-pending heartbeat does not authorize a refund. Preserve the current
Unicode/control/bidi canonicalization and transaction-hash replay regressions in
`tests/integration_tests` and the X1/X2/X3 suites. The current objects are in-memory
models. A production adapter must instead consume M08/M13 verified finality and
the durable nullifier/asset/event transaction described below; serializing a PoC
`Finalized` enum does not create that proof.

Recovery tests for composition must reopen exact identity/generation, deliver a
stale timer or mismatched stage binding, interrupt between the two confirmed
application/Safety advances, and prove no second publication/signature or false
readiness. Boundary ports own no hidden durable state: adapters declare their
store/anchor and reconstruct only from M03/M07/M08 authoritative readback.

The feature-gated `trnm-poco-node-host/src/handoff_runtime_v1.rs` now owns a
candidate join between a live native application owner, its freshly read
committed pre-certificate receipt, strict M01 context and the role-specific
durable journal. `CandidateHandoffRuntimeV1` verifies path/store affinity and
exact row/head/configuration bindings before signing or new-only recovery.
Old/continuing restart is explicitly fenced as described below. Its private
recorded result retains intent, signature, application commit/artifact and context
identity. It creates no keys and cannot activate Core, authorize ordinary votes,
publish via a Core callback or close the whole-node checkpoint barrier. Full
positive joined-node and epoch crash/restart acceptance remain necessary.

### Planned native client composition and bootstrap profile

The `native-public-candidate-v1` composition replaces the fixed workload source
inside `trnm-poco-lab-validator/src/consensus_runtime.rs::maybe_propose_v1`.
Its leader drains the M05 durable native queue into the existing
`continuous_runtime.rs` preview/proposal signer/network path. Followers execute
the exact transmitted block under their own application owner; they need not
receive the submit request. A nonleader may acknowledge its own durable queue
and wait for its scheduled view; no transaction-gossip guarantee is implied.
The live endpoint, queue, proposal owner and finalized readback share the same
configured chain/root and process lifecycle. `trnm-poco-node-host`'s default
inert I/O and production-start refusal remain unchanged; wiring a candidate
socket does not open them. Legacy `trnm-rpc` and G1 fixture finality are excluded
from this composition.

Network delivery can race a local Timeout or an earlier Vote in the same
view. The candidate ingress first authenticates the proposer witness and
checks the parent-time-independent view/parent/height relations and requires
any TC to contain and select the exact separate justify QC. Only then does it
strictly process the complete carried QC/TC and read the resulting local view
and phase. A proposal for an older view, or for the current view
whose owner is already `VoteSigned`/`TimeoutSigned`, returns an explicit
no-vote outcome. This outcome does not attest body execution or full proposal
acceptance, issue a signing lease, reset a signed owner, or add an execution
coordinate. Any actual carried-certificate progress still updates finality
bookkeeping and the timer; future proposals must pass the unchanged exact
parent/binding/execution path. Invalid witnesses, conflicting certificates,
failed durable readback and unexpected authority errors remain errors. The
network actor must not terminate merely because an authenticated delayed
proposal arrives after its local timeout; direct local voting remains strict.

The signed public campaign descriptor adds the chosen profile, application
signer-policy digest, `wall_clock_epoch_ms`, client socket relative name, M05 queue
limits, maximum block cadence and finite drain budget. Application signers are
an explicit list of signer ID, stable canonical identity, role and public key,
validated for duplicate/conflicting identity and role before store creation.
Their policy commitment is part of the native genesis/bootstrap derivation;
existing workload-key genesis or databases must never be silently retargeted.
Initial credits are either explicit genesis state or real operator-signed
transactions from the declared campaign policy, not hidden fixture funding.

For an explicitly isolated candidate campaign, generate fresh application client
and operator keys only under that campaign's owner-controlled 0700 key directory,
with exclusive 0600 files. Copy only public policy to validators. Client-side
signing retains the private material; request bodies, reports, logs, validator
config and proof artifacts contain no client private key. Do not regenerate
keys on restart or borrow production keys. Campaign generation must reject an
occupied namespace and derive a fresh declared genesis/bootstrap; an existing
network joins by its exact public descriptor. Generation does not authorize
production activation or HSM claims.

The frozen canonical laboratory genesis keeps timestamp 0 and its existing
hash formula. The new candidate profile commits one agreed `wall_clock_epoch_ms`
in its manifest-bound descriptor. Native envelope validity and block timestamps
use **chain-relative milliseconds**: `W = now_unix_ms - wall_clock_epoch_ms`,
with checked subtraction. The existing envelope field names retain `unix_ms`
for wire compatibility; capabilities and signing clients must explicitly expose
this candidate time domain and never sign raw Unix time for this profile.
The coordinator chooses a fresh epoch before commissioning the h1-h3 prefix;
validators reject a future epoch or clock skew instead of inventing an offset.
No 1ms fixture validity width applies. Consensus timers use a monotonic clock
separately. For a regular proposal let `P` be the exact authenticated parent
timestamp, `W` the owner-derived chain time and `S` the authenticated
`max_block_time_step_ms`:
compute checked `T = min(max(W, P+1), P+S)`. If arithmetic overflows or the
parent is more than the signed candidate skew allowance (default 5,000ms)
ahead of local chain time, return `TIME_UNREADY`; do not move the clock backwards.
If a resumed chain lags owner-derived chain time, empty certified blocks may advance its
parent-relative clock; new client admission waits until chain time is within
the same allowance. This local readiness rule changes no frozen timestamp rule.

Suggested candidate client TTL is 300,000ms, with maximum 600,000ms. Admission
checks the signed envelope at the owner clock and forbids a client from selecting
the server time; proposal execution rechecks it at T using existing strict
envelope rules. An accepted transaction can therefore expire before inclusion
and must obtain a durable local expiry record. All nodes use the block timestamp
for deterministic execution, never their local wall time. Repeated requests do
not extend signed expiry. Observed skew is recorded as readiness evidence.

When there are no pending transactions, propose honest empty Regular blocks at
the declared bounded cadence (development suggestion 250ms). Empty successors
execute through the same root/commit/Safety path, contain no fake client
transaction and do not contribute to business goodput. Graceful stop closes
admission first; selected user blocks must obtain their two certified descendants
or the bounded drain ends with `DRAIN_INCOMPLETE` and durable pending work.
Reserve at least two successor heights beyond the last admitted business target;
`max_blocks` cannot silently truncate finality while reporting campaign success.
On startup restore body/nonce/proposal/proof state and reconcile unresolved
handoffs before exposing the client socket as ready. Migration and recovery
failures preserve the prior databases and keep signing/submission fenced.

### Migration handoff ownership

M15 hosts the M13 handoff ledger but does not become the source-finality or
state-sync authority. `MigrationHandoffRecordV0` is persisted through
`SqliteMigrationHandoffStoreV0`; its typed phases are
`VerifiedSource -> ProjectedDelta -> DurableInstall -> ReadbackCas ->
CutoverAgreed -> RuntimeReady`. The record digest binds the finalized source
binding, verified checkpoint-context digests, target genesis/root, projection,
durable install/readback, cutover agreement, rollback floor, and separate
M01/M02/M08 readiness receipts. Every mutation is an immediate SQLite CAS,
followed by WAL checkpoint, file/parent fsync and full decode/readback. Any
stale revision, substituted context/projection, root mismatch, incomplete
readback, malformed cutover agreement, or missing readiness receipt fails
closed; `fence_v0` records uncertainty durably.

This ledger closes the in-memory-projection gap. It remains a candidate
integration contract: M15 must obtain actual owner receipts and external
crash, disk-full, replacement, multi-host and finality evidence before a
deployment can enable installation or consensus activation. No production
switch is changed by the presence of this API.

## State machine

```text
Constructed -> ConfigValidated -> OwnersLocked -> AuthorityRecovered
 -> NetworkEligible -> Serving -> Draining -> Stopped
any state -> Blocked(reason)   or   RecoveryRequired
```

### Startup operation

1. Validate the signed public configuration, artifact identity and feature set.
   Reject duplicate validator identity, unsupported schema and wrong genesis.
2. Acquire exclusive descriptor-pinned namespace ownership. Check permissions,
   available journal capacity and expected store identities; do not auto-format.
3. Connect external lease/watermark/signer services using their public policies.
   Confirm identity and fencing generation before loading a signing capability.
4. Recover Safety and signer journals, then the M08 commit ledger and its M07
   application/checkpoint targets. Let each owner verify its own predecessor
   chain; M15 only compares returned verified identities and completion status.
   The default-off epoch candidate may then call the owner-only
   `CandidateEpochRuntimeV1::ensure_incremental_epoch_commit_owner_v1()` bridge;
   it requires an already joined schema6 edge, rechecks every physical cut, and
   returns no node or signing authority. A missing schema6 owner, malformed
   schema7 row, or lost migration response remains recovery-required.
5. Recover M04 pending ingress/payload and M05 transaction journal. Resolve each
   uncertain prepared/commit receipt against M08; retain unresolved work.
6. Establish the M13 trusted checkpoint context and exact validator epoch.
   Reject mismatched chain, epoch, source/target root or external anchor.
7. Construct verified authority session/host ports. Only `AuthorityRecovered`
   can enable M04 DATA processing and signing/voting capabilities for the dev role.
8. Start read-only status first, then authenticated peer lanes, then M05 RPC
   admission. Publish readiness with source/config/authority identities.

`NetworkEligible` is not merely “port bound”. Network sockets may be prepared
while recovery runs, but no DATA or transaction admission is handed to Core.
A missing required port returns `CAPABILITY_UNAVAILABLE`; no fixture fallback.

### Serving and shutdown operations

Each host step consumes one verified ingress/fact or timeout from its bounded
queue and returns explicit effect intents. M15 dispatches effects to the owning
port and supplies exact receipts; it never advances stages from wall-clock guesses.
Control-plane loss does not stop consensus. Required signer/replay authority loss
stops the affected signing/admission path and reports recovery-required status.

On SIGTERM: mark not-ready; reject new submissions; stop accepting new DATA;
resolve already durable intents or leave their recoverable predecessor records;
flush owner journals; stop workers; release leases/descriptors last. Never clear
a queue containing sole copies of an acknowledged payload. At drain deadline,
exit with `DRAIN_INCOMPLETE` and retained recovery records. SIGKILL tests must
recover the same invariants without any shutdown callback.

### Upgrade operation

Stage a content-addressed binary and signed compatibility manifest. Verify
source/artifact identities, schema/protocol support and signer-watermark policy.
Drain the old process; lock owners once; perform any approved migration into a
fresh namespace; validate the target and immutable migration receipt; activate
only the expected target digest. Never run two owners with one validator key.
A binary rollback is allowed only if it can open the **current** authority state
without reducing watermarks or undoing finalized state. Otherwise stop; do not
restore a convenient older database to make the previous binary run.

## Persistence and recovery

### Public transaction to state-sync recovery join

The public transaction adapter persists in this order: authenticated `CheckTx`,
the M05 admission/WAL record, proposal and ordered/execution receipts, the
sign-intent fence, the signed envelope, broadcast intent/receipt, and finally
the authenticated finality readback. A state-sync join is a separate read-only
owner operation. `apply_finalized_readback_and_bind_native_sync_v1` may therefore
return `Sync` after the finality record is already durable; it must not roll that
record back or submit the transaction again.

After a process crash or lost sync response, reopen the exact journal and call
`ProductionTxNodeAdapterV0::bind_durable_finalized_readback_to_native_sync_v1`.
This path reconstructs `FinalizedReadbackV0` from the recovered lifecycle and
performs one fresh SQLite snapshot read through
`bind_durable_finalized_readback_to_native_state_sync_store_v1`. It does not
call the external finality source, append a finality frame, re-sign, or
re-broadcast. The join still carries only partial sync progress; claiming a
complete snapshot requires M13's independently verified
`NativeVerifiedSnapshotV1` capability. Block, height, state-root, binding and
manifest substitutions remain typed fail-closed errors.

### Native retained-proof consumer (M15-M13-BRIDGE-V1)

The only permitted composition point for the M08 retained-proof bridge is the
node-owned, read-only recovery path. The consumer
`verify_retained_native_finality_path_v1(independently_configured_anchor, path,
limits, budget)`
budget-checks and canonical-decodes the bounded
`NativeEpochFinalityPathV1`, then passes its ordered `EpochFirst` transitions and
`Ordinary` links to M13's `verify_native_trust_path_v1`. The anchor is
operator/host configured and independently pinned; bundle bytes, peer identity
or a recovered database row cannot establish it.

M08-PREHANDOFF-EXPORT-V1 extends this consumer's local-storage tag allowlist to
exactly 10 and 13. Both use identical independently anchored M13 verification;
the tag cannot supply a validator set, joint certificate or successor context.
All other tags reject before signature work. Schema13 finality/history export
still requires the original complete proof ledgers: a pre-handoff receipt alone
cannot substitute for a missing attached checkpoint certificate. The producer
and consumer regression must verify a genuine attached checkpoint after cold
open, preserve previously available schema10 history across migration, and
reject unavailable pre-attachment paths and unsupported tags.

The consumer compares the verified terminal header against the path target
header, parent, height, timestamp, epoch/config context and application state
root. Target P digest, commit sequence and record digest are local M08 storage
metadata and may receive only shape/nonzero checks; they are never remote
authority. The consumer then returns the verified finality-path capability to a separately owned
snapshot adapter. This phase does not feed M08's private Borsh sparse
`PersistentAuthTreeSnapshotV0` bytes to `NativeStateSyncSessionV1`, and cannot
issue `NativeVerifiedSnapshotV1`; snapshot manifest/chunk format, historical
coordinate recomputation and installation require a separate versioned
contract. The operation is one read-only M08 export followed by M13
verification: it does not reopen M08 during verification, consume a proof,
mutate the commit ledger, or retry with an alternate anchor.

The consumer returns an explicit unsupported result for a missing schema-10
ordinary proof, pre-schema-10 ordinary history, unknown edge schema or any
schema-8/9 record that would require authority promotion. It must not use the
C+3 first-new record as a substitute C+4 proof. M15 currently has no approved
native snapshot installer, signer activation, public transport, or wiped-node
catchup caller for this bridge; those remain closed activation gates. A
successful consumer test therefore proves only authentic retained evidence and
strict trust-path verification; it proves no snapshot staging or installation.

The authentic native-owner fixture now exports C18→C32 across two later
handoffs and invokes this exact consumer. The C18 pin and a negative C17 pin
are captured from independently generated fixture headers/configuration before
export. Both epoch transitions verify; wrong anchors, header/parent/config and
proof substitutions, reordered/truncated steps, missing/extra epoch evidence,
schema9 and caller byte/link limits reject. Changing nonzero local P/sequence/
record identifiers leaves the signed finality result unchanged, demonstrating
that those local identifiers do not grant remote trust. This test does not
connect the bridge to a network endpoint or installer.

### Bridge-relay auxiliary contract boundary

Registry-owned `contracts/bridge-relay/src/lib.rs` is an in-memory Rust model,
not an enabled bridge, canonical WASM artifact or deployed light client.
`BridgeSettlementMessage` binds source chain/bridge/tx/log index, target
chain/bridge, receiver/asset/amount, nonce/deadline, receipt status and config
version. Keep the existing `hash_message`, `settlement_id`, `nonce_key` byte
algorithms and their tests; JSON field order must not replace these identities.
Its configured signing set is a bridge-specific allowlist, not M02 voting weight.

`submit_proof` checks external/message deadline equality and expiry, nonempty
threshold-valid configuration, target domain, config version and success receipt
status, then unique authorized Ed25519 signatures (32-byte key + 64-byte signature
each). It marks the exact proof digest used only after validation.
`finalize_settlement` first rejects an already-finalized settlement, calls proof
validation and consumes the action/domain-bound nonce. A nonce collision rolls
back that call's proof mark and audit additions; success marks settlement finality.
Existing `*_with_version` admin operations compare the expected config generation
before mutation. Errors include `InvalidConfigVersion`, `ProofExpired`,
`InvalidTargetChain/Bridge`, signature/threshold failures, `ProofAlreadyUsed`,
`NonceAlreadyUsed` and `SettlementAlreadyFinalized`; preserve their distinction.

These signatures attest a supplied message. A `tx_receipt_status=1` field does
not independently verify source-chain execution or finality. A future host adapter
must provide a named source-chain verifier/trust anchor before releasing assets;
the native M13 verifier cannot implicitly verify every external chain.
Caller-supplied `now_ts` must come from the deterministic host context, not each
validator's wall clock. Until both integrations exist, the release composition
exposes no bridge asset-release port and reports `CAPABILITY_UNAVAILABLE`.

Planned durable integration stages proof/nullifier/finalized-set/config changes,
M12 asset effect and normalized audit outbox in one M07/M08 commit transaction.
An in-memory success or `consume_audit_log()` is not a durable receipt. On restart
load the committed root and rebuild projections; never recreate empty proof/nonce
sets over a previously used bridge namespace. Unknown I/O outcomes require exact
commit readback before retry. Do not GC replay keys merely because proof expiry
passed; require the owning protocol's authenticated retention rule.

Proposed dev adapter limits are <=100 configured bridge signers, <=100 signatures,
32 KiB request and one atomic settlement effect per request; reject before crypto
or allocation. Test valid threshold, duplicate signer/domain/nonce, stale config,
terminal replay with changed nonce, rollback on nonce conflict and crash cuts
across bridge mark/asset effect/audit publication. Existing crate tests cover the
memory model; host crash/asset-release tests remain required before activation.

M15 owns no second consensus database. Its lifecycle record is diagnostic and
contains process/config/binary identities, recovered owner digests, transition
and result. Recovery decisions come from M03/M07/M08 and verified service ports.
Public config changes require a new generation; private key rotation follows M03.

Uncertain open/migration/commit failures are `RECOVERY_REQUIRED`, not successful
startup. Preserve original directories read-only for diagnosis. Repeated restart
must be idempotent: the same immutable migration source/target returns the same
receipt or a clear conflict. Health probing cannot perform migrations.

When a LAN validator exits non-successfully, the runner must preserve the same
per-validator diagnostic classes used by a successful run (report, signed runtime
journal, start certificate, metrics, final state and bounded replay archives) before
cleaning the owned stages. Collection is best-effort and diagnostic-only: an
individual copy failure is recorded separately, never replaces the first process
failure, and cleanup still runs. Preserved files remain subject to the existing
owned-stage, regular-file, symlink, size and sealed-transport checks; partial or
inconsistent copies are not recovery evidence.

## Resource bounds

Proposed private-devnet supervisory defaults below are local operational limits,
not consensus validity parameters. Validate sums against per-module budgets.

| Resource | Dev default / failure policy |
|---|---|
| Config file | 256 KiB, depth <=16, <=32 configured peers |
| Startup/recovery deadline | 120 s initially; timeout stops startup and preserves stores |
| Graceful drain | 30 s; then terminate with incomplete-drain reason |
| Restart backoff | 1/2/4/8/16/30 s, at most 5 attempts in 10 min; then require operator action |
| Worker pools | Execution 1/2/4/8; separate bounded peer/RPC pools from M04/M14 |
| Open file budget | 4096 initial ceiling, reserve 128 for recovery/status |
| Temporary artifact bytes | 2 GiB default; reject staging before extraction if insufficient |
| Diagnostic log space | 256 MiB rotating files; authority journals never use log rotation |

A timeout never downgrades a required safety check. Operators may increase a
local recovery deadline in a new validated config after capacity assessment;
they may not increase protocol limits through an environment override.

## Security

Separate build from publication. Candidate code executes without repository,
release or signing credentials; publishers execute no candidate code and only
accept content-addressed verified manifests. Build inputs include source tree,
lockfiles, toolchain, features, target and base image. `ReleaseBundleV0` adds
artifact/SBOM/provenance entries and verifier identity; signatures are verified
through `ReleaseSignatureVerifierV0`, not a nonzero digest check.

Two independent builds compare artifact digests using the existing release
bundle contract. Nonreproducible results require an explained, reviewable diff;
never relabel one builder twice. Release approval names the actual artifact,
not a topic-branch test result. Dev test keys must be isolated from real custody.

## Observability and SLO

Status exposes lifecycle state, blocked reason, binary/config/profile identity,
last recovered authority height, last finalized height, queues, owner health,
restart count and `candidate_only`. Liveness means the supervisor responds;
readiness means required ports and authority recovery permit the advertised role.
They must remain separate. Publish startup/drain/recovery latency distributions
under `authority-hot-path-v1`; build reproducibility uses `evidence-tooling-v1`.

## Verification and evidence

| Operation | Positive test | Negative / crash test |
|---|---|---|
| Config | Same typed descriptor yields same digest despite whitespace | Unknown key, key inline, wrong chain/profile, candidate feature in prod |
| Start | Four isolated candidate processes recover and exchange real bounded traffic | Duplicate owner/key, missing lease, stale signer watermark, wrong ledger root |
| Restart | Durable tx/peer intents resume to one effect | Kill before/after every module-open, prepared ACK and commit barrier |
| Drain | All ACKed bodies retained, no new admission after not-ready | Deadline expiration, blocked disk, hung peer, SIGKILL |
| Upgrade | Approved schema migration opens exact target | Old binary cannot open new schema; rollback must not lower authority |
| Artifact | Independent digests and signature verification agree | Binary/SBOM substitution, wrong target, absent evidence, unsigned manifest |

Run existing CLI/host/production-composition/release-bundle tests as focused
regressions. The full dev lifecycle additionally must demonstrate signed user
submission -> network ordering -> execution -> M13-verified receipt -> restart.
A candidate command's help output or a single report is not that test.
M03/M04/M05/M07/M08/M13 supply owners; M14 consumes status/API; M17 seals evidence.

## Activation boundary

Private-devnet completion means the reproducible bounded lifecycle works with
explicit development keys and profiles. Production additionally needs real
custody, rollback protection, multi-host authentication, required independent
reviews and external fault/soak evidence for the exact release bundle. No
administrator flag, healthy endpoint or generic port implementation supplies
those missing capabilities. Current fail-closed production startup remains valid.

### Candidate cadence across rotating leaders

Native public cadence is measured against the committed parent timestamp, not
only a per-process timer. When chain time is ready, every leader waits until the
proposed timestamp is at least `parent_timestamp + block_cadence_ms`; checked
overflow rejects progress. Otherwise leader rotation would multiply the nominal
block rate and exhaust a bounded campaign before clients can observe finality.
Empty clock catch-up blocks may advance by the committed maximum time step
until skew readiness returns. This candidate cadence is a test profile limit,
not a throughput claim or a change to frozen consensus validity.


### Ordinary retirement before candidate handoff custody

Old and continuing validators must commission `CandidateHandoffRuntimeV1` via
`from_owners_with_original_ordinary_v1`. This consumes an independently obtained
`ConfirmedSignerNodeCheckpointFactsV0` and checks its affinity against the actual
original live ordinary journal plus fresh exact local/external readback. The
private selection retains its path, owner affinity, journal ID, external scope,
complete profile checksum and original watermark. Ordinary and handoff scopes
must be explicit and distinct. Same validator, same key and same signer-profile
reference are insufficient; neither a different-scope journal nor a reopened
scalar-identical journal can replace the selected live owner.

The retirement method checks this selection before joining native/Safety or
performing external CAS. It then freshly joins actual journal8 terminal
`CheckpointApplied`, strict old finality and COMMITTED native checkpoint. Host
cut generation, Safety revision/checksum and native cut come from those owners.
Retirement preserves the original owner affinity when consuming its ordinary
API. Both before and after handoff signing, the host checks that exact retired
owner and fresh external terminal policy against the prior selection. Bare
`from_owners` and `sign_handoff_exact` admit only a new-only validator whose ID
and key have no old-set custody.

**Restart limitation:** the existing native whole-node checkpoint capability is
private and binds the older Safety profile; a durable terminal14O/14E producer
that independently restores the original ordinary journal/scope/profile is not
implemented. `recover_with_retired_ordinary_exact_v1` therefore returns
`OriginalOrdinaryRecoveryUnavailable` before any owner read/reconciliation/CAS.
It never assigns the caller's supplied retired fields to the expected selection.
A complete fix must retain the original source pin in the actual durable node
checkpoint, fresh-read it under its own owner, join the exact retired local and
external source, and only then construct a recovery capability. A public scalar
constructor or a copied live capability is forbidden. This is a remaining
activation/recovery boundary, not a completed restart feature.

Real SQLite-owner tests use two journals with identical set, author and signing
key reference but different external scopes. The prior original selection
rejects the second active and retired owner, allows the real original retirement,
and rejects a same-path/same-scalar reopened owner. External services in these
host binding tests are test doubles; M03 separately tests the real Unix daemon.
Full native/Safety/retirement positive host acceptance remains required.

`trnm-consensus-safety-store` is an optional dependency of the explicit
`persistent-authority-candidate` host feature solely to perform this owner join.
It does not enter the default host/production dependency closure. The host does
not evaluate SafetyRules, write raw Safety records, accept caller-supplied
activation booleans, or receive private keys. A retired ordinary receipt itself
is not a publish permit, complete joint certificate, or new-epoch signing lease.
End-to-end activated runtime and new lease validation remain separate acceptance.

### Native candidate fleet application identity and source aliases

The actual `FleetCampaignIdentityV1` legacy constructor continues to require
nonzero corpus and policy hashes. The explicit `new_native_v1` constructor
uses the previously invalid pair of zero workload hashes as a reserved native
application discriminator and appends exactly one nonzero 32-byte native
profile digest before the validator count. Old valid campaign encodings stay
unchanged. The Ready/Start signatures cover this complete identity. The public
verifier independently loads the manifest-bound application profile and must
match its digest; missing, zero, mixed or substituted native profiles reject.
The inactive zero workload fields in summary JSON confer no fixture authority.

Source candidate preparation preserves a tracked documentation alias as Git
mode `120000`, its literal UTF-8 relative target bytes and original blob hash.
The strict clean-commit inventory still reconstructs the original commit tree.
Only `docs/*.md` aliases directly targeting a tracked, non-executable regular
Markdown document inside `docs/` are accepted; executable paths, untracked
links, absolute targets, traversal outside docs, chains, cycles and directory
links reject. Canonical tar uses a symbolic-link member with fixed metadata.
The verifier validates this inventory before extraction; the builder extracts
all regular members first and creates only these validated aliases afterward.
No source file is materialized under a false original Git hash.

### Terminal outgoing whole-node checkpoint projection v1

The candidate `epoch-handoff-checkpoint-candidate` interface uses the existing
672-byte external node-checkpoint CAS envelope with a distinct, domain-separated
application projection. It does not reinterpret the native-K projection or make
schema13 recovery accept schema14. A successor requires the independently
recorded predecessor checkpoint, whose signer scope, journal ID and full profile
checksum must match the retired original owner. Its sequence and application
height cannot be ahead of the actual retirement source and committed C. A lower
signer sequence is accepted only when a fresh audited snapshot of the original
retired journal contains that exact historical checksum (including the special
sequence-zero initial checksum). Journal8 supplies privately constructed audited
migration-source facts; predecessor Safety journal/profile/revision/record/chain
must equal that exact journal7 origin. The retained committed native history must
also authenticate the predecessor application block/root/height/time. Legacy
application projection fields do not grant any P, ACK or signing capability.

The producer joins a fresh, owner-affine retired signer receipt, strict
pre-handoff context, actual journal8 terminal14O head and actual committed native
C readback. The successor binds the exact retirement terminal watermark, Safety
journal/context/revision/record/chain checksum, native committed P/artifact/overlay
and commit sequence digest, descriptor and owner generation. Retirement happens
before this CAS; losing its response never restores ordinary signing. Before the
CAS, recovery accepts only the exact predecessor; after it, only the identical
deterministically rebuilt successor. Every third external state fails closed.
A fresh synchronized readback is mandatory before returning a non-Clone token.

That token retains the actual independent checkpoint owner and retired receipt.
Host handoff recovery and both sides of signature production revalidate it; a
public decoded checkpoint or caller-supplied tuple cannot construct the token.
The existing scalar-only retired restart entry remains fenced. This projection
qualifies terminal14O/original-custody recovery only; full14E activation still
requires journal9, its native epoch edge and a separate new ordinary lease.

The default-off host `epoch-join-test-fixtures` regression drives real Core,
journal8 and native speculative P through H1..C8 and two seals. Its original
SQLite signer produces ten votes only after fresh Safety persistence; host
retirement joins the actual committed C. All local Core/application/Safety,
independent node-checkpoint, retired signer and handoff owners are closed; native
and Safety reopen and regenerate fresh receipts from exact retained evidence.
The recovered host returns the identical persisted handoff signature without
another key call. Eight independently checksummed
but substituted genesis predecessors (Safety identity/profile/revision/record/
chain, application block/root and signer prefix checksum) reject before CAS.
An identical-key/profile/scope second retired journal rejects; a later independent
checkpoint fences the recovered host before key access. Genesis commissioning
and the external watermark service are explicit test inputs. This close/reopen
test does not claim a combined process-kill matrix, external HSM/KMS rollback
protection, new ordinary signing authority, or multi-host epoch activation.


### Full-epoch node-lineage checkpoint v1 candidate

The default-off `epoch-runtime-candidate` implements this comparison codec,
bounded schema2 store, continuing-author initial activation and initial-only
recovery. This is not a production activation claim. The V0 672-byte record and its invariant
`signer_exact_watermark.scope == scope` remain frozen. Full epoch activation
uses a distinct V1 record and explicit SQLite schema2 migration. Stable node
lineage identity is separate from the current ordinary signer's scope. No new
scope is hidden inside a V0 recovery-closure hash.

`EpochNodeCheckpointV1` is comparison data. Canonical local encoding is the
following ordered fields; all integers are unsigned big-endian, every Hash32
is exactly 32 bytes, and no trailing bytes, padding or unknown tags are allowed:

| Ordered group | Fields and exact local representation |
|---|---|
| Envelope | ASCII `TRNMNC01` (8 bytes), codec u16=1, phase u8, role u8, predecessor-kind u8, lineage_id Hash32, origin_checksum Hash32, generation u64, predecessor_checksum Hash32 |
| Active consensus | genesis_hash Hash32, chain_id as u16 byte length then canonical UTF-8 bytes (1..128, same identity as frozen chain ID), protocol_version u32, epoch u64, author as u16 byte length then canonical ValidatorId bytes (1..128), validator_set_id Hash32, parameters_hash Hash32, owner_generation u64, phase_authority_binding Hash32 |
| Source Safety | option u8; 0 carries no bytes, 1 carries journal_id Hash32, context_ref Hash32, revision u64, record_checksum Hash32, chain_checksum Hash32 |
| Target Safety | journal_id Hash32, context_ref Hash32, revision u64, record_checksum Hash32, chain_checksum Hash32 |
| Epoch/application edge | checkpoint_block_id Hash32, checkpoint_height u64, checkpoint_state_root Hash32, terminal_old_block_id Hash32, terminal_old_height u64, terminal_old_view u64, terminal_old_qc_id Hash32, native_authorization_id Hash32 |
| Current real application | block_id Hash32, height u64, epoch u64, view u64, timestamp_ms u64, state_root Hash32, native_store_id Hash32, native_commit_id Hash32, p_sequence u64, p_digest Hash32, artifact_digest Hash32, overlay_digest Hash32, commit_sequence u64 |
| Retired custody | option u8; 0 carries no bytes, 1 carries retired_epoch u64, retired_author as u16 length then canonical ValidatorId bytes (1..128), retired_validator_set_id Hash32, retired_parameters_hash Hash32, scope Hash32, journal_id Hash32, profile_checksum Hash32, source_sequence u64, source_chain_checksum Hash32, terminal_sequence u64, terminal_chain_checksum Hash32, retirement_record_checksum Hash32 |
| Active ordinary custody | option u8; 0 carries no bytes, 1 carries scope Hash32, journal_id Hash32, profile_checksum Hash32, sequence u64, chain_checksum Hash32 |
| Integrity | Hash32 = H(`trnm.node.epoch-lineage-checkpoint.v1`, all preceding record bytes) |

Here H(domain, payload) is exactly SHA-256 of the concatenation
`b"trnm.domain.hash.v1" || u64_be(domain.len()) || domain || u64_be(payload.len()) || payload`.
The domain is the literal ASCII bytes, without a terminator; lengths count bytes.
The integrity payload excludes only its final 32-byte integrity field.
The immutable origin checksum uses the identical H layout with domain
`trnm.node.epoch-lineage-origin.v1` and the entire canonical origin record,
including that record's own integrity field. These definitions do not depend
on a same-named helper in another crate or on a multi-part hash convention.

Closed phase tags are 0 ActivationCommitted, 1 Ordinary, 2 EpochRetired, and
3 EpochRetiredNative13 under M15-EPOCH-RETIREMENT-V6, and 4
EpochHandoffAttachedNative13 under M15-HANDOFF-ATTACHMENT-V8 below. The name
ActivationCommitted means the composite physical cut was committed; decoded
bytes do not prove that a process received a lease. Role tags are 0 Continuing,
1 VirginNew, 2 Removed. Predecessor kinds are 0 exact terminal V0 record,
1 exact V1 record, 2 explicitly commissioned virgin lineage record. Hashes are
nonzero except explicitly absent option payloads; options contain no zero-filled
placeholder structs. Generation/owner generation are positive and checked for
overflow. The complete record is at most 8192 bytes before any allocation;
unknown future layouts require a new codec. This is neither CEV0 nor a new
consensus signing domain.

Role is explicitly phase-relative. In ActivationCommitted and Ordinary it
describes how the author entered the **current** epoch e. At EpochRetired it
describes whether that same current-epoch author remains eligible for e+1;
the active consensus group still names e, never e+1. Every combination not
listed below is rejected before persistence or lease issuance:

| Phase / role | Source Safety option | Retired custody option and evidence epoch | Active ordinary option | Authority |
|---|---|---|---|---|
| ActivationCommitted / Continuing | 1: exact preceding terminal cut | 1: retired e-1 signer, copied exactly from preceding retired record or first V0 origin | 1: virgin e signer, sequence0 | Live lease only after actual composite owner join and Core ACK |
| ActivationCommitted / VirginNew | 0: no fabricated local old Safety | 0: no fabricated old custody | 1: virgin e signer, sequence0 | Separate commissioning constructor; currently fenced |
| Ordinary / Continuing | 1: unchanged incoming source cut | 1: unchanged incoming e-1 retirement | 1: same e scope/journal/profile; actual synchronized watermark | Only the existing e lease can continue |
| Ordinary / VirginNew | 0: remains absent throughout this epoch | 0: remains absent throughout this epoch | 1: same e scope/journal/profile; actual synchronized watermark | Same rules as ordinary Continuing, without invented old history |
| EpochRetired / Continuing | 1: exact last recorded local e Safety cut before terminal transition | 1: **current e signer** retirement, replacing any incoming e-1 evidence | 0: no ordinary handle, including no terminal handle in this option | Old-role handoff only; e+1 lease requires a later ActivationCommitted |
| EpochRetired / Removed | 1: exact last recorded local e Safety cut before terminal transition | 1: **current e signer** retirement, replacing any incoming e-1 evidence | 0 | Old-role handoff only; no next local Core or ordinary lease |
| EpochRetiredNative13 / Continuing or Removed | 1: exact settled e source cut | 1: current e retirement bound to native13 pre-handoff owner cut | 0 | Only explicit V7 role custody and V8 attachment; no activation |
| EpochHandoffAttachedNative13 / Continuing or Removed | 1: unchanged tag3 source cut | 1: unchanged current e retirement | 0 | Strict native joint attachment plus local comparison only; no activation |

EpochRetired / VirginNew is invalid. An author that entered e as VirginNew
changes role to Continuing or Removed when retiring e, based on the strictly
verified outgoing new set. It cannot keep a role label that omits retirement.
The retired payload must name the preceding active ordinary identity; the
preceding checkpoint's exact active watermark must be an audited prefix of the
actual retirement source watermark. Its terminal sequence is the retirement
source sequence+1. The terminal chain checksum is stored solely in
retired custody. Keeping the old active option or copying e-1 retirement into
EpochRetired is invalid, even if that older retirement is authentic.

The other groups also have closed phase semantics. ActivationCommitted and
Ordinary retain the incoming full joint `phase_authority_binding`, incoming
C/C+2 edge and native handoff `native_authorization_id`; only target Safety,
current real application and active ordinary watermark advance in Ordinary.
Legacy tag2 EpochRetired replaces those three incoming bindings with the outgoing strict
pre-handoff context binding, outgoing C/C+2 edge, and freshly confirmed native
checkpoint `post_execution_authorization_id`, respectively. Target Safety is
the actual terminal local e cut, and current application is exactly outgoing C.
This cut requires checkpoint/two-seal finality but **no joint certificate**.
Requiring a full next joint binding here would circularly require the old-role
signature before retiring the owner allowed to produce it.

For the first continuing activation, predecessor-kind0 names the actual
independently stored terminal14O V0 checkpoint. The lineage ID is its original
scope, and origin_checksum binds that entire original 672-byte record under
H(`trnm.node.epoch-lineage-origin.v1`, record). Generation is predecessor generation+1.
Source Safety equals the actual journal8 terminal cut; target Safety equals the
opaque pending14E initial request freshly persisted to journal9 at revision+1.
The edge names real C and terminal C+2; current application remains exactly C.
Retired custody is required and matches the original retired owner/checkpoint;
active ordinary custody is required, uses the exact new configuration/author,
a distinct scope/journal identity, and sequence0 with the actual virgin chain
checksum. The complete joint evidence comes from journal9's strict context.
No old header/epoch is relabeled and no seal creates a native P.

Ordinary successors preserve lineage/origin/active epoch/configuration and
custody identity, use generation+1 and the exact previous V1 checksum, and
advance only through actual ordered Core/P/commit/signer readbacks. Owner
generation stays exact through Ordinary and EpochRetired; the next
ActivationCommitted increments it by exactly one. Any real application-height
advance strictly increases both P sequence and native commit sequence. Qualified
application height never decreases; view comparison applies only within the
same epoch. Exact retries require byte equality, including signer sequence and
chain checksum. EpochRetired requires actual active-custody retirement before
any old-role handoff signature and grants no new ordinary lease. The next
ActivationCommitted must consume that exact retired predecessor, strict next
epoch evidence, next Safety owner and fresh next ordinary scope: e becomes e+1,
role becomes Continuing, source Safety equals the predecessor target Safety,
retired custody is copied byte-for-byte from the predecessor's current e
retirement, and the new active ordinary payload starts at sequence0. It installs
the now-complete joint binding and native handoff authorization for that edge.
An EpochRetired / Removed record cannot take this successor; returning in a
later epoch needs a separate reviewed commissioning protocol. Same-ID/new-key
and new-ID/old-key migrations reject unless an explicit custody-migration rule
is implemented; a new-only ID cannot bypass retirement by reusing an old key.

VirginNew initialization is a separate commissioning API. It requires an
independently pinned old checkpoint/strict joint evidence and a configured
virgin lineage identity, no prior local Safety or signer record, a local author
and key absent from the old set, and a new ordinary sequence0 namespace. It
must not synthesize a journal8/local-old-validator history. This constructor
remains fenced until its complete Core/native producer exists. Removed role is
accepted only in EpochRetired, active ordinary option is absent, and neither a
live new driver nor a new signing lease can be returned.

The candidate store keeps application_id `0x54524e43` but sets user_version2 in
the same `BEGIN IMMEDIATE` transaction that creates the exact three STRICT,
WITHOUT ROWID tables below, copies the verified origin, writes the initial V1
record/head and removes the legacy table. Migration requires exactly one V0
scope row, the independently expected exact N1 record and actual old store
owner. Other scopes cause `MultipleLineagesRequireExplicitMigration`, never
silent deletion. The old V0 opener rejects user_version2, so an old writer
cannot append after migration. Reopening schema2 never auto-migrates or creates
missing files. WAL/FULL mode, descriptor/inode/parent-directory checks and fsync
barriers retain the V0 owner requirements. Schema2 enables SQLite
`NO_CKPT_ON_CLOSE` through its safe configuration API; explicit sync remains
mandatory and WAL/SHM survive owner closure. Both sidecars must already exist
with unchanged identity before and after cold open; missing files fence without
recreation.

| Table | Columns / keys / checks |
|---|---|
| `epoch_node_origin` | lineage_id BLOB32 PRIMARY KEY, origin_checksum BLOB32, predecessor_kind INTEGER CHECK 0..2, original_record BLOB CHECK length 1..8192; immutable after creation |
| `epoch_node_records` | lineage_id BLOB32, generation BLOB8 big-endian, predecessor_checksum BLOB32, checksum BLOB32, record BLOB length 1..8192; PRIMARY KEY(lineage_id,generation); retain current and previous only |
| `epoch_node_head` | lineage_id BLOB32 PRIMARY KEY, generation BLOB8, checksum BLOB32; CAS exact previous generation+checksum, changed row count exactly1 |

Every record repeats origin_checksum so two-record pruning cannot disconnect
it from migration. Readback verifies exact closed schema (at most four bounded
schema rows, no unbounded SQL sort), one lineage/origin/head, ordered consecutive
retained generations, canonical records, checksum links and immutable origin.
SQLite row limit is 12 KiB, SQL limit 64 KiB, maximum database/WAL each 8 MiB,
SHM limit64 KiB and busy timeout100 ms for this bounded candidate profile.
These are explicit local fixture limits; deployment profiles may lower them or
select reviewed larger limits before creating a namespace, never silently
substitute production defaults. Record lengths are checked before copying.

| Failure/cut | Required disposition and authority result |
|---|---|
| Foreign original source, missing edge/P, invalid membership or nonvirgin new signer | `JoinRejected`; no CAS, Core ACK or key call |
| Before schema2 transaction commit | Source schema1 remains exact or destination is rejected; reopen at independently expected predecessor only |
| Commit/sync response lost | `CommitUncertain`; consume live candidate handles, accept only exact predecessor or exact deterministic target on explicit reopen; every third state fences |
| After schema2 durable head, before Core ACK/lease return | Reopen all owners; strict journal9/native/custody joins must match the exact V1 target, then remint one private runtime; no reinitialization of the signer |
| Pending signer decision after activation | Reconcile the actual signer journal/external watermark and Core intent before any new key request; exact recorded response can replay |
| Missing sidecar, changed inode, stale independent generation, source/target substitution | `OwnerFenced`; no repair, fallback to V0, scalar override or live Core |

The public candidate activation constructor in M02 owns the actual journal9,
native edge/application, original retired checkpoint/custody and new ordinary
journal. Only after this V1 store confirms the exact composite cut may it use
the private driver's ordinary trusted-host `StorageAck` seam. The store itself
returns a non-Clone fresh-owner receipt, never a Core, signer or lease. Required
acceptance includes whole-owner reopen, all three migration crash cuts, both
new-scope and old-scope substitutions, current/previous pruning, stopped old V0
writer, pending-sign exact replay, and at least two actual epoch transitions.

The schema2 store has actual SIGKILL tests before transaction commit, after
commit and after explicit sync; each cold read accepts only the exact original
V0 cut or exact deterministic V1 target. Additional regressions cover the
already-open old writer, multiple V0 lineages, immutable origin substitution,
closed schema, current/previous pruning, independent stale head and live/cold
missing-sidecar fencing. The concrete consumer freshly compares native's strict
activation binding with journal9's exact joint binding (distinct from the native
application authorization ID), verifies same continuing author/key, and consumes
the typed retired checkpoint owner before migration. Codec/store fixtures alone
do not establish a complete repeated-epoch runtime or multi-host epoch acceptance.

Migration retains the original DB/WAL/SHM identities through the transaction,
checks them before commit and after commit before sync, and never re-pins a
replacement sidecar. The first-timeout signer uses a private producer adapter:
after the journal's final external-watermark callbacks, it freshly checks the
independent V1 cut, actual Safety, native C/strict edge and original retirement
immediately before entering the injected key producer and before accepting its
result. A changed owner rejects at that boundary, including changes caused by
an external-watermark callback after earlier runtime checks.

The actual continuing-author fixture starts from ten old-epoch signatures and
consumes the native checkpoint, strict handoff, journal9, original retirement and
virgin new signer. Its activation emits one timer and no signature; first timeout
advances the independent generation three times and emits one new signature.
A whole-owner close/reopen reproduces the initial activation with no key call,
then the same first-timeout path succeeds. Progressed Ordinary recovery through
the initial-only constructor rejects. The final watermark callback replacement
test copies identical native DB bytes to a new inode and proves rejection before
any new signature. These are local candidate results; proposal/finality driving,
progressed recovery, commissioning and repeated crossings still require their
own actual-owner implementation and fault evidence.

The same candidate exposes the exact first-proposal boundary through
`CandidateEpochRuntimeV1::admit_epoch_proposal_v1`. It accepts only the exact
new-epoch `EpochHandoff` at `edge.first_application_height()`, persists Core's
Safety request, advances and rereads the independent lineage checkpoint, then
ACKs the request and retains the single Core-issued `PayloadValidationRequest`.
`execute_admitted_epoch_proposal_v1` continues that retained request through the
explicit native schema-4 bridge, deterministic application preview, durable P,
fresh P readback, strict epoch body commitments, Core's issued application seal,
typed D, and the exact Safety NativeValid C journal request. The regression
`actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing`
runs this with a real native-root proposal and proves the key callback count
does not change; the test uses a bounded 32 MiB worker stack because the native
authenticated snapshot computation is intentionally large. A failed
persistence/checkpoint step consumes the runtime. The strict native K
continuation is implemented below, and the regression now supplies a real
first-new proof vector, commits K, and revalidates the progressed application
cut without another signer call. Vote/finality collection, crash recovery after
a progressed obligation, and repeated crossing remain separate gates.

The epoch C construction uses
`NativeValidTransitionV0::from_core_delivery_v0` and its
`validate_against_core_delivery_v0` readback. This binds the exact Core D
carrier's route, validation identity, canonical Valid checksum, completion
revision and post-ack action while enforcing the canonical one-attempt shape
and preserving the frozen 328-byte Safety context. The seven host-owned commitments in that context are
still derived from the native P/application D readback because Core does not
own those rows; this seam therefore does not constitute complete source
authentication for an arbitrary host manifest. A future epoch-specific sealed
delivery-facts carrier must close that remaining boundary before production
release.

### Authenticated carrier wake-up (M15-TC-REFERENCE-WAKE-V1)

When a Proposal frame has passed the authenticated wire decoder, its embedded
QC and every QC referenced by its carried TC are independently verified
carriers. M15 records those QC references atomically in the bounded collector
before routing the Proposal body; the carried TC and Proposal body remain
subject to the normal authority gate and are never frozen by this step. A
buffered or stale Proposal therefore cannot suppress a later standalone
certificate, while its verified QC evidence can wake pending TimeoutVotes.

Every QC/TC/Proposal frame that adds a carrier must perform one bounded retry
of pending timeout certificates after admission. Retry may only consume exact
collector references already authenticated under the active validator set and
parameters; it cannot promote a body, substitute a QC digest, bypass owner or
parent checks, or refund verification work. Failed staged registration leaves
the live collector unchanged, and malformed or conflicting carriers are
rejected before any live mutation. The regression must cover an alternate
same-coordinate QC digest, a pending TC whose exact QC arrives through a
Proposal, malformed Proposal non-pollution, and successful TC formation.

### Ready quorum with deferred QC carriers (M15-TC-READY-QUORUM-V1)

The live timeout retry path may form a TC from the authenticated timeout-vote
subset whose exact QC carriers are currently present, but only after that
subset independently reaches validator-set quorum power. Votes whose carriers
are absent remain retained and may be included by a later retry. The strict
collector API remains fail-closed when any retained vote lacks its carrier.

The live subset is built in deterministic signer order and includes every
currently ready vote, with existing canonical QC-reference ordering and the
selected-high-QC maximum. Every present carrier is checked for exact digest
equality, canonical coordinate, and strict QC validity before the ready-power
decision; only an absent carrier is deferred. A known conflicting, malformed,
or non-canonical carrier therefore rejects the retry even when another ready
subset has quorum. The candidate TC is fully shaped and verified before it is
frozen. A later carrier cannot rebuild a different first TC, and a ready
subset below quorum waits for a retry.

This path changes no Core, owner, signer, parent, or application authority. A
TC formed from the ready subset remains independently verifiable by Core; an
unknown retained vote is not evidence until its exact QC carrier is admitted.
Acceptance uses seven real signing keys and covers ready quorum with unknown
carriers, below-quorum waiting followed by a late carrier, known-reference
conflict rejection, and first-TC freeze after a late carrier.

### Authoritative QC and proposal witness (M15-TC-PROPOSAL-BINDING-V1)

Core retains its deterministic highest QC, including the digest tie-break for
separate valid quorum subsets at the same block/view. A verified TC may select
another QC and still advance the view. The host must preserve that Ready owner,
its native parent and all durable signer/checkpoint obligations. It must not
lower Core's high QC or halt solely because the two certificate digests differ.

For a direct successor view the proposal uses Core's exact QC and no TC. For a
skipped view it uses the exact selected QC bytes from the retained verified TC,
only if that QC certifies the same genesis/chain/protocol/epoch/validator set,
view, height and block as the authoritative native parent QC. Synthetic anchors
require full equality. The proposal's TC/justify relation remains exact; complete
signature, ancestry, SafeToVote, P/Core-Valid, persistence and key guards remain
mandatory. Incoming proposals use the same coordinate join after authenticating
the proposer and complete carried certificates. Certificate identity is never
used interchangeably in persistence, replay or signer records.

If the selected QC is genuinely older or refers to another parent, the Ready
owner continues authenticated ingress and local timeouts but cannot author a
proposal. The scheduler checks witness availability before native preview or any
proposal key call. A later compatible current-view TC can supply the witness even
when Core reports no state change; signed owners retain their phase. Retention
keeps Core's full QC and every referenced QC of the retained TC independently.
A same-view conflicting certified block still reaches strict rejection.

Regression evidence must use real quorum subsets, actual Core/native/Safety/
signer owners and real timeout votes. It must cover a lower selected digest at
the same coordinate, exact witness construction and received voting, genuine
older-parent waiting followed by timeout progress, and unchanged rejection of a
valid TC paired with a substituted justify. This contract alone is not LAN
acceptance evidence.

### Same-parent pending body admission (M15-SAME-PARENT-BODY-V1)

The pending-proposal classifier is an inert scheduling boundary after strict
wire/proposer/certificate verification, before native execution or Core input.
It must not discard a proposal solely because its ordinary justify QC has a
smaller digest than the current Core high QC. The exception requires exact
`epoch`, `validator_set_id`, `view`, `height` and `block_id` equality; the strict
wire context already binds genesis, chain and protocol. Synthetic anchors retain
byte-exact identity. A distinct subset remains a distinct certificate in every
archive, TC, signer and persistence record.

For this same-parent ordinary case, missing exact local execution keeps the
body buffered. Only the existing native known-execution or exact durably
subsumed-reference rule permits dispatch. Every referenced QC in a carried TC
must pass the existing readiness predicate first. The consumer then rechecks the
complete authenticated parent context, exact TC/justify relation, increasing
view/time and native roots. Core keeps its higher QC; this classifier grants no
voting, signing, Synced or persistence authority. Different parent coordinates
retain the existing ordered stale/buffer decision and strict Core checks.

Ready may execute and vote through its original persistence-before-sign path.
TimeoutSigned may execute the eligible late body only through the existing
Synced path, retaining the original timeout signature/intent and never signing
a second same-view timeout. VoteSigned and all other consumer phase guards are
unchanged. Genuine regression must pass the actual strict wire and pending
classifier with two real quorum subsets, prove both Ready voting and late
TimeoutSigned execution followed by a real next QC, retain the larger Core QC
before advancement, and cover missing execution, foreign coordinates and
non-selected missing TC references. This corrects the earlier classifier test
which treated a smaller digest at the same parent as stale; it is not by itself
LAN or performance acceptance.

### Leader-independent certificate delivery (M15-QUORUM-DELIVERY-V1)

Every validator that locally forms a strictly verified QC or TC queues its first
certificate for publication and application, independently of the next-view
leader. This applies to authenticated remote votes, local votes, local timeouts
and deferred timeout quorums whose exact QC carriers have just arrived. A
quorum-ready validator must not discard its certificate solely because another
validator is scheduled to lead; a lagging designated aggregator would otherwise
prevent all ready validators from advancing despite a live quorum.

Publication remains behind the existing exact local execution-readiness gate.
A QC requires its authenticated native execution coordinate or the existing
durably subsumed classification; a TC requires readiness for every referenced
QC. No bare height, quorum count or leader identity substitutes for local P.
The QC archive remains durable before publication and authority advancement;
TC handling retains its existing authenticated owner/persistence path. The
first-certificate collector freeze, exact-ID deduplication, first accepted TC
per view, compatibility checks and all pending/outbox limits remain unchanged.
Complete QC carriers are disseminated so subsequent TimeoutVote digests remain
resolvable even when ready nodes retain different valid quorum subsets.

A genuine seven-validator regression omits the scheduled aggregator from
consensus delivery and requires the remaining five real signer/Core/native
owners to form, queue and adopt certificates. It verifies exact publication,
duplicate freezing and missing-execution deferral. This tests consensus
aggregation; transport behavior with an offline peer requires separate evidence.
Full-mesh all-validator publication has quadratic network fanout and establishes
no throughput, offline-node or multi-host acceptance claim by itself.

### Ready parent selection after late execution (M15-READY-REBASE-V1)

A genuine Synced body can leave a Ready owner's retained native parent ahead of
Core's authoritative high QC. Before proposal authoring or voting, an explicit
Ready-only operation may restore the exact selected QC parent. This is an
application projection update: Core state, Safety journal/profile/revision,
record and chain checksums, and every signer identity/watermark field remain
unchanged. Only the independent whole-node checkpoint generation increments,
with its exact previous checksum. No Core input, StorageAck, timer, signature or
signed-owner conversion is emitted. Existing TC persistence still requires its
separate exact Safety revision+1 policy; exact/no-effect certificate replay
remains an actual no-op.

Hold one exclusive cross-store owner fence across fresh source checkpoint,
Safety/signer, native committed head and source P/K reads; verify the complete
height-contiguous selected-QC path from exact live P/K rows to the committed
application tip before checkpoint CAS. Recheck those actual owners, the new
checkpoint and the selected path after CAS before publishing the projection.
Retain every existing valid prepared descendant, including the synced child
which Core has not selected. Missing/substituted P/K, changed namespace or
unsettled signing/validation/finalization obligations fail closed. A failed
consuming operation cannot restore Ready from cached scalar facts.

Reuse the existing committed-application-anchor / retained-selected-high-QC-path
checkpoint profile and canonical hashes. Cold recovery must accept the exact
unchanged Safety/signer heads and audit the complete persisted P/K inventory;
this does not enable recovery activation or remove signed-ancestry replay gates.
A freshly Synced cut retains NativeValid rather than Ordinary. Admit this case
only for the original Synced/action=None transition, after joining its exact
strict Safety record checksum to terminal K's safety closure. An inert SQLite
helper derives all immutable manifest fields from the original K and compares
the entire NativeValid context. The original Delivered-D row checksum is taken
from that authenticated Safety record and is bound by K's exact Safety checksum;
it must not be replaced with K's checksum or an invented K-sequence-minus-one.
The ordinary no-sign closure domain, exact validation identity, completion
revision and full P/K inventory remain mandatory. The older anchor-only V0
reconstruction helper and its semantics remain unchanged.
Tests reproduce real TC→Ready→late Synced child→alternate same-height proposal,
prove zero rebase key calls and one later genuine Vote, exercise corruption
before CAS, and cold-open a real rebased cut without fabricated rows.

### Late body after a signed timeout (M15-TIMEOUT-SYNC-V1)

An existing TimeoutSigned owner may consume a genuine late ordinary proposal
through the existing Synced no-sign application path and return the same signed
phase. It retains the exact original TimeoutVote bytes and signing facts; this
operation grants no Ready handle, new Vote, timeout or proposal-key capability.
The proposal must be no newer than both the original signed timeout and current
Core view, and must extend the actual authenticated native parent by one height.
VoteSigned remains outside this path.

Before execution and after the complete P/D/C/K, independent whole-node CAS and
Core ACK, freshly join the actual Safety, signer, application/validation and
checkpoint owners. Reject pending TC/QC synchronization, finalization or signing
obligations rather than lose their deferred effects. Reuse the existing Synced
route's exact NativeValid action=None and empty final ACK requirement. Preserve
Core view, last timeout and last voted coordinates. Every signer identity,
watermark, capacity, tail and pending-intent field remains byte-exact; only the
signed owner's comparison checkpoint is refreshed to the new durable cut.
Execution or persistence uncertainty consumes the owner and remains fail-closed.

Network fallback records an execution only after this complete path succeeds.
An exact replay or another parent is a no-progress refusal and retains the signed
owner. Later authentic QC/TC processing still uses its existing consuming path
to Ready. Tests require a real signed timeout, nonempty late body, real P/D/C/K,
unchanged timeout bytes and all signer facts, replay/refusal preservation,
zero additional key calls, and subsequent genuine certificate progress. No
missing-body hash or caller-supplied Valid fact can satisfy this path.

### Durable timeout scheduling after a late Vote (M15-TIMEOUT-REARM-V1)

Core's durable `last_timeout_view` is the scheduling fence, independent of the
current Ready, VoteSigned or TimeoutSigned wrapper. Expose it only as an inert
read-only phase fact from the owned Core. A same-view QC with another genuine
quorum subset can restore Ready and permit a late proposal Vote while retaining
the original timeout. Such progress must not schedule or sign another timeout
in that view. This rule applies to initial/cold owner scheduling, progress and
phase-only rearming, and the final expiry check before consuming an owner.

If `last_timeout_view >= current_view`, keep the pacemaker disarmed. Direct
timeout misuse is rejected before taking the live owner and changes no Safety,
signer, application or checkpoint facts. Retain the original timeout decision,
signature and durable sequence; do not synthesize an ACK, reconstruct a new
timeout from a newer high QC, or weaken the exactly-one-persistence requirement
for a fresh timeout. A genuine TC or QC advancing beyond the retained timeout
view may arm the new view and use the unchanged persist-before-sign path once.

The real-key regression covers timeout signing, a second same-parent QC at the
same view, a late native proposal and Vote, duplicate timer/direct-call refusal
without another key call or durable revision, and subsequent genuine TC
advancement followed by exactly one new-view timeout.

### Pure direct-input rejection containment (M15-DIRECT-INPUT-CONTAINMENT-V1)

After the mesh owner's exact sender/session join, the direct ordinary consensus
lane classifies rejection only at its initial, bounded, strict wire decoder.
Malformed/truncated/oversized or invalid-signature payloads, statement-author
mismatch and an unsupported ordinary frame kind produce a typed peer rejection
before collector mutation. Reconfirm the pinned local set/parameter hash and
nonzero session separately; unknown local membership or owner/context mismatch
remains an internal fatal error. The original strict admission API still
returns its error; only the runtime's explicitly contained entry handles the
closed peer-rejection outcome. No arbitrary `anyhow` chain is swallowed.

Retain at most one first-rejection record per actual validator ID (at most N):
frame kind, SHA256 of original payload, a closed reason code and a checked u64
dropped-frame count including the first rejection. This process-local direct
input quarantine persists across transport reconnects for this owner lifetime.
Subsequent ordinary direct frames from that peer are discarded without another
decode or signature check. This is not a socket disconnect, new authority or
durable recovery certificate. Emit only the bounded first-rejection diagnostic;
keep rejection records unchanged apart from the count. Counter overflow,
impossible inventory growth and unknown identity remain fatal.

Drop/rejection is not consensus progress. The normal owner loop processes at
most 64 queued ingress events per tick, including its initial blocking receive,
then returns to timer/control/finality work. Preserve existing byte, crypto,
queue, collector and pending-action ceilings. Collector errors (including
capacity, equivocation and conflicting certificate evidence), downstream Core,
native execution, signer, storage, fsync and namespace/CAS failures retain their
existing fatal behavior and counters. No terminal report, zero-violation,
quorum, clean-stop or six-host acceptance predicate is relaxed.

Real-key tests require rejected Vote/QC/Proposal payloads to leave the complete
live owner and collector unchanged, retain the exact first rejection facts,
and allow another honest peer's genuine votes to form a QC and advance the
same owner. Tests also retain fatal identity/collector/namespace failures and
prove finite drain under an always-ready rejected stream. Outer authenticated
frame/MAC failures, sparse relay, fleet barrier and restart ingress have their
own current fatal policies; this slice does not claim their containment or
full Byzantine-network availability.

### Per-peer ordered delivery (M15-PEER-OUTBOX-V2)

A bounded broadcast queue preserves FIFO independently for each destination.
Each flush examines retained broadcasts oldest first and attempts at most the
oldest unsent frame for each peer. A backpressured peer keeps its own exact frame
pending but does not prevent other peers from receiving subsequent frames on
later flushes. Successful enqueue to the authenticated mesh removes only that
peer from the frame's remaining destinations. Session binding, reconnect and
transport errors retain their existing mesh semantics; no unavailable peer is
dropped or treated as successful delivery.

A shared payload counts once toward the existing frame and byte limits until
its last destination accepts it. Fully delivered rows may retire independently
of an earlier row that another peer still needs. Empty-destination and capacity
refusals leave byte accounting unchanged. Each flush is bounded by retained
broadcast and configured-peer limits. A persistently unavailable peer can still
exhaust the bounded queue; this change removes global head-of-line blocking but
does not establish indefinite operation during a permanent network outage.
Tests require healthy-peer progress, per-peer FIFO after recovery, excluded
recipients, exact byte retirement, refusal atomicity and unchanged hard limits.
Actual host-loss acceptance still requires the signed multi-host run evidence.

### Closing a bounded post-timeout context (M15-TERMINAL-DIRECT-QC-V1)

A bounded height stop requires an actual Ready owner, no retained proposal TC,
and an authoritative QC certifying at least the requested last height. Merely
receiving or signing that last proposal cannot cancel the pacemaker: if its QC
is missing, the real timeout/reproposal path must remain available at the same
height. A duration stop also waits for Ready without retained TC context. Both
stops retain the positive-finality and drained-native-work conditions; neither
clears a post-timeout obligation. The hard drain deadline still fails an
unfinished run and the proposal height cap never increases.

A runtime that adopts a TC records the new current view as its outstanding
post-timeout context. The context closes only after an actual durable certificate
transition returns Ready with an authoritative QC at or above that view, no
retained proposal TC or pending TC synchronization, and application height equal
to finalized height. The runtime's exact native/Safety/signer/whole-node terminal
audit and all network, pending-work and quiescence requirements remain mandatory.

The old scalar rule required finality to reach the highest proposal submitted
before the TC. That incorrectly required extra blocks beyond a bounded run's
height limit: a QC at height11 can finalize height9 while pre-timeout height10
is a valid retained speculative execution. Its original P/K and signer records
must remain available, but it must not be reported as finalized. A genuine
regression must finish with the direct QC while finality is below that submitted
tail, then consume the real independently audited terminal owner. Signed phases,
retained TC context and unapplied finality continue to block closure. A late TC
that cannot obtain a direct successor QC within the run's limits remains an
unresolved terminal result; this rule does not invent more height capacity.

### Bounded timeout-collector diagnostics (M15-TC-DIAGNOSTIC-V1)

Failure-only diagnostics may record at most the last eight timeout-vote
coordinates: view, exact high-QC digest, signer identity, and whether the local
authenticated collector formed a TC. Fixed counters record accepted, formed,
queued and admitted items. The diagnostic is emitted to the existing bounded
stderr capture and never to the signed event subject; `SafetyHalted` keeps its
stable subject and journal semantics. It must not include signatures, raw
frames, proposal bodies or private key material. A failure record also carries
a fixed blocker bitmask for terminal readiness, including pending TC/certificate,
pending proposal, outbox, authority phase, and application/finality mismatch.
Mesh or authority fact read failures set dedicated blocker bits instead of being
treated as an empty or ready projection.
The terminal mask also reports active journal faults, an unmet nominal deadline,
an unmet quiet period, and an unmet minimum metrics interval.
“Accepted” means admitted to this runtime’s authenticated route; it is not a
claim that a network peer received the vote.

### Runtime handoff and acceptance closure (M15-RUNTIME-CLOSURE-V1)

The current continuous runtime now has an explicit ordinary follower path. A
late authenticated proposal is queued only after the signed-owner admission
decision; `Ready` can execute it through the M13 `SyncedNoSign` route.
`TimeoutSigned` can now use the separately bounded `M15-TIMEOUT-SYNC-V1`
closure and retain the same signed phase; `VoteSigned` remains untouched.
The route is `receive_unbound_proposal_v1` → `vote_ready_proposal_v1` →
`sync_late_proposal_v1` → native P/D/C/K/whole-node checkpoint → the original
`Ready` or `TimeoutSigned` phase.
The final Core ACK is required to emit no effects, and the external signer
watermark must be byte-identical before and after the operation. A late-body
fallback must restore the exact non-Ready owner before returning a no-op; it
cannot discard or reconstruct a signed owner. Once either eligible owner has
been consumed for native execution, an execution error still fences that owner.

This is a concrete composition boundary, not a liveness claim. The executable
regressions are
`trnm-poco-lab-validator/src/continuous_runtime.rs::ready_synced_proposal_commits_without_vote_or_watermark_advance_v1`,
`...::late_network_proposal_after_timeout_syncs_without_new_signature_v1`, and
`trnm-poco-node/tests/native_signed_vote_replay.rs::synced_proposal_commits_without_creating_a_signer_intent`.
They prove no-sign execution and signed-owner preservation with real SQLite,
native execution and Ed25519 proposal evidence. They do not prove a production
listener, arbitrary fork catch-up, cross-epoch import, or physical-host
performance.

After D/C, `commit_admitted_epoch_finality_v1` accepts only the caller-owned
bounded CEV0 first-new finality bytes, calls the native strict K verifier and
commit CAS, freshly reads the committed epoch P/K row, and then advances the
independent node checkpoint's application cut. A malformed, substituted or
replayed proof consumes and fences the runtime before any alternative proof can
be tried. The regression
`actual_epoch_runtime_executes_native_p_core_d_and_safety_c_without_signing`
now includes a real descendant proof vector, successful K, and a post-K current
cut revalidation. `recover_pending_epoch_validation_readback_v1` now provides a
strict pre-P crash/restart readback: it authenticates the exact first-new
proposal obligation, old application head and all custody/checkpoint owners,
and returns a typed receipt without resuming validation.
`recover_progressed_obligation_readback_v1` provides the pre-K boundary: it
reconstructs the strict journal9 state, verifies the exact pending vote
obligation, reopens native P, confirms the pre-K application edge and all
custody/checkpoint owners, and returns a typed receipt without rebinding Core
or releasing a signer. The follow-on
`recover_progressed_continuing_v1` path now consumes that exact receipt after a
process-shaped restart: it rebinds a private Core with the persisted signature
gate, joins the same native P and custody/checkpoint owners, writes the signer
intent before invoking the producer, then persists and reads back the Safety
release before returning one verified Vote broadcast. The regression
`actual_epoch_runtime_progressed_recovery_resumes_one_vote_after_restart`
proves one producer call and no pending signer/Safety intent after recovery.
Finality collection, a second complete epoch and repeated-crossing campaign
remain separate gates.

The F1 acceptance harness must therefore run only after this route is present
in the built binary: at least four independent hosts, declared CPU/RAM/disk,
fixed signed workload, packet loss/RTT/partition matrix, process crash and
separately labelled power-cut runs, then catch-up across the C/C+1/C+2/C+3
boundary. Raw logs must include finalized goodput, end-to-end p50/p95/p99,
queue/drop rates, state bytes, restart and catch-up time, source/tree and
configuration digests. A local lab test or a successful build cannot promote
`CORE-LIVE-001`, `TX-PROD-001`, `SYNC-PROD-001` or `F1`; machine truth stays
fail-closed until those artifacts are independently reviewed.

### First-new Core application settlement (M15-EPOCH-FIRST-APPLY-V2)

An explicit consuming continuation of the candidate first-new owner closes one
Core finalization/application acknowledgement. The existing V1 first-new APIs
and their native-only K meaning remain unchanged. The V2 continuation retains
exactly the genuine first-new Prepared execution and at most two consecutive
ordinary child executions. Each child is admitted as a complete signed proposal
through the private Core, its real validation request is persisted and ACKed,
and its original body is executed against the exact owner-affine Prepared
parent. Fresh native P readback and strict body/receipt commitments precede
Core's sealed Valid and exact journal9 NativeValid persistence. Proof headers
cannot substitute for bodies, execution, validation provenance or Prepared rows.
Both the existing online/resumed V1 Vote and this continuation re-confirm the
exact retained native P and its matching durable Core Valid artifact/overlay
immediately before and after the actual key producer, after external-watermark
callbacks. An unchanged committed parent cannot stand in for that child P.
Timeout signing retains its existing owner checks without requiring native P.

Only the exact third block's authenticated QC may drive this bounded operation's
Core finality. Core must itself emit and durably retain the first-new queue
front before the private application host obtains its single-use apply permit.
The host installs the matching non-cloneable apply authority once, joins the
permit to the exact native P, original proof and durable Core Valid completion,
then performs native K and a fresh owner-affine committed readback. Application
readback digests bind the actual native owner configuration, previous/new heads,
P/artifact/overlay/commit sequence, original finality and canonical accepted
Valid result; they are comparison commitments, never substitute receipt rows
or public caller-selected authority. The host consumes the permit only after
this readback and gives the resulting typed receipt to the same private Core.

The resulting NativeFinalizationApplied Safety request supplies the exact
transition manifest. Journal9 persistence and fresh request confirmation, then
the independent node checkpoint's matching Safety/native/custody CAS, precede
StorageAck. Any uncertain write, owner substitution or failed join consumes the
continuation without releasing signing or ACK authority. No raw Core, signer,
permit or mutable state is exposed. This slice settles only the first-new
application; child P remains speculative. It does not retire custody, activate
a second epoch, recover a progressed continuation, or enable journal10.
Acceptance uses real native bodies and signed child proposals/QCs, asserts
Core finalized/applied equals native head, preserves the two child P rows and
rejects foreign/missing execution, substituted finality and duplicate phases.
Tests run on the default thread stack without stack-size overrides.

### Ordinary continuation to the authenticated cutoff (M15-EPOCH-CUTOFF-V3)

A distinct consuming V3 owner may continue only a successfully settled
M15-EPOCH-FIRST-APPLY-V2 owner. The original V1 first-new and V2 one-settlement
APIs retain their fences; there is no public downcast or caller-supplied phase.
The V3 bound is computed from the already authenticated active epoch geometry:
application settlement stops at checkpoint height minus snapshot lead. This
slice requires at least two ordinary lookahead heights before the checkpoint;
a profile whose cutoff plus two reaches the checkpoint is rejected explicitly.

The owner retains only the two outstanding real Prepared executions after each
successful application settlement, and at most three while processing the next
complete signed ordinary proposal. The proposal must extend that exact final
Prepared parent. Original native execution, Core-owned validation, journal9
NativeValid persistence, signer intent persistence and before/after-key P/Valid
revalidation all precede release of its Vote. The native-cut verifier is shared
by normal owner refresh, post-K refresh and both sides of the actual key call:
before first K it checks the original committed checkpoint, and afterwards the
exact independently checkpointed committed P, head, sequence, artifact, overlay
and active header coordinates, retaining original edge owner/binding checks.
A valid-byte replacement of that progressed application's file during the
external-watermark callback must reject before the actual key is called.
The next exact QC lets Core derive
its own queue front. Native K, the unchanged opaque apply-receipt path, exact
journal9 tag-3 readback and independent node checkpoint CAS precede the ACK.
Only after all of these succeed may the committed front leave the retained
window. No block is treated as Valid merely because a later proof contains it.

At the cutoff, Core finalized/applied and native committed head must agree;
the two consecutive lookahead P remain uncommitted and retain their original
P digests. Further proposal, signing, QC and application operations on this
bounded owner fail closed. The read-only cutoff checkpoint grants no epoch,
retirement or recovery authority. The accepted fixture is a continuation of the
same real first-new owner through committed C15 with original Prepared C16/C17,
not a newly commissioned owner or synthesized settled SQL state. It also checks
that applying/signing phases cannot be repeated or crossed out of order.

Checkpoint candidate selection and checkpoint/seal signing require their own
explicit joins; this slice does not execute seals, retire the active signer,
create journal10, activate another epoch, or recover a progressed V3 owner.

### Outgoing native13 retirement (M15-EPOCH-RETIREMENT-V6)

This candidate-only operation consumes the actual V5 owner after checkpoint C,
S1 and S2 have completed native13 commit, Core application, journal9 persistence,
independent node CAS and ACK. It retires the current ordinary signer N. The
incoming retired signer W remains separately authenticated custody history and
cannot stand in for N. No role key, joint certificate, activation, Core timer or
progressed recovery capability is released by this operation.

Before retiring, freshly join the exact settled private Core state and journal9
head, immutable incoming edge/custody, original C/S1/S2 finality, actual committed
C P/artifact/overlay/Core Valid, deterministic retained cutoff selection, native13
receipt and independent node checkpoint. The current signer must match the
independently recorded ordinary scope/journal/profile/watermark with no pending
intent. The canonical old-role intent is derived from the receipt's strict
pre-handoff descriptor and configurations. The existing owner-consuming signer
retirement producer persists and syncs its local terminal record, advances the
independent external terminal fence, then freshly confirms both. Its host cut
binds journal9 owner generation/revision/checksum and the original native13
`committed_owner_cut_ref_v1`; this never means the legacy authorization ID.

At committed C, selection revalidation uses native13 receipt recovery's existing
strict historical cutoff derivation, not the future-checkpoint planning API.
Freshly compare the retained cutoff P/head/digest/persist and commit sequences
to the original selection; the recovered receipt must match its complete
commitment digest, new set and parameters. The native recovery independently
recomputes those choices under the authenticated old context. The planner's
requirement that the checkpoint be ahead of the committed head stays unchanged.

TRNMNC01 adds only closed phase tag3 `EpochRetiredNative13`. Tags0..2 retain
identical bytes and meanings. Tag3 retains the same field grammar/checksum domain,
but `edge.native_authorization_id` means exactly the native13 owner-cut commitment
and `phase_authority_binding` means its strict pre-handoff binding. The outgoing
C/C+2 edge replaces the incoming edge; application and target Safety remain the
exact settled source cut, source Safety equals that target, ordinary custody is
absent, and retired custody names newly retired N. Role is Continuing iff the
strict outgoing new set contains the author, otherwise Removed. Only actual
Ordinary→tag3 with generation+1 and exact predecessor checksum is allowed;
ActivationCommitted→tag3, tag2→tag3 and every tag3→activation/ordinary transition
remain closed. Decoded bytes and scalar cut equality grant no authority.

After actual retirement, rejoin the original native/Safety/cutoff/current signer
source identity before the independent CAS. Confirm the exact target durably,
repeat every source/custody join, then confirm the node target again. Any error
consumes the live owner; there is no ordinary signer fallback or public Core
escape. The retained result supports fresh confirmation of this retired cut
and the explicit consuming M15-HANDOFF-ROLES-V7 entry below. Existing explicit
signer-retirement recovery remains separate from future
V6 whole-owner recovery. Tests must use one real V5 flow, verify the current N
local/external terminal heads and ordinary reopen refusal, reject stale/foreign
joins, and prove old tag2 compatibility plus unknown/illegal phase rejection.

### Checkpoint preparation from the real cutoff (M15-EPOCH-CHECKPOINT-V4)

A distinct consuming V4 owner accepts only the completed V3 cutoff owner and
its two original uncommitted lookahead executions. This bounded profile requires
those executions to end at checkpoint minus one; it admits one complete signed
checkpoint proposal extending that exact Prepared parent. The checkpoint height
and cutoff are derived from the private Core's authenticated active parameters.
The original V1/V2/V3 phase fences and owner identities remain unchanged.

Before any proposal-driven mutation, M08 recomputes deterministic selection from
the actual committed cutoff. Its exact native head, P digest/sequence and commit
sequence must equal the independent application checkpoint; the proposed next
epoch commitment must equal this locally computed result. A validly signed but
incorrect commitment is rejected without writes or key calls. This read-only
refusal leaves the bounded owner available; once any mutable operation begins,
the private owner is removed and restored only after complete success, so an
uncertain write cannot be retried through an unfenced capability.

The genuine Core proposal produces its own validation request. Execution uses
the original body and exact owner-affine Prepared parent. Native P readback,
locally executed state/receipt roots, checkpoint body commitments and the fresh
cutoff-derived commitment precede sealed Core Valid, journal9 NativeValid,
independent checkpoint CAS and ACK. Regular and checkpoint execution share this
private persistence pipeline with explicit kind-specific commitment validation;
no ordinary-only public API becomes a checkpoint route.

The explicit checkpoint Vote entry retains the existing signer-journal intent
persistence and complete owner/P/Core-Valid checks. Both sides of the actual key
producer also recompute selection and match the independently checkpointed
cutoff and checkpoint header. A timeout still requires no P; seals receive no
missing-P exception. The successful terminal phase retains uncommitted C16/C17/
C18 and only the real checkpoint Vote. It does not establish checkpoint finality,
execute seals, apply C16/C17/C18, retire a signer, create journal10, activate a
successor, or recover a progressed owner. Acceptance extends the genuine C15
fixture with a signed wrong-commitment refusal, actual C18 P/D/C and Vote, exact
journal/node readback, unchanged committed cutoff, and phase-repetition rejection
on the default thread stack.

### Seal Votes and pre-handoff application (M15-EPOCH-PRE-HANDOFF-V5)

A consuming V5 continuation accepts only V4's completed checkpoint Vote and
retains the same private Core, original P16/P17/P18 and exact cutoff selection.
It admits exactly the original signed S19 then S20. Each proposal must satisfy
the shared strict runtime verifier and empty-seal geometry/body kernel against
its actual retained parent. Core itself records the consensus-valid seal and
creates the Vote obligation; journal9 persistence, exact fresh state readback
and independent node checkpoint CAS precede ACK. No seal receives a native
application P, Valid completion or execution receipt.

Key-boundary provenance is an explicit private sum of application P, seal, and
timeout. Application Votes preserve the existing mandatory P/Core-Valid join;
timeouts keep their existing no-P rule. The seal branch requires an exact unique
original SignedProposal in the freshly recovered journal9 boundary, the same
private Core pending Vote, active configuration and authenticated parent, and
strict signature/QC/TC plus scheduled height, preserved checkpoint state and
commitment, canonical empty payload/receipts/evidence checks. It also freshly
confirms the real checkpoint P and its durable application Valid source. These
joins run after external callbacks both before and after the actual key call.
A caller cannot promote a header, boolean, hash or absent P into seal authority.

QC(C18) carried by the strictly authenticated S19 creates Core's genuine C16
queue front first. The original seal remains inert private input while the
unchanged typed application path commits P16, strict original proof and fresh
K readback, then journal9 tag-3/node CAS/ACK. Only after that ACK is the original
S19 delivered as a Core proposal, durably retained and voted. S20/QC(S19)
similarly creates and applies C17 before admitting and signing S20. Core's
prohibition on simultaneous signing and finalization outboxes remains intact.
Selection is rederived from the retained committed cutoff and compared to its original P/head/sequence/config
choices while the independent current application cut advances to C16/C17;
those current heads must not be mistaken for the cutoff. Only the actual
QC(S20) may create Core's C18 front, with original C18/S19/S20 evidence.

The native owner first confirms the exact independent current C17 cut and
explicitly invokes the existing migration to schema10, preserving its missing
original-proof refusals for older later-edge schemas. This also handles the
original schema4 first-handoff owner. It reconfirms the same C17 cut, then
explicitly migrates schema10 to13; neither migration may change the application
head or sequence. M08 receives the original Core finality, locally derived descriptor and
cutoff choices, commits C18 through its strict pre-handoff API, and independently
reopens the returned owner-bound receipt. That actual committed readback feeds
the same Core-issued apply authority, exact journal9 NativeFinalizationApplied
record, independent checkpoint CAS and ACK. C18 ends finalized/applied with no
pending Vote, validation or application front. The retained schema13 receipt is
unattached; neither role signature nor a successor edge has been created.

Each mutable phase consumes its private owner until complete success; uncertain
writes or failed joins fence further progress. There is no public Core or signer
escape, recovery rebind or activation API. Retirement is available only through
the explicit consuming M15-EPOCH-RETIREMENT-V6 operation above. Genuine V5 acceptance runs
C15→C18→S19→S20 on the default stack, checks exact queue targets and P/K/readback
joins, retains original signed seals, rejects wrong/nonempty seal proposals and
wrong phase/finality, and verifies the schema13 unattached receipt while custody
remains active. An actual external-watermark callback replaces the genuine native
database with identical valid bytes at a different namespace identity before a
seal key call; the seal provenance join must reject with zero key calls. Existing application and timeout signing regressions remain
required when changing the shared key boundary.

### Pruned direct consensus ingress (M15-DIRECT-STALE-INGRESS-V1)

An authenticated peer can deliver an old queued Vote, TimeoutVote, Proposal,
QC or TC after this node has advanced its retained-view watermark. The direct
runtime must still decode the complete bounded statement, verify its original
signature/certificate and configured domain, and require the carried author to
match the authenticated sender where applicable. Only after those checks may
a view below the common ingress/relay watermark return inert `None`.

An authenticated, valid but pruned frame must not stop the node, count as a
protocol violation, populate the collector/proposal identity cache, create a
Core input or touch Safety/signer state. Its transport sequence remains consumed
by the original authenticated mesh. Malformed, wrong-author or bad-signature old
frames remain errors, and an inconsistent local watermark remains an error.
The watermark is never lowered, pruned evidence is never recreated, and frames
inside the retained window continue through the original strict collector.
This rule applies to direct remote admission only; local-origin reservations
and the separate relay protocol retain their existing contracts.

### Concrete native live staging composition

M15 composes M06's codec/recomputer with M13's verified native path and bounded
chunk session under **M06-M13-LIVE-V1** in
[M13](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md). Its native wrapper fixes
schema/version itself, owns the concrete recomputer, and returns a distinct
private-field staging result. A generic M13 snapshot result cannot substitute
for this native validation. Execution-ready installation still requires locally
derived replay history and an independently implemented atomic owner boundary.

## M15-RUNTIME-METRICS-FLOAT-V1 — lossless signed JSON readback

The existing candidate runtime metrics schema2 contains finite positive binary64
latency samples and CPU duration. Its producer hashes the exact compact body JSON,
signs that hash, exclusively creates and syncs the evidence file, and verifies a
fresh typed readback before releasing the terminal evidence chain. Every finite
metric emitted by the serializer must decode to the same binary64 value and
re-encode to the original bytes on both Linux and macOS. The lab package enables
serde_json's correctly rounded `float_roundtrip` decoder explicitly; it must not
depend on feature unification by an unrelated workspace package. This preserves
the schema, domains, signatures and measured precision. No rounding, normalization
after signing, alternate decoder fallback, or weakening of canonical byte equality
is permitted. Noncanonical whitespace/number encodings, nonfinite/zero samples,
modified signed metrics, unknown fields and oversized evidence remain rejected.

Regression evidence uses the actual fractional values observed in the failed LAN
run, signs the original body with an independent test key, writes through the
existing durable writer, and requires exact typed/byte/signature readback. It
also mutates the measurement while retaining the signature and rejects the
result; lossless encoding is not measurement authenticity or performance
acceptance. A repaired decoder cannot promote a prior failed fleet campaign.

### Native13 retired-owner handoff roles (M15-HANDOFF-ROLES-V7)

This bounded live-process composition consumes the actual
`EpochRetirementRuntimeV6<W,N>` and an independently selected actual schema1
handoff signer journal into `EpochHandoffRolesRuntimeV7<W,N,H>`. The constructor
also consumes that journal's M03-HANDOFF-HEAD-V1 confirmation, requires the same
owner/path and fresh exact virgin head (sequence zero, no pending intent or
terminal fence), and joins the complete role profile to the original native13
strict context and current retired N key identity. Its external scope differs
from both incoming W and outgoing N scopes. The original tag3 independent node
checkpoint remains exact and grants no activation transition.

Only role-specific canonical handoff intents derived from that original strict
descriptor/configuration are accepted. Removed members can sign OldSet only;
continuing members can sign either distinct role through an explicitly role-enabled
profile. Removed members may retain an OldSet-only profile; no profile is
converted or widened by this consumer. Every invocation first
reconfirms the exact selected schema1 head and the complete V6 native13,
retained cutoff/P/Core Valid, journal9, W/N retirement and tag3 source. A private
producer wrapper repeats that same V6 join immediately before and after the
actual key call; callers cannot replace this guard. Existing schema1 intent
commit/fsync/external advancement precedes the key, and verified signature
commit/fsync/external advancement precedes release. The final exact schema1
readback must advance by exactly two events for a new role or remain byte-exact
for an already returned role; intent/signature and terminal-fence semantics must
remain exact. Any uncertain or failed operation fences the consumed V7 owner.
Exact successful role retry returns the original signature without another key
call. No ordinary or proposal signing API escapes this owner.

V7 retains actual journals and source owners rather than scalar custody labels.
It adds no durable layout or tag3 successor transition. Missing independent cut,
foreign role head/profile, stale native/Safety/retirement namespace, or producer
callback mutation must reject before release; mutations observed before the key
must produce zero key calls. This slice ends at durably recorded local role
signatures. Aggregating both remote quorums, native attachment, Journal9→12/Core
V2 activation and whole-owner recovery remain separate consuming joins; none is
claimed by a signature receipt or by reopening a schema1 journal alone.

### Fresh readback of a consumed terminal owner (M15-TERMINAL-READBACK-V1)

`PocoNodeLabTerminalOwnerV0::confirm_terminal_cut_v1` and its continuous-owner
delegate revalidate the original consumed cut without reconstructing Ready,
Core sealing/apply capabilities or any signing lease. The terminal owner keeps
its original private retained executions and proposal-journal configuration.
It uses the native/P-K cross-store root fence, original full Safety and signer
head audits, exact independent checkpoint, full immutable schema3 native
inventory and each retained P/K join. The authenticated head, durable sequence,
Prepared count, complete signer inventory and original K aggregate must remain
identical to the cut captured at consumption; an unchanged committed head
alone is insufficient.

Local namespaces are checked before and after the actual external signer
watermark readback. All Safety/native/K/checkpoint comparisons are repeated
after that callback and never adopt replacement metadata as a new trust pin.
Any failed readback permanently fences this terminal owner. Successful calls
return only the original inert facts, and exact repetition does not mutate a
store or release an effect. A transport shutdown consumer must call this seam
before publishing Park and after mesh workers have joined, before signing
existing terminal evidence. It must still independently validate all queued
network/lifecycle obligations. This seam neither makes a quiet observation a
terminal certificate nor permits recovery or renewed ordinary signing.

Required genuine regressions consume a real finalized/applied owner, repeat an
unchanged exact read, then replace the native, P/K, Safety or checkpoint
namespace or change its durable cut. Every mutation must reject and latch the
failure; restoring original files cannot reactivate the terminal owner.

## M15-DIRECT-TERMINAL-BARRIER-V1 — coordinate an actual clean stop

The seven-validator direct candidate previously let the first locally quiet
node close its sessions while other honest nodes were still establishing their
quiet interval. Those peers then correctly refused CleanStop because an
unavailable session remained. A common nominal deadline cannot synchronize
these independent state machines. The correction is an explicit bounded
Prepare/Park exchange, scoped to this direct controlled campaign.

1. **Prepare.** The existing terminal predicate must pass unchanged: actual Ready,
   original Safety/signer/native/checkpoint joins, positive applied finality, no
   queued Core, client, network or restart work, no active/expected fault, common
   nominal horizon and local quiet interval. A strict frame binds the original
   fleet-start certificate digest, sender, finalized height/block/state/chain
   roots, and independently selected local checkpoint digest. The local source
   is freshly rechecked before publishing. Prepare is only an observation; it
   cannot waive missing work, authorize a disconnect or grant consensus power.
2. **Park.** After all seven exact, unique peer Prepare records agree on the
   shared finality cut, the local cut must still match the original local
   Prepare. The live authority is consumed through the existing
   `ContinuousValidatorTerminalOwnerV0` constructor. This destroys live
   application/signing paths and pins the original durable namespaces. Only
   this inert owner can publish Park, bound to the canonical, sorted full
   Prepare-set digest. Missing or changed source facts fail; there is no return
   from Park to ordinary voting. A peer's earlier Prepare alone cannot park
   the local owner.
3. **Finish.** Every configured validator must have an authenticated Park for
   that same original Prepare set. Outbound obligations must be drained. Only
   disconnection of an already admitted, matching parked peer is an expected
   shutdown; all other unavailable sessions remain blockers. After stopping
   and joining mesh workers, every residual ingress item is still checked:
   exact barrier repeats or matching parked-peer lifecycle observations can
   drain; consensus/restart work, an unknown peer or conflicting barrier fails.
   Existing signed journal, report, metrics, archive seal, final-state semantics
   and independent full-fleet agreement verification remain mandatory.

The original authenticated `MeshInboundFrameV0` owner, with its exact remote,
session and generation check, is the admission boundary. These direct control
messages are not transferable signatures, finality proofs, public certificates,
restart authority, or acceptance evidence. They cannot be injected through a
standalone byte decoder into a live owner, nor relayed under another origin.
Each phase retains at most one bounded record per configured identity; exact
repeats are inert, conflicts and resource exhaustion fail, and the original
finite drain deadline applies. No extra grace sleep replaces peer agreement.
Sparse transport retains its existing behavior and is not covered by this
direct-profile closure. Crashes or missing peers may fail this no-fault campaign;
this protocol is not fault-tolerant termination or recovery.

Required regressions cover staggered quiet intervals, all-seven participation,
Prepare without Park, mismatching finality or set hashes, stale fleet/session
input, exact retries, late ordinary work, namespace substitution before local
Park, and residual disconnect events queued behind the final quiet check. A
new real multi-host run remains necessary; prior failed evidence is immutable.

Because inbound frames and outbound lifecycle observations have separate
workers, an exact current-session disconnect observed after local Park may be
retained as one of at most twelve obligations until the peer's Park arrives.
It does not explain a prior ordinary fault or permit completion. Missing Park
still fails at the original deadline; a foreign generation/session fails
immediately. The common Prepare-set hash contains only sorted canonical inner
payloads, never peer-specific outer signatures, sessions or sequence numbers.

The closed inner wire has magic `TRNMTB01` (8 bytes), phase u8 (1 Prepare or
2 Park), original StartCertificate SHA-256 (32), and origin ID (32). Prepare
then carries height u64 little-endian and five fixed 32-byte digests in order:
block, state, chain, node checkpoint, local evidence cut (241 bytes total).
Park instead carries the full Prepare-set SHA-256 (105 bytes total). Unknown
phase, any other length/trailing bytes, or zero height/digest/identity rejects.
The set digest hashes domain `TRNM/DirectSevenTerminalPrepareSet/V1` followed
by one NUL byte, count u32 little-endian (7), then all seven canonical Prepare
payloads sorted by validator ID. The local-cut digest hashes domain
`TRNM/DirectSevenTerminalLocalCut/V1` plus NUL, local ID, process-instance and
checkpoint-generation u64 little-endian, checkpoint and signer-inventory
SHA-256, archive context SHA-256, archive sequence u64 little-endian and head
SHA-256, journal head sequence u64 little-endian, head SHA-256, and next sequence
u64 little-endian. These are original producer facts; no caller-selected root
can replace the saved full snapshot comparison before authority consumption.

The consumed owner is freshly reaudited before Park, after all network workers
join, and after terminal evidence signer callbacks before success returns.
An authenticated frame already decoded by a worker cannot disappear at stop:
it must reach the finite residual queue or record a terminal failure if bounded
admission is unavailable. A real internal or strict parser failure discovered
while joining remains fatal; only shutdown-caused transport loss is inert.

Selecting a normal height/duration stop also closes new native-client admission.
Readiness freshly requires the original client's accepted-work queue to be
drained at the exact finalized height; an earlier drain observation alone does
not waive subsequently accepted work. Ordinary read-only client responses do
not become consensus progress or a reason to restart the terminal barrier.

### Native13 joint attachment from actual role custody (M15-HANDOFF-ATTACHMENT-V8)

This candidate operation consumes the actual `EpochHandoffRolesRuntimeV7<W,N,H>`.
It retains the incoming retired W, outgoing retired N, original journal9/Core
owner, native13 committed C, original tag3 checkpoint, and actual role journal
and selected head. An inert role receipt, decoded node record, or peer kernel
cannot reconstruct this owner. Continuing requires both local roles recorded;
Removed requires the old role and never gains new-set signing. New-only entry,
cold owner reconstruction, Journal12 activation and new ordinary custody remain
outside this operation.

`attach_joint_handoff_v8(self, kernel)` bounds the original canonical kernel at
8 MiB before copying. Its exact descriptor, terminal header and terminal QC join
the retained strict pre-handoff context. Local role custody is independently
bound to its actual profile, pending-free head, old-role fence, original intent
and original signature. A valid weighted quorum may omit the local validator;
if a quorum includes it, its signature must equal the original recorded local
role bytes. Structural decoding grants no certificate authority. The unchanged
native `attach_later_epoch_handoff_v1` producer performs complete strict old/new
quorum signatures, exact checkpoint/two-seal/prefix and deterministic selection
validation, atomically retains the original full evidence and fsyncs it.

Before native mutation, after native readback, before independent node CAS and
after CAS/readback, the composition freshly joins its original source and role
owners. The returned native edge must belong to this application and match C's
P digest/commit sequence/head/parent binding, original terminal S2 and C+3
geometry. Read-only confirmations recover that exact native edge through its
original strict retained proof; Arc affinity or a supplied scalar is insufficient.
Role watermark callbacks precede a fresh native/Safety/retired/checkpoint audit.
After the final W/N retirement callback, M03-LOCAL-CUSTODY-READ-V1 rechecks the
original role head and both original W/N retirement records without callbacks;
the subsequent strict native/Safety/node reads also invoke no external service.
A late retirement callback that replaces or advances the role journal must
therefore fail before node CAS or result release.
No role or ordinary key producer is accepted by V8. Failure or uncertainty consumes
the entry owner; a returned attached owner latches any later failed confirmation.
A committed native attachment with an unadvanced node checkpoint remains a fenced
recovery case, not an excuse to reconstruct the live owner from database fields.

TRNMNC01 retains its version, field grammar and all original tags 0..3 bytes and
meanings. New closed tag4 `EpochHandoffAttachedNative13` permits only tag3→tag4,
with generation+1 and exact predecessor checksum. It preserves source/target
Safety, application, epoch/configuration, role and current-N retirement fields.
The edge geometry is unchanged; `native_authorization_id` is the actual native
successor binding. `phase_authority_binding` is the framed SHA-256 domain
`trnm.node.epoch-handoff-attachment.v8`, using the existing node transition hash
framing (`trnm.poco-node.epoch-native-valid.v1`, u64 domain length/domain, then
each u64 part length/part), binding the original tag3 checksum and
pre-handoff owner cut, every returned native edge fact, the original kernel hash,
actual role profile/watermark/fence, and each present local intent fingerprint and
signature. These are inert comparison fields, freshly rederived from retained
actual owners. The original V6 tag3 record is kept separately and never relabeled.
Tag4 has no activation or ordinary successor in this slice.

`confirm_joint_handoff_exact_v8` requires byte-for-byte equality with the original
kernel and reaudits the full attached cut without adding a signature, native
sequence or node generation. `confirm_attached_cut_v8` returns only the original
comparison record. Acceptance uses one genuine V5→V6→V7 execution, original local
role signing, a real sufficient joint quorum omitting the local validator, strict
native attachment, independent node readback, exact retry, unchanged Safety and
signer heads, and refusal of changed kernel/custody/source. Existing tag2/tag3
compatibility and illegal tag4 transitions remain covered. These checks do not
claim successor activation or crash recovery of the composite owner.
