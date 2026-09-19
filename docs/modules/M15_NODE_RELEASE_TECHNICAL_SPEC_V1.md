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
| `trillionnium/crates/trnm-poco-node-host/src/lib.rs` | Persistent host lifecycle boundary | Recover actual module owners before serving |
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

Closed phase tags are 0 ActivationCommitted, 1 Ordinary, 2 EpochRetired. The name
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
EpochRetired replaces those three incoming bindings with the outgoing strict
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
