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
