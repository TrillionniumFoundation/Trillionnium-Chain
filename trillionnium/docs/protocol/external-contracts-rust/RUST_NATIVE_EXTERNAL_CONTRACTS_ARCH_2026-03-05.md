# Rust Native External Contracts Architecture (2026-03-05)

> Decision lock: **all external smart contracts move to Rust-native implementation**.

## 0. Scope and Goals

This document defines the architecture spec for external contracts on the current Rust L1 stack:

- `trnm-state`: deterministic state transition + storage root.
- `trnm-node`: block assembly, pre-exec/order, commit loop, events.
- `trnm-rpc`: ingress/query gateway and public API surface.

### Goals

1. Standardize contract runtime to **WASM + Rust `no_std`**.
2. Define **Host ABI**, storage/event/error code spec, determinism constraints.
3. Provide unified interfaces for three contract families:
   - `SettlementVault`
   - `BridgeRelay`
   - `GovernanceGuard`
4. Define bridge boundaries to Rust L1 components (`trnm-state/trnm-node/trnm-rpc`).
5. Provide migration path from prior legacy external-contract skeleton to the current `contracts/` subtree and its future host-runtime closure.

---

## 1. Runtime Model

## 1.1 Contract Execution Runtime

**Chosen model:** `wasm32-unknown-unknown` + `#![no_std]` contract crates.

- Contract artifacts: deterministic WASM bytecode.
- Runtime in node: WASM VM sandbox (single deterministic profile).
- No host syscalls except explicit Host ABI.
- Gas-metered instruction execution.
- Memory is linear memory only (no allocator behavior that depends on host randomness).

Rationale:

- Keeps execution deterministic across validators.
- Rust tooling uniformity with L1 codebase.
- Better static analysis/testability than a mixed VM path in the current stack.

## 1.2 Package Layout (target)

```text
contracts/
  sdk/                    # common macros, ABI types, codec, error/event defs
  runtime-spec/           # host ABI traits + fixture host for tests
  settlement-vault/
  bridge-relay/
  governance-guard/
  integration-tests/      # golden tests with deterministic replay
  audit-events/           # shared audit-event schema crate (adjacent, not sdk/runtime closure)
```

Current repository snapshot note:

- The layout above is the **target architecture inside the current `contracts/` subtree**, not a claim that the full workspace already exists in-tree.
- The current repository already contains contract crates for `settlement-vault/`, `bridge-relay/`, and `governance-guard/` under `contracts/`.
- The current repository also contains `contracts/audit-events/` as a shared audit-event schema crate adjacent to this target layout.
- Validation and workspace-root references should therefore point at `contracts/Cargo.toml` in the current tree, not a nonexistent `contracts-rust/Cargo.toml` path.
- `audit-events/` is helpful for normalized event truthfulness, but it does **not** by itself mean `sdk/`, `runtime-spec/`, or `integration-tests/` are already implemented.
- Until those pieces land and are wired to the host runtime, this document should be read as an architecture baseline and boundary spec, **not** as proof that canonical WASM host integration is complete.

---

## 2. Host ABI Specification

Contracts cannot access state/network directly; all effects go through Host ABI.

## 2.1 ABI Versioning

- ABI version key: `host_abi_version: u32`.
- Node advertises supported versions.
- Contract manifest pins `min_host_abi` and `target_host_abi`.
- Any mismatch => deploy rejected.

## 2.2 Core ABI Surface (v1)

```rust
trait HostAbiV1 {
    // context
    fn block_height() -> u64;
    fn block_timestamp_ms() -> u64;
    fn tx_hash() -> [u8; 32];
    fn caller() -> Address;
    fn contract_address() -> Address;

    // metering
    fn charge_gas(units: u64) -> Result<(), HostError>;
    fn gas_left() -> u64;

    // storage (namespaced)
    fn storage_get(key: &[u8]) -> Option<Vec<u8>>;
    fn storage_set(key: &[u8], value: &[u8]) -> Result<(), HostError>;
    fn storage_delete(key: &[u8]) -> Result<(), HostError>;

    // events
    fn emit(topic0: [u8; 32], topic1: Option<[u8; 32]>, data: &[u8]) -> Result<(), HostError>;

    // interop/system calls (strict whitelist)
    fn transfer(to: Address, amount: u128) -> Result<(), HostError>;
    fn verify_sig(scheme: SigScheme, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool;
}
```

## 2.3 ABI Security Rules

- No floating-point operations exposed.
- No host clock randomness; only consensus timestamp/height.
- No network/filesystem APIs.
- Syscall whitelist is frozen per ABI version.

---

## 3. Storage / Events / Error Codes

## 3.1 Storage Spec

- Key space: `/<contract_id>/<module>/<key>` (byte prefix).
- Value encoding: canonical codec (Borsh or parity-scale, choose one and freeze in `sdk`).
- Canonical ordering for iteration outputs (lexicographic bytes).
- Write set is explicit and committed via node execution pipeline.

State root inclusion:

- Contract storage deltas must be merged into `trnm-state` deterministic hash pipeline.
- Hash includes: key bytes + value bytes + version counters.

## 3.2 Event Spec

Unified event envelope:

```text
event_schema=v2
fields:
  contract_id
  event_type
  tx_hash
  block_height
  topics[0..n]
  payload_bytes
  payload_codec_version
```

Rules:

- Event payload must be deterministic and canonical encoded.
- Event emission order is execution order.
- Max payload size and max event count per tx are protocol constants.

`trnm-rpc` mapping:

- Expose typed view for known event types.
- Always preserve raw payload for forward compatibility.

## 3.3 Error Code Spec

Error codes are numeric + stable string name.

```text
0x0000-0x00FF : host/runtime common
0x0100-0x01FF : settlement-vault
0x0200-0x02FF : bridge-relay
0x0300-0x03FF : governance-guard
```

Contract failure response format:

```json
{
  "ok": false,
  "code": "CONTRACT_ERR_0x0102",
  "message": "insufficient_locked_balance",
  "retriable": false
}
```

Constraints:

- Do not change semantic meaning of existing code points.
- Add-only policy for minor releases.

---

## 4. Determinism Constraints (MUST)

1. **No wall clock / randomness** inside contract.
2. **No floating point** in contract logic.
3. All collections in stateful logic must use deterministic iteration order.
4. Host ABI returns only consensus inputs.
5. Panic behavior standardized (panic => deterministic abort + code mapping).
6. Memory and recursion limits fixed in protocol constants.
7. Bytecode hash pinned at deploy/upgrade and validated by all validators.

Determinism test gates:

- Multi-node replay test: same tx sequence => same state root + same event log.
- Differential run across architectures (arm64/x86_64) with golden vectors.

---

## 5. Unified Contract Interfaces

All three contract families implement a common lifecycle trait plus domain trait.

## 5.1 Common Trait

```rust
pub trait ExternalContract {
    fn contract_id() -> [u8; 32];
    fn abi_version() -> u32;
    fn init(input: &[u8]) -> Result<(), ContractError>;
    fn execute(method: u32, input: &[u8]) -> Result<Vec<u8>, ContractError>;
    fn migrate(input: &[u8]) -> Result<(), ContractError>;
}
```

## 5.2 SettlementVault Interface

Purpose: custody, lock/unlock, settlement payouts.

Required methods:

- `deposit(account, amount)`
- `lock(account, lock_id, amount, reason)`
- `unlock(lock_id)`
- `slash(lock_id, to_treasury, amount)`
- `settle(lock_id, recipients[])`
- `balance_of(account)`

Invariants:

- `sum(available + locked) == total_managed`.
- No negative balance; saturating checks forbidden for accounting paths.

## 5.3 BridgeRelay Interface

Purpose: cross-domain message relay + proof verification gate.

Required methods:

- `submit_message(domain, nonce, payload, proof)`
- `ack_message(message_id, proof)`
- `revert_message(message_id, reason_code)`
- `message_status(message_id)`

Invariants:

- `(domain, nonce)` uniqueness.
- Idempotent re-submit semantics.
- Replay protection bound to source commitment root.

## 5.4 GovernanceGuard Interface

Purpose: policy/timelock/authorization checks around sensitive operations.

Required methods:

- `propose(param_key, new_value, eta_height)`
- `cancel(proposal_id)`
- `queue(proposal_id)`
- `execute(proposal_id)`
- `is_authorized(actor, action)`

Invariants:

- Timelock must be enforced by block height, not timestamp.
- Sensitive key update rate limits must stay deterministic and explicit.

---

## 6. Bridge Boundaries to Rust L1

## 6.1 `trnm-state` Boundary

Responsibilities:

- Own canonical state root and versioned object model.
- Provide contract storage namespace and delta application API.
- Validate deterministic state transitions and conflict/version checks.

Contract engine -> state boundary:

- Input: read-set snapshot + tx context + method call.
- Output: write-set + emitted events + gas used + result/error.
- `trnm-state` applies output atomically or rejects.

## 6.2 `trnm-node` Boundary

Responsibilities:

- Pre-exec scheduling / conflict grouping.
- Run WASM contract execution in deterministic sandbox.
- Enforce gas, step limits, event quotas, timeout/rollback policy.

Node must not:

- Introduce non-deterministic host data.
- Reorder side-effectful execution after ordering decision.

## 6.3 `trnm-rpc` Boundary

Responsibilities:

- Encode/decode contract calls and responses.
- Surface typed query/event APIs.
- Keep raw binary payload endpoint for forward compatibility.

RPC compatibility policy:

- Old clients receive stable error code fields.
- New contract methods exposed via versioned RPC namespaces.

---

## 7. Migration: Legacy External-Contract Skeleton -> `contracts/`

## 7.1 Migration Steps

1. **Freeze legacy contract line**
   - Mark the legacy external-contract skeleton read-only.
   - Stop adding features; only archival reference.

2. **Evolve the current Rust contract subtree toward the target workspace**
   - Grow `contracts/` toward the target `sdk` + contract-crate + runtime-spec layout instead of introducing a second parallel top-level path.
   - Add CI for `wasm32-unknown-unknown` build and size checks once those target pieces begin to land.
   - Snapshot truthfulness note: the current repository already has `settlement-vault/`, `bridge-relay/`, `governance-guard/`, and adjacent `audit-events/`, but still does **not** have the target `sdk/`, `runtime-spec/`, or `integration-tests/` directories wired as one canonical host-runtime workspace.

3. **Define ABI and codec lock**
   - Freeze Host ABI v1 and payload codec.
   - Publish canonical test vectors.

4. **Port business logic by module**
   - Settlement first, then Bridge, then Governance.
   - One-to-one mapping of methods, events, error codes.

5. **Determinism test phase**
   - Golden replay tests vs fixed tx corpus.
   - Cross-platform deterministic root/event checks.

6. **Dual-run shadow phase (node feature flag)**
   - Keep legacy path for comparison only (no canonical writes).
   - Compare outputs; block release if mismatch.

7. **Cutover**
   - Enable Rust contracts as canonical path.
   - Keep rollback feature flag for one release window.

8. **Remove legacy external-contract runtime dependencies**
   - Delete or archive legacy execution glue after stabilization.

## 7.2 Key Risks and Mitigations

1. **Semantic drift from legacy contract behavior**
   - Mitigation: method-level parity tests + fixtures from the old skeleton.

2. **Encoding incompatibility**
   - Mitigation: single canonical codec + vector tests in CI.

3. **Determinism regressions**
   - Mitigation: no_std restrictions + replay test gate mandatory.

4. **Gas/model mismatch causing DoS surface**
   - Mitigation: conservative initial gas table; tune only via governance.

5. **Bridge replay/proof validation bugs**
   - Mitigation: strict nonce domain separation + exhaustive negative tests.

6. **Operational rollback complexity**
   - Mitigation: explicit feature flags + staged rollout + checkpointed recovery drills.

---

## 8. Rollout Governance and Acceptance Criteria

Cutover acceptance requires all:

> These checkboxes are **future cutover gates**, not a claim that the current repository snapshot already satisfies them. Until they are all evidenced, this document remains an architecture/boundary baseline rather than proof of production Host ABI/runtime closure.

- [ ] ABI v1 frozen and documented.
- [ ] Three contracts compile to deterministic WASM (`no_std`).
- [ ] State root/event equivalence in replay suite (100% pass).
- [ ] RPC compatibility checks pass on existing clients.
- [ ] Security review completed for Host ABI + bridge replay protections.
- [ ] Runbook for rollback and incident response published.

---

## 9. Non-Goals (this phase)

- Native EVM compatibility.
- Dynamic JIT or host-dependent optimization strategies.
- Arbitrary third-party contract uploads before sandbox hardening completes.

---

## 10. Immediate Next Deliverables

1. `contracts/sdk` minimal crate with ABI/event/error primitives.
2. `trnm-node` host adapter trait + deterministic WASM executor feature flag.
3. `trnm-state` contract storage delta API and root hashing inclusion.
4. Contract-specific RFCs for SettlementVault/BridgeRelay/GovernanceGuard method schemas.

---

**Status:** architecture baseline approved for Rust-native external contracts.
