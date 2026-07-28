# TRNM Canonical Runtime Freeze

Date: 2026-07-28
Status: binding architecture decision for the public-testnet production candidate

## Decision

The only production-candidate state transition is:

`CometBFT -> trnm-consensus-app -> trnm-runtime -> committed state/AppHash`

`trnm-protocol` owns typed wire and state types. `trnm-runtime` is deterministic and
must not depend on networking, filesystems, databases, wall clocks, or CometBFT.
`trnm-consensus-app` owns ABCI++, durable storage, snapshots, validator lifecycle,
and translation between signed envelopes and the pure runtime.

The `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`, and `trnm-sim`
binaries are legacy harnesses. No new protocol capability may be added to them.
A legacy test cannot be cited as evidence that the canonical runtime supports a
feature.

## Frozen Day-1 Scope

Day-1 includes only:

- accounts, balances, sequential account nonces, gas, and fees;
- task creation, reward escrow, assignment, and worker stake;
- result commit and reveal;
- paid consumption receipts;
- challenge, governance resolution, unchallenged settlement, and deterministic
  expiry/refund or worker-deadline slashing for every pre-terminal escrow state;
- validator lifecycle already committed through the CometBFT adapter;
- minimum deterministic ABCI execution events. A versioned durable indexer event
  schema and replay service remain later public-surface work.

Bridge, oracle, external contracts, general ZK execution, token-based work-unit
inflation, and frontend write flows are deferred. They remain research or legacy
capabilities until they enter the canonical path with end-to-end evidence.

## Feature-to-Runtime Matrix

| Capability | Canonical implementation | Status | Evidence boundary |
| --- | --- | --- | --- |
| Signed envelope and signer policy | `trnm-finality-types`, `trnm-consensus-app` | Implemented | CometBFT gates |
| Typed transaction decoding | `trnm-protocol`, `trnm-consensus-app` | Implemented | Unit and CometBFT gates |
| Unknown payload rejection | `trnm-consensus-app` | Implemented | Production build path |
| Accounts, balances, and issued-supply commitment | `trnm-runtime` | Implemented | Four-validator canonical slice |
| Sequential account nonce | `trnm-runtime` | Implemented | Replay rejection on four validators |
| Gas, fee charging, and explicit fee collector | `trnm-runtime` | Implemented | Resource rejection and balance evidence |
| Bounded fee-policy governance and fee distribution | `trnm-runtime` | Implemented | Four-validator policy/distribution slice |
| Task reward escrow and worker-accepted stake | `trnm-runtime` | Implemented | Forced-assignment rejection and four-validator slice |
| Salted commit/reveal and challenge window | `trnm-runtime` | Implemented | Runtime tests and four-validator slice |
| Paid consumption receipt | `trnm-runtime` | Implemented | Four-validator canonical slice |
| Value-conserving challenge/resolve/settle | `trnm-runtime` | Implemented | Runtime conservation tests and four-validator slice |
| Deadline expiry/refund/slash | `trnm-runtime` | Implemented | Runtime tests and four-validator deadline expiry |
| Minimal indexed execution events | `trnm-consensus-app` | Implemented (minimal) | ABCI `ExecTxResult`; durable schema still open |
| Validator add/remove/rotation | `trnm-consensus-app` | Implemented | Six-process lifecycle gate |
| State sync and crash recovery | `trnm-consensus-app` | Implemented | Four/five-process recovery gate |
| Dynamic public account-key onboarding | none | Not implemented | static authorized-signer allowlist |
| AppHash v4 incremental authenticated tree | none | Not implemented | v3 remains linear |
| Proof query and pruning | none | Not implemented | blocker for scale phase |
| Asynchronous resumable snapshots | none | Not implemented | v2 snapshot remains synchronous |
| Threshold governance and timelock | none | Not implemented | operator key only |
| Staking, unbonding, jail, slashing | none | Not implemented | mainnet blocker |
| Authenticated multi-host topology | deployment layer | Not implemented | local loopback only |
| HSM/KMS/remote signer | signer integration | Not implemented | mainnet blocker |
| Durable indexer and explorer API | none | Not implemented | read surface remains partial |
| Bridge/oracle/contracts/ZK platform | legacy/research paths | Deferred | not Day-1 |

## Upgrade and Dependency Boundary

This branch still reports application version 3, store schema 2, and snapshot
format 2. The canonical transaction semantics in this freeze are therefore
**fresh-genesis/reset-only** evidence. They must not be rolled into an existing
app-version-3 network or restored from an older snapshot. The AppHash v4 phase
must add an explicit versioned migration or a reviewed export/new-genesis
procedure before any in-place upgrade claim.

The `trnm-node` binaries are frozen legacy harnesses, but
`trnm-consensus-app` temporarily imports storage, Merkle, and signer-policy
library types from the same package. AppHash v4 must extract those production
library boundaries before the legacy package can be removed completely.

## Acceptance Rules

1. A capability is implemented only when a typed transaction executes through the
   canonical path on every validator and changes the shared AppHash deterministically.
2. Unknown or deferred payload types fail closed; they may not become opaque state.
3. Economic rewards must be funded by an explicit payer or escrow. A consumption
   receipt proves attribution and settlement but does not mint value.
4. Performance claims require historical-size workloads and multi-host evidence;
   loopback throughput is diagnostic only.
5. Public-testnet and mainnet readiness remain false until the open rows above are
   closed by reproducible gates.

## Canonical Vertical-Slice Gate

`trillionnium/scripts/consensus/spike_cometbft_four_validator.sh` executes the
funded account → task escrow → worker acceptance → salted commit/reveal → paid
consumption → challenge → resolution path through four real CometBFT validators.
The gate compares canonical SQLite object rows across every validator, proves the
issued supply equals all terminal account balances, checks the terminal task and
account nonces, and requires identical AppHash and block history. It checks
expected transaction events on the broadcast node; cross-node block-results event
comparison remains part of the durable indexer gate.

The same gate changes the bounded fee policy, distributes collected fees to a
governed treasury account, expires a second task exactly at its exclusive result
deadline, and rejects a client-forced worker assignment, an exact commit replay,
an over-gas transaction, an unknown payload type, and a proof query before
AppHash v4. The latest local evidence schema is
`trnm_canonical_vertical_slice_evidence_v1`; a passing local run remains
development evidence and is not multi-host public-testnet proof.
