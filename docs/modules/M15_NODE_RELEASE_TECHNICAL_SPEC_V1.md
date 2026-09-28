# M15 Ordinary PoN node, Hepta integration and release composition — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M15; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own composition, startup/shutdown, packaging and activation of one ordinary PoN node with
separately owned services. It contains no domain state machine, alternative consensus, model
trainer or hidden task store.

## PoN Interfaces

PoNNodeConfig; StartPoNNode; StopAndReconcile; ResumeBranchState; InstallWorkProfile;
ConnectHeptaAdapter; BuildRelease; StageFreshInstance. These are proposed interfaces; current
PoCO binary names cannot imply implementation.

## PoN State machine

Bind exact genesis/profile/work primitive and binaries; acquire writer/authority fences; reopen
branch/application/effect journals; reconcile unfinished reorgs and external operations; load
bounded networking/verification/mining workers; only then admit work and requests. Hepta startup
uses existing model/artifact/operations owners. Shut down with bounded drain and retained
unresolved identity; never discard an attempt to regain readiness.

## PoN Persistence and recovery

Startup joins M03/M07/M08/M13 exact contexts and independent local effect frontiers. Recover one
owner per domain, not filesystem-inferred authority. Fresh-genesis migration keeps legacy
namespace read-only. Global release inclusion does not force local model activation; use new
admitted generations.

## PoN Resource bounds

Reserve consensus/verification/recovery floors separate from mining/training/serving; bound
threads, file descriptors, GPU memory, queues and shutdown. A model-proving failure cannot
starve chain validation or local safety.

## PoN Security

Supply-chain profile substitution, accidental old BFT dependency, unqualified work fallback,
remote-signer reuse, arbitrary downloaded model execution and central coordinator key
aggregation. No feature flip or CLI label activates a network.

## PoN Verification and evidence

Exact binary ordinary startup/request/shutdown; real work/fork/reorg; integrated Hepta parameter
loop; author/worker failures; multi-host recovery and power cuts; actual Cargo production
closure excludes retired active BFT logic; independent accepted deployment.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-release-bundle`](../../trillionnium/crates/trnm-release-bundle/README.md): `cargo test --locked -p trnm-release-bundle --all-targets --all-features`.
