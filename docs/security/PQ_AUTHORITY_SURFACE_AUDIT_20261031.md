# Trillionnium-Chain PQ authority surface: first-pass source audit (2026-10-31)

**HOLD / NOT A COMPLETE AUTHORITY MAP / NOT A PRODUCTION-SECURITY CLAIM.**

A first-pass research scan should not treat every `Ed25519` import as a deployed exploit, or every ML-DSA verification as an authorized effect. The [source scanner](../../scripts/ci/pq_authority_surface_scan.py) inventories Rust sources under `trillionnium/crates` with explicit line numbers, file SHA-256 digests, known owner hints and **unreviewed** indicators.

```sh
python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
python3 scripts/ci/pq_authority_surface_scan.py --summary-only
python3 scripts/ci/pq_authority_surface_scan.py > /tmp/pq-authority-sources.json
```

## Known starting points (not evidence of deployment)

| Source | Observed cryptographic boundary | Missing end-to-end proof |
| --- | --- | --- |
| `trnm-types/src/transfer.rs` | Classic Ed25519 transfer address/signature | Which native profile, if any, actually gives this path ledger authority; PQ-only path must reject downgrade |
| `trnm-service-settlement/src/engine.rs` | Two registered classical signer keys on bilateral settlement | Trace registration, settlement effect, replay, rollback and production reachability |
| `trnm-research-protocol/src/command.rs` | Research command has Ed25519 authorization | Determine if downstream command creates execution/upgrade authority |
| `trnm-research-protocol/src/hepta_handoff.rs` | Hepta V1 validates Ed25519 and research authority set | V1 must never authorize PQ-only Hepta FinalUse or install |
| `trnm-research-protocol/src/hepta_handoff/pq.rs` | New ML-DSA-65 V2 candidate and external pin | Actual roster freshness, operation-journal CAS, FinalUse, crash/reorg recovery |
| `trnm-data-availability/src/cell/discovery.rs` | Classic provider record verification | Whether any live PQ-only provider admission trusts legacy V1 |
| `trnm-data-availability/src/cell/discovery/pq.rs` | ML-DSA provider record V2 | Current externally rooted key directory, revocation, live dispatch |
| `trnm-pon-node/src/ingress.rs` | Legacy classical session constructor has PQ-profile denial in #627 | All alternate transport/CLI/bootstrap entrypoints and actual native owner routing |
| `trnm-crypto-primitives/src/pq_auth.rs` | Canonical ML-DSA verification primitive | No role, nonce, spend, governance or release is granted by a correct signature alone |
| `trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs` | PQ account/application candidate | Canonical nonce, state/reorg, origin and live effect propagation under configured PQ profile |

These are verified source-path locations in the candidate branch lineage, not exhaustively analyzed authority flows. Imports or signature validation do not independently prove active network permission or exploitation.

## What the scanner guarantees and does not

- It fails on missing curated critical source files, symlink Rust source/directory, oversized source, invalid UTF-8 or unstable read length. New Rust signature-indicator files appear under `unreviewed-source-hit`, not as approved PQ routes. Fixed test fixtures include missing-path, unknown Ed25519/PQ code, symlink and size/encoding negatives.
- It reports source hash, line numbers and both classic/PQ indicators (including ECDSA, RSA, Schnorr and alternative PQ library hints), but cannot infer which functions grant an effect; can miss aliases, native C/Python, externally linked libraries, macro expansion, indirect verification, dynamically loaded plugins and wire-level downgrade. It includes test-only and dead code.
- At each actual authorization sink the reviewer still must collect: selected profile; caller; message/domain; authoritative key provenance; generation/revocation; replay and state transition; crash/reorg/total-DB rollback behavior; legacy/fallback decisions; exact native tests; independently retained evidence.
- **PQ-only release condition:** every effect-authorizing path is either PQ-authenticated with independent current trust root and test-proven transition semantics, or rejects the PQ profile before creating an effect. A classic+PQ `OR` policy cannot satisfy this goal. Classic+PQ `AND` is defensible only with a verified migration policy and both signatures bound to the same exact statement.

This is a first audit artifact to make the missing inventory visible, not a claim that all entrypoints were found or all hold gates are closed. The original whole-chain [six-gate claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) remains **HOLD** regardless of this scanner's result.


## PN0–PN6 convergence dependency coverage

The source corpus also pins the current client refusal, History admission, TCD1,
M12/M09 and rehearsal owners, their relevant regression sources, and these guards.
These paths are mandatory even when they contain no `pq` filename or signature
primitive. PQ-named descendants in `trnm-research-protocol` and
`trnm-service-settlement` are now included in the same recursive source check.
A changed source needs a new blob pin; removing both a dependency and its pin
cannot make the required boundary disappear. This is source identity and coverage,
not runtime control-flow analysis or native test acceptance.

| Boundary and exact source | Existing owner and permitted effect | Qualification still required |
| --- | --- | --- |
| `trnm-pon-node/src/ingress/{public_v2.rs,public_v3.rs}` and `ingress.rs` | Classical clients reject the PQ account profile before work/connect; owner-aware routes also check the selected native network owner. PNQ2 transport and NPQ6 application selection remain distinct. | Exercise every configured client/CLI/recovery route on the final binaries; a PQ transport signature alone cannot authorize a classical application effect. |
| `trnm-pon-node/src/ingress/history_import.rs` and `store/operator_continuous_owner.rs` | The exclusive continuous receiver accepts only one complete extension bound to the current parent/generation and the original signed validation/activation allocations, durable operation journal and resource interval. Native packet, task, Work and M06 checks remain in the original owners. | General multi-page/fork discovery and shared polling still require their own durable History authority. Source coverage is not evidence of arbitrary history-sync support, independent acceptance or PQ account migration. |
| `trnm-data-availability/src/cell/{closure.rs,release.rs}` | TCD1 binds the loader's already selected profile, generation, file graph and content identities. The original TCR1/TCL4 acquisition produces checked cache bytes. | The caller must supply trusted expected pins and the real loader must retain its CURRENT/selector/FinalUse authorization. TCD1 and a download completion marker are neither signatures nor an install/lease/retirement permission. The separate Hepta repository requires its own source and binary qualification. |
| `trnm-pon-node/src/store/{funding.rs,funding/payment.rs,storage_service.rs}`, `trnm-service-settlement/src/native_budget.rs` and `trnm-data-availability/src/cell/retention.rs` | Original M06 funding/payment observations remain monetary authority. Retirement reobserves an exact completed M12 effect against that journal's chain context before M09 uses the current height. Unknown effects keep their reservation; same-chain reorg reconciliation does not redispatch or mint funds. | The embedding owner must provide the original trusted M12 journal. TCR1 itself does not bind an externally supplied journal identity; direct local retention APIs are not remote authorization. Current height is not finality, a reservation is not currency, and retained local rows do not prove physical rollback resistance or future custody. |
| `trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs` | The existing isolated rehearsal and cold readback preserve the source; they do not activate blocks or invoke external M09/M12 effects. | External owner drain/reconciliation, retained revocation, accepted PN0–PN5 evidence and the existing governed decision remain mandatory. `migration_executed`, `old_work_promoted`, `consensus_activation`, `production_enabled` and `external_journals_imported` remain false. |

The scanner's curated hints include these non-cryptographic owner dependencies so
they cannot silently vanish from a signature-only inventory. A source hash is an
identity record, not an audit attestation. The integration checker and six-gate
claim guard retain their original negative claims; no new acceptance or activation
switch is introduced. Historic upstream commits and reports keep their historic
scope and are not evidence for newly edited sources. Native behavior, cancellation,
crash/reorg recovery and cryptographic qualification must be reported separately
with their exact tested sources and actual outcomes.

## 2026-10-31 P0 extension — unqualified non-src Rust source coverage

The initial source inventory excluded crate Rust files outside `src`: build scripts, examples, benches, integration tests, and nonstandard folders. These may be executable or may generate authority-related code. The scanner now reads all `*.rs` files under `trillionnium/crates` and retains the same 1 MiB-per-file and 20,000-file limits. It also recognizes additional classical and PQ indicator spellings. Adversarial fixtures exercise five distinct non-src source locations, a non-src symlink and invalid UTF-8, with explicit refusal.

A successful scan still **does not** prove any input reaches a production effect sink, establish PQ-128, inspect linked C/Python/Go code or expanded macros, or qualify a trust root. Test-only hits and dead code remain unreviewed indicators. The six-domain security claim is still **HOLD / UNQUALIFIED** and production activation remains false.

## 2026-10-31 P0 fail-closed directory coverage

An `os.walk` scan without `onerror` can silently skip an unreadable *unreviewed* subtree and return an incomplete authority inventory even when all ten curated sources remain available. Checking only the `crates` directory also misses an ancestor symlink at `trillionnium`. Both are **evidence-completeness failures**, not demonstrated chain exploits. The scanner now refuses a symlink at the supplied root, `trillionnium` or `crates`, and rejects any directory enumeration error instead of treating unseen files as absent. Authored test fixtures cover a symlinked ancestor and a deterministic injected `PermissionError` (works even as root).

This source-only improvement does not make directory reads atomic under a hostile filesystem namespace, trace source aliases or C/Go/Python, identify live effect sinks, prove a PQ trust root or qualify the chain. Keep the six-domain HOLD and no production activation.

## 2026-11-06 actual owner and final-use readback

The following map was read from PQ candidate `cad4c18f` and its source composition
with owner candidate `b173c1f`. It records actual interfaces and missing caller
connections, not deployment or native acceptance of the combined source. The
composition retains the existing HOLD assertions. A source scan, successful
merge, or component receipt cannot substitute for execution on its final source,
configuration, dependencies and binaries.

| Boundary | Actual source and caller | Authority carried; boundary still open |
| --- | --- | --- |
| Account identity and transactions | [Native PQ accounts](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs), selected through the Node's explicit account/network configuration | Real pinned ML-DSA verification, generation and nonce checks belong to the selected profile. This does not migrate classical accounts or qualify every ordinary configuration. |
| Tasks and application effects | [Application V6](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs) and [task owner](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs) | Account/task signatures enter the existing execution and funding rules. A network peer signature alone does not confer task ownership, funds, Hepta FinalUse or exactly-once external effects. |
| Parent recovery | [Public-submit recovery](../../trillionnium/crates/trnm-pon-node/src/public_submit.rs) | `submit_with_verified_parent_recovery` requires the original classical network profile before recovery I/O. This refuses the disallowed composition; it does not implement PQ parent-state recovery. |
| Node identity and confidentiality | [Ordinary TLS CLI](../../trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs) → [native TLS owner](../../trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs) → original PNQ2 admission | Explicit loopback TLS requires the configured hybrid exchange and ML-DSA mutual identity, with inner-signer binding. Other listeners, private-task coverage, WAN operation and PKI custody remain separate qualification work. |
| Peer revocation and replay | [PNQ2 durable owner](../../trillionnium/crates/trnm-pon-node/src/store/pq_network.rs) | The selected owner retains sequence, request/result, resource and peer-revocation state; `revoke_pq_network_peer` invalidates its execution epoch. This is not a universal certificate-revocation or release-retirement service. |
| Software and configuration publication | [M15 release authority](../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs) | Separate `NodeSoftware` and `ProtocolConfiguration` quorums bind versions, expiry, current root and checkpoint. `accept_bundle` also verifies bundle declarations. No Chain product installer/configuration consumer was found for this authority. |
| Governance | [Local governance guard](../../trillionnium/crates/trnm-governance-guard/src/lib.rs) and M15's distinct configuration role | The guard checks local caller roles, timelocks and versions; it is not a PQ-authenticated network governance entry. M15 configuration signatures do not automatically wire that local guard to a deployed authority. |
| Cell publication and acquisition | [CPR2 publisher checks](../../trillionnium/crates/trnm-data-availability/src/cell/pq.rs) → [actual `trnm-cell` caller](../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell.rs) | `release_at` rechecks the supplied current key/generation/sequence view. The CLI pins that view for one acquisition and bounds its lifetime. Checked cache bytes and TCD1 loader pins are not installation, CURRENT selection or activation permission. |
| Cell activation and current publication | M15 `CellActivation`, `accept` and `check_current` | A distinct activation quorum requires the matching live current-generation `CellManifest`. `check_current` rechecks role/content, expiry, root generation and expected checkpoint. No Chain product activation consumer was found; its success returns no execution capability. |
| Release retirement and root rotation | M15 `rotate_root`, retained key history and `check_current` | Rotation requires old and new offline-root quorums; removed keys cannot return. Old-generation publication observations fail current checks. This does not provide deployed key custody or atomically retire a running external consumer. |
| Checkpoint and journal recovery | [M03 checkpoint daemon](../../trillionnium/crates/trnm-checkpoint-store/src/main.rs) and [external journal pin](../../trillionnium/crates/trnm-checkpoint-store/src/journal_checkpoint_v1.rs) | Existing-state reopen requires an independently retained expected complete-journal checkpoint. Local integrity checks and an exported file do not establish its independent custody or future freshness. |
| PNQ2 rollback recovery | [Witness service component](../../trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs) and [transaction integration](../../trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs) | Current/CAS and local commit protect exactly the PNQ2 resource, peer and request tables under the independent-witness premise. Account state, blocks, History, CURRENT and Hepta owners are outside this root. |
| Bootstrap and legacy migration | M15 `bootstrap_pinned`; [trusted precommit/checkpoint importer](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs) | Root pins and prior PQ identity commitments are independent protected configuration. The importer targets a new research network; it does not prove precommit timing, source finality/retirement, or recover ownership after classical keys are compromised. |
| Release-finality reference | [Ed25519 reference](../../formal/release-finality-v2/protocol.py) and [read-only native verifier](../../trillionnium/crates/trnm-pon-node/src/release_finality.rs) | The existing V2 certificate profile is classical and non-activating. A valid certificate observation grants neither installed-model permission nor production finality; no PQ deterministic-finality qualification follows. |
| PoN work, hashes and chain selection | [Native work relation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) and [current quantum/DAA research](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md) | Correct signatures do not qualify cheapest valid work, quantum oracle implementation, hash assumptions, difficulty adjustment or adversarial fork economics. These remain separate work-security obligations. |
| Hepta final use | [Existing cross-repository boundary](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) | The actual Hepta consumer, revocation/frontier owner and provider-effect recovery require their own fixed source/binary pair with Chain. No Hepta result or product adoption is inferred from this Chain source audit. |

### Missing M15 consumer is an implementation boundary

On the fixed PQ source, searching Chain Rust/Python callers finds
`PqReleaseAuthorityV1` and `.check_current(...)` only inside the release crate and
its tests. Other crate manifests contain no dependency on `trnm-release-bundle`;
its workspace membership is not a consumer. The only non-test M09
`release_at(...)` call is the `trnm-cell` acquisition check. These observations
must be repeated when a new consumer is added, including indirect wrappers.

The pending installer/activation connection must bind all of the following at
its actual commit/use boundary:

1. The exact installed artifacts and their source/provenance closure, after
   reading the bytes that will actually be used.
2. M15 role/content/version and current root, plus the independently fresh
   checkpoint and trusted time used for `check_current`.
3. For a Cell, the current manifest and activation decisions, CPR2 publisher
   generation/sequence and the selected loader/CURRENT state. These are distinct
   identities; equal content digests do not make their versions interchangeable.
4. The actual execution permission, stable operation identity and retained
   outcome, with refusal/reconciliation for revocation, timeout, cancellation,
   crashes and uncertain external effects.

A new observation wrapper without that actual consumer would leave the same
gap. This audit neither adds an installer nor changes the meaning of an existing
signature, download marker, verified bundle or cached publication observation.

### Recovery domains cannot be substituted

M15 recovery replays signed events against an externally supplied checkpoint.
Its in-memory kernel supplies neither persistence nor an independently fresh
witness. Restoring its journal and a sibling expected-checkpoint file together
cannot prove the absence of a newer authorization or retirement event.

The PNQ2 witness has a different binding, wire contract and protected root from
the M03 complete-journal authority. [Node constructors](../../trillionnium/crates/trnm-pon-node/src/store/pq_network.rs)
explicitly distinguish creation from existing-state reopen and select the
incompatible `PqWitnessV4` namespace. The current `pq-tls-serve` CLI instead uses
`open_with_pq_network`; it does not select a witness. The TLS library can carry
a witness-backed Node, but ordinary CLI wiring still needs protected writer and
witness identities, bounded connection establishment, explicit provisioning and
reopen policy, and a real separately retained service/recovery checkpoint.

The current tree provides `DurableWitness` as a component and test service, not
a deployed independent daemon or custody arrangement. Its fresh Current reply
is not a distributed lease: database clones sharing a writer can observe the
same pending state. CAS orders the protected transitions; it does not establish
exclusive execution or whole-node rollback protection. Loss of a successful CAS
reply remains uncertain until explicitly reconciled, never permission to replay,
refund or reset the owner. See the [complete three-table boundary](PQ_NETWORK_DURABLE_WITNESS_V1.md).

The integrated source must retain these distinctions while exercising its real
success, refusal and recovery paths. Whole-chain PQ, quantum work security,
independent deployment, production activation and consensus authority remain
unqualified; none is promoted by this map or the TLS startup repair.


### 2026-11-06 advancing target: Cell V3 transport and storage effects

The actual integration target `56897f125df27994efa1dda935f2c62eceb36de9`
adds an explicit `PersistentRarestFirstV3` public-cache transport. The ordinary
[`trnm-cell` CLI](../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell.rs)
selects it in `serve`, `fetch` and `fetch-release`; the
[persistent owner](../../trillionnium/crates/trnm-data-availability/src/cell/network/persistent.rs)
implements `fetch_cell_persistent_rarest_first`, its to-file variant and the
corresponding serve/ready interfaces. They use ordinary TCP and TCQ3/TCS3,
not the Node PQ TLS owner. V3 refuses old transport frames without an implicit
fallback, and inventory/payload share the existing frame, byte, connection and
deadline limits. This explicit transport separation and content verification do
not establish authenticated confidential transport for private tasks. Add these
real listeners to the still-open all-listener confidentiality boundary.

The same target tightens the
[storage-service owner](../../trillionnium/crates/trnm-pon-node/src/store/storage_service.rs):
`retain_native_cell` and `repair_native_cell` invoke the original effect-context
check before budget opening, reservation or physical hold. That check reobserves
funding and its anchor, rejects foreign network/parameters/genesis or stale owner
state, and binds the exact policy, claim, operation, effect and height window.
Pending/completed operations retain their original reconciliation boundary.
These are current owner/journal and custody-window checks, not new network
credentials, a PQ governance root or an independent rollback witness.

The target does not change the public-submit recovery guard, M15 current-use
kernel or local TLS certificate implementation. Their missing PQ recovery,
actual installer/activation consumer and ordinary-CLI witness connections remain
open. The composed Cell, storage/replay and preparation controls need new native
observations on the combined source; either parent's reports retain their own
source, binary and resource limits.
