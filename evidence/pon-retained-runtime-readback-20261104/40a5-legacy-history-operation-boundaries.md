# 40a5 Legacy History operation boundaries

## Scope and source binding

This is a read-only source review, not native execution, a timing result, a test pass, or a deadline repair. No production source, test, budget, branch, or CI run was changed by this review. The primary source is `40a5ba25e40fd5eda5b04fc1c3811320d438de11`, tree `75fe3367c4896a4f2d5f5dd561914613ec999343`.

| Source under `trillionnium/crates/` | Exact blob |
| --- | --- |
| `trnm-pon-node/tests/ancestry_long_sync.rs` | `ed1213d2d850ab0a8634e24ba7dd8d67cc1ee786` |
| `trnm-pon-node/src/store.rs` | `900b9dc8034856c6ee04caf0e1fd99bdbda6fc76` |
| `trnm-pon-node/src/store/historical_commitment.rs` | `a66ede7323f326fb38e48df7e54286a8fc82fe46` |
| `trnm-pon-node/src/ingress.rs` | `7c1ceca413da2f7004603b17cb19713b9bf681c6` |
| `trnm-pon-node/src/ingress/history_import.rs` | `742c236acf5c80fa694c1a6061b7cd4ead2576d3` |
| `trnm-mvcc-fee/src/pon_commitment.rs` | `c2b3a10ab5c0c87cfb670ecd82613e56f14938dd` |
| `trnm-mvcc-fee/src/pon_executor.rs` | `0d8ea0bf4b5f64b354b6a12c2b90efe670b8883f` |
| `trnm-protocol/src/pon_wire/state_root_arithmetic.rs` | `14b5cbf88ad07fcc76a15c109c6f58bf46b84465` |

Independent file readback also found the selector, store, commitment and executor blobs unchanged at `faae36cfaa3332ef20c7f94ac5e816641a1ee884`; the arithmetic blob above was read identically at `73ab6e9a83bcc836e261d93f9bb23ceafe556758`. These are file comparisons, not qualification of either later commit.

## 1. The original 4105-block selector uses Legacy storage

The selector constructs both validator and confirmer with `Node::open` (lines 137 and 265). In `store.rs`, `open` → `open_with_fault` → `open_inner` selects `StateBackend::Legacy` (1060–1071, 1217–1239). The separately named authenticated opener selects `AuthenticatedV1` (1076–1104).

Consequently, authenticated campaign `account_graph`, CurrentAccounts, native account-root and AuthenticatedV1-only SQL observer costs do not measure this selector. Its Legacy M06 commitment computation remains relevant. Changing the opener would change the experiment and is not an equivalent optimization.

## 2. A normal new receiver packet has one W1 entry and one M06 execution entry

This count describes a valid new packet on the selector's exclusive, unowned receiver path, with a stable SQL epoch and no earlier failure or recovery continuation. It is not a count of completed work in a failed archived run, nor a count of individual speculative transaction executions inside M06.

- `history_import::admit_packet` performs header/context preflight, then calls `verify_history_work` once (309–338). Unowned public preflight does not reconstruct the parent State: `precheck_public_admission_context_with_progress` takes the header-only branch (`store.rs` 3411–3427).
- `verify_history_work` creates the private WorkCheckedPacket through the original full W1 verifier (258–285; `store.rs` 651–671). The exclusive path passes that object into `admit_work_checked_with_control` (368–378); it does not verify the same W1 again.
- Final admission constructs the current parent through `check_admission_parent` and `state_at_with_progress` (`store.rs` 3536–3581, 4111–4115). At the second original parent checkpoint, a matching epoch reuses this same parent State; an unstable or changed epoch performs the full check again (4167–4179).
- The canonical M06 entry is `execute_derived_core_with_rejection` (4185–4198). After writes, persistence independently reconstructs the parent and child with two `state_at_with_readback` calls (4407–4419).

Thus the ordinary successful receiver path has three historical State constructions: the execution parent, the post-write parent, and the post-write child. Actual extra epoch checks, failures and duplicate/recovery paths must be counted separately. The validator's earlier packet-generation work is outside this receiver count.

## 3. The 128-block snapshot interval repeats State reconstruction, not old W1 or M06

Legacy snapshot cadence remains every 128 blocks; the retention rule keeps at most 64 non-genesis snapshots plus the genesis anchor (`store.rs` 4355–4379). The authenticated per-block snapshot branch does not apply.

`state_at_with_readback` reads an actual snapshot, checks its complete canonical bytes and root, then replays actual stored deltas. Every replay step checks its before-value, reconstructs State, checks the current recorded root, and runs continuity validation (3210–3294). This path does not call the old block's W1 verifier or execute its transactions again.

For a healthy sequential receiver with all scheduled snapshots intact, the parent at height `h-1` replays `(h-1) mod 128` deltas and the just-written child at `h` replays `h mod 128`. The two independent parent constructions still each read and check their replay. These are source-derived path lengths, not observed timing or archived completion counts. The last planned page at height 4105 has parent distance 8 and child distance 9 before activation.

The existing historical cache has at most 8 entries, 2 MiB payload and 16 MiB retained software charge (`historical_commitment.rs` 11–13). A candidate indexed by block/root still enters complete current-State checking (90–112). It cannot return State, skip SQL/delta checks, or replace the replay with an earlier validity verdict. The same-call admission-parent reuse already removes a separate redundant construction when its epoch is stable.

## 4. The final page contains a separate deep activation operation

The selector requires one packet per page and asserts the active tip remains genesis until all 4105 pages have returned successfully (299–319). The importer activates only the final packet of a complete page (`history_import.rs` 514–527). Activation keeps the same original admission operation and absolute page deadline (386–393); it receives no new 30-second allowance.

On the normal uninterrupted path, the final activation first checks observed history headers (`store.rs` 5637–5653, 5677–5686). It then takes the deep-reorganization path from genesis to the 4105-block target, builds 4105 attach steps, checks that retained step sequence, and resumes it (5260–5324, 5501–5509). This is an expected source path, not proof that a failed run entered or completed those steps.

Each completed step applies stored deltas to staging and validates the complete actual staging State (5517–5535). The enclosing transaction then independently reads and validates the still-active genesis State before its commit (5071–5076 → 2367–2407 → 2321–2353). There are therefore staging and active-State checks per step, in addition to intent, retained-step, final-root, publication and event checks. Reorganization does not redo old W1 verification or old M06 transaction execution.

The original final independent `settings.state_root` comparison remains at 5542–5550. Every step's transaction, cancellation boundary, durable cursor, active-state check and termination accounting remains in place. An interrupted operation may stop before or during these stages; its completed step count is unknown without retained evidence.

## 5. Existing pure arithmetic is not evidence that a new wrapper would fix the deadline

Node already owns `commitment_root_arithmetic` (`store.rs` 772, 1624). Its FullRootArithmetic wrapper has a fixed 2 MiB retained-material limit; contention, poison or an arithmetic error falls back to the independent original root (`pon_commitment.rs` 32–62). That limit is not an RSS or total transient-allocation bound.

The underlying StateRootArithmetic retains one optional material entry (137–140). Complete key/value input, bounds and collision checks still precede mathematical reuse; a partition hit requires equality of its complete original leaf-hash tuple slice (241–300, 354–422). Actual nonces and liabilities are not excluded from State or replaced by cached validity.

Current Legacy persisted-State checks still call `settings.state_root` directly (`store.rs` 2335–2341). A proposed wrapper was not applied. If that single mathematical entry were used for both staging and active checks, those calls would alternate staging and genesis inputs; continuous reuse between adjacent staging States cannot be assumed.

Any future equivalence review would also have to retain the original `root_for_config` order: fresh `pq_accounts_v2::validate_state`, then growth-profile dispatch, then the ordinary root (`pon_executor.rs` 487–495). A naked FullRootArithmetic root is not a profile-aware replacement. No such change, independent regression execution or performance result is claimed here.

## Evidence boundary

The frozen 44d four-lane failure readback is separate evidence (durable JSON blob `a0a2242073b800ea558b5585399ac920422b125a`). Its x64 runs reported server lifetime expiry followed by IO111; its ARM runs last reported the 4000 full-sync milestone and later PUBLIC_REQUEST_DEADLINE before server lifetime expiry. Those outputs do not identify the failing remaining page, whether final activation began, its completed cursor, or the specific deadline check. The remaining 105 pages cannot be attributed to root computation alone.

For 40a5, commit-run metadata reports priority run `41785836221` completed/cancelled, attempt 1. Its jobs endpoint returned an empty list; a separate peer metadata read reported total_count 0. There is no executed 40a5 priority/History lane result to inherit from 44d.

No per-stage timing of this original Legacy selector was established in this review. The source proves repeated reconstruction and the activation topology; it does not establish their measured cost shares or demonstrate a safe deadline repair. The unmeasured wrapper remains unapplied. No native test count, business acceptance, whole-chain PQ acceptance, throughput improvement or independent external signoff follows from this note.
