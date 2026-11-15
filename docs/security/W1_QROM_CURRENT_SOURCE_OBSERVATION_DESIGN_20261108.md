# W1 QROM current-source observation: proposed additive continuation

Status: review prototype only. This patch adds a separate observation entry. It does not change either historical QROM workflow or make either original workflow pass.

## Why the historical gates failed

The six retained GitHub jobs for pull request 821 at candidate commit `0101b0ce76239832e0b2d19d0fd3f07e40fabeb4` and prospective merge `d5ba8574297839ed06e7a016207827b7993825c6` used the same tree `f57618067a8106d0a96f74dd38291a25416ff68c`. Their source-before and source-after receipts agreed. The two QROM lanes correctly rejected source bytes outside their historical profiles.

The lifetime ledger retains source base `7150d96a2112875b4afcf3023361a5cef4a0e4b1` and 20 source pins in `scripts/w1_lifetime_ledger.py`. Only `trillionnium/crates/trnm-pon-node/src/store.rs` differs from those pins. The implementation contract retains source base `cb114b13bf848a77634e40a08b31b30c7c758e7b`, 16 project files, three audit helpers, and its original byte limits in `config/pon/w1-qrom-implementation-v1.json`. Two project files differ: the W1 verifier `main.rs` grows from 9,233 to 11,172 bytes, and `pon_wire.rs` grows from 32,354 to 32,654 bytes. The other project files and all three audit helpers retain their original bytes.

The 20, 16, and three groups contain 37 distinct paths. This proposal retains those groups and adds no mathematical assumption. It pins two original owner files separately, giving 39 distinct checked file contents including the original lifetime owner and implementation contract.

## Reviewed source differences

| Selected source | Historical SHA256 | Reviewed current SHA256 | Reviewed difference |
| --- | --- | --- | --- |
| `trillionnium/crates/trnm-pon-node/src/store.rs` | `b712a86b9997a098df5e8257f309d22445b2c749c9aa474457e958a0f65f5153` | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` | Composed Node owner, authenticated service, observation and recovery paths, plus the reviewed private field rename. This is an expanded runtime, not a new lifetime bound. |
| `formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs` | `07415e8e3bb53f3e81dd489e4ebda63368170efbe4a217ae6b0dd6cc0af14128` | `5e102fcbe4881e3d163c7a8b65364304b14d080ae64f23b0d5032daa84208aa7` | Adds the `native_once` full-relation replay helper and `--native-once` dispatch. The prior receipt-verification branch remains. The new helper retains false parent eligibility and admission claims. |
| `trillionnium/crates/trnm-protocol/src/pon_wire.rs` | `be816ee5b209098fa790d6e190d1d9c659634ac22d58b95c83dc8b49899c70cd` | `ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b` | Adds the typed funded-service reservation and decision tags and their lengths. Existing legacy reservation and decision cases remain. |

The proposed profile has a distinct schema and file: `TRNM-W1-QROM-CURRENT-SOURCE-OBSERVATION-PROFILE1`, `config/pon/w1-qrom-current-source-observation-v1.json`. Its complete byte SHA256 is fixed independently in the new owner. Editing the source revision, a pin, path roster, budget or qualification field invalidates that profile. The profile binds the reviewed F2 selected bytes; it does not assert that all future repository commits are equivalent to F2.

## New entry and exact result scope

`scripts/w1_current_source_observation.py` requires an explicit checkout, profile, exact current Git head, and fresh output outside the checkout. It first validates all selected current bytes and both unchanged original owner files. It loads the exact validated original Python owner bytes in private modules without replacing their constants or functions.

It executes the original ledger source survey and original implementation report builder. The only accepted original outcomes are the two specific historical refusals that occurred in the retained jobs:

- `source identity mismatch: trillionnium/crates/trnm-pon-node/src/store.rs`
- `input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs`

Unexpected original success, a different exception, a missing input, an unreviewed current file, or a changed owner is refused. It derives the three-path difference set from the original immutable tables and actual current inputs. It rereads the selected files after executing both original guards.

The CLI also reads every selected Git blob from the caller's exact current commit before and after the observation, checks the exact current profile sizes and hashes, and checks HEAD before and after. A reviewed worktree copied over a different committed source, an untracked file missing from the commit, or a forged current head is refused. These are selected-file checks; they do not replace the repository's complete raw source receipt.

The separate result is `CURRENT_SELECTED_SOURCE_OBSERVED_HOLD`, with schema `TRNM-W1-QROM-CURRENT-SOURCE-OBSERVATION1`. Both original `source_scope_passed` fields remain false. The original unknown lifetime budget is included without modification. The report explicitly sets all of the following to false:

- Original named test rosters completed and original workflows passed.
- Saved proof and upstream checks reached.
- Current binary executed, dependency closure complete, and whole repository source verified.
- Authenticated provenance, post-quantum soundness, complete W1 soundness, quantum work, lifetime bound, production qualification, and consensus admission.

Quantum security bits remain null. No historical configuration, source base, binary, proof, upstream snapshot, archive, or workflow is overwritten. No byte bound in the original owners is relaxed. Local runner/account/ancestor integrity remains a trust assumption. The inode and symlink controls do not claim protection from malicious same-UID ABA replacement or backup rollback.

## Validation completed for this prototype

Twenty named Python controls passed in the local selected-source mirror. The first fourteen cover real original refusals, changed/missing sources, file and ancestor symlinks, immutable original owners, unreviewed or promoted profiles, unexpected original success, unrelated original failures, mutations during observation, report isolation, and strict JSON. Test doubles are used only for explicit refusal controls, never as cryptographic evidence.

Six additional controls invoke the real CLI against temporary Git repositories containing the selected source fixture. They verify selected-blob binding, forged-head refusal, a different committed blob despite reviewed worktree bytes, an untracked selected file, create-only output, and a real FIFO replacing a previously successful regular-file fixture. The FIFO control requires an explicit non-regular-file refusal within a three-second subprocess deadline; a parent timeout is an uncaught test failure. Selected files are opened with nonblocking and close-on-exec flags before fstat rejects non-regular files, so opening a FIFO cannot wait for a writer. These temporary commits are synthetic test fixtures and are not a final F3 source campaign.

The actual local function observation validates the 37 reviewed paths and preserves both original refusals. No full QROM test roster or saved-proof/upstream gate was run by this prototype. The earlier complete decoded logs for all six original F2 GitHub jobs, their raw tuples, hashes and source mapping remain in the separate diagnosis archive.

## Why this is separate from a workflow migration

This patch deliberately has no workflow edit. A future versioned CI entry must retain the original guard's refusal and complete each original named roster under an explicitly reviewed historical/current test-input model. It must separately bind any current compiled binary, upstream dependency graph, saved proof and current runtime path. Reusing old proof or binary snapshots as current evidence would be invalid.

The added report can make the exact reviewed source drift visible now. It cannot supply a missing QROM extraction theorem, a total lifetime query budget, a concrete complete W1 quantum bound, a work-cost guarantee, or production qualification. Those obligations remain HOLD.

## Original retained run references

- [W1 QROM closure run 42515032701](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42515032701), jobs 128836076731 and 128836076552.
- [QROM implementation run 42515032598](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42515032598), jobs 128836076425 and 128836076720.
- [Credit contract run 42515032608](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42515032608), jobs 128836076247 and 128836076706. Its separate stdout-order fix preserves the original 43 controls and strict parser; it is not part of this QROM proposal.
