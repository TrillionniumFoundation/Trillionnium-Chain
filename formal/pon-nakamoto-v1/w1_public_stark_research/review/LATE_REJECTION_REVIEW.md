# Typed late-stage rejection controls for P3 0.8.0

Qualification remains **HOLD_NO_GO**. This is an implementation and measurement review, not a worst-case verifier-cost theorem. The helper is `examples/mutate_last_query.rs` relative to the delivered crate root. It leaves the frozen verifier and its first campaign unchanged.

## Why another control is needed

A changed trace commitment, public statement or preprocessing key changes the Fiat–Shamir transcript. In this P3 release, changed query indices can change the number of digests required by a pruned multiproof. A verifier can therefore reject such a control at `SiblingCountMismatch`, before most query arithmetic or FRI commitment authentication. Reaching the arithmetic component alone does not imply reaching its later checks.

The new controls keep the statement, independent expectations, commitments, out-of-domain openings, final polynomial, grinding witnesses and trace degrees unchanged. They change a typed query-response value only. The helper requires an exact canonical decode/re-encode round trip, the original component envelope, fixed trace degree, fixed binary-fold layout and exactly 64 queries. It also checks that the bytes encoding every proof-carried transcript field stay identical, that the full proof byte length stays identical, and that at least one proof byte changes. The output is a new file; no existing proof is overwritten.

## Actual shared-proof layout

The pinned `FriProof` contains `input_openings` per input batch and `commit_phase_openings` per FRI round. Each round has `sibling_values[query][sibling]` and one shared `opening_proof`. It does **not** contain one independent Merkle path per query.

For the actual MMCS, the shared proof is `PrunedMerklePaths<Goldilocks, 4>`. Its only data field is `sibling_hashes: Vec<[Goldilocks; 4]>`. Digests are ordered by ascending tree level, then ascending parent index, then ascending missing-child position. The last digest is a boundary in this shared tree frontier; it is not intrinsically the last query's path.

These facts come from the actual retained registry sources:

| Source | SHA-256 of original source |
|---|---|
| `p3-fri/src/proof.rs` | `9c6efe2f05ec8f89f43ea1f2e706bf0fd826d9191d20d12b24ea2da10ad494a6` |
| `p3-fri/src/two_adic_pcs.rs` | `926b6ecfe0c3c2ae3956d77f78795c3d5d4b7b171c16ec1ae251852c2d2a24cb` |
| `p3-fri/src/verifier.rs` | `975392a464c823c93c9ec50ce4e73d17a8b0fbdf22f047f887fb749dcf7280a3` |
| `p3-merkle-tree/src/mmcs/batch.rs` | `f893dbbb6818e386980d7cee66383725e5546832071a2975fc4b3cedb0cca1b4` |
| `p3-merkle-tree/src/pruning.rs` | `ae09ad2377b6bf3166ebbb4ef6402b9d09fb642b9dbafe749b075e0c9c2b2da5` |
| `p3-merkle-tree/src/mmcs/mod.rs` | `8164c4089590055bed06739a327b4561ce4793f3bc19b730fd1c24d77dec1e4c` |

The audit used local exports identified under `round2_runtime/`; those identifiers are not required paths in a delivery package. Pinned official source locations are [p3-fri 0.8.0](https://crates.io/crates/p3-fri/0.8.0) and [p3-merkle-tree 0.8.0](https://crates.io/crates/p3-merkle-tree/0.8.0); the precise source-file locators and hashes are in `AUDIT_SOURCE_LOCATORS.json`. The PCS associated-type excerpt explicitly identifies `FriProof<Challenge, FriMmcs, Val, Vec<BatchMultiOpening<Val, InputMmcs>>>`. The MMCS implementation explicitly aliases its `MultiProof` to `PrunedMerklePaths`.

## Verifier order

The reviewed `verify_fri` derives its shape from the verifier's claimed domains and fixed parameters, checks proof lengths against it, replays the transcript, and then performs these stages in order:

1. Authenticate all input multiproofs and build reduced openings.
2. Sequentially walk query indices 0 through 63. For each query, execute every fold and compare the result with the final polynomial.
3. After **all 64 query chains** have passed, authenticate each commit-phase multiproof in round order.

The second stage collects each round's reconstructed rows and group indices for the third stage. This is observable in the actual loops; it is not inferred from the word “FRI.”

## Two controls and their interpretation

| Mode | Typed mutation | Path it exercises |
|---|---|---|
| `last-fold-query-value` | Add one to the extension-field sibling value in the last fold of query 63 | Preserves all input authentication and queries 0–62. Ordinarily reaches the final-polynomial comparison at the end of query 63 and rejects with `FinalPolyMismatch`; commit-phase multiproof authentication has not yet begun. The actual subtype is checked from execution. |
| `last-fold-auth-sibling` | Find the last FRI round with a nonempty external digest vector; add one to the last Goldilocks element of its last digest | Leaves all query arithmetic and final-polynomial checks unchanged. Reaches commit-phase authentication in that round, after the preceding rounds. The expected P3 error is `CommitPhaseMmcsError(CapMismatch)`, with all vector lengths unchanged. |

The last few small FRI trees may have no external digests because the sampled leaves cover the whole relevant tree. The second mode selects the last **nonempty** vector and records every round's digest count. It fails explicitly if there is no such vector. It does not silently mutate a different proof field. Its selected round is not necessarily the final round of the verifier.

The exact cap error is source-verified. `verify_batch_pruned` first completes `walk_pruned_frontier`, then compares the surviving digest with the committed cap entry. A mismatch returns `CapMismatch`. In this configuration cap height is zero, so the cap has one root. The enclosing FRI verifier maps this to `CommitPhaseMmcsError`; it is distinct from the earlier input multiproof `SiblingCountMismatch`.

For the fixed full traces there are 13 SHA rounds and 17 arithmetic rounds, with one sibling value per binary fold and 64 query rows per round. The helper enforces those shapes before mutation.

## Execution contract

The CLI is:

```sh
mutate_last_query MODE INPUT_PROOF OUTPUT_PROOF
```

The final success JSON contains `status: MUTATED_RESEARCH_PROOF_ONLY`, `qualification: HOLD_NO_GO`, the exact typed mutation path, before/after field encodings, proof hashes and sizes, changed-byte count, unchanged transcript-field hash and the retained verifier order. It explicitly says verification is pending. That record is not itself a rejection result.

The coordinator runs both modes against both SHA and arithmetic proofs, with the original statement and expected files unchanged. Rejection must come from the intended proof component; an I/O, parser, envelope, vector-length or changed-transcript failure is not a substitute. The observed lower-level error and phase timing are retained. Compilation and these four executions have separate evidence from the frozen first campaign.

The first late-control harness attempt expected the spelling `RootMismatch` for the second SHA control. P3 actually returned the correct source-defined `CapMismatch`, and the strict harness stopped before the arithmetic controls. This was an error in the test oracle's expected label: the real verifier had rejected the mutation. That failed harness attempt is retained. The correction is to require the precise `CommitPhaseMmcsError(CapMismatch)` outcome, rather than broadening the harness to accept arbitrary failures. The mutator and verifier source do not change for this correction.

## Observed first-run controls

The corrected run-01 job `1a1b86dc83a-12894-f4a` completed with all four expected rejection variants. The reviewer independently read its status and complete control summary, checked each base-proof hash against the original three positive verifier records, and checked that each input manifest retained the original statement and the unmutated proof component. Each control changed exactly one byte while preserving its full proof length and all transcript fields.

| Component and control | Selected zero-based fold | Component verifier phase, ms | Whole process outer time, s | Observed subtype |
|---|---:|---:|---:|---|
| SHA, query 63 value | 12 | 307.770117 | 0.392141531 | `FinalPolyMismatch` |
| SHA, shared digest | 9 | 282.503417 | 0.371105078 | `CommitPhaseMmcsError(CapMismatch)` |
| Arithmetic, query 63 value | 16 | 36.030056 | 0.992656347 | `FinalPolyMismatch` |
| Arithmetic, shared digest | 13 | 50.640468 | 0.990253018 | `CommitPhaseMmcsError(CapMismatch)` |

For SHA, the selected shared digest was index 3 of fold 9; folds 10–12 had no external digests. For arithmetic it was index 1 of fold 13; folds 14–16 had no external digests. The last field element, index 3, was incremented in each selected digest. The exact source-guided path inference follows from the pinned sequential verifier, the unchanged transcript and earlier proof data, and the observed rejection subtype. The runner does not add per-query timing instrumentation.

The original first-attempt job `1a1b8695b7c-12894-f24` remains recorded as failed with exit code 1 because of its incorrect expected label. Full evidence hashes and control identities are in `runner_review.run01_late.json`. Later final-source runs are recorded separately and do not overwrite these samples.

## Observed final-source controls

The complete final-source job `1a1b875cbb9-12894-f8f` generated a fresh proof pair, passed three fresh positive verifications, and then completed all four controls again. The final script compares all three artifact hashes against all three positive records before mutation. The independent review also checked each control's base-proof hash, unchanged statement and companion proof, exact one-byte change, preserved proof length, unchanged transcript fields and precise rejection subtype. The final verifier binary has SHA-256 `7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc`.

| Component and control | Selected zero-based fold | Component verifier phase, ms | Whole process outer time, s | Observed subtype |
|---|---:|---:|---:|---|
| SHA, query 63 value | 12 | 288.901837 | 0.428773269 | `FinalPolyMismatch` |
| SHA, shared digest | 9 | 281.934488 | 0.598215414 | `CommitPhaseMmcsError(CapMismatch)` |
| Arithmetic, query 63 value | 16 | 24.104283 | 0.994634917 | `FinalPolyMismatch` |
| Arithmetic, shared digest | 13 | 50.361420 | 1.043657165 | `CommitPhaseMmcsError(CapMismatch)` |

The target indices, base proof hashes and mutant hashes were observed to equal run-01's identities; their timings were measured anew. The late-control maximum is 1.043657165 seconds in this run. It is separately reported from the 2.238432757-second ordinary commitment-change sample, which still failed at an early input-multiproof shape check and whose wall time includes a 965.892610-ms read/decode phase. A longer observed process time does not by itself locate a later verifier stage.

The helper's four outer wall times were 0.643284814, 0.815016416, 0.775778136 and 0.728702660 seconds respectively. These are costs of this particular mutation utility using an already available valid proof, not a cheapest attack cost or a from-zero proof construction cost. The complete observations and raw evidence hashes are in `runner_review.run02.json`.

## Limits

This is a measured path construction for one retained proof pair and four controlled changes. It does not maximize cost over all malicious inputs, prove a resource bound, establish a globally latest rejection point, or upgrade noninteractive security. The shared multiproof layout is the reason the exact target and traversal order are reported instead of a generic “last query” label.
