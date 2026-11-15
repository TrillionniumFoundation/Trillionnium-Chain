## Why

The fixed W1 v2 proof profile needed a concrete bridge from its guest and recursion artifacts to the assumptions of a post-quantum proof, and explicit accounting for the remaining composition and lifetime obligations. Catalog agreement and successful receipt verification alone do not supply those arguments.

This continues the existing W1 v2 branch in Draft. Current candidate: `1a14f7d4826363daefac9ec10131c66d7e70ece7`, including the original implementation map and the new closure work.

## What changes

- Independently reconstruct the saved R0BF guest's initialized memory, image ID and embedded kernel identity; interpret both complete generated AIR DAGs and reproduce their degree-at-most-five bound.
- Independently compute all 27 allowed recursion code commitments from the complete official ZKR byte streams using a C NTT/LDE/Poseidon2/Merkle implementation. Every ID matches the fixed catalog, and the tree built from those computed IDs matches the configured control root.
- Add an exact-rational Theorem 10.6 composition evaluator, a finite shared-oracle diagnostic and a lifetime ledger. Their inputs retain explicit assumptions, enlarged query domains and unknown project values; none produces unconditional security bits.
- Add a digest-pinned roster of 105 actual named controls and a separate head/prospective-merge workflow. Completion requires every execution stage, matching source before/after, complete named results and unchanged qualification scope. Tests also check the saved 27-result evidence against the separate program inventory; CI does not rerun all large commitments.
- Retain all fifteen original obligation identities, detailed remaining premises and three independent authorization/proof/work decisions. The observed fixed v2 release feature/profile sub-scope is marked complete without asserting compiler, recursive-semantic or production qualification.
- Repair the generated distributed-source inventory after the original 7150 hosted failure: add exactly the two earlier QROM configs and the new closure roster. The unchanged generator and its Git fallback now reproduce all 1,361 entries.

## Validation and provenance

- 314 W1 Python tests pass; the 105 new named controls are included in that count.
- 147 separate retained CI-contract/source-integrity tests pass.
- All 27 real code-commitment computations pass, with independent small-transform/hash/tree and returned-record review.
- Repository checks and workspace rustfmt pass. The fixed report reproductions match their entire saved bytes.
- On frozen source `7150d96a2112875b4afcf3023361a5cef4a0e4b1`, the new native v2 release verifies the fixed receipt, completes native relation replay, matches the official image calculation and rejects receipt/artifact tampering and four proof-environment variables. Its graph enables exactly `std` and `disable-dev-mode`, and its actual context excludes dev, segment and Groth16 outer paths. The full frozen-workspace/strict-Clippy run is separately in progress at this body update.
- The earlier 7150 hosted QROM head and prospective-merge jobs passed complete before/after source checks over 11,052 entries and 1,095,556,148 bytes. Those records belong to 7150; the new candidate needs its own hosted results. The earlier complete PR snapshot also retains unsuccessful broader checks and is not presented as all-green CI.
- Local partial historical-evidence checkouts are explicitly distinguished from complete hosted source verification. Original failures, limited-source observations and the corrected temporary local harness trial remain retained.

## Acceptance boundary

The complete QROM bound, adopted lifetime quantum budget and unconditional project security bits remain unknown. The indexed January CDHZ statements have not been proven equivalent to the latest full manuscript. The fixed bytecode commitments do not prove compiler correctness, all program semantics, all reachable traces or zero-padding exclusion.

PQ authorization, complete computation proofs and quantum-resource/chain-weight security remain separate HOLD decisions. The proof parameters, guest, accepted verifier profile and native work/Node admission rules are unchanged. This PR does not merge main or activate production.

The detailed entry point is `docs/security/W1_QROM_CLOSURE_CONTINUATION_20261107.md`; exact evidence and machine disposition are under `evidence/pon-w1-qrom-closure-20261107/`.
