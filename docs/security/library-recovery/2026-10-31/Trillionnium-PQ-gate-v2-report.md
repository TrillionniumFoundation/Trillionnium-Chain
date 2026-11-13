# 2026-10-31 | Whole-chain PQ evidence gate v2: policy and source-inventory hardening

## Current implementation status

**Independent offline hardening only.** GitHub reads and writes to `TrillionniumFoundation/Trillionnium-Chain` returned `403 / Sorry. Your account was suspended`. This delivery has not read the current HEAD or PR #550, has not executed a Trillionnium node, and has not pushed a branch or PR. No PQ-128 or production activation certification is asserted.

## Specific weaknesses fixed in the *previous offline auditor*

The 2026-10-31 predecessor accepted a caller-controlled `minimum_quantum_security_bits` and a policy-controlled `required_solver_cases` list. Setting the security minimum below 128 and deleting all quantum solver categories could weaken the mandatory checks while producing a misleading metadata-only precheck result. The source inventory also silently omitted source files larger than 3 MB, unreadable files and symlinked files, yet reported `scan:complete=PASS` when it found no hits. It could also treat a Git subdirectory as the checkout root.

This v2 revision:

- Hardcodes a **floor** of 128 bits and 9 minimum adversarial quantum-solver classes in the auditor; user policy may require more, never fewer.
- Preserves **additional** solver families requested by policy, so appending a new adversarial case creates a mandatory check.
- Freezes the repository identity and historical candidate W1 manifest path at the code level, rejecting a silently redirected JSON path.
- Makes oversized, unreadable, symlinked, or uninspected source inputs visible in `classic_crypto_review_leads.skipped_*`, and **blocks release metadata readiness** when any are skipped.
- Blocks metadata readiness for source trees with zero inspected source files and requires the exact Git checkout top-level directory.
- Rejects evidence artifacts containing symlink components, even when a symlink target is still inside the checkout.
- Includes `.py` and `.sh` in heuristic source leads because authority scripts may be in orchestration layers.

## Test evidence

`python3 -m unittest discover -s tests -v` = **26 passed**, on self-contained synthetic repositories. This is **not a test of the actual Chain**. The full captured test log is in `test-results-v2.txt`.

## Integration procedure once GitHub access is restored

1. Freeze exact Chain `main` SHA, production branch, eligible PR heads, and actual deployment/activation policy. Confirm no other work has already installed `security/pq` before applying the add-only patch.
2. Compare this kit to any existing audit implementation; do not blindly overwrite code. If `security/pq` is absent, apply `Trillionnium-PQ-gate-v2-add-only.patch` at repository root on a review branch.
3. Run `python3 -m unittest discover -s security/pq/tests -v` and the auditor in `--mode scan` on the real worktree. Do not classify historical/test-only Ed25519 tokens as production flaws without tracing the reachable authority graph.
4. Create dynamic rejection tests for each **active authority**: Ed25519-only after cutover, signature stripping in hybrid AND, wrong chain / epoch / role, revoked owner, replay, and nested evaluator/provider/Hepta release rights.
5. Freeze the **actual live** proof system and establish end-to-end proof-soundness assumptions/recursion composition independently of a candidate manifest. Do not change `pq_128_security_qualified` to true without security evidence.
6. Test the *legal* W1 relation's cheapest classical and quantum solver/difficulty and full rollback/recovery (with an independently protected external anchor). Record node-level p95/p99 and worst invalid-proof cost.
7. Require independent review and immutable evidence tied to the source HEAD, then decide which production claims, if any, are justified.

## Strict epistemic limits

This tool checks metadata, file digests and the completeness of a **heuristic** source search. Its full-suite success and even `METADATA_READY_INDEPENDENT_SECURITY_REVIEW_STILL_REQUIRED` can never demonstrate the correctness of ML-DSA, zero-knowledge proofs, all runtime authority paths, or quantum mining security. A policy can assert a claim that its referenced artifact does not actually prove. Independent human and machine validation remains mandatory.

Primary reference material: NIST FIPS 204; RISC Zero Security Model 3.0 (STARK 96/99 bits and Groth16 not quantum safe); Bailey & Sattath (arXiv:2403.08023), which is an adversarial model for some PoW systems rather than a proven attack on W1.