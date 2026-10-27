# PQL11 — recursive post-quantum source identity gate (research only)

Status: **DRAFT / HOLD_NO_GO / NO PRODUCTION AUTHORITY**.

Parent: PQL10b PR #492 at exact commit `668c41cead73ebef83212094d0c077ee788f1570`, itself stacked on #491 and the frozen PQL9 research lineage.

## Actual security counterexample

The preceding `_check_pq_source_coverage` iterated only the immediate children of the formal and native crypto/protocol source directories. An unpinned `experiments/pq_nested_downgrade.py` or `src/research/pq_nested_downgrade.rs` was therefore invisible to enumeration while the manifest's previously pinned files could still match. This was a **source inventory omission**, not an ML-DSA break, signature forgery or existing production exploit.

The new guard iteratively scans all descendants under the same three existing owner roots; it refuses newly found unpinned PQ/PQG/PQL `.py`, `.c`, `.rs` implementation files, any symlinked descendant and more than 10,000 scanned entries. A pinned nested implementation still requires exact Git blob identity. The check and its fixture test source are now themselves required, hash-pinned inputs to this research corpus. Explicit negative tests cover nested Python/Rust source, a nested directory link and traversal exhaustion; a positive test covers a pinned nested file followed by byte substitution rejection.

No existing protocol, W1 work, signature, transaction, chain state, normal Hepta authority, installed 2,048-byte transaction cap or production/release flag changes. This checker never authenticates actual signers, rollback anchors, quantum mining work or an independent operator; pinned bytes alone are not cryptographic acceptance.

## Qualification required

Run on an exact complete checkout: `bash scripts/project-preflight.sh` followed by `python3 scripts/ci/check_pq_research_integration.py` and `python3 -m unittest -v scripts/ci/test_pq_research_integration.py`, then all inherited scoped ML-DSA and native Rust tests. This environment cannot clone the complete repository or run Cargo; no full-tree, CI, public WAN, HSM, power-loss or independent acceptance claim is made.
