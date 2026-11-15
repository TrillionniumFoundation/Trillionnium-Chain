# Merged Python/source gate evidence

This delivery binds the retained observations to commit `2d46d8682201bc0619f5b156af50e77fb399322e`, tree `5ae5317304588cca8295a19dd512c8e853f1ef5b`.

`original/` is an unchanged byte copy of all **95 original evidence files (6,174,209 bytes)**. Original README links retain their relative layout. No gate was rerun and no original log was edited while preparing this delivery. No repository, Git object cache or index was copied.

## Suite execution counts

| Suite | Reported test executions |
| --- | ---: |
| FJS1 | 34 |
| EC1 | 21 |
| Lifecycle query | 26 |
| Source integrity | 43 |
| CI execution | 77 |
| CI contract negatives | 108 |

**309 is the sum of these six suite reports, including overlap; it is not a deduplicated test count.** CI execution imports the source-integrity `TrackedSourceTests`, so those executions appear in more than one suite. No number of unique tests is asserted. This clarification also governs shorthand totals in the unchanged original reports.

The preflight, CI static contract, inventory, invariant and current-implementation checks passed. Detailed-contracts/applicability initially rejected absent fixtures; both original refusals remain intact. Thirteen real manifest/qualification blobs, totaling **965,044 bytes**, were retrieved for the fixed commit, verified by recomputed Git blob OID, and materialized at their tracked paths. The original validators then passed. No placeholder or guard exception was used.

## Coverage and source identity

All 13 reviewed native/formal source bindings and the recorded 2,415 non-evidence source hashes matched. The recorded HEAD/tree were fixed and Git status was clean. This does not constitute the canonical full raw-worktree identity qualification: at that observation, **12,646 tracked evidence files remained unmaterialized and 12,646 skip-worktree entries would be rejected by the original source guard**.

The full repository-truth lane and merged-tree `check_repository.py` were **not executed or reported as passing**. The independent Git-tree Markdown check is separate evidence and does not replace those gates. All physical-execution and production qualification flags remain false.

- [Coverage and count semantics](coverage.json)
- [Source identity and unchanged-copy provenance](source-identity.json)
- [Original complete report](original/README.md)
- [Initial missing-fixture refusals](original/attempt-01/summary.json)
- [Successful fixture-backed follow-up](original/module-fixtures-attempt-01/summary.json)
- [Thirteen actual fixture blob bindings](original/module-fixtures-attempt-01/materialization.json)
- [Full-lane source-identity boundary](original/canonical-source-identity-boundary.json)
- [Durable process logs and outcomes](original/runtime-jobs.json)
- [Physical file SHA-256 inventory](physical-sha256.json)

The physical inventory includes every delivery file except its own self-describing JSON file. It uses directory traversal without Git ignore filtering and includes failed attempts and all raw log streams.
