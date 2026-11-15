# Chain source integration handoff — 2026-11-05

This directory preserves byte-exact source-check receipts and integration provenance outside the Chain repository for the parent agent's later evidence-only publication. The child performed no remote writes. It does not claim native, cryptographic, deployment or activation acceptance.

## Fixed commits and execution attribution

| Role | Commit | Tree | Actual verification scope |
| --- | --- | --- | --- |
| Initial migration repair | `36f5d18a93834792025326cfb178415d78103e42` | `2721dbf2f3b58327b51d1d452d0504fa5427df75` | Earlier original-profile native M06 full package: 239 passed, 7 ignored; strict Clippy and workspace formatting passed. Historical receipts are retained in the repository. |
| Earlier integrated native source | `14fcbede085b414a9621aef3f288d2b1ca1839ae` | `64b1a7e4072eddac05604d4bb4b1ef713e10d874` | Earlier original-profile native M06 full package: 246 passed, 8 ignored; strict Clippy and workspace formatting passed. These results remain attached only to this exact source. |
| Fixed concurrent upstream | `dba49c2f66d8a72d6845c70958c4a24d6c4e7e89` | `25ae0d2035b763b916575292d04571e93a512dd1` | Exact metadata/tree and 21 incoming blobs imported and verified; all peer source preserved. |
| Local combined E218 | `e218ec649509e328eee4c7ef6021d96c647514ef` | `07add784b1e1be265ea0e4cc2fc4381a18c8e51f` | Corpus, distributed inventory, complete repository/link checks and 35 Python source-negative fixtures passed on this exact clean checkout. Native / strict Clippy / Rust formatting: NOT_RUN. |
| Published source S | `70df2c644ed8dd64afa1e7533743664cddacb9da` | `ef6eee36f4ac1cc823b29a2e499e2f2ef6b54855` | Corpus, distributed inventory and complete repository/link checks passed on this exact clean checkout. The 35 fixtures were not rerun on S. Native / strict Clippy / Rust formatting: NOT_RUN. |

S has ordered parents `160b6f91e39708454d1edd200ab9ef2b4192192e` and `14fcbede085b414a9621aef3f288d2b1ca1839ae`. S differs from E218 only in four peer evidence documents: three modifications and the added `v2-setup-followup.json`. Every other terminal Git blob and mode is identical. The exact raw diff and all four fetched-blob verification records are included. Source equivalence outside these documents does not relabel E218 execution as execution on S.

## Merge preservation

The E218 overlay has 49 changed paths: 45 own evidence files, the two migration Rust files, the existing plan and the existing corpus. All untouched concurrent terminal entries are preserved exactly. The plan adds only the original 1,234-byte note; removing it yields the current peer plan byte-for-byte. The corpus preserves current formatting/content and changes only the two migration source pins. The current README scopes newer peer source changes and marks native gates NOT_RUN. Historical native and research receipts are unchanged.

The research result of 230 tests remains attached to its original executed checkout and recorded 52-input equivalence, not to S or newer DAA source. The sibling CI result of 154 fixtures remains synthetic evidence with native execution count zero; it does not constitute hosted CI execution, current source native coverage or a release gate.

## Actual source commands

The following commands passed on both E218 and S; each exact source-before/source-after, elapsed time, command and raw output hash is in its own JSON receipt:

```sh
python3 -B scripts/ci/check_pq_research_integration.py
python3 -B scripts/refresh_distributed_source_inventory.py --check
python3 -B scripts/ci/check_repository.py
```

Only E218 executed the following fixture suite (35 passed, zero failed):

```sh
python3 -B -m unittest discover -s scripts/ci -p test_pq_research_integration.py -v
```

S repository checks covered 26 packages, 1,146 Rust files, 2,970 local links and 25 normal dependency edges. Its corpus checked 487 exact source blobs across six upstream heads and retained `HOLD_NO_GO`; cryptographic acceptance, whole native authorization migration, runtime activation and node activation remain false. Repository link checks establish source/document consistency, not the security claims of those documents.

## Complete-check time versus current disk state

All 9,817 tracked working copies were present during the three S checks; all three finished naturally before any reclamation. To support the concurrent runtime native build under severe shared disk pressure, the parent then authorized removing exactly the prior 213 historical evidence working copies. Every path was checked against S, the index, the prior reclamation list, its actual disk Git blob SHA and byte size before removal. All Git blobs, source and new evidence remain present. The 213 paths are now marked skip-worktree, and the current checkout is therefore not completely materialized although Git status is clean. The complete record is `published-source/working-copy-reclamation-after-checks.json`: 781,622,789 logical bytes / 781,922,304 allocated bytes reclaimed. A future complete repository check requires restoring these paths from their retained Git blobs and clearing their skip-worktree flags first.

## Layout and integrity

- `e218-source/`: original E218 receipts/logs, exact raw commits and the combined integration handoff.
- `published-source/`: original S receipts/logs, exact raw commit, source mapping and the later working-copy reclamation receipt.
- `provenance/`: exact commit metadata, source composition/materialization/overlay records, raw E218-to-S diff, 21 dba incoming-blob records and four S peer-blob records.
- `final-handoff.json`: final source, check scope and current materialization state.
- `index.json`: SHA-256 and byte count for every other file in this directory. The index intentionally excludes itself.

The full recursive tree metadata and raw blob payloads are not duplicated here: imported native Git objects retain them, and the provenance records bind the full input metadata hashes and each fetched blob. Overlay manifests retain the exact original scratch paths as provenance; payloads can be retrieved from the imported Git objects by their recorded IDs. No existing native/research receipt is rewritten or widened by this handoff.
