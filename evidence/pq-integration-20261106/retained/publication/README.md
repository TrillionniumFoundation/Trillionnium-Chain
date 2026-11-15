# Chain PQ integration evidence — frozen pre-final snapshot

Candidate: `f85fea4e8da02404d513d074ceb35ad5292b017b`  
Tree: `0c1da9d2c13052b30af600e2a32a5eb286e985de`  
Captured: `2026-11-06T09:03:58.396546+00:00`

This package preserves historical failures, scoped repairs, actual TLS red reproduction,
source publication identities, and the final candidate's five locked/offline dependency
graphs plus 23 isolated material-verifier tests. It does **not** yet contain completed
f85 desktop native validation or the final f85 CI ledger. Those inputs are explicitly
pending in `collection-status.json`; no empty placeholder is a test result.

## Audit the content

`file-manifest.json` lists each copied file's bytes, SHA-256, category and original
location. `FILES.tsv` is the compact reviewable path list. All original receipts are
copied byte-for-byte, including failures, old absolute paths and old status snapshots.
The collection status records qualification boundaries and corrected interpretation
of historical drafts without rewriting them.

The 37-file desktop red, both local SIGKILL attempts, 74-file local-component record,
1230-file raw CI index, complete initial fresh-service reports, five-lock histories,
packaging/registry repairs, two preparation failures and the cancelled2e9 run remain
separate. Original job IDs, source identities, raw text and hashes remain available.
No counts across overlapping exact selectors/full suites are presented as unique tests.

## Verify the transport

The publication bundle uses deterministic PAX tar metadata, zstd compression and parts
of at most1.5MiB (1,572,864bytes). `archive-index.json` binds every part, the reassembled
archive and every inner member. The standalone verifier checks all hashes, sizes,
safe regular-file membership and coverage without extracting or executing evidence:

```sh
python3 verify_curated_evidence.py archive-index.json
```

The root should publish the parts, archive index, verification receipt and standalone
verifier. The assembled transport and expanded payload are working copies; avoid
publishing duplicate large transports or copied binary/source trees.

Final native/CI outcomes should be retained in an additive, independently indexed
supplement, then cited by the final report. This frozen snapshot must not be relabelled
as successful whole-chain PQ, production, WAN, independent custody or quantum-work
qualification.
