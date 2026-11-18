# Complete original r20 business records

This is immutable evidence for source `119cbdc8b7060df28b74230fa9265ada7bc75541`, Actions run `44298913299`. Both x64 and arm64 genuinely executed the original 4-second, 0.25-CPU, 16-worker campaign. Their pressure confirmation target remains **0/1**; the attack-free baselines are 1/1. These records are not r21 measurements.

`119c-full-records.tar.xz` preserves 312 original artifact members (126,630,405 raw bytes) byte for byte. It contains every original JSON report, process receipt, stdout/stderr, error, cost/Host log, and failure/cancellation field. Twelve ELF executable files are omitted; their original names, sizes and SHA-256 remain in `119c-MEMBERS.json`, alongside both original GitHub ZIP digests and every retained member digest. The original complete ZIPs remain in the operator's earlier readback workspace; their digest identities do not depend on Actions retention.

The archive includes `x64/from-zero-native/confirmation/report.json` and the corresponding `arm64` path in full. `119c-ARCHIVE.json` binds this archive and its exact member index. Independent verification on the publishing host re-read and hashed every retained member before publication.

The r21 code candidate is the separate commit `27d6a4b19ff58de78f3f5804e44ccae41857c794`, tree `bba212bffc9debcdf4a3f82fef7e1516ba7c8593`. This evidence-only ref does not modify that candidate, its original campaign, its policy, or its outcome.
