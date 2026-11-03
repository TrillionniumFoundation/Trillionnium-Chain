# Chain PQ hosted supplement — run 41704279631

This is a **partial captured observation**, not an all-matrix pass. The ARM64 HEAD control failure is retained. Whole-chain qualification remains **HOLD / UNQUALIFIED**.

Local capture time: **2026-11-03T20:46:45.592623+00:00**. This freezes the three supplied official artifacts as read for packaging; it is not a live statement about subsequent CI completion. No tests were run or rerun during packaging.

## Exact sources and observed results

[GitHub Actions run 41704279631](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41704279631) tested candidate `8a74a9e42a9efbc52d83e861f64f03efd40f1406`. The actual prospective merge is `6ab5906347c148ca2def1c0bb02a187ece51c77f`; both have recorded tree `3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7`. Head and prospective-merge identities remain distinct.

| Captured lane | Artifact ID | Controls | Complete Node suite | Build / strict Clippy exits |
| --- | ---: | --- | --- | --- |
| x64 HEAD | 13270005067 | 43 passed / 0 failed | 944 passed / 0 failed / 23 ignored; exit 0 | 0 / 0 |
| x64 prospective merge | 13267419961 | 43 passed / 0 failed | 944 passed / 0 failed / 23 ignored; exit 0 | 0 / 0 |
| ARM64 HEAD controls | 13267292698 | 42 passed / 1 failed | Not available in this capture | 0 / not captured |

The ARM64 HEAD failure is `store::pq_rollback_witness::tests::guarded_charge_pending_revocation_survive_service_cold_restart`, recorded by `native-11.json`, exit **101**. The original log reports `PQ_WITNESS_DEADLINE` at `store/pq_rollback_witness/tests.rs:225:14`. Complete `native-11.json` and `native-11.log` are retained under `arm64-head-controls/`. This package records the failure without assigning its cause; detailed diagnostic review is separate.

No complete ARM64 HEAD or ARM64 prospective-merge result is included. Missing results are not passes, and the x64 successes do not waive the ARM64 failure. Counts are per lane, not a total of unique tests. Earlier `45962558` evidence and its original failures remain separate and unchanged.

## Byte-preserving archive

- Archive: [`chain-pq-ci-run-41704279631-partial-members.tar.xz`](chain-pq-ci-run-41704279631-partial-members.tar.xz)
- Compressed bytes: **463,852**
- Archive SHA-256: `d0bd3218a2d46f793baded6f2954e902d9897054cfd0cb1dea7bf174e4ae7293`
- Original payload: **487 members / 23,402,793 bytes**.
- Total archive members: **490**, including three metadata copies.

All members of all three ZIPs are retained byte-exact under `x64-head/`, `x64-merge/` and `arm64-head-controls/`. Every archived member was read back and checked against its original length and SHA-256; no member is missing or extra. The source ZIP hashes were checked before and after packaging. The supplied [`summary.json`](summary.json) is copied without changing any byte or dropping fields.

**This TAR/XZ hash is not an original GitHub ZIP hash.** The archive preserves uncompressed member bytes; it does not reproduce the original ZIP container or its filesystem metadata. Original ZIP identities are:

| Namespace | Artifact ID | Original ZIP bytes | Original ZIP SHA-256 |
| --- | ---: | ---: | --- |
| x64-head | 13270005067 | 1,051,309 | `c5a29e38f1888d20355a03ec2f82d75ae7f0bf437ecedf8a063b838207cb13c2` |
| x64-merge | 13267419961 | 1,055,769 | `588f8c1897c29146ce7410b3140c457c13c3f33197a3eac639ff53aebb36b4c8` |
| arm64-head-controls | 13267292698 | 286,963 | `29fd8c8d770c6cf7b6dc2742a9c0c118ffc6479714e3a16bcd220c33c5a7d13d` |

[`source-artifacts.json`](source-artifacts.json) records original ZIP identities, source/run URLs, capture time and partial scope. [`member-manifest.json`](member-manifest.json) records every original path, archive path, byte count and SHA-256. `metadata/` contains exact copies of both manifests and the original summary.

The outer package has six files: this README, the archive, the two manifests, the original summary and [`SHA256SUMS`](SHA256SUMS). Verify the five non-checksum files with `sha256sum -c SHA256SUMS`. Packaging integrity is separate from native execution results and cryptographic qualification.
