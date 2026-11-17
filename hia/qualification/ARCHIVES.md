# Complete evidence archives

Large final evidence archives use contiguous volumes. Each manifest binds every regular part, its exact offset and its SHA256, as well as the complete reconstructed archive. This changes storage only; source identities, failed observations and qualification scope remain unchanged.

All original archives were read back member by member. Each volume set was then physically reassembled and compared with the complete original bytes. The complete CI ZIP and its original independent binary remain inside the Application archive.

| Evidence | Manifest | Reconstructed bytes | SHA256 |
| --- | --- | ---: | --- |
| mempool-typed-development | [manifest](mempool-typed-development.parts/manifest.json) | 13481848 | `b6e7094c222029bd7aab426af8528720d35b288f8960675ef021341cd800750c` |
| execution-application-ci | [manifest](execution-application-ci.parts/manifest.json) | 35301924 | `3019de38c6f00a12de4e6276ffd70f1115d7345ea5082216972fbc07886b696b` |
| work-owner-development | [manifest](work-owner-development.parts/manifest.json) | 26328788 | `b5c82d8e2b2c1976ce8fa4399e637dd9cceea93d95d5cf9c29d4315d2ec759db` |

## Reconstruct

Run from the repository root. The commands create a private output directory, concatenate only the declared parts, and check the complete archive before use.

```bash
trnm_evidence_dir=$(mktemp -d)
cat hia/qualification/mempool-typed-development.parts/part-000 hia/qualification/mempool-typed-development.parts/part-001 hia/qualification/mempool-typed-development.parts/part-002 > "$trnm_evidence_dir/mempool-typed-development.tar.xz"
printf '%s  %s\n' 'b6e7094c222029bd7aab426af8528720d35b288f8960675ef021341cd800750c' "$trnm_evidence_dir/mempool-typed-development.tar.xz" | sha256sum --check
cat hia/qualification/execution-application-ci.parts/part-000 hia/qualification/execution-application-ci.parts/part-001 hia/qualification/execution-application-ci.parts/part-002 hia/qualification/execution-application-ci.parts/part-003 hia/qualification/execution-application-ci.parts/part-004 hia/qualification/execution-application-ci.parts/part-005 > "$trnm_evidence_dir/execution-application-ci.tar.xz"
printf '%s  %s\n' '3019de38c6f00a12de4e6276ffd70f1115d7345ea5082216972fbc07886b696b' "$trnm_evidence_dir/execution-application-ci.tar.xz" | sha256sum --check
cat hia/qualification/work-owner-development.parts/part-000 hia/qualification/work-owner-development.parts/part-001 hia/qualification/work-owner-development.parts/part-002 hia/qualification/work-owner-development.parts/part-003 hia/qualification/work-owner-development.parts/part-004 > "$trnm_evidence_dir/work-owner-development.tar.xz"
printf '%s  %s\n' 'b5c82d8e2b2c1976ce8fa4399e637dd9cceea93d95d5cf9c29d4315d2ec759db' "$trnm_evidence_dir/work-owner-development.tar.xz" | sha256sum --check
```

The original archive formats and embedded indexes are unchanged. A successful archive reconstruction does not qualify a new source commit, close any runtime gate, or execute an original test again.
