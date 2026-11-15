# Chain PR #909 — terminal CI evidence, byte containers V2

This revision changes evidence representation only. It preserves the exact original source index and review and all 55 underlying evidence artifacts. It does not change source, CI policy, failure classification, workflow state or any ref.

## Integration files

- `SOURCE_INDEX.json` is the unchanged original index: Git blob **5075184f6a4ef9db4ac9f47547b16f00b76ae2b1**, 125,072 bytes, SHA-256 **81a687ebf188e0e16e3e189d5e1e8ec32930b408ad9eaa5aa2d668597319fa67**.
- `SOURCE_REVIEW.md` is the unchanged original review: Git blob **1f7433264e41581affbbd636e1e19b1da7fb1cdb**, 7,736 bytes, SHA-256 **87798b80939b109f15d8c86232fc41ff0fbe7503795539f3a21a35ae5928f7f5**.
- `INDEX.json` is the authoritative V2 mapping from every original artifact to its direct file or ordered containers, together with byte verification results.
- `TREE_ENTRIES.json` is a Git tree-entry proposal for the 81 payload files, including this README and INDEX. The proposal intentionally excludes its own entry to avoid a content-hash cycle; its own blob can be added as one separate entry.

The original SOURCE documents remain historical records of V1. Their raw `.log` paths are logical original-artifact names, not a request to put those raw logs into the V2 tree. V2 supersedes only their storage/tree recommendation.

## Exact representation change

All **40 original logical log parts** are represented by base64 JSON containers. The original lengths, SHA-256 values, Git blob IDs and logical part identities are unchanged. A part larger than 350,000 bytes is split into ordered byte segments; a byte segment need not independently decode as UTF-8.

The byte inspection also found literal U+FEFF characters inside both serialized macOS 404 tool responses. Those two original artifacts are encoded in the same way. The remaining **10 original API JSON bodies and 3 tool-return serializations** contain no U+FEFF or line-end spaces/tabs and remain unchanged.

The result is:

| Representation | Files |
| --- | ---: |
| Base64 JSON containers for 40 log parts and 2 tool responses | 64 |
| Direct, unchanged API/tool artifacts | 13 |
| Unchanged SOURCE index and review | 2 |
| V2 INDEX and README | 2 |
| Total payload tree entries | 81 |

The 64 containers total **14,986,901 bytes**. The largest is **467,889 bytes**, below the requested 480,000-byte cap. All new containers are ASCII JSON with a final newline, without literal BOM characters or line-end spaces/tabs. No original byte was trimmed, normalized, dropped or replaced. The 15 unchanged direct files, including the two SOURCE documents, were also rechecked for these byte conditions.

This is a representation check, not an execution of the repository's whitespace gate or another CI run. No checker or allowlist changed.

## Reconstructing original bytes

1. Find an original artifact in `INDEX.json.original_artifacts`.
2. For a direct artifact, use the listed unchanged file and verify its length, SHA-256 and Git blob ID.
3. For a container-backed artifact, read its listed containers in segment order. Parse the JSON and base64-decode only the `base64` field.
4. Require every `segment.byte_start_in_original` to equal the previous exclusive end. Verify each segment's byte length, SHA-256 and Git blob ID, then concatenate without separators. Verify the reconstructed original artifact's length, SHA-256 and Git blob ID.
5. To reconstruct a whole job log, use the original logical part order in SOURCE_INDEX and concatenate the reconstructed parts without separators. Container metadata also records the exact range in the whole log. Verify the original whole-log length, SHA-256 and Git blob ID.

Git blob IDs use SHA-1 over `blob <byte length>\0` followed by the exact bytes. Base64 is storage only; decoding does not confer any new test or source qualification.

## Verification performed

Every one of the 64 serialized container JSON files was parsed and decoded again after construction. All segment hashes and contiguous ranges were checked. The reconstruction produced all **18 whole failed-job logs** and both encoded tool responses byte-for-byte equal to the retained originals; all 20 complete-object lengths, SHA-256 values and Git IDs matched.

All 42 encoded original artifacts were checked against their source-index hashes before encoding. The 15 direct files were checked against their original hashes. Every create_blob response matched the independently computed container Git ID. Three container objects, including a maximum-sized one and a BOM-bearing error original, were formally GET-read back and compared exactly; that sample is identified in INDEX. It is not described as a full remote readback of every object.

The decoded logs preserve their original BOMs, timestamps, ANSI characters, CR/LF bytes, meaningful whitespace and long JSON lines. They remain the exact decoded UTF-8 strings delivered by the GitHub connector; no claim is made about the redirect's ZIP or HTTP wire bytes.

## Source and result boundary, unchanged

PR head **e338c000f26e9357ed33213624da787a3a009ed9** has tree **876aa62d1ab49458d29e9168f4c69e7b47b8884b**. Actual prospective merge **bfa5cf58953a67dd9b9a27ce52b63524933a029d** has tree **4b08c77fd511466c8f2e5bc46307e0d6fd629063**, with base **c84162378f34b9284e90587df4c466dfee3e193b** and the head as parents.

| Original run | Terminal result |
| --- | --- |
| priority 43030977438 | failure; 7 failed / 6 succeeded / 1 skipped jobs |
| required-baseline 43030977601 | failure; 11 failed / 10 succeeded jobs |
| cleanup 43030977513 | failure; 6 succeeded / 2 cancelled jobs |

The detailed source-bound causes and unresolved details remain exactly as recorded in SOURCE_REVIEW. In particular, the merge-only NPQ6 runtime failure is not attributed to the successful head runtime job; repeated schema-hash errors and aggregation failures are not counted as independent root causes. Unavailable macOS logs and unexposed child/artifact details remain unknown.

No ordinary business closure, independent C adoption, ordinary NoUpdateRollback, whole-repository green result, new native test result or ref publication is asserted by this packaging revision.
