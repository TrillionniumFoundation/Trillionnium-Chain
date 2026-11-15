# Sealed publication material review — 819309fd

No identifiable real GitHub token, unredacted Authorization credential, active
presigned download URL, or private-key marker/literal was found in this fixed
publication scope. This is an evidence-publication audit; original business gates
remain HOLD.

The sole actual scanner job 1a1b7feb04e-12894-cf2 completed successfully with
exit 0, no timeout/cancellation, and complete durable output at
2026-11-07 22:04:46 UTC. The preparation/readback failures are retained separately.

## Actual scope

| Package | Outer files | Outer bytes |
| --- | ---: | ---: |
| core-14-package-v1 | 812 | 309,985,457 |
| w1-components-metadata-package-v1 | 402 | 18,307,518 |
| w1-components-transport-v2-package | 152 | 16,697,336 |
| w1-range-v3-package | 56 | 6,660,441 |

All 1,422 outer files, 17,854 archive members, and 53 decoded gzip streams were
read, including original core ZIP contents and raw binary/SQLite bytes.
The combined byte-stream count was 19,329 and the scanned byte total was
3,365,225,860. There were no skipped streams, read/hash errors or package changes.
All payload manifest hashes and all four SHA256SUMS/SEAL pairs matched.

## Classification

There were 284 pattern matches. The 280 Cargo metadata URL matches were
unresolved URL templates, 14 in each of 20 retained cargo-graph files.
Classification of the exact preexisting match offsets found no userinfo or
credential/signature query parameter in those URLs.

The other four matches are two public synthetic URL/Authorization inputs in each
of the two Range reader test variants. All four are static AST constants in
test_signed_url_is_not_retained_in_diagnostics, supplied to the sanitizer and
checked with assertNotIn. No matched credential value is printed in this review.

Independent source inspection distinguishes public deterministic development
signing fixtures and serialized protocol Cookie values from the private,
per-instance random server HMAC secret. The examined original report writers do
not emit that secret.

## Retained records

- [Core conclusion and counts](REVIEW_CORE.json)
- [Original scanner result](scan-result.json)
- [Complete stream inventory](scanned-stream-inventory.json)
- [Synthetic response-control classification](candidate-classification.json)
- [Exact template-URL classification](template-url-classification.json)
- [Fixed-source writer classification](SOURCE_CLASSIFICATION.json)
- [Preparation and readback failures](PREPARATION.json)
- [Actual scanner source](scanner.py)
- [Durable job logs and exit records](jobs/)

Pattern matching and the examined writers cannot prove that arbitrary unlabeled
high-entropy bytes are nonsecret. No online credential/URL validity test was
performed. Large W1 ZIPs retained outside these four Git publication packages are
outside this review scope. Frozen packages were not edited; no download, CI/native
rerun, or GitHub write was performed.
