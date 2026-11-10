# Strict Clippy succession for the bounded-input repair

The functional Python repair was executed at `8d4c915939f2ae7659e254ec3475d2dadb919f2a`. Its original 34-test
suite, 43 source-integrity tests, real FIFO comparison and other original checks
remain in [the original packet](../pon-dynamic-input-bound-20261110-685a/README.md).

The new strict Clippy execution is bound only to `da002c3227e92d625a73b26706420fab32cdf2d8`, tree `4e205ea8d4a1a9f30f7bcaa81272b33c42dbaca9`.
The later commit carrying this packet is an evidence commit; it does not receive
a new execution claim. All 1,638 Rust/Cargo paths have matching modes and Git
blob identities between the functional source and this tested evidence head.

## Actual succession

| Observation | Actual result | Execution scope |
| --- | --- | --- |
| Original 120-second strict Clippy | Exit 124, not passed | `8d4c915939f2ae7659e254ec3475d2dadb919f2a`; original packet retained |
| First extended attempt | Source recorder refused; Cargo never started | `index-refusal/`; hidden index flags and the collector's subsequent KeyError are preserved |
| Fully materialized extended attempt | Exit 101, not passed | `default-system-provider/`; selected OpenSSL 3.0.13 exposes no `ossl350` API |
| Original provider download | Cancelled with exit -15 while downloading | `interrupted-provider-download/`; unfinished original records remain unfinished |
| Official source acquisition | Complete archive SHA256 matches the fixed pin | `source-acquisition/`; 51 HTTP byte-range responses, full lengths and digests |
| Original provider preparation with local archive | Exit 0 and real ML-DSA-65 sign/verify/wrong-message rejection | `pinned-provider-run/ci-observations/pq-provider/` |
| Same workspace/all-target/all-feature strict Clippy | Exit 0, passed | `pinned-provider-run/checks/strict-clippy-pinned-1800s.json` |

The original recorder checked all 26,266 tracked entries and 2,503,223,251 raw
bytes before and after the new native commands. The strict Cargo arguments are
unchanged from the extended failing attempt, including locked/offline,
workspace, all targets, all features and `-D warnings`. The hard command budget
is 1,800 seconds and `CARGO_BUILD_JOBS=2`. No Rust source, Cargo file, feature set,
warning level or algorithm was changed to obtain this result.

## Materialization and dependency identity

The initial source refusal identified 14 absent tracked archives with skip-worktree
flags. Only this task's worktree was restored from its existing HEAD using
`git sparse-checkout disable`. The exact original flags, 500,852,393 missing
committed bytes, Git objects and resulting zero hidden flags are retained.
The original source verifier remained unchanged and subsequently verified the
complete materialized source before and after execution.

The default environment selected OpenSSL 3.0.13 headers and `ossl300`; the failed
PQ test compilation requires the existing `ossl350`-gated API. The repository's
unchanged `prepare_pq_provider.sh` fixes OpenSSL 3.5.9 and source archive SHA256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
Its supported `TRNM_PQ_SOURCE_ARCHIVE` input avoids another download while still
performing a fresh digest check, static build, installation and positive/negative
ML-DSA-65 smoke checks. All five installed backend input fingerprints were checked
again after Clippy. The exported seven-field provider environment is retained.

The source archive, range bodies, build/install trees, test private keys and raw
redirect headers are outside this observation packet. Per-range status, lengths,
digest and complete stdout/stderr, the complete archive digest, provider receipt
and complete build/smoke log are retained (the latter as lossless gzip). Public-asset redirect headers and the
unrelated denied-directory names from the dependency search remain only in the
operator state; their exclusion is explicit. No private smoke key is published.

## Lossless log transport and publication refusal

The first publication attempt stopped before commit because the unchanged
`git diff --cached --check` reported five trailing-space lines in the original
OpenSSL build output. The actual exit-2 diagnostic and outer exit-1 terminal are
retained under `publication-history/whitespace-rejection-08/`.

`raw-log-transport.json` maps every affected original logical path and original
operator path to its actual `.gz` member. It binds the original byte count and
SHA256, stored byte count and SHA256, encoding, and successful full decompression
comparison. The original build log and the diagnostic quoting those five lines
are deterministically compressed with timestamp zero and no embedded filename.
Their decoded bytes match the original raw files still retained in operator state.
Original command fields and execution receipts are unchanged. The finite packet
manifest lists the actual compressed members; the transport map explains the two
original logical paths, so neither is an unexplained missing observation.

The standard whitespace gate and staged/push project preflights run again on this
explicit successor. No lint, feature, assertion or whitespace rule is suppressed.

## Limits

This closes the requested local strict Clippy gate under the recorded dependency
environment. It is neither a native test-suite run nor a release decision. The
provider helper did not execute the complete upstream OpenSSL suite and does not
establish an independent cryptographic implementation. CP/CG/CQ, six-confirmation
risk, model efficacy, work-cost lower bounds and whole-chain security are not
established. Whole-chain qualification and production activation remain false.

The packet manifest binds the finite set of published observation bytes; it is
not an external execution attestation. Its local `.gitattributes` preserves raw
bytes by disabling line-ending conversion. Earlier failures, cancellation,
initial log-publication omission and the corrected GitHub CLI body-update failure
remain visible in the two packets and Git history.
