# PQ quorum preflight and root-family observations

Status: **component evidence / HOLD**. This work continues the existing PQ
candidate at `12e510b211110d93d9ead07e02c07a1eecc28ae9` (tree
`a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f`). The final source validation
receipt identifies the committed successor; precommit observations below keep
their explicit file identities and are not relabelled as committed-source runs.

See the [authority review](../../docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md)
and the [single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Release regression

The original production kernel with the nine new regression tests returned
**3 passed / 6 failed**. The fixed kernel returned **9 passed / 0 failed**.
The red cases expose the original interleaving of structural checks and
signature mathematics. They are preserved as expected failure observations,
not counted as passing verification gates. The green checks also retain
extra-signature refusal, complete state equality on refusal, root retirement,
historical recovery, current generation checks and expiry.

The cache test reaches its missing-entry red assertion first. Its remaining
key-ID and SPKI mismatch cases run in the green loop; this is not three
independent red observations. Formatting is the only test-source difference
between the recorded red and green overlays. No primitive-call counter was
added; the ordering claim uses the source control flow and observed errors.

- [Baseline compilation receipt](baseline-build/receipt.json): compilation only.
- [Red receipt](quorum-red/receipt.json) and [original output](quorum-red/stdout.log).
- [Green receipt](quorum-green/receipt.json) and [actual output](quorum-green/stdout.log).
- [Provider verification](baseline-build/provider-verified.json).

An initial green launch had an unknown local outcome. The remote job directory
and systemd unit were absent, and the original kernel was still unchanged.
The exact same idempotency key did not launch a duplicate. A guarded recovery
used a create-only output directory before any mutation. That infrastructure
observation is retained separately from the successful test result.

## Independent fuzz graph repair

The first complete CI contract check refused the new normal dependency because
the independent fuzz lock still omitted the edge from `trnm-release-bundle`
to `trnm-protocol`. The [original refusal](source-integration-initial-failure/ci-contract.stderr.log)
is retained. An offline metadata resolution added exactly that one local edge;
the complete parsed package lists, versions and all other lock fields were
unchanged. The primary workspace lock is unchanged. See the
[repair receipt](fuzz-dependency-repair/receipt.json) and
[one-line lock diff](fuzz-dependency-repair/lock.diff).
The [non-test library precheck](non-test-library-precheck/receipt.json) also
passed; final committed-source validation remains separately identified.

## Root-family experiment

The [frozen harness](../../formal/pon-nakamoto-v1/pq_root_quorum_research.py)
and its [18 codec/policy tests](../../formal/pon-nakamoto-v1/test_pq_root_quorum_research.py)
use a trusted fixed AND policy. The ML-only component has a separate frame and
always returns `hybrid_policy_satisfied=false`; it cannot grant the combined
policy even after relabelling its frame. All keys are explicitly public,
deterministic test fixtures. Temporary private key files were not archived.

The real OpenSSL 3.5.9 run completed **64 distinct proposals**, **128 paired
observations**, **9 legal subset combinations**, and **12 refusal controls**.
There were **877 native commands**: 429 signing and 435 verification calls,
plus version/key-generation/public-export commands. The three signature
rejections are expected controls, not tool failures. Total run time was
324.237 seconds.

| Path, 64 observations each | Stage | Median ms | Empirical p95 ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-87 component | Sign and encode | 20.468 | 25.184 | 400.484 |
| ML-DSA-87 component | Verify complete component frame | 16.539 | 20.398 | 52.994 |
| ML-DSA-87 component | Combined | 37.429 | 47.128 | 414.864 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Sign and encode | 4,120.412 | 4,643.601 | 5,161.910 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Verify complete AND frame | 36.787 | 72.509 | 301.864 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Combined | 4,160.439 | 4,682.190 | 5,204.239 |

The common proposal is **846 bytes**. The component frame is **15,484 bytes**,
and the complete AND frame is **75,378 bytes**. The trusted full 3+3 roster and
configuration is **8,717 bytes**, encoded separately. The frame includes
selected signer SPKIs and signatures, but excludes prior distribution of the
complete configuration. The approximately four-second combined cost is
dominated by signing/encoding, not verification.

- [Complete result and scope](root-quorum-research/result.json).
- [Independent consistency/statistical readback](root-quorum-research/analysis-receipt.json).
- [Raw observations, gzip](root-quorum-research/observations.jsonl.gz).
- [Every native command record, gzip](root-quorum-research/commands.jsonl.gz).
- [Artifact hashes](artifact-index.json).

Compression preserves the exact JSONL bytes. The raw observation SHA-256 is
`2868b1bdd190988ed13c5312bd9e68d5ab77e1c66aadc30e6653e88a71011dac`;
the raw command SHA-256 is
`b86e8409e6bea29d12a7f359c31eba7e42fe19ef985be6c2199fa5f1c853b878`.
No samples or outliers were removed. Statistics use ordinary median and
nearest-rank p95. Stage medians need not sum to the median of total duration.

These are command-cold observations on a shared, non-isolated Linux host,
including process startup, key import, temporary file IO and command-record
flushing. Cargo validation may overlap. Runtime limits were requested
(100% CPU quota, 2 GiB, nice 5, 1800 seconds), but the post-exit systemd query
cannot prove their historical enforcement. They are not reserved resources,
host attestation, warm-EVP measurements, production throughput or production
tail guarantees.

## Qualification boundary

The fixed research verifier is not connected to a production root owner.
Current views are independent fixture snapshots, not durable root transitions
or anti-rollback enforcement. This experiment does not measure configuration
distribution, independent custody, WAL, network, deployment or a complete
key-management lifecycle. No deployed keys, protected main, services or
activation state were changed. All production, whole-chain PQ, physical
rollback and cross-repository Hepta final-use claims retain their original HOLD.
