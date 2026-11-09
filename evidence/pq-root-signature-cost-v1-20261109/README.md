# PQ root signature cost observations — 2026-11-09

**Qualification: HOLD.** This evidence records a bounded change to reuse successfully expanded ML-DSA-87 public verification keys, continued full signature verification, and a local observation of the V3 root cryptography APIs. The original frozen campaign completed **29 top-level commands: 25 exited zero and 4 failed**. Its successful component observations remain usable within their stated scope; the campaign did not pass as a whole.

The retained object contains public verification material. Every successful quorum call still requires all four signatures, and attempted calls retain the original verification-budget reservation. This record establishes neither production activation nor whole-chain post-quantum security. The original results, later source publication, inventory correction, and serial follow-up have distinct identities below. The subsequent corrected-source serial follow-up completed 20/20 selected commands successfully while preserving the original failures.

## Source identities

| Role | Commit | Complete Git tree | What was observed |
| --- | --- | --- | --- |
| Original local execution | `c9fb3fa61e2aadbdeaf39e85a7e21604d72581b7` | `704b67dc07f94e1770452f154d72c002b5ac1af0` | The original 29-command campaign and every cost sample in this record executed against this source. |
| Published source | `5840295dd0442804e80449ec7eb4b74dc3e68a3b` | `704b67dc07f94e1770452f154d72c002b5ac1af0` | Published through the connected GitHub API. The complete tree and all 15 published source blob IDs matched the local source; commit metadata differed. This commit was not separately executed in the original campaign. |
| Inventory correction and follow-up source | `d239bc8f683da7cdc8a4b9dc8e763d67e74680f6` | `37032e79799b9b21acc5b7f4ed1d74cc6bf97185` | Child of the published source. Two paths changed to include the cost example in the native source inventory and update that inventory's corpus blob pin. The serial follow-up uses this source. |

The two correction paths are:

- `trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs`
- `config/pon/pq-cross-branch-corpus-v1.json`

The cryptographic implementation and the cost example have identical bytes across these source versions. The inventory correction changes the complete tree, so the original campaign and its performance observations retain the original `c9fb3fa6` execution identity. No result is relabeled as an execution of a later commit. The correction addresses the hosted source-inventory rejection retained in [hosted-source-ci.tar.gz](hosted-source-ci.tar.gz).

[source-publication.json](source-publication.json) records the original publication, tree comparison, draft [PR #839](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/839), and bundle identity. [source-c9fb3fa6.bundle](source-c9fb3fa6.bundle) preserves the original local commit; it has prerequisite commit `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0` and is not a standalone clone of the whole repository.

The `source_patch.path` in the publication record names the `source-c9fb3fa6.patch` member inside `setup-and-provenance.tar.gz`; it is not an additional top-level file. The source bundle is also provided directly for convenient import.

The original source checks before and after execution matched **11,775 tracked entries and 1,120,494,956 tracked bytes**. These are endpoint consistency checks. They do not establish continuously enforced source immutability or independently authenticated execution.

The existing Cell PQ release path already retains ML-DSA-65 verification keys and separates manifest/chunk verification from root authorization. This change reuses expansion within the root cryptographic component; it does not remove a root-quorum operation from a previously measured Cell hot path. See the [cost boundary document](../../docs/security/PQ_ROOT_SIGNATURE_COST_V1.md).

At 2026-11-09 14:33:04 UTC, all four corrected-source hosted source/inventory steps had completed successfully (head and prospective merge, x64 and arm64). The complete jobs remained in progress. That readback is retained separately; the new root cost example was not part of the existing hosted cost workflow.

## Retained artifacts

| Artifact | Contents and purpose |
| --- | --- |
| [campaign-summary.json](campaign-summary.json) | Original command results, source identity, and explicit HOLD and qualification fields. |
| [raw-campaign.tar.gz](raw-campaign.tar.gz) | Original `frozen-campaign-c9fb3fa6/` records, stdout/stderr, nested native-suite logs and summaries, source endpoints, environment, dependency graph, raw cost JSONL, and binary identity. Successful and failed records are retained together. |
| [setup-and-provenance.tar.gz](setup-and-provenance.tar.gz) | Retained toolchain/provider setup receipts, provenance inputs, resource observations, and available setup logs. The inventory and manifest specify the actual retained files. |
| [hosted-source-ci.tar.gz](hosted-source-ci.tar.gz) | Retained hosted CI observations of the source-inventory rejection. This is separate from the local campaign and its compiler failures. |
| [source-publication.json](source-publication.json) | Local-to-published source mapping and explicit limits of that mapping. |
| [hosted-correction-source-gates.json](hosted-correction-source-gates.json) | Actual successful source/inventory steps on the corrected head and prospective merge for x64 and arm64; complete jobs were still in progress at the recorded snapshot. |
| [failure-ledger.json](failure-ledger.json) | Earlier setup, development, execution-environment and publication observations, including failures for which no local raw stream was retained. Such observations are not reconstructed logs. |
| [cost-analysis.json](cost-analysis.json) | Independent parsing and arithmetic for the original completed cost command, including every measured timing, byte checks, budget totals, and qualification limits. |
| [cost_analysis.py](cost_analysis.py) | Standard-library Python parser used to produce that analysis. It does not execute the benchmark or independently verify native signatures. |
| [followup-summary.json](followup-summary.json) | Separately recorded serial follow-up at `d239bc8f`, preserving the original failed observations. |
| [raw-followup.tar.gz](raw-followup.tar.gz) | Follow-up command logs, source endpoints, source delta, environment, and result records. |
| [source-c9fb3fa6.bundle](source-c9fb3fa6.bundle) | Original locally executed source commit, with the prerequisite noted above. |
| [run_frozen_campaign.py](run_frozen_campaign.py), [run_serial_followup.py](run_serial_followup.py), [assemble_evidence.py](assemble_evidence.py) | Retained orchestration and packaging source. Paths describe the original workspace; these are execution records rather than a claim of portable unattended reproduction. |
| [assembly-observations.json](assembly-observations.json) | Retained initial packaging rejection: identical members were ordered differently when recompressed. The corrected assembler reuses frozen archive bytes and verifies their members. No source/test result changed and the failed attempt was not published. |
| [manifest.json](manifest.json) | Exact file and archive-member byte lengths and SHA-256 digests. The manifest excludes its own hash. |
| [verify_evidence.py](verify_evidence.py) | Checks listed file bytes, archive membership and member bytes without extracting or executing archive content. It verifies retained byte integrity, not independent execution authenticity. |

## Original campaign: 25 of 29 commands exited zero

The original run used Rust/Cargo **1.95.0**, the locked dependency graph, pinned OpenSSL **3.5.9**, `CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, and `RUST_TEST_THREADS=1`. Cargo profile optimization and debug settings were unchanged. The native and control lanes ran concurrently, with commands serial within each lane. The cost command ran only after both lanes had finished. Host load was not controlled.

The following four top-level commands failed. All four retained `timed_out=false` at the outer campaign-command level; the journal failure was an inner signing-subprocess timeout.

| Original command | Exit | Observed failure and scope |
| --- | --- | --- |
| `native-v3` | `1` | The `root-owner` child compilation exited `101` after the `trnm-pon-node` compiler process received signal 9 (`SIGKILL`). The owner tests did not execute. Earlier V3 component suites completed as listed below. |
| `native-v4` | `1` | The recovery-floor, provider-readback, and callback-budget child builds each exited `101` with a compiler `SIGKILL`. Their native V4 tests did not execute. |
| `v2-native-journal` | `1` | The 14-test suite ended with one error. An OpenSSL `pkeyutl` SLH-DSA-SHA2-256s signing subprocess exceeded its existing **15-second cap**, and `BackendError` propagated. This was not an invalid-signature verdict. |
| `strict-workspace-clippy` | `101` | Compilation of the `trnm-pon-node` library test target under Clippy received `SIGKILL`. This is not an observed lint diagnostic and does not constitute a strict-Clippy pass. |

The source of the compiler kills is not established. The retained evidence does not identify OOM or any other particular actor as the cause. The journal's environment cause is likewise unestablished. Original failures remain in the record regardless of follow-up outcomes. See the raw command streams and nested `native-v3/` and `native-v4/` records in [raw-campaign.tar.gz](raw-campaign.tar.gz), together with [failure-ledger.json](failure-ledger.json).

### Completed test suites

These are individual observed suite results, **not a sum of independent tests**. Selectors can overlap broader library runs; in particular, the ten V3 structure tests are included in the default crypto library run.

| Original suite or selector | Observed result | Raw record within `frozen-campaign-c9fb3fa6/` |
| --- | --- | --- |
| Default `trnm-crypto-primitives` library | 175 passed, 0 failed, 0 ignored | `default-crypto.stdout` |
| Default `trnm-release-bundle` library | 43 passed, 0 failed, 0 ignored | `default-release.stdout` |
| V3 crypto structure selector | 10 passed | `native-v3/crypto-structure.log` |
| V3 native crypto integration suite | 9 passed | `native-v3/crypto-native.log` |
| V3 retained-key selector | 3 passed | `native-v3/crypto-cached-keys.log` |
| V3 root kernel selector | 12 passed | `native-v3/root-kernel.log` |
| V2 native signatures | 14 tests, terminal `OK` | `v2-native-signatures.stderr` |
| V2 native effect readback | 6 tests, terminal `OK` | `v2-native-readback.stderr` |

The successful native suites include real dual-family signatures, exact suite/OID checks, changed-message and changed-signature rejection, continued full-quorum verification with a retained roster, and original budget accounting. Preflight, format, dependency metadata, corpus, claim guard, source-integrity, repository/link, CI-contract, custody and migration control commands also exited zero; exact commands and streams are retained in the campaign records. Passing controls are not evidence that custody, migration or whole-chain deployment is complete. The original campaign did not execute every workspace test or a complete protocol lane.

Earlier development builds encountered `ENOSPC` before tests or the example ran. Their tool-observed failures are retained in the failure ledger, which explicitly states that their raw local stdout/stderr files are unavailable. They are separate from the frozen campaign's `SIGKILL` and timeout observations.

## Local root-cryptography cost observation

### Method and scope

The cost example executed normally with exit `0` on **`c9fb3fa6`**, emitted **41 complete JSONL rows**, and ended with the unique checked `complete` marker. The loaded runtime reported **`OpenSSL 3.5.9 29 Sep 2026`**. The release executable had `debug_assertions=false`. The cost command took **70.388480022 seconds including release compilation**; that command duration is not a signature-verification latency.

One ephemeral public fixture was repeated. It contains current and successor rosters of three ML-DSA-87 keys and three SLH-DSA-SHA2-256s keys each. Fixture signatures were generated and self-checked using real OpenSSL APIs. ML-DSA-87 acceptance in the V3 API uses its RustCrypto verifier; the SLH-DSA path uses its native OpenSSL verifier. Private key handles were discarded before sampling, and no private key material was emitted.

The **16,360-byte synthetic statement** contains the two complete encoded public rosters, length framing, and the explicit observation namespace `TRNM/Observation/RootV3CostStatement/v1\0`. It is not a serialized owner action or an owner-authorized request. The resulting approval message is **16,392 bytes**. Pure signatures use an empty FIPS context and the versioned domain in the exact application message.

The measured sequence was one warmup for A, one warmup for B, then **8 ABBA blocks**, yielding **16 measured samples per arm**:

- **A — fresh roster decode and full quorum:** decode a new roster for each call, then verify all four approval signatures.
- **B — retained roster and full quorum:** reuse the roster previously verified during warmup, then verify all four approval signatures again.

Both arms use the same message and signature bytes. Each call receives a fresh four-attempt budget, and the returned signer identities and charged counters are checked. Only successfully expanded public ML-DSA-87 verification material is reused; authorization, message acceptance and signature acceptance are not cached. Budget construction, JSON output serialization and roster destruction are outside the timed intervals. Fixture creation, key generation, signing and native self-checks are reported separately; their recorded setup duration was **7.449734346 seconds**.

### Observed timing distributions

All table values are milliseconds. Medians are the arithmetic mean of the two central observations in each 16-value sorted arm. Raw nanosecond values remain in [cost-analysis.json](cost-analysis.json) and the original JSONL.

| Metric | Fresh A, 16 samples | Retained B, 16 samples |
| --- | ---: | ---: |
| Operation minimum | 2.355533 | 2.067234 |
| Operation median | 2.894356 | 2.311466 |
| Operation maximum | 3.641617 | **4.362337** |
| Full quorum verification minimum | 2.332568 | 2.067116 |
| Full quorum verification median | 2.873417 | 2.3113335 |
| Full quorum verification maximum | 3.615548 | **4.362179** |

The retained-arm operation median was **20.14% lower** in this observation; its verification-only median was **19.56% lower**. These are descriptive ratios of per-arm medians. The retained arm had a **higher observed maximum** on both metrics. This record therefore establishes no tail improvement, population speedup, p99 bound, throughput gain or old-code-versus-new-code performance effect.

The host was shared and uncontrolled; the recorded load averages immediately before the cost command were approximately **12.11 / 19.37 / 22.55**. ABBA ordering limits some order imbalance but does not make the host controlled, supply independent fixtures, or establish a statistical population result. These timings do not measure Cell reads, owner history replay, external effects, network operation or complete transition latency. No performance acceptance threshold was defined.

### One combined API observation

Separate from the ABBA samples, one invocation sequence used a single shared ten-attempt budget:

| Stage | Observed API wall time | Cumulative reserved verifications | Cumulative charged input bytes |
| --- | ---: | ---: | ---: |
| Four current approval signatures | 3.934803 ms | 4 | 93,638 |
| Six successor possession signatures | 12.684951 ms | 10 | 305,127 |

The current roster was already verified during ABBA; the successor roster had not previously been verified by the V3 API. These are two stage timings from **one** combined mathematical-API observation, with no distribution claim. They omit the owner lifecycle and external-effect pipeline. Their sum must not be reported as complete owner-transition latency. The final counter is ten attempts, not four plus ten independent attempts.

## Signature bytes, public encoding and budget charges

### Actual public fixture bytes

| Material | Bytes | Interpretation |
| --- | ---: | --- |
| One ML-DSA-87 raw public key / raw signature | 2,592 / 4,627 | Standard algorithm sizes. |
| One SLH-DSA-SHA2-256s raw public key / raw signature | 64 / 29,792 | Standard algorithm sizes. |
| Four current approval signatures | **68,838** | `2 × 4,627 + 2 × 29,792`; raw signature bytes only. |
| Six successor possession signatures | **103,257** | `3 × 4,627 + 3 × 29,792`; all six successor keys prove possession. |
| Both groups of raw signatures | **172,095** | Ten raw signatures; not a complete owner-transition frame. |
| SPKI bytes per roster | 8,088 | `3 × 2,614 + 3 × 82`; actual DER-encoded public keys. |
| Encoded current roster | 8,152 | Public keys plus this protocol's roster encoding. |
| Encoded successor roster | 8,152 | Same roster encoding size. |
| Synthetic statement | 16,360 | Observation namespace, length framing, and both encoded rosters. |
| Approval message | 16,392 | Exact framed message used by the quorum API. |
| Successor possession messages | 16,564 each for three; 16,572 each for three | Exact six message lengths, retained individually in the analysis. |
| Complete owner-transition frame | Unknown / unmeasured | No complete frame-size claim follows from the signature sums. |

### Original API reservation counters

The existing budget deliberately reserves conservative input charges. These are not measured network bytes, allocation totals, actual hash-call counts or a lifetime quantum-adversary query bound.

| Scope | Reserved verifications | Charged input bytes |
| --- | ---: | ---: |
| Every full quorum invocation | 4 | 93,638 |
| All 32 measured ABBA calls | 128 | 2,996,416 |
| Two warmup calls | 8 | 187,276 |
| One combined invocation sequence, final cumulative count | 10 | 305,127 |
| All V3 API calls above | 146 | 3,488,819 |

The quorum charge is `16,392 + 8,152 + 4 × 64 + 68,838 = 93,638`. The successor stage adds the existing conservative reservation `(16,360 + 256) × 6 + 8,152 + 6 × 64 + 103,257 = 211,489`, producing the combined cumulative **305,127**. The ten setup signatures and ten native fixture self-checks are setup operations reported separately; they are not included in these V3 API budget totals. No budget was skipped or reset to obtain the retained-roster observations.

## Independent readback and byte integrity

[cost_analysis.py](cost_analysis.py) independently re-read the finished original command. It checked strict JSON and event order, the unique terminal marker, 8 ABBA blocks, 16 samples per arm, separate warmups, signer IDs, exact DER/OID and roster framing, public lengths and hashes, original budget formulas, and all reported statistics. It also checked the cost command's exit status, source endpoints, stream digests and binary record. It retains the overall campaign failure rather than requiring or implying that every command passed.

The locally retained post-command executable was separately rehashed:

- Executable: **8,311,072 bytes**, SHA-256 `fe253686880f8f6ddaede9328b47d619cf36aaf12c8f09c0f140c004d325b99e`.
- Cost stdout: **470,753 bytes**, SHA-256 `55223b204dbcc990255e7db48bc0e0e279ed12933c65d66d3ecc10d903e00007`.

The parser validates reported outcomes and arithmetic; it does **not** independently perform native signature verification. The executable digest identifies the local post-command bytes; it is not an independently authenticated proof that a particular executor ran them. The package manifest and archive digests provide retention and integrity checks, not execution attestation or FIPS 140 validation.

With the complete evidence directory present, run `python3 verify_evidence.py` to check its listed bytes and archive membership. The checker reports byte integrity only. To recompute arithmetic after extracting the original campaign into a separate working directory, use `python3 cost_analysis.py --campaign <path-to-frozen-campaign-c9fb3fa6> --out <new-analysis-path>`. The optional `--binary <path>` additionally checks a separately retained matching executable; the recorded analysis used that option. Keep regenerated output outside the evidence directory so the original records and exact file inventory remain unchanged.

## Separate serial follow-up

The follow-up uses source **`d239bc8f683da7cdc8a4b9dc8e763d67e74680f6`**, `CARGO_BUILD_JOBS=1`, and **all commands serial**. Original profile optimization/debug settings and the original test and signing-subprocess timeouts remain unchanged. Its source delta is the two-path inventory correction above. It records its own source endpoints and environment; it does not replace the original failures or relabel the original cost data.

The completed [followup-summary.json](followup-summary.json) records **20/20 executed commands passing**, zero commands skipped, and matching complete source endpoints. [raw-followup.tar.gz](raw-followup.tar.gz) retains every corresponding log. This is a separate successful follow-up on the corrected source; the original campaign remains 25/29 with its four failed observations.

| Follow-up scope | Actual result |
| --- | --- |
| Inventory, corpus, claim, dependency, formatting, source integrity and repository/link gates | All selected commands exit 0 |
| Crypto library strict Clippy, all targets and features | Exit 0 with `-D warnings` |
| Whole-workspace strict Clippy, all targets and features | Exit 0 with `-D warnings` |
| Complete V2 native journal suite | 14 tests, terminal `OK` |
| V3 native root owner suite | 20 passed, 0 failed or ignored |
| V4 native recovery floor suite | 8 passed, 0 failed or ignored |
| V4 native provider readback suite | 12 passed, 0 failed or ignored |
| V4 native callback budget suite | 6 passed, 0 failed or ignored |

No test timeout, cryptographic budget, profile optimization or debug setting was relaxed. One build job and serial execution describe the follow-up conditions; they do not retrospectively establish the cause of earlier compiler kills. This task also reclaimed five reproducible, already-completed debug test executables to recover temporary capacity before the remaining Node build. Source, libraries, raw logs and the measured release executable were retained; the exact cleanup receipt is in the setup archive.

The original crypto/default-library selectors and cost data were not relabeled as executions of the corrected source. The complete Git delta proves that the cryptographic implementation and cost example have unchanged bytes. No full protocol lane, all-workspace test campaign, independent custody or production activation is inferred from these selected passing suites.

## Standards and unresolved qualification

[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) specifies ML-KEM for key establishment; [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) specifies ML-DSA, and [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) specifies SLH-DSA. The raw key and signature sizes above are those parameter sets. Standard algorithm selection does not establish correct protocol composition, implementation security, custodian independence, safe recovery or whole-chain security. A KEM does not replace identity signatures or business authorization. A reported OpenSSL version and real primitive execution do not establish a FIPS 140-validated deployment.

The fixed root rule remains **ML-DSA-87 2-of-3 AND SLH-DSA-SHA2-256s 2-of-3**, with complete current approvals and all required successor possessions. It has no single-family OR fallback. Different algorithm families do not by themselves prove independent custodians, and their security categories cannot be added into a new combined security-bit claim.

The original campaign explicitly retains these boundaries:

- **Whole-chain qualification and production activation:** false. A passing component or integrity check is not an activation decision.
- **Complete composition coverage and actual lifetime failure bound:** unproved / null. Budget counters and these samples do not fill those bounds.
- **Independent custody, recovery-anchor independence and actual external-effect verification:** unverified by this evidence.
- **Native M15 production integration and migration authorization:** both qualification fields remain false in the retained V4 records.
- **Complete protocol/workspace acceptance:** selected owner and continuation suites and strict workspace Clippy passed in the separately recorded follow-up. The original failed builds remain retained. Neither campaign executed every workspace test or a complete protocol lane, and hosted source gates do not establish complete hosted native-job success.
- **Execution authenticity and continuously enforced source immutability:** not established. Exact retained bytes and matching source endpoints provide a narrower form of evidence.
- **Cell hot-read cost, full owner replay, end-to-end transition latency, network throughput and population tail behavior:** unmeasured.

**Status remains HOLD.** This package supports exact byte accounting, observed full cryptographic verification with retained public-key material, and the bounded local timings above. It does not supply the remaining deployment, protocol, custody, composition or lifetime-risk qualifications.
