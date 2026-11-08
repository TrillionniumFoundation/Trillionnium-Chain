# 819309f W1 — authorized transport-v2 supplement

**Business acceptance remains HOLD.** This is a read-only retrieval supplement to the frozen W1 v1 package. No CI or native work was rerun.

The candidate is `819309fd312298e099642e1253b1d4ba07113e98`, base `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`, ordered merge `28df21f965e0348690836c9c854dab645827a03d`, tree `f9d63abb9e2931fd78e26ccb87e3a7955068f267`. All records belong to original W1 run `42402618462`, real push attempt 1, ProfHepta.

## Complete coverage and preserved failures

[W1_COVERAGE.json](W1_COVERAGE.json) retains all 20 component lanes and distinguishes the original 20/20 GitHub job successes, v1 14 complete / 6 UNKNOWN, each eligible transport-v2 attempt, and final independent artifact/native-record coverage. The original v1 six 240-second transfer failures and partial ZIPs remain unchanged. [v1-reference/](v1-reference/) binds that frozen package.

Only those six exact timeout-affected artifact IDs were eligible for one additional GET each, with a separately declared 900-second observer limit and at most two parallel transfers. The plan was saved before the GETs. Identity was verified as ProfHepta before and after. A non-timeout integrity, identity or transfer failure stops new GETs; already in-flight observations remain retained. There is no retry-until-green policy.

Complete ZIPs must match the original GitHub byte count and SHA256, then pass the same internal manifest, H/M source/context, ELF/binary identity and original native process record checks. The exact same pinned pure-reader wrapper is used; its original reader result must match the retained manifest. Transfer or reader UNKNOWN is never renamed a native failure or a business success.

## Retained evidence

The original pure-driver rows contain an ancillary `stage1_status: null` because the helper read `status` rather than the actual `coverage_status` key. This field was never used for gating: the wrapper required the authenticated archive/source/manifest booleans before importing any original reader. This supplement explicitly records those actual booleans and preserves the original rows unchanged. No native outcome, coverage count or business criterion is changed.

[artifacts/](artifacts/) contains original source receipts, native manifests, logs and independent readbacks. [observation/](observation/) holds the exact transfer plan and full summaries. [observer/](observer/) preserves scripts and authoritative job outcomes. Text above 256 KiB is stored as lossless level-1, zero-timestamp gzip; [FILES.json](FILES.json) records original and packed sizes/hashes and every compression was decompressed and checked.

Original full or partial ZIPs stay in the durable external directory. [EXTERNAL_ARCHIVES.json](EXTERNAL_ARCHIVES.json) records their exact paths, original GitHub identities, observed byte counts and SHA256; each was rehashed at this seal. The original binaries and large native stdout remain inside those original ZIPs, not in this metadata-only supplement.

The separate 14-core package is unchanged: original service/fresh pressure confirmation remains 0/1; History confirmer activation remains genesis; four State lanes pass their own controls. Source or Host success and component record consistency do not satisfy these business gates. The 4-second service window, 30-second import deadline and 1800-second server lifetime are unchanged. No production TPS, hardness, full-system performance or COW claim is established. Historical artifact `11531476198` remains UNKNOWN and is not replaced.

[SHA256SUMS](SHA256SUMS) covers the payload; [SEAL.json](SEAL.json) records this supplement independently from v1. Copy the full directory and retain both sealed versions.
