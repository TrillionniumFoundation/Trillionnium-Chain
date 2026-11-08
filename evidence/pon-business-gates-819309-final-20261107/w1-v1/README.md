# 819309f W1 component evidence — v1 single-attempt readback

**HOLD.** This package preserves the once-only observation of the 20 W1 component lanes from the real integration-branch push. It supplements the separately sealed 14-core business package and does not replace any business gate.

The exact head is `819309fd312298e099642e1253b1d4ba07113e98`; actual base `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; deterministic ordered merge `28df21f965e0348690836c9c854dab645827a03d`; tested tree `f9d63abb9e2931fd78e26ccb87e3a7955068f267`. GitHub workflow run `42402618462`, event `push`, attempt `1`, actor `ProfHepta`.

## Distinct denominators

- GitHub reports **20/20 component jobs successful**. Full workflow totals remain **37 jobs: 26 success / 11 failure** and **34 native lanes: 24 success / 10 failure**.
- Independent ZIP size/digest, complete internal manifests, original H/M source receipts, actual ELF architecture and binary hashes are checked separately.
- Original pinned pure readers are applied only to authenticated retained native outputs. Their results must equal the original manifest reader values. This observation executes no native work, changes no environment or source, and grants no business or hardness qualification.
- Per-lane coverage, all exceptions, native command denominators and UNKNOWN values are in [W1_CORE.json](W1_CORE.json). Full records are in [artifacts/](artifacts/) and [observation/](observation/).

## Transfer failure preservation

Each v1 ZIP GET is limited to 240 seconds, with at most two concurrent GETs and no retry. A timeout may leave a partial ZIP whose size and digest cannot equal the full GitHub artifact. Such a record remains UNKNOWN; it is **not evidence that the GitHub-produced artifact is corrupt**, and does not change the original native job conclusion.

Original full and partial ZIP bytes remain in the durable external observation directory, with observed SHA256, expected GitHub digest, timeout and exit records in [EXTERNAL_ARCHIVES.json](EXTERNAL_ARCHIVES.json). Every listed ZIP was rehashed at this seal. Large ZIPs, ELF binaries and large campaign stdout are intentionally excluded from this small metadata package. Authenticated ZIP inventories preserve every original member identity.

A separately authorized transport-v2 may later fetch only timeout-affected original artifact IDs once with a distinct 900-second observer bound. It must retain this v1 failure record unchanged and report its own coverage. That changes no 4-second service, 30-second import, 1800-second lifetime, Host or CI execution budget.

## Retained sources and limits

[metadata/](metadata/) contains the terminal full-denominator GitHub snapshot. [pinned-readers/](pinned-readers/) contains exact-head original readers and their source/import pins. Text files larger than 256 KiB are stored as lossless gzip (level 1, zero timestamp); [FILES.json](FILES.json) records both original and packed byte counts and SHA256, and every compressed copy is decompressed and compared before sealing. [observer/](observer/) preserves this independent observer, preparation records and errors; [FILES.json](FILES.json) maps copies back to original paths.

The false-trace/full-limb, legal-strategy and rank/batch component records retain their original scope flags. Pure reader success is internal record consistency, not a new PNW1 transcript replay, public-service pass, production activation or TPS measurement. Missing historical artifact `11531476198` remains UNKNOWN and is not replaced by any similar source or component artifact.

The 14-core package remains authoritative for the four original service and two fresh lanes (pressure confirmation 0/1), four State lanes, and four History lanes (active confirmer still genesis). Source and Host success do not satisfy those business gates.

## Integrity and copy

Copy this whole directory without modifying files. [SHA256SUMS](SHA256SUMS) covers every payload file and [SEAL.json](SEAL.json) records the package size and manifest digest. No credentials, unrelated operator files, repository mutation, dispatch, rerun or GitHub message is included.
