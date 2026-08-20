# Stage0 native reproducible-build observation — d6bb34c1

This directory preserves the raw JSON boundary for the 2026-08-20 Stage0
build observation. The strict source candidate binds commit
`d6bb34c149edd07d6412b169c471dbb017eb301e`, Git tree
`d14ed7015b13f487738451e4243b8ec962db0f87`, the empty Git status,
`trillionnium/Cargo.lock`, and candidate-tar SHA-256
`bf1f77a229d6eae8e975481728e157e87c6bb9e923ec0e3c2f8f422918e4ae58`.

`build-a.json` and `build-b.json` are the two exact X230 builder stdout
records. Each invocation performed two independent Cargo release builds in an
isolated Cargo home. The four Linux builds agree byte-for-byte on both role
binaries. `macos-build-a.json` and `macos-build-b.json` preserve the same
two-invocation/four-build observation on native Apple arm64. The schema-3
`aggregate-build-report.json` joins one deeply rehashed report and binary set
from each architecture to the same strict source candidate.

The candidate tar, offline Cargo registry cache, and binaries are intentionally
unbundled. Their content addresses and byte lengths are recorded in
`manifest.json` and the raw reports. The Linux manifest is deliberately scoped
to the X230 observation, so its cross-architecture and aggregate claim bits
remain false even though the sibling aggregate record is present.

The record is an unsigned manual-SSH operator observation. It does not provide
cryptographic host attestation, prove which physical machine executed Cargo,
or upgrade any validator-run, multihost, performance, geo-WAN, fault, or
production claim. The deep verifier rehashes the exact source candidate and
common Linux ELF binaries supplied out of band:

```text
python3 scripts/poco-fleet/check_stage0_reproducible_build_evidence.py \
  docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820 \
  --source-candidate /path/to/candidate-a.tar \
  --validator-binary /path/to/trnm-poco-lab-validator \
  --material-builder /path/to/trnm-poco-lab-material-builder
```
