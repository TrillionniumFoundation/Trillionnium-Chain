# Stage0 native-build, fresh-clone, and rust-src control observations — d6bb34c1

This directory preserves the raw JSON boundary for the 2026-08-20 Stage0
build observation and later 2026-08-21 fresh-clone and rust-src control
observations. The strict source candidate binds commit
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

`fresh-clone-gates-report.json` preserves the later 2026-08-21 manual-SSH X230
observation. It binds two byte-identical fresh clones, empty statuses, the same
commit/tree, `Cargo.lock`, source archive, and transport bundle. The initial
offline attempt found the job-local Cargo cache incomplete and public
dependency fetch was used; the formal rerun then completed offline with fmt,
check, and the recorded key tests passing. The referenced logs are not bundled,
runner identity is not cryptographically attested, and a real 7-validator run
was not performed.

`rust-src-drift-build-report.json` is the raw schema-3 report from an unpatched
builder invocation after rust-src was installed. Its two internal builds match,
but its validator hash/size changed to `4e625e42…1b59`/15,062,816 and its
material-builder hash/size changed to `6a3fb166…b74c`/5,382,936. Both differ
from the 2026-08-20 baseline despite the same d6bb34c1 candidate, Cargo.lock,
source archive, rustc 1.95.0 commit, and `rustc -vV` hash. The physical rust-src
sysroot path entered `.rodata`; therefore the raw report's
`reproducible_build=true` is only an invocation-local claim.

`rust-src-remapped-v2-committed-control-build-report.json` is the final
corresponding X230 control. The runner cloned the complete tool bundle with
`git clone --no-local`, detached at exact clean commit `08efb8f4`, required an
empty status, kept the evidence-bound v1 builder byte-for-byte frozen, and used
the tracked v2 wrapper to replace only its native build seam with canonical
rust-src path remapping. It exited zero, emitted its final JSON, and restored
the historical validator `cdf379d6…8c74`/15,060,832 and
material-builder `40ff33c3…f3b6`/5,381,608 outputs across its two internal
builds. `rust-src-cross-time-control-report.json` binds both raw reports, the
historical baseline, commit/tree/parent, tool-bundle hash and length, clean
checkout facts, and recorded v1/v2 tool hashes. The tool bundle SHA-256 is
`064f85fd…891e` over 25,569,603 bytes; the bundle itself is not tracked here.
This control supports native Linux cross-time reproducibility through committed
tool code. The fix remains absent from d6bb34c1 and c971f1b0f, the runner is not
cryptographically attested, and the raw schema-3 report does not self-bind the
tool commit or wrapper hashes.

`manifest.json` remains the immutable 2026-08-20 build-only observation, so its
fresh-clone claim bits correctly remain false for that earlier campaign. The
later report plus the directory-level `../status.toml` advance only the current
fmt/check/key-test observation truth; they do not retroactively rewrite the
build manifest, erase the later cross-time drift, or move the 7-validator bit.

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
