# Stage0 frozen-candidate remap observation — 30c145ff6

This directory records a manual-SSH, offline X230 build observation for a
frozen clean source candidate.  The observation input is commit
`30c145ff69adbbf5d9ef94569ed2e4425e94f2d7` (parent
`04a139ae4114b76280ccbea59e76d83c71a39bb6`), Git tree
`8233640ab97b6cb9b5bd7adf2a0e96a74cc1aa86`, and empty Git status.  The shared
working tree may advance after this record; this directory intentionally does
not claim to describe the later branch tip.

Two fresh no-alternates clones produced byte-identical `clean-commit-v1`
candidate archives.  Both passed `check_source_candidate.py --require-clean`.
The candidate archive is 75,847,680 bytes with SHA-256
`672b9332b8069c98265adf27a1f52890607be924aa690720436a9072b21f6fc5`; its
`trillionnium/Cargo.lock` is 52,221 bytes with SHA-256
`89ec87a67f299182785989e8815f72cda2c12382ed4fed0e4b033c16f1451fb9`.

The X230 run used Rust 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`)
and the tracked v2 builder from the frozen candidate's remap-fix lineage
(`c8b8c8977`).  `out-a` used the `/home/trnm-ci` toolchain, whose rust-src is
absent.  `out-b` used the `/home/qian` toolchain, whose rust-src is present;
the v2 seam maps that physical rust-src root to the canonical rustc commit
root.  Each invocation performed two independent offline release builds.
The two invocations produced byte-identical validator and material-builder
ELFs:

* validator: 15,516,144 bytes,
  `957bdcf9684fa78a90d7a93505a1457a6dc1943f749e3d98e32e05c8123041bb`;
* material-builder: 5,428,304 bytes,
  `62f1ebaca17a4b2b804b94a9f7e57b74723ba21955524b0b2ca0de1ce0502af8`.

The raw reports, complete build logs, source archive, and both output ELFs are
preserved in the unbundled operator artifact referenced by `manifest.json`.
The tracked reports and candidate checker output are included here so the
source and output bindings remain reviewable without copying deployment
secrets or starting a validator.

This is only a scoped remap/build observation.  It does **not** satisfy the
Stage0 truth gate by itself: `status.toml` is intentionally unchanged,
`validator_run_7_completed` remains false, no validator binary was executed,
and all runtime/production/multihost flags remain false.  In particular, the
report's `reproducible_build=true` is invocation-local; the remap-active
environment fact is bound here by the tool hash, rustc identity, and raw
operator bundle, not by an attested host.

The raw bundle is intentionally unbundled from Git.  Its exact hash, remote
path, local operator path, and contents are recorded in `manifest.json` and
`raw-bundle.sha256`.
