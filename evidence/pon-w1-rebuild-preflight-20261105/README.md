# W1 v2 rebuilt-image preflight, 2026-11-05

## Result and retained boundary

The current locked host and guest build completed, and the independent v2
verifier built, passed its two retained tests and strict all-target Clippy.
The verifier also completed the original 1,000 native full-relation replay
iterations with the external A/B commitments. These are not proof observations.

The rebuilt 376,200-byte guest has SHA-256
`2f07c5d7020cf375cd152064bfd2c2f4a67f2a0da88f107cd958b2cf1db3c347`.
Its image differs from the independent verifier's unchanged fixed v2 image.
The original host/guest/relation/crypto/protocol source and guest lock were not
edited. Actual guest strings contain this executor's absolute checkout and
Cargo-cache paths; the SDK does not apply path remapping by default. This is
observed path-dependent build input, not a demonstrated exclusive cause of the
image mismatch or a successful reproduction of the historical guest.

The original coordinator completed full execution and started segment zero
without checking the independent image pin. The run was interrupted when that
mismatch was noticed. Its raw log is retained; no terminal measurement was
written, no segment receipt was observed and cleanup completeness is not claimed.
There is no complete v2 proof and the 58 actual saved-receipt controls remain
unexecuted. No security, cost, admission or production gate is closed.

## Correction and validation

The coordinator now rejects a mismatched v2 image immediately after reading
its prepared manifest, before checkpoint payload hashing or any proof stage.
The independent Rust verifier remains the cryptographic authority; its image
pin and profile are unchanged. Two new parser controls check all eight image
word substitutions and agreement with both existing independent pins. The
28 retained/new observer controls passed without skips.

The repaired coordinator was exercised against the actual mismatching prepared
checkpoint: [image-rejection.json](image-rejection.json) records exit failure,
zero stages, zero proof trials and the unchanged 7,200-second total,
300-second segment, 1-GiB free-disk floor and 256-MiB checkpoint cap.
This scoped rejection is not a successful fresh proof.

## Environment recovery

Official RISC Zero v3.0.3 host tools and the r0.1.88.0 Rust archive were acquired
with SHA-256 matching the previously retained download pins. The actual r0vm
SHA-256 matches the Rust host's fixed pin. The old missing-tool and disk-floor
conditions are resolved here (more than 26 GiB free at preflight), but image
reproducibility is a new, separate unresolved prerequisite.

The two initial failures are retained: rzup ignores symlink toolchain directories;
and the nested guest Cargo process removes CARGO_HOME, selecting a read-only
default home. An actual extracted toolchain directory and an owned writable
build HOME resolved those environment failures. No source lock, verifier pin,
proof limit, acceptance expectation or production switch was relaxed.

[Summary](summary.json) records the exact source, identities and log digests.
To proceed, reproduce the fixed image from declared deterministic build inputs,
or introduce and review a separately namespaced reproducible profile with a
new full proof and all real controls. Do not overwrite the existing pin merely
to make this build acceptable.
