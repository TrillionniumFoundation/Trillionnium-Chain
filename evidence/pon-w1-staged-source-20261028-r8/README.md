# Staged W1 conditional-receipt source review

**Source-only PASS; new host compilation, cryptographic controls and proving
remain NOT_RUN.** The preceding baseline build remains in
[the actual build packet](../pon-w1-batch-build-20261028-r8/README.md).
This packet does not change its measured outcome or claim a batch benefit.

The new [staged host](../../formal/pon-nakamoto-v1/w1_batch/host/src/staged.rs)
uses an actual composite session, lifts and joins only that session's consecutive
segments, validates and retains the complete unresolved conditional claim,
requires genuine final verification rejection, and resolves it with the actual
already-verified original full W1 leaf. It then requires the full successful
claim with empty assumptions and actual final verification. These are code
paths awaiting execution, not observed cryptographic results.

Read-only review checked the exact official SDK 3.0.6 client, server, conversion,
claim and verifier source files listed in
[reviewed-sdk-source-pins.json](reviewed-sdk-source-pins.json). Root separately
reviewed the staged source and the SDK `join`/`resolve` signatures. Another
collaborating reviewer supplied the typed Asset/protobuf distinction and the
fact that composite `claim()` erases attached assumptions. These reviews are
local source reviews; they are not independent WAN operators or experimental
observations. The source uses Inline typed receipt assets, compares complete
claims, and never submits an expected claim as a proof or assumption witness.

[result.json](result.json) records the actual low-load controls: all 12 existing
independent public-byte controls passed, host formatting passed, and the Git
whitespace check passed. The full raw stdout/stderr are retained. Source bytes
and both independent locks for guest/statement/methods were compared with
baseline commit `5a7b8e24ab638f443695880e475b35cb40706af4` and were unchanged.
Those observations establish neither Rust type correctness nor a genuine
conditional proof. Rust tests, strict Clippy and the normal host build remain
the separate H0 qualification.

The [staged pilot contract](../../formal/pon-nakamoto-v1/w1_batch/STAGED_PILOT_CONTRACT.md)
proposes H0 at 180 wall seconds / 360 child CPU seconds / 2.5 GiB sampled RSS /
256 MiB target growth / a 1 GiB free-disk floor. A later one-attempt P1 at
600 wall seconds must bind the actual new host hash and unchanged guest bytes.
Only that future real run can establish one-leaf conditional rejection and
resolution. Reusing the original leaf still supplies exactly one work; its
41,887.28597837 observed CPU-second lower bound remains in full economics.
