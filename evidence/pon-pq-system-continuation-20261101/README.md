# PQ system continuation evidence

Whole-chain status: **HOLD / UNQUALIFIED**.

This directory records the reconstructed native candidate, not the earlier lost
working copy. The source, contracts and remaining gaps are described in
[the security record](../../docs/security/PQ_SYSTEM_CONTINUATION_20261101.md).

Native execution records are collected against exact source commits. A
missing or still-running record is not a pass. Original failures and environmental
blocks must remain distinguishable. The five network controls are first executed
against the original implementation plus the test additions; the reconstructed
fixed candidate is then executed separately. External witness tests must be run
on the actual combined source, including real PQ effects and cold reopen.

The dedicated CI repeats the named controls on x64 and ARM for both the candidate
head and its ordered prospective merge. It retains raw command logs and source
checks; child-process harness entry points are excluded from the meaningful
control count. Existing broader tests and original capacity budgets remain in
force. No prior internal code review or source-check result is an independent
cryptographic audit or production acceptance.

## Reproduced original behavior

The baseline plus only the five recovered tests is local Git commit
`e34f2d2f63ea0d10232b3440e93ce20e508e8a73`, tree
`64e27258405f82aa41b80d040a581626c19b0f6b`, parent
`5606a97104f9cd3243befc2921ccace3fae2c369`. The exact local object and test
sources are retained in [the base64-encoded Git bundle](red/red-source.bundle.base64) and
[the tests-only patch](red/tests-only.patch). This local commit is not mislabeled
as a remote GitHub commit. Decode the bundle with standard base64 before Git
import and verify its [encoding receipt](red/red-source-bundle-encoding.json);
this lossless text encoding preserves the exact local Git objects.

The locked, offline Rust 1.95.0 all-features Node library build completed in
314.899 seconds using the original crate optimization, debug assertions and
overflow checks. The actual binary SHA-256 was
`3ce9c3807c8a3872e5c96bb5a468dcc4c0b787535a020d454acf6beb902401d9`.
See [the compiler artifact](red/recovered-network-red-binary.json) and
[the build record](red/recovered-network-red-build.json).

The five tests executed with loopback sockets permitted: **1 passed, 4 failed,
0 ignored**, libtest duration 11.22 seconds, command exit 101. All four failures
are behavior failures; none is a socket sandbox denial. Full
[raw output](red/recovered-network-red.log) and
[before/after source record](red/recovered-network-red.json) are retained.

| Control | Original implementation result |
| --- | --- |
| Elapsed deadline before durable charge and cached replay | FAIL |
| Deadline while waiting for the signature owner lock | FAIL |
| Signed expiry while waiting for the owner lock | FAIL |
| Cancelled intake before allocation/connection credit | FAIL |
| Failed signature remains charged; valid same-sequence PQ transfer changes balance by 42 and survives cold reopen | PASS |

The failed baseline is expected evidence of the defect, not a successful gate.
The fixed combined candidate must independently pass these same controls and
its actual external-witness tests before component success can be recorded.
