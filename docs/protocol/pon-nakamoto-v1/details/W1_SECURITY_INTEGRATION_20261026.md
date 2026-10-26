# W1 P0–P6 security integration candidate — 2026-10-26

**SHADOW_ONLY / HOLD_NO_GO.** This tree is a source-only composition of the exact
unmerged draft heads listed below. It has one parent, Chain #335
`db0dad68f0909460e8b1cf0c248d8bab4b59c129`, and **is not** a GitHub merge of the child PRs.
No W1 genesis, ticket, proof format, target, chainwork, FinalUse, current
parent checks, or production consensus flag is changed by this integration.

| Child draft | Exact source SHA | Scope |
| --- | --- | --- |
| #339 | `2787ad3959359bc5377d982a7ab46a2d76d44e0e` | W2-C receiver-local grants; stateless unpaid issuance; bound caller, proposal, receiver, MAC, epoch, one-use paid memory |
| #340 | `7ed523093e89bd50ce85775ca023028fdc3a58c7` | Original-domain metered pinned History W1 + M06, typed local CPU-owner fatality, remote false-error separation |
| #342 | `e55107450eb1a1f051a6c98101f3f88b7afa8f91` | Fixed host-cgroup guard for all remote History sync modes and source-bound public import API |

Each of the 12 inherited file blobs is inserted unchanged from its frozen
source branch. No child branch was altered by constructing this preview.

**Actually executed local research**: independent Python W1 oracle plus
W2-C stateless tests: ten of ten pass; SHA256-independent Git blob identity
for the new stateless code, tests and W1 oracle was verified before that
execution. This is *not* an exact full Rust repository checkout or host test.
The deliberate cloned-secret/same-epoch W2-C replay test succeeds in
demonstrating a SECURITY FAILURE if epoch custody is broken.

**P0–P6 remain OPEN** pending exact original four historical transcript bytes
and receipts, native Rust preflight/toolchain/format and actual CPU ownership
on the integrated binary, GPU/ASIC cost measurement, P3 mixed malicious/valid
traffic, A03 nine qualified attack runs with each 3/3 honest confirmation,
a complete sound low-verification-cost W2 proof, and P6 externally controlled
cryptanalysis/third-party reproduction. Existing optional positive arithmetic
fact reuse and exact rejection caching do not bound distinct challenges.

Physical kernel resource containment cannot guarantee admission fairness.
Loopback forwarding and standalone embedded calls require an independently
qualified source and resource owner; caller-supplied source addresses are not
remote peer attestation. Invalid W1 never grants chainwork; local Busy or
unknown CPU accounting never changes chain validity. Preserve all negative
observations and all signed resource/development profiles.
