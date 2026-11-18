# Original-window liveness: r20 failure and r21 confirmation

The r21 candidate completed the original independent confirmation target on
both hosted architectures. This result is read from the full native reports;
it is not inferred from process exit codes or job conclusions. The earlier
r20 failures remain preserved alongside the new run.

## Source and execution identity

| Record | r20 | r21 |
| --- | --- | --- |
| Actual tested source | `119cbdc8b7060df28b74230fa9265ada7bc75541` | `27d6a4b19ff58de78f3f5804e44ccae41857c794` |
| Workflow run | `44298913299` | `44314787729` |
| Policy ID | `ae83a59b214d10a93bccd557b3c9b20c05742648a52414bc3a2d32ecf03469cb` | `eac3a96f115592a98d5ebea84ef80b7752f8abbc4270ef7cc6d1e4050510505e` |

The r21 source tree is `bba212bffc9debcdf4a3f82fef7e1516ba7c8593`.
It exactly equals the complete locally validated tree of
`cf54f385930258b601339777dc18da487a34d797`; Git Data commit normalization
produced the actual remote commit above. The executed source identity is
27d6, not cf54. Draft PR #956 retains this source head. This post-run evidence
is appended on a separate evidence branch and does not rewrite frozen code.

The r21 x64 job is `134837923622`; arm64 is `134837923590`.
Both source records say `kind=head` and `tracked_worktree_verified=true`.
Source checking itself has no test-execution authority.

## Actual business outcomes

All four runs retain the original 4,000,000,000 ns business window, 16 attack
workers, and CPU limit `25000 100000` with burst zero. Before and after
snapshots also retain memory 2,147,483,648 bytes, swap zero, and 256 PIDs.
The original attack loop, native verification, and confirmation criterion
are unchanged. The signed honest body sequence and attacker body set are
identical across the four raw reports; each report also binds its own
attack-free and pressure phases to the same signed packet sequence.

| Candidate / architecture | Attack-free confirmation | Pressure confirmation | Pressure latency | Native work started / failed / completed Submit |
| --- | --- | --- | --- | --- |
| r20 x64 | 1/1 at 2.876945732 s | 0/1 | No confirmation | 483 / 476 / 7 |
| r20 arm64 | 1/1 at 1.815331154 s | 0/1 | No confirmation | 473 / 466 / 7 |
| r21 x64 | 1/1 at 3.050875408 s | **1/1** | **3.346073556 s** | 71 / 64 / 7 |
| r21 arm64 | 1/1 at 1.815154207 s | **1/1** | **2.106682700 s** | 71 / 64 / 7 |

Both new pressure phases report all of the following as true: confirmation
before the original deadline, finite business target, protocol invariants,
full native state equality, closed accounting, and no attack accepted.
Both completed seven honest Submits and seven independent History page
replays. Each replay retained 1,099 fresh W1 Host checkpoints: 7,693 accepted
checks in each architecture, with zero rejected or unfinished work checks.

Both new pressure phases published 64 known-invalid-body eligibility hints
and observed 64 corresponding waits. The hint is published only after a
strict native negative result or exact strict negative-cache fact. Hello
cannot create or refresh it. The fixed 256-slot, 1,000 ms table leaves
ineligible items outside eligible FIFO heads and avoids issuing a paid grant
or reserving a worker/body while they wait. Later admission still runs the
original authentication, canonical body, challenge, context, fresh Host,
W1, and accounting checks. This is the explicit r21 policy change.

Earlier `7e4b96d4` diagnostics are a separate campaign. Their work counts or
mutation reservations must not be substituted for the r20 119c measurements
in this table. `SUMMARY.json` reads all four actual reports and includes
their full service metrics and exact file hashes.

## Costs and scope

The following CPU and peak RSS are from the original `wait4` process
receipts for the complete confirmation-test child, including both baseline
and pressure, final Rust report serialization/write, and exit.

| Candidate / architecture | Whole test CPU | Peak child RSS |
| --- | --- | --- |
| r20 x64 | 1.981317 s | 123,456 KiB |
| r20 arm64 | 1.698870 s | 119,028 KiB |
| r21 x64 | 1.715559 s | 67,976 KiB |
| r21 arm64 | 1.249400 s | 70,748 KiB |

These are observed single-run differences, not a repeated-run statistical
claim or isolated causal estimate of the cost delta. Peak RSS includes the
pre-exec child image; it is not attributable solely to Rust or pressure.
The parent Python's post-child hashing, verification, and receipt writing
are outside these child receipts. `process.json` does not retain the numeric
waited PID, so no independent numeric PID equality claim is made.

For r21, pressure traffic-plus-join CPU was 0.843454329 s on x64 and
0.619376792 s on arm64. Its wall durations, 4.202637351 s and 4.033820388 s,
include joining and therefore extend beyond the business deadline. Complete
pressure-phase CPU, including setup and final state/observation readback,
was 0.877617668 s and 0.647775000 s. Phase clocks exclude the final report
write; the whole-child receipts include it.

Phase, actor, dispatch and Host clocks are nested in the child totals and
must not be added again. The aggregate parallel challenge wait of about
61 seconds in each new pressure phase is not elapsed wall time or CPU.
The wider parent cgroup before/after CPU includes all five native tests and
their driver, so it is a separate scope. Build and other-test receipts are
retained separately in the raw archives. Physical I/O/network bytes, energy,
currency fees, and complete system cost remain unknown. They are not zero.
The independent cost review records these boundaries and verifies all eight
before/after resource-limit snapshots.

## Retained originals

`27d6-full-records.tar.xz` contains 312 exact original non-ELF members,
83,333,163 uncompressed bytes, including full reports, source identities,
host/limit snapshots, manifests, process receipts, and stdout/stderr.
No failure fields were removed. Only 12 compiled ELF executables are omitted
from the compact archive. `27d6-MEMBERS.json` records all original members,
their original byte sizes, SHA-256, ZIP CRC, inclusion status, and the two
original artifact ZIP digests. The corresponding r20 archive and member
index remain in `../r20-119c/`.

| r21 object | Bytes | SHA-256 |
| --- | --- | --- |
| Compact original archive | 2,020,984 | `532b1302e7297c14da65f0c5b1c0f7361604087b905aa5a34868799b542f3dfc` |
| x64 original report | 8,644,635 | `4d35f81acdbca0b43527efda09b798543e81a6a49fbfc5b27c1f0391b52b2890` |
| arm64 original report | 9,109,989 | `c0531c2147ea03e0249424116ce40e3fbd64373f8e0bebd50d06c72d4880b30d` |
| x64 original ZIP, artifact 14432798175 | 9,259,973 | `07fa10715c01cd6792c099472fb5dac00ea61880711cd22044dcf4d11f244e3a` |
| arm64 original ZIP, artifact 14433572562 | 8,885,150 | `626535723afb70fb8630cdd727bbe243e80561d9d5a84e4afe2fa8f3b6502031` |

`R21_READBACK.json` binds the new source, actual target fields, limits, fresh
checks and cost receipts. `SUMMARY.json` compares the exact old/new raw
reports. `INDEPENDENT_WAIT4_REVIEW.json` retains the independent read-only
source and receipt review. These derived files do not replace the originals.

## Qualification boundary

This is a passed native liveness result for the recorded controlled loopback
campaign on two hosted architectures, with a shared controller and one run
per candidate and architecture. Production activation, public-network and
independent-operator qualification remain false. The repair targets repeated
known-invalid canonical bodies; it does not establish arbitrary novel-body
or Sybil fairness, saturated WAN performance, or broad statistical robustness.
