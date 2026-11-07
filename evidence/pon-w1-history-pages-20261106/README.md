# W1 independent History confirmation: bounded r16 pages

This continuation starts at the existing #688 integration candidate
`0ca272d09d1522b0ffd740e441b6d3de1ed81de6`, tree
`8c3417aa4bfec4c8ed068d615bba83583360a632`. Its original availability failures
remain failures. Source changes and local component controls do not close the
original fixed-Host business gate or establish production qualification.

## Original execution, not a build-only failure

The [original W1 job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42300306639/job/128176050245)
and [artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42300306639/artifacts/13544132326)
executed the real business phases after successful build and Host preparation.
The downloaded ZIP SHA-256 is
`95e919c1ab96334797b01f9b57c958677738445daeb0015d36aedf2235a99edf`,
matching the original job's upload digest. The exact source and binary before
and after execution, raw JSON field paths, phase observations and timing
breakdown are retained in [original-readback.json](original-readback.json).

The original test binary SHA-256 is
`0f2ebdd5c16710a266c4c49da841ffe73d1ef503f4785860e971e142090f27d5`;
the original four-second test source SHA-256 is
`51c6091335463b21bceb16eb8f9108f612fea85e95a6e076696e484e0a6ac41a`.
These are identities of the original execution, not of the new candidate.

| Original scenario | No-attack confirmation | Pressure confirmation | Honest pressure ACKs | Failure |
|---|---:|---:|---:|---|
| Fixed original packet | 1 in 1.768242 s | 0 | 7/7 | `PUBLIC_REQUEST_DEADLINE` during third History replay |
| Fresh challenges | 1 in 1.809166 s | 0 | 7/7 | `FRAME_DEADLINE` on the second History request |

Both pressure phases retain zero accepted attack blocks. Fresh-challenge
construction submitted 226 distinct challenges and recorded 210 complete
transcript refusals. ACK success does not establish independent confirmation.

The fixed qualification remains one aggregate quarter CPU, 2 GiB memory,
zero swap, 256 PIDs, 16 attack workers and the original four-second absolute
window. The independent client must download actual History, perform full
native W1/M06 replay, persist and activate the observed chain, then satisfy
depth six and the original required-work predicate within that window.

## What the raw timing establishes

The original pressure client starts its first History fetch only after all
seven submissions: at 1.907372 s in the fixed-packet phase and 2.452540 s in the
fresh-challenge phase. The old service returns one block per History page.

| Pressure page | Host checkpoint calls | Host CPU | Import caller CPU | Host/import ratio | Import wall |
|---|---:|---:|---:|---:|---:|
| Fixed packet, page 0 | 1,182 | 37.522 ms | 43.152 ms | 87.0% | 990.086 ms |
| Fixed packet, page 1 | 1,172 | 35.482 ms | 41.442 ms | 85.6% | 598.461 ms |
| Fixed packet, page 2, failed | 254 | 8.744 ms | 10.452 ms | 83.7% | 102.446 ms |
| Fresh challenge, page 0 | 1,185 | 39.018 ms | 45.523 ms | 85.7% | 1,199.869 ms |

Host intervals are nested inside import intervals; adding them would double
count CPU. The comparison concerns the recorded calling-thread intervals,
not an unmeasured aggregate of all workers. Baseline independent replay plus
confirmation costs 268.203/268.637 ms CPU for seven pages. The original cold
History account starts at zero credit; its 100 ms reserve and 250 ms/s refill
require approximately 400 ms before its first operation. That allowance is
not prefilled or removed.

The fixed-packet pressure submissions' aggregate context/admission/commit
owner waits are only 0.010/2.120/0.295 ms. Those observations do not support
reducing the failure to honest submission mutex contention. Repeated roughly
90–100 ms wall intervals are consistent with CPU competition, but no scheduler
trace establishes the cause of each individual interval.

## Candidate changes

V3 serves at most sixteen consecutive packets using the existing 2,096,128-byte
total hexadecimal payload allowance. All ancestry, packet-length and body
queries share one 1,024-step SQL account. Pagination stops before starting a
candidate whose conservative lookup allowance cannot fit. Once a candidate is
inspected, a budget, corruption or cancellation error remains an error; it is
never converted into successful truncation. Packet length is checked before
BLOB allocation, and identity, parent, height and settings-selected decoding
remain mandatory. An inspected packet that does not fit the remaining byte
allowance is validated before becoming the next page's candidate.

The Node owner continues to protect current reads. This is not a new SQLite
transaction snapshot. Formatting owned packets remains outside the owner lock;
the next cursor is the actual last packet ID and `complete` is true only at
the fixed requested tip. The original single-packet API and V2 remain intact.

The fixed-neighbor poller and submission-recovery client consume complete,
bounded pages. The poller retains every packet's original metered W1/M06
admission and only activates the fixed tip at the last packet. Submission
recovery compares all returned bytes and cursors with the same local branch
and retains its stable signed Head/History/Head check. Continuous operation's
separately signed exact-one-extension authority remains restricted to one
packet; ordinary paging does not expand it.

The signed resource profile is explicitly r16. It changes the History clause
to `history-up-to16-total-hex2096128-shared-sql1024-same-owner-current-reads`.
The existing numeric resources, workers, CPU credit, packet limit, output
pool, cancellation and deadlines remain. Exact independently derived vectors
and properly signed old-cookie refusal controls distinguish the new profile.
Historical r10–r14 and historical r13/r14 arithmetic observations retain their
original identities. The separate r15 performance candidate is not included
or relabelled by this change.

## Host optimization boundary

The baseline already uses stack buffers, retains immutable path spellings and
removes selected adjacent duplicate checks. Each remaining W1 progress boundary
still observes current boot, parent inode/device/root/mode, calling-thread
membership and five current limits through complete fresh reads.

Cached controller-file descriptors were considered but not adopted. A held
descriptor preserves the original open capability across permission changes
and may refer to a different object than the current path after replacement.
The reviewed Linux seq-file offset-zero regeneration does not resolve those
authority and path concerns. This candidate changes neither Host checks nor
their placement, and contains no invented cgroup or qualified Host result.

## Separate three-run native campaign

The [original native job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42300306625/job/128176076115)
also built and ran real business tests. Three attempts lasted
112.610/112.283/111.917 seconds and returned exit 101, without startup or report
validation errors. Their original business criteria were not met. Its binary
SHA-256 is `4a7cc272a71bbd82960498db0965393896888d3fddcb9d4823c5eebc7457c7c3`.

That campaign uses three thirty-second phases, 0/24/24 attackers, 21 business
blocks, four seed blocks and 1,024 seed transfers. Receiver and verifier run
under the fixed quarter-CPU/2-GiB parent while attackers remain in the original
controller domain. It is a separate denominator from the four-second test.
The retained readback verifies the original manifest and upload log; it does
not claim a newly downloaded and independently hashed complete native ZIP.

## Qualification boundary

The [first-publication local observations](local-observations-before-hosted.json)
retain actual logs and the native source blobs: 26 release submission-recovery
controls, the real pinned-peer socket control, the current campaign-profile
control and the separate six-second network-only business control pass. The
mining CLI suite retains one pass and one startup refusal,
`PUBLIC_HOST_PROCESS_UNAVAILABLE`. No successful follower run is inferred from
that refusal. The release library-test compilation receives `SIGKILL` both with
two Cargo jobs and with one; the signal is observed, while an OOM cause is only
an inference without a killer trace. These failures remain in the record.
At that publication snapshot the explicitly labelled local debug=0 library
component build and final strict workspace Clippy are pending. Those local
component builds never substitute for original release/Host qualification.

The unchanged original four-second workload and fresh-challenge workload must
execute on the new exact source in the genuine fixed Host environment. The
native campaign also retains its original three-run criteria. Local compilation,
unit controls, reader rejection tests and source integrity checks are useful
component evidence, but do not substitute for those executions. No accepted
work, confirmation threshold or production activation flag is promoted here.
Controlled low-resource observations do not imply public-network saturation
TPS or a universally safe four-second/depth-six production confirmation rule.
