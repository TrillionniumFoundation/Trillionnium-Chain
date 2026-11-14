# Original W1 service failure: independent artifact readback

Status: **HOLD**. This packet preserves a failed native service observation from
[run 43147686753 / job 130949245394](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43147686753/job/130949245394).
It performs no new native execution, no consensus activation and no security qualification.

## Exact execution and storage identities

The executed source is 229b14c2d366a257f51f287d502a550df2332338, tree
b386c32458589f81944ddd69c04a56c28c55e284. Source-before/after readbacks agree:
28,344 tracked entries / 2,583,659,022 bytes. The retained ELF and recorded
before/after SHA256 agree: 378046c3a9f9daa50a98068b59dca42a4077bddb5b1b57e893b22774faf6273b.

[Original GitHub metadata](original-artifact.metadata.json) identifies artifact
13918630109, 5,953,185 original ZIP bytes, SHA256
454d78fbb47f518af1347cbbad787a23b7f7e9755a988dd2cd9d80af92be2d70.
Its [ordered raw parts](original-artifact.parts.json) reconstruct every original
ZIP byte; no part exceeds the unchanged 4,194,304-byte per-file reader cap.
The [member manifest](original-artifact.members.json) retains all 57 unique,
safe regular members, their exact sizes, CRC32 and SHA256. Every ZIP CRC,
extracted member byte and native-manifest file digest was checked.

## Observed finite business outcomes

All seven honest block submissions were accepted in every phase. This does
not establish six-depth confirmation by the independent verifying client.

| Native observation | Baseline confirmed / latency | Pressure confirmed | Pressure fully replayed History pages | Last pressure replay |
| --- | --- | --- | --- | --- |
| Original retained false packets | 1 / 1.787982368 s | 0 | 4 of 7 | Index 4: PUBLIC_REQUEST_DEADLINE |
| Fresh unique false challenges | 1 / 1.797712234 s | 0 | 2 of 7 | Index 2: PUBLIC_REQUEST_DEADLINE |

Original pressure accepted the seventh submit at 1.211857594 s; its last replay
ran from 3.906324324 to 4.001116728 s. Fresh pressure accepted the seventh
submit at 2.008660220 s; its last replay ran from 3.800028410 to 4.000987683 s.
Both pressure confirmation timestamps and successful confirmation latencies
remain null. There is no post-window confirmation credit.

The [original native log](original-native.log) reports exit 0 because its native
assertion covers safety/accounting invariants. Its finite target is false and
the strict reader correctly rejects CONFIRMATION_TARGET. The
[fresh native log](fresh-native.log) retains exit 101 and the explicit failed
four-second/six-depth business assertion at fresh_challenge.rs:244.
Neither native command reached its outer timeout. [Native manifest](native-manifest.json)
retains both failures and source/binary identities. Failed business targets are
not converted to passes by the successful component W1 cost experiments.

## Resource and causality boundary

The original resources remain four seconds, sixteen attack workers, cpu.max
25000/100000, two GiB memory, no swap, and 256 PIDs. Host readbacks have no
read errors or memory/OOM events. Actual kernel counters show 26,534,907 usec
additional CPU use and 101,890,113 usec additional throttled time over the
complete approximately 110-second inside-controller interval. That interval
includes builds, source checking, both tests and reporting; those counters are
not phase-specific or per-request causal attribution.

Each observed History page contains one packet, and successful imports advance
the cursor. This evidence does not show repeated full seven-block replay per
request. Shared import releases the writer during CPU refill and full W1.
The two-millisecond software CPU-account polling and repeated Host checkpoints
are possible profiling targets, with no established safe shortcut or causal
performance repair here. Full verification, resource ownership and the original
absolute deadline remain required.

[Findings](findings.json) retain exact phase numbers and scope.
[Reported summary](reported-summary.json) retains the fuller report-derived
timings, actual page/Host observations and relevant CPU scopes. These are
readbacks of reported observations, not independent W1 mathematical replay,
execution authentication, an adversarial cost lower bound or WAN qualification.
The current profile-binding repair and later candidate CI have separate source
identities; this historical failed service execution is not assigned to them.
