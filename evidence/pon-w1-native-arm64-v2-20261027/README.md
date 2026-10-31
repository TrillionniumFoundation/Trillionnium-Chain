# Complete current W1 v2 on actual ARM64

This is a readback of one completed native ARM64 experiment, not another mining
run. All 4,032 offered cohorts completed. The complete original ZIP, including
the actual ARM executable and every failed search, is retained losslessly.

Exact source: 2b070fafcdd253c142da90fd7306d211057d3418, tree
2cf9c9813928ffdda3b181f521c51fe5e0e51f77. Actual
[run 40507587240](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40507587240),
job 122200761109, succeeded. The cost step ran from 13:16:30 to 13:28:54 UTC on
2026-10-27. The capture measured 741.246320278 seconds wall time,
737.572342 user CPU seconds, 3.329002 system CPU seconds and 37,288 KiB maximum
waited-child RSS. These are observations from a shared host, not resource
reservations or exclusive hardware measurements.

## Cross-architecture result

An independent source-aware readback compared this entire run with the retained
[original x64 experiment](../pon-w1-native-v2-e9c4bb0-20261027/README.md).
The fixed compiled-source hashes, input material bytes, seed/header/target and
all 4,032 cohort non-timing fields are equal, including every proof stream,
per-search final ticket, winner/miss, exhausted search, preparation count,
unsupported outcome and native-admission count.

Both runs contain 702,232 producer attempts, 93,740 winning calls and 58,916
exhausted searches. They share 42,316 distinct queried header contexts, 5,659
winning contexts and 509 distinct native maintenance winning headers.
There are 10,464 successful native admission calls per run, including repeated
calls on already-known packets in the same Node. These are neither 10,464 new
blocks nor 509 additional independent headers on the second host. Every winning
call separately runs the original production W1 primitive verifier.

The ARM driver used its prespecified 1,800-second internal / 1,860-second outer
window; the x64 run used 900 / 960 seconds. Both completed the same whole fixed
grid without clipping. The different caps do not create different offered work.

## Cheapest measured eligible producer

The maintenance-split-limb arm had the least observed producer CPU in all eight
eligible native maintenance groups on each host. The following fixed horizon-256
groups use two rounds, 1,055 actual attempts, 509 winning calls and three exhausted
searches. No failed search is removed from the numerator.

| Host | Preparation policy | Actual preparations | Best CPU ms / winning call | Prepared CPU ms / winning call | Best / Prepared |
| --- | --- | ---: | ---: | ---: | ---: |
| x64 | Prepare for every search | 512 | 0.949931 | 1.230739 | 0.771838 |
| ARM64 | Prepare for every search | 512 | 1.309669 | 1.598562 | 0.819280 |
| x64 | Retain preparation within each round | 2 | 0.903603 | 0.930592 | 0.970999 |
| ARM64 | Retain preparation within each round | 2 | 1.260630 | 1.305780 | 0.965423 |

The producer measurement charges preparation and every actual proof/challenge/
ticket attempt. It excludes verifier work, Node admission, report IO and harness
stream hashing. Production verifier wall time remains separately in the raw
data. These numbers establish no network-to-persistence improvement or chain TPS.

On ARM, the new scalar low-rank arm beat Prepared in 2 of its 64 supported
aggregate groups; the paired arm did so in zero groups. Neither was the cheapest
of all supported arms in any group. Both completed 48,604 attempts and 6,452
primitive winning calls, and both had zero native admission calls. Their special
matrix fixtures do not gain registered useful-task or reward eligibility from
primitive W1 acceptance.

The data contain two rounds per group on two shared hosts. Small differences are
not confidence bounds or stable speedup guarantees. Cross-host elapsed-time or
RSS ratios cannot be attributed solely to the architecture.

## Original bytes and execution identity

[The archive manifest](archive.parts.json) binds all 40 ordered pieces, the
complete 10,226,619-byte ZIP SHA-256
fd92550ad8efb9271dd4bc1e2de3e470200fcefeb7f75396f087974fa2d64cc7,
and all 18 original member hashes/CRCs. Concatenation in index order reconstructs
the original ZIP, including the full 7,202,421-byte gzip and 28,315,895-byte
uncompressed raw observation log.

The original artifact contains the actual 8,533,968-byte ELF64 little-endian
AArch64 executable, SHA-256
a41d0d8eaa131af03cdb782ff797ac140042fa4c37e54ab63bb686e20eb678ee.
Its original before/after capture hashes and both copied binary records match.
The x64 artifact retains before/after hashes but not its executable; that
difference remains explicit.

Original source-before and source-after bytes are identical and record the verified
checkout of 5,984 tracked entries / 780,587,706 bytes at the exact ARM source.
The original compiler is Rust 1.95.0 on aarch64-unknown-linux-gnu, with the same
package optimization levels, one build job, debug info off and incremental off.
The host reports four available CPUs and Neoverse-N2 through lscpu. That reported
model is not physical hardware authentication. cpu.max and memory.max were
unavailable in the original simple observations; null does not mean unlimited.
The original logs, Cargo graph and source records remain inside the full ZIP.

[The actual independent readback](readback-observation-001/terminal.json)
completed in 15.424802363 seconds with exit 0 and unchanged reader source.
Its raw stdout/stderr and exact reader bytes are retained. The
[derived comparison](derived/review.json) contains every native group, both
complete low-rank reductions, observed host metadata and explicit limitations.

## Reproduce without running the miner

From a checkout containing this evidence and its inherited x64 evidence:

    python3 evidence/pon-w1-native-arm64-v2-20261027/readback.py --out /tmp/pon-arm-v2-new

The reader verifies every original ZIP member, actual executable identity,
source-bound original checker, complete raw log, original CI summary, and every
cross-architecture cohort. It also writes the complete original artifact ZIP
into the new output directory. It never executes the retained binary.

OPEN: GPU implementation and actual hardware, energy, authenticated/exclusive
hardware, more independent runs and hosts, other registered useful-task
structures, globally cheapest adversarial work, proof cost, public ingress DoS
and end-to-end throughput. The default miner, consensus, difficulty rules and
source algorithms are unchanged. All hardness, production, useful-model and
consensus-authority qualifications remain false.

## Local repository checks

Source inventory, CI-contract and the 26-package staged preflight passed. The
complete local repository checker failed with exit 2 at the existing sparse
historical link docs/README.md to ../evidence/pon-v1/README.md. Its exact stdout,
stderr and result are retained under root-review; no full-repository PASS is
claimed. The original hosted 2b source repository check succeeded before the
actual ARM experiment.
