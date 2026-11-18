# E305 actual CI: original-window instability and retained counterexamples

**HOLD_NO_GO. The unchanged original four-second business gate is not robustly closed.**
In this batch the exact E305 head failed independent confirmation, while its
prospective merge passed. Both fresh-challenge cases failed. All four mixed-service
cases failed their original two-second maximum-gap predicate, even though every
honest probe and mutation completed successfully. No runtime, budget, deadline,
probe count, validation rule or business predicate is changed by this evidence
successor.

The small [SUMMARY.json](SUMMARY.json) was independently read back before
publication. [MANIFEST.json](MANIFEST.json) binds the original provider ZIP bytes,
original workflow/job metadata, losslessly gzip-wrapped job consoles and extracted readable receipts.
All six failed business-job provider archives are complete, with provider size
and SHA-256 verified: **16,118,256 bytes**. Original reports, databases, native
binaries and failure logs remain inside those archives. No business test or CI job
was rerun to obtain this readback.

## Exact source and observed results

- Candidate: `e305ec2fb3c98734936041af75f502cf6791f7f2`.
- Actual prospective merge: `77ea3ef3bd0928bb9f07455bd0e7d8daeed754dd`.
- Both tested trees: `351b9e851a9650e6a38208326b2cd331f6ccb187`.
- Recent batch run: [44335100372](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44335100372).
- W1 work-security run: [44335100770](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44335100770).

The original source-before and source-after receipts match. They record complete
tracked-source verification; that identity check itself executes no business
tests. The successful runtime observations on 974 and 01a remain attached to
their original runs. Identical Rust or identical trees do not transfer a pass
between executions. This batch contains one execution per listed cell; it does
not measure a failure probability or isolate the cause of timing differences.

### W1: original same-packet and fresh-challenge experiments

All four attack-free baselines confirmed 1/1 with equal complete state. Every
pressure case admitted all seven honest submissions. Business acceptance still
requires the original independent replay and confirmation.

| Actual source / experiment | Pressure result | Exact observed stopping point |
| --- | --- | --- |
| E305 head / original same-packet | **0/1, finite=false, full state=false** | All seven network history calls succeeded. Independent replay accepted the first six pages; page seven ran from 3.991027725 s to 4.000481900 s and returned `PUBLIC_REQUEST_DEADLINE`. No final confirmation occurred. |
| 77ea prospective merge / original same-packet | **1/1, finite=true, full state=true** | All seven network history calls and seven page replays succeeded. Confirmation ended at 3.580161489 s in the phase clock; reported business latency was 3.502254746 s. |
| E305 head / fresh challenges | **0/1, finite=false, full state=false** | 221 distinct constructed/submitted challenges; 205 full transcript rejections. The first history page arrived, then its replay ran from 2.492869399 s to 4.094982162 s and returned `PUBLIC_REQUEST_DEADLINE`. |
| 77ea prospective merge / fresh challenges | **0/1, finite=false, full state=false** | 245 distinct constructed/submitted challenges; 229 full transcript rejections. First replay succeeded at 3.960879742 s. The second network history request ran from 3.961014244 s to 4.057530602 s and returned `IO: Resource temporarily unavailable (os error 11)`; there was no second replay. |

The merge/fresh verifier-error array is empty because this failure occurred in
the network request. It is not a successful replay or confirmation. In all four
pressure cells accounting and protocol invariants remained true, the receiver
matched the valid honest prefix, and no attacker packet was accepted. These
properties do not substitute for the finite business target.

Both actual Host lanes retain the original before-and-after limits:
`cpu.max=25000 100000`, `cpu.max.burst=0`,
`memory.max=2147483648`, `memory.swap.max=0`, `pids.max=256`.
The requested observation window remains **4,000,000,000 ns** and the pressure
uses 16 attacker workers. The same compiled test binary hash is
`3aa131e2e692943efdecf0e59f50e26ab02013abe5c81efdf31867f0d2eec70b`;
the exact source identities still remain distinct.

### Mixed service: the failed predicate includes the quiet tail

Each of the four Linux/ARM and head/merge cells retained 130 attempts across two
phases. In **each phase**, all 16 honest probes and all 8 honest mutations
succeeded. Full work observation, complete producer-state equality, refusal of
invalid paid work, refusal of false transcripts and injected-fault refusal were
all true.

| Cell | Phase 0 maximum gap (ns) | Phase 1 maximum gap (ns) | Including-restart maximum gap (ns) |
| --- | ---: | ---: | ---: |
| ARM prospective merge | 3,327,924,201 | 3,332,360,125 | 3,342,223,579 |
| x64 prospective merge | 3,329,537,904 | 3,312,013,539 | 3,343,361,512 |
| ARM head | 3,332,198,810 | 3,329,922,352 | 3,346,107,756 |
| x64 head | 3,339,860,576 | 3,337,149,572 | 3,351,470,497 |

The original limit is **2,000,000,000 ns**. In every phase the reported maximum
equals `phase.ended_ns - last_successful_probe.ended_ns`. The probes finished
within roughly the first 0.19–0.22 seconds of each phase; subsequent sequential
false-transcript requests extended its end to about 3.53 seconds. Thus this is
an actual failure of the specified phase-wide service-gap predicate, **not a
record of 16 unanswered probes**. The complete tail and restart intervals remain
in the denominator.

Read-only runtime inspection found no Rust change between the retained 974
runtime and E305. The existing exact authenticated-body refusal delay is 500 ms,
and successful repeated mathematical refusals refresh that same-body delay.
The reports retain the initial short refusal and seven subsequent approximately
492 ms calls per phase. That observation explains the timing pattern, but this
follow-up does not reduce the delay, modify burst credit, shorten the phase,
remove the quiet tail, add probes or change a predicate to fit eight serial
requests. No safe implementation repair preserving all original gates has been
established here.

The separate network-only case in all four cells still passed **24/24 native
confirmations**, full-state equality and reopen equality under its own six-second
window. That is neither the mixed gap result nor the four-second W1 experiment.
The W1 cgroup limits must not be silently assigned to the mixed-service case.

## Cost scope and remaining unknowns

These are actual whole-process CPU observations, including failed, cancelled and
retried work. The traffic-and-join interval is slightly wider than the exact
four-second business window. It is not an exact-window CPU measurement.

| Pressure cell | Traffic + join CPU (ns) | Traffic + join wall (ns) | Whole-phase CPU (ns) | Whole-phase wall (ns) |
| --- | ---: | ---: | ---: | ---: |
| E305 original | 983,376,946 | 4,006,182,711 | 1,030,845,776 | 4,268,175,557 |
| E305 fresh | 1,016,937,756 | 4,095,868,046 | 1,071,940,928 | 4,364,244,861 |
| 77ea original | 922,780,052 | 4,009,543,192 | 966,373,251 | 4,120,834,598 |
| 77ea fresh | 975,695,139 | 4,061,923,976 | 1,029,279,163 | 4,285,355,269 |

Whole-phase observations add setup and final state/observation readback to traffic
and join. Actor, verifier, dispatch and Host clocks are nested inside these
process intervals and must not be added again. The process envelope excludes
child processes, its own final serialization and report writing. Energy and
exact-window CPU remain unknown; the process-level physical-network-byte field
is null. The original detailed observations and retained-file measurements remain
available in each full report.

Build preparation is separate from service-resource observation: head CPU
457,832,174,000 ns / wall 243,136,293,987 ns; merge CPU 371,745,888,000 ns /
wall 194,921,031,867 ns. These were real no-run preparations, not business passes
or costs charged to the four-second window. Mixed reports retain all per-attempt
construction/search/elapsed measurements and native service counters; they do
not provide this complete process-cost envelope. No universal full-cost,
energy, monetary or production-efficiency claim follows.

## Pipeline and archive integrity

The four recent jobs reached the actual public-TCP business step and failed its
mixed finite-target assertion. Later lint/binary-retention steps were skipped;
source-after verification and artifact upload succeeded. The two W1 fresh jobs
built successfully, provisioned and checked the actual fixed parent resources,
then failed their business step. Twenty other W1 jobs succeeded and one
integration-push job was skipped; their original API metadata is retained.
Their unrelated successful artifacts (about 1.606 GB) are not represented as
downloaded. There is no pipeline-only explanation for the business failures above.

Two archive retrieval failures are separately retained: an initial zero-byte
network-timeout read and a 2,456,496-byte truncated fresh ZIP after a 90-second
retrieval timeout. Later read-only GETs obtained the complete provider bytes.
These are retrieval costs, not new CI attempts or business retries. Original
failure stderr remains in the native evidence directory; only a sanitized
description is published to avoid redistributing temporary redirected URLs.

This evidence successor adds only this directory and PR readout. It preserves
the earlier 974, 01a and E305 observations, all original gates, no-force-push
policy, Draft status and the overall **HOLD_NO_GO**. It grants no independent
operator, WAN, Sybil-resistance, work-hardness, model capability, production or
reward qualification. Any workflow naturally triggered by publication belongs
to the new evidence head and must be reported separately.

The initial evidence preparation stopped before commit creation because a whitespace
check detected trailing blanks in the original GitHub console bytes. The complete
failed preparation and exact consoles are retained with lossless gzip wrappers;
decompressed bytes and original SHA-256 match. No original log was trimmed and
no whitespace rule, source gate or business predicate was weakened.
