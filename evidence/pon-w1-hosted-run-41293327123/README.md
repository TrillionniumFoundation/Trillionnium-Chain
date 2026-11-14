# W1 hosted run 41293327123: cost observation and service verdicts

**The workflow result is FAIL because both service jobs fail the original business
target.** All four cost-observation jobs succeed. Those outcomes answer different
questions and are retained together.

- Measured head: `c041564b8a6bb0b98ca9c30e7871878427e5d9a4`.
- Measured prospective merge: `b824293d71a346a3461705b5eb129e7b83ce2920`.
- Both measured trees: `11c25a7d409b6281d3f90dc56f0ebb2c1a96b305`.
- [Original run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293327123)
  and [code PR 675](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/675).

This evidence-only continuation descends from the measured head. It changes no
code, workflow, dependency, resource policy or qualification parameter. The code
PR keeps its measured head; the archive commit is not relabeled as executed code.
`SCOPE.json` and the original GitHub run/job objects record this boundary.

## Complete hosted cost execution and raw readback

All four lanes execute the original locked dependency graph on their native
Linux architecture after the caller environment repair. Each records **72 real
prefix preparations, 288 independent searches, 573 hash attempts, 288 complete
forged candidates and 1,152 native verification calls**. Each of the production,
reference, existing limb and experimental column-limb paths returns `Transcript`
on all 288 candidates. There is no native semantic alert or exhausted search.

The reader is rerun over each complete original JSONL and reproduces the retained
manifest's reader object exactly. All retained artifact hashes, exact source
identities, binary architecture and execution/copy hashes are rechecked. The
1,585 recorded timing objects in each lane have positive CPU and wall values and
retain their original nesting checks. The original compiler, release profile,
source and Cargo configuration guards pass without an override.

For each verifier, the number below is total native rejection CPU divided by
total actual attacker cohort CPU across all 72 preparations and four searches
per preparation. It is a ratio of aggregate CPU, not an average of class ratios.

| Source / architecture | Production | Reference | Existing limb | Experimental column-limb |
|---|---:|---:|---:|---:|
| Head / x64 | 27.900714 | 29.247240 | 22.987900 | 26.233754 |
| Head / ARM64 | 25.879495 | 35.306865 | 24.202815 | 24.347462 |
| Merge / x64 | 28.400389 | 29.746069 | 23.346257 | 26.728313 |
| Merge / ARM64 | 24.945341 | 34.040729 | 23.318099 | 23.455976 |

Across the nine material-class aggregate ratios, production ranges are
22.740116–36.818171 (head x64), 24.075215–28.301786 (head ARM64),
23.391137–36.737801 (merge x64), and 22.578596–27.627071 (merge ARM64).
These are observed class extrema, not confidence intervals or worst-case bounds.

The existing limb path has lower aggregate rejection CPU than the new column
path in all four observations. The new path is retained as a research comparison;
the production verifier remains unchanged. These finite invalid-work observations
do not establish performance for every valid workload or justify changing the
default based only on a cheaper result here.

The attacker denominator includes actual prefix setup, every failed and winning
hash attempt, trace retention/encoding, and winning proof buffer construction.
It excludes later output, destruction and networking, and the attack can avoid
the experiment's evidence-retention overhead. More extensive reuse, different
algorithms or hardware may cost less. The 24.95–28.40 aggregate production range
therefore establishes neither a cheapest-attacker lower bound nor a public-network
amplification factor. It is not directly comparable to the historical 6.86–7.90
observation with different source, host and cost boundaries.

[Full cost readback](cost/cost-readback-summary.json) records raw JSONL hashes,
all class totals, actual clocks, binary identities, controls and scope flags.
[Download identities](cost/downloads.json) identify all four original ZIPs:

| Source | x64 | ARM64 |
|---|---|---|
| Head | [Original ZIP](cost/cost-x64-head.zip) | [Original ZIP](cost/cost-arm64-head.zip) |
| Prospective merge | [Original ZIP](cost/cost-x64-prospective-merge.zip) | [Original ZIP](cost/cost-arm64-prospective-merge.zip) |

The archive retains both the complete ZIPs and exact raw-capture XZ files beside
each lane's manifest/readback. The observed Python readback script is preserved
byte for byte, including its original local paths; it is provenance, not a
portable entrypoint. To rerun the protocol reader, extract a lane's original
`campaign.stdout` from its ZIP outside the checkout and invoke
`python3 scripts/pon_w1_false_trace_reuse_reader_v1.py /path/to/campaign.stdout`
using the measured code source.

### Cross-architecture byte comparison

Removing only the explicitly enumerated CPU/wall timing objects yields the same
1,811-record, 29,953,187-byte canonical JSONL on all four lanes:
`731a31f7e84032bd440bdf09938b412345c47224b58853f053d2cb525446a0d3`.
The compressed canonical streams were also compared byte for byte; one identical
[canonical archive](cost/canonical-without-timing.jsonl.xz) is retained.

This comparison preserves every material byte, task/challenge/trace/ticket,
nonce and target result, complete winning proof, verifier path/order/verdict,
coverage count and qualification flag. It does not replace the four original
timed streams. It establishes no equality of performance or hardware and is not
an independent Python execution of the W1 relation. The exact excluded fields
and canonical encoding are listed in the readback summary.

## Service results under the original budget

Each source executes the original repeated-packet test and the fresh-challenge
successor. The fixed four-second window, sixteen attack workers, six-depth
confirmation, non-root UID, shared Host and `cpu.max = 25000 100000` remain.
Both release builds succeed; both final Host validations report no Host errors.

The seven signed blocks are constructed before each service observation. The
times below measure submission, independent replay and confirmation of those
packets; they do **not** measure live mining of six new blocks or promise real
network finality in four seconds. Nakamoto confirmation remains probabilistic.

| Source / traffic | Baseline six-depth confirmation | Pressure confirmed transactions | Pressure durable independent height | Complete Transcript refusals |
|---|---:|---:|---:|---:|
| Head / original | 2.581386168 s | 0 | 2 | 297 |
| Head / fresh | 2.698647338 s | 0 | 2 | 255 |
| Merge / original | 2.682026893 s | 0 | 2 | 300 |
| Merge / fresh | 2.581118886 s | 0 | 2 | 265 |

All four pressure phases return `ok` for all seven honest Submit calls. Every
independent-client database has exactly three blocks: genesis and heights one
and two. Each reaches only its third History call before the original window
ends. The two original-traffic phases receive that third page, then local import
returns `PUBLIC_REQUEST_DEADLINE`.

The two fresh phases fail at a different boundary:

| Source | Third History start | Return | Observed result |
|---|---:|---:|---|
| Head | 3.976555034 s | 4.001027842 s | `IO: Resource temporarily unavailable (os error 11)` |
| Merge | 3.954962861 s | 4.054548170 s | `FRAME_DEADLINE` |

Both fresh calls have `returned_after_window=true`. No third page reaches local
import, so their `verification_errors=[]` is not a successful business outcome.
The fresh native assertion exits 101 after saving the complete report. The
original test exits zero while reporting `finite_target_met=false`; its runner
correctly refuses that outcome. No late result is credited.

Fresh head constructs 271 unique challenges and merge constructs 281, with no
exhausted search or reached worker attempt cap. All four observers report zero
dropped records and measurement failures. No attacker input is accepted.

[Service summary](service/summary.json) and
[independent readback](service/independent-readback.json) retain exact History
rows, errors, CPU scopes and read-only SQLite queries. The queries use
`mode=ro&immutable=1`, verify source ZIP member bytes and retain database hashes
before and after; all four return `[3, 0, 2]` for block count/minimum/maximum height.

Complete original archives, checked against GitHub artifact digests:

| Source | Artifact ID | Original ZIP | SHA-256 |
|---|---:|---|---|
| Head | 13078475975 | [head.zip](service/head.zip) | `b855b64cc01a0461d8654b1fd9f583eb686c3fb9687e23e780c81c00985ff2ba` |
| Prospective merge | 13077889185 | [prospective-merge.zip](service/prospective-merge.zip) | `5578ed1daca71790d7c76a1a8766378df011d4e94bcbe641957e83de6aadcb6e` |

These ZIPs preserve original manifests, reports, logs, actual binary, databases
and Host observations. The source and binary bindings are verified before and
after execution. The native service binary is identical in both sources and in
the preceding run:
`8e862696158f8bbc4a6c8fab2c6506b08fefb91008d809288a09cea1d418f2a9`.

The [preceding run](../pon-w1-work-security-ci-followup-20261101/README.md) has
slower baselines and genesis-only pressure databases. This run admits two blocks
but still fails confirmation. The different partial progress and timings are
separate finite observations of the same binary; they are not an improvement
attributable to the unrelated cost-runner invocation repair. Neither observation
is discarded in favor of a faster sample.

## Other native checks and remaining qualification

On each of the four x64/ARM64 × head/merge cost jobs, the original locked Cargo
graph supports 98 successful W1 module tests, six successful native fuzz semantic
tests and strict primitive Clippy. These are scoped component checks, not all
workspace tests. The separate
[native-boundary diagnostic run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293327206)
also completes all four native boundary jobs, including strict all-target Clippy,
original accounting/cooffered regressions and before/after source verification.
Its job metadata is retained here; a retained historical-failure diagnostic is
not counted as a current service success.

The original
[required-baseline run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41293327130)
is queued at this observation time behind the preceding run's runtime shards.
Its unchanged concurrency policy preserves those earlier observations. No full
required-baseline success or remotely passed new inventory gate is inferred from
the narrower native jobs or local inventory check.

The existing [work-security profile](../../config/pon/work-security-acceptance-v1.json)
remains a proposed diagnostic policy, not a consensus parameter. Four false-trace
searches sharing one prefix do not replace its `[1, 8, 64]` legal-winner
amortization requirements. Invalid candidates are not accepted-work winners.
The four-second service experiment does not replace its sixty-second window,
forty-nine-second offer span, at least one hundred honest offers with zero
failures and a two-second honest p99 deadline. Every original threshold remains.

Full relation correctness, fresh binding, cheapest legal adversarial work,
economical refusal, independently confirmed service and model utility remain
separate obligations. This run supplies no cheapest-work lower bound, permissionless
fresh-identity fairness proof, public-WAN acceptance, model-quality acceptance,
Hepta installation authority or whole-chain post-quantum proof. Qualification
and production activation remain **HOLD**.

Static inspection suggests repeated History resource checks may be worth
profiling, but no per-stage cost attribution or optimization benefit was measured.
No resource check frequency, verifier, queue policy or deadline was changed to
make this observation pass.
