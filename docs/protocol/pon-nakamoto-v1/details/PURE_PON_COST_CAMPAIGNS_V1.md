# Finite pure PoN cost and ingress campaigns

These two native examples measure the unchanged W1 relation and the explicit
[pure public profile](PURE_PON_PUBLIC_BOOTSTRAP_V1.md). They have bounded inputs,
reports and deadlines, preserve failures, and cannot qualify hardness, useful
model work, public fairness or production operation. Run each in isolation from
other campaigns when interpreting timing; record any host contention.

The complete 2026-10-27 observation, its source/binary capture manifests, all
3,456 producer cohorts, both attacked cold-reopen phases and limitations are
retained in [the evidence report](../../../../evidence/pon-pure-cost-bootstrap-20261027/README.md).
That host was not exclusive. The fixed-cohort reduction includes every offered
strategy, unsupported setup, both targets and preparation modes; it does not
select a fastest observed arm or turn a benchmark into a hardness qualification.

## Fixed producer matrix

`pon_pure_cost_campaign` offers all twelve current concrete producer strategies
on every material: general, structured, tiled classical, one-level Strassen,
paired field products, blocked zero, integer paired zero, one-zero rank-one,
maintenance split limb, maintenance periodic, maintenance prefix, and maintenance
integer paired. Unsupported constructors produce explicit rows with their real
setup cost. There is no fallback arm and no selection of the best observed arm.

Nine input classes cover the periodic fixture, rank-checked full-field matrices,
both zero, identity, rank-one, sparse diagonal, each orientation of one-zero with
one nonzero rank-one operand, and the actual public genesis maintenance matrices.
Only maintenance with the native expected target is admitted by a native Node;
other classes and the harder target are primitive observations, not registered
neural jobs. Every winning proof passes the unchanged production verifier.

The default batch offers horizons 1, 8, 64 and 256, cold preparation for each
search versus one preparation reused through the batch, two targets, and two
rounds. Round order rotates the same fixed strategy list. A search retains every
actual trial, including exhausted searches and those preceding a winner. The
denominator is preparation plus all producer attempts; validation, native
admission, report I/O and harness stream hashing are separately identified.
Unknown CPU observations stay unknown. No warm-up or slow initial sample is
discarded. Nested horizons and paired arms share challenge streams and therefore
are not independent samples.

The experiment compares complete header/proof/ticket stream hashes across all
supported algorithms and preparation modes. It also compares 64 distinct late
product failures through the original verifier and exact-public-product filter,
alternating order and recording fact setup separately. This comparison does not
cover correct-product/false-transcript attacks.

```sh
cargo build --locked --profile test --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example pon_pure_cost_campaign
target/debug/examples/pon_pure_cost_campaign \
  --searches 256 --attempts 8 --rounds 2 --seed 1 --seconds 900 > cost.jsonl
python3 scripts/ci/check_pure_pon_cost_campaign.py cost.jsonl --output cost-check.json
python3 scripts/ci/summarize_pure_pon_cost_campaign.py cost.jsonl \
  --output fixed-cohorts.json --csv fixed-cohorts.csv
```

Use the actual `CARGO_TARGET_DIR` path in place of `target`. The repository's
`test` profile optimizes the node and crypto packages at level 3, M06 at level 1;
the Cargo banner's overall `unoptimized` label does not override those package
settings. Record the toolchain, full profile settings, source commit, source-file
hashes, exact command and executable hash. The example writes a failed terminal
record on a bound or mismatch; an incomplete run must not become a passing
aggregate. The consistency reader rejects dropped unsuccessful trials, missing
offered cohorts, unpaired streams, forged CPU zeroes and native-scope promotion.
Its own tests use synthetic fixtures explicitly separate from measured evidence.

## Unique invalid trace ingress

`pon_pure_ingress_campaign` uses two independent native receivers by default,
each with two TCP listeners sharing that receiver's original CPU and intake
owner. A single host's receivers have independent budgets; this is not a claim
of one network-wide resource bucket. Cold initial credit is checked at every
reopen. The campaign fetches the public bundle, retains a genuinely produced W1
seed, and records acquisition cost once.

Each attacker changes the challenge and fabricates a new target-winning trace
without computing its required W1 relation. The exact original A/B/C are reused.
These are deliberately invalid proofs, with unique packet/body identities at each
receiver and new arbitrary caller keys. The attack's short hash search is the
construction of a fraudulent W1 claim; it is not a protocol admission gate.
The same prepared invalid packet is sent once to each independent receiver, so
sender preparation can be compared with repeated receiver work. A single honest
worker interleaves complete newly generated W1 proofs through the same queues.
Any invalid acceptance terminates as failure.

The default sequence is a 15-second honest cold baseline, a 45-second attacked
cold reopen and a second 45-second attacked cold reopen. All use actual TCP and
native admission, with unchanged global bounds. Per-request records include
failed calls, latency, transport CPU, zero transport trials, generation attempts
and preparation cost. Matched receiver observations record actual full-work and
dispatch thread CPU, including unknown/missing observations. Those CPU intervals
are nested and must not be added. Reactor CPU and physical network bytes are not
covered by those observations.

Summary records include all-call p50/p99, accepted-call p99, honest accepted
receiver calls per observed second, distinct honest packets accepted by all
receivers, refusal reasons, original budget flow and observation coverage.
The denominator includes client deadline tails. A packet-count bound ending a
phase early is explicit; it is not a completed duration claim. The source-fixed
trace/caller domains, observed genesis timestamp and seed header are retained.

```sh
cargo build --locked --profile test --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example pon_pure_ingress_campaign
target/debug/examples/pon_pure_ingress_campaign \
  --baseline-seconds 15 --attack-seconds 45 --receivers 2 \
  --attack-workers 4 --max-groups 8192 > ingress.jsonl
python3 scripts/ci/check_pure_pon_ingress_campaign.py ingress.jsonl \
  --output ingress-check.json
```

Loopback success is not a WAN or Sybil-liveness proof. Bounded resource use can
coexist with zero honest goodput under attack; retain that outcome. Real model
tasks, accelerator kernels, task supply, non-amortization arguments, multiple
physical hosts and independently reproduced longer runs remain separate work.

## Separate transcript-sidecar research

The [full-transcript sidecar cost and soundness screen](PURE_PON_TRANSCRIPT_SIDECAR_RESEARCH.md)
analyzes all 512 intermediate tiles, grouped Freivalds checks, random folding,
matrix-size thresholds and the missing quantum Fiat-Shamir argument. Its counts
are analytical, not a new campaign or proof of useful-work hardness. It does not
change any retained measurement, native acceptance rule or activation state.

## Source-derived native verification operation bounds

This is a static research calculation, not another benchmark. It refers to
`trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs` at source
`9e05ad5d237660fb0ea8b40dd5c29af4225551d3`, file SHA256
`9d28d64da80fd059c1619a17d24b6959a76bbdb64108600adc4dc95fe6c2636d`.
Line pointers below identify that exact source. The normal `verify` at lines
386–398 selects `VerificationKernel::Transposed` through lines 403–416;
this calculation does not substitute the reference or limb research kernel.

The counted multiplication is one **data operand times data operand** inside
the field dot products, accumulated in `u128` before reduction. It is not a
machine-instruction count. With `N=64`, `R=8` and `q=2^32-5`:

| Stage | Data-by-data scalar multiplications | Source |
| --- | ---: | --- |
| Four noise streams | 0; each generates 512 accepted canonical words | `expand_with_progress`, lines 195–221; calls at 704–707 |
| `E=EL*ER`, `F=FL*FR` | `2 * N*N*R = 65,536` | Lines 708–711; dot-product loop at 662–688 |
| All cumulative transcript tiles | `(N/R)^3 * R*R*R = 512 * 512 = 262,144` | Lines 732–765 |
| Four correction products after a matching trace | `4 * N*N*R = 131,072` | Lines 795–798: `A*FL`, its product with `FR`, `ER*B'`, its product with `EL` |
| Total through trace comparison | **327,680** | The trace mismatch returns at 614–615 |
| Total through final C comparison | **458,752** | Product reconstruction precedes the comparison at 624–632 |

All four noise expansions must finish before E/F computation starts. Each
stream permits at most 128 hash calls, then returns `NoiseBudget` if still
short; rejection sampling therefore has a code-enforced bound. A completed
stream needs at least 64 calls because each hash provides at most eight words.
No successful task or previous product skips these native verifier stages.

Reduction is additional work. Through trace comparison there are exactly
`8,192 + 8,192 + 32,768 = 49,152` calls to `producer_reduce`: E/F output,
construction of A'/B', and every cumulative tile element. The four correction
products add 9,216 reductions and final subtraction adds 4,096, for **62,464**
through C comparison. Each reducer at lines 646–654 contains two constant
multiplications by 5, two additions and at most one final subtraction. Those
constant operations, dot-product additions, transposes, byte copies, comparisons
and bounded allocations are not included in the data-by-data count above.

For SHA-256, distinguish a complete hash invocation from its 64-byte compression
blocks, including mandatory final padding. The helper at lines 159–168 prefixes
the 10-byte `TRNM-PON1\0`, a 2-byte tag length, the tag, and a 4-byte length
before every part. The trace at lines 729–731 instead uses its own 16-byte
`TRNM-PON-TRACE1\0` followed by the 32-byte challenge.

| Hash | Exact message bytes before padding | Compression blocks per invocation |
| --- | ---: | ---: |
| `task` | `10+2+4+2*(4+16,384) = 32,792` | **513** |
| `ticket` | `10+2+6+2*(4+32) = 90` | **2** |
| Each `noise` call | `10+2+5+(4+32)+(4+1)+(4+4) = 66` | **2** |
| Complete trace | `16+32+512*(8*8*4) = 131,120` | **2,049** |

The block count is `ceil((message_bytes+9)/64)`. Completing all four streams
and the trace therefore uses 259–515 hash invocations and **3,076–3,588
compression blocks**, counting task and ticket once. The upper count is
`513+2+4*128*2+2,049`; it is not 3,588 separate SHA API calls.

| Native return path, with the stated checks reached | Data-by-data products completed | Cumulative SHA compression bound |
| --- | ---: | ---: |
| Wrong length/version, zero target or noncanonical A/B/C | 0 | 0 |
| Wrong task | 0 | 513 |
| Ticket above target | 0 | 515 |
| `NoiseBudget` | 0 | At most 1,539 |
| Completed replay with wrong trace | **327,680** | At most 3,588 |
| Matching trace with wrong C | **458,752** | At most 3,588 |
| Successful `VerifiedWork` | **458,752** | At most 3,588 |

The cheap error order is explicit at lines 511–575. Production decodes only
A/B, checks the C wire words first and hashes the original canonical A/B bytes.
C comparison can stop at its first mismatch, but all corrections are computed
before that comparison. The retained test
`transcript_mismatch_skips_corrections_but_matching_digest_requires_product`
at lines 1549–1578 checks this distinction; it was read, not rerun for this note.

These bounds exclude header/challenge construction, Node state/task lookup,
outer prechecks that may duplicate hashes, network/disk work, scheduler effects,
allocator/system behavior and arbitrary caller progress callbacks. The plain
`verify` callback is a no-op. `verify_with_progress` may stop earlier at its
original cancellation checkpoints. Neither a callback count nor
`full_work_started` proves completion of all 458,752 products: a wrong trace
skips corrections, and a cancelled invocation may not finish even its trace.
This finite source operation count supplies no elapsed-time ceiling, CPU lower
bound, non-amortization argument or PoN security proof. All sealed observations
and their original failures remain unchanged.
