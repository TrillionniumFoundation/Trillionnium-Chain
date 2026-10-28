# Complete W1 Succinct proof: actual completion, benefit gate failed

This packet contains a **real complete Succinct STARK for the frozen, original
PNH1/PNW1 W1 relation**. All 59 original execution segments were proved, and the
final receipt passed fresh-process verification in both the pinned SDK 3.0.3
host and the separate hardened SDK 3.0.6 verifier. It does **not** pass work
package 2A's practical-benefit criterion: the saved proof is 5.2225 times the
native witness size, and its measured decode-and-verify median is 30.0526 times
the original native full-replay median on this fixed input.

Nothing here activates a consensus path, replaces Node admission, establishes
work hardness, or qualifies the chain as post-quantum. The original 90-minute
TIMEOUT and the subsequently interrupted supervisor remain separate failed or
unknown observations. Neither is rewritten as a successful controller run.

## Exact statement and source

| Item | Actual frozen identity or size |
| --- | --- |
| Original prover/guest source | `64be7c4ad51d432e7736ad135476262e23e968f5` |
| Original source tree | `4157fb5cec32f74dc0d0fe50a4ad93ee11eafbca` |
| Hardened verifier source | `dd4fb0a65a734bdccac23a061dc0d6c72b69188f` |
| PNH1 header | 318 bytes |
| PNW1 native witness | 49,188 bytes |
| Complete input | 49,506 bytes |
| Public journal | 16,818 bytes |
| Final full Succinct receipt | **256,886 bytes** |
| Final receipt SHA-256 | `ca4d3c9f5159b7001abae7491604cadbbbfa97c0f93d90d5943e48936813ca2b` |
| Existing work ID | `ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd` |
| Additional tickets from proof randomness | **0** |

The guest calls the original `pon_work::verify` through `native_replay`; it does
not substitute a task-only precheck, sampled openings, or a shortened transcript.
The relation includes canonical decoding, task commitment, nonzero target,
challenge-bound noise rejection, every ordered transcript prefix, full product
reconstruction, trace and ticket checks. The public journal binds the exact
header, trace, ticket, original block/work identity and complete product.
Final readback independently rechecks these public-byte bindings and verifies
the original prefix inventory hash, every immutable checkpoint file, and the
preserved prefix of the append-only stage log.

This is source reuse plus actual cryptographic and byte-level evidence, not a
formal proof of compiler correctness or the proof system's complete security.
The source-level relation and native/reference controls are documented in the
[relation implementation](../../formal/pon-nakamoto-v1/w1_zkvm/relation/src/lib.rs)
and [staged prover contract](../../formal/pon-nakamoto-v1/w1_zkvm/STAGED_PROVER.md).
The independent full gate is in the
[hardened verifier](../../formal/pon-nakamoto-v1/w1_hardened_verifier/src/main.rs).

Parent availability, the branch-required target, task-window rules, transaction
authorization, M06/state transitions and receipts remain Node responsibilities.
A proof of this complete W1 subrelation is not a proof of the entire block.
The existing work ID and chainwork rule remain unchanged; neither prover
randomness nor proof encoding creates another logical mining attempt.

The complete source recovery bundles are separately published under
[the source-closure packet](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/131f673d9563e72aca7139f3239856957d118d49/evidence/pon-w1-source-closure-20261028).
They require the stated public prerequisite commit; a shallow default-branch
checkout alone is not claimed to contain every frozen experimental commit.

## Actual outcomes and retained interruptions

All times in the raw records are UTC.

1. The original 5,400-second cumulative budget ended with an actual compression
   stage timeout, return code 124. Its original result SHA-256 remains
   `e5a7a12890293656f0f14afd7126dfa8569953aa4bfcfc1c7247ce73d9e0fddf`.
   All 59 segment proofs and a cryptographically verified 15,128,458-byte
   Composite existed, but the Composite was ineligible for final acceptance.
2. A separately declared continuation began at **02:07:15.241745**, retaining
   the whole original execution, prior costs and cached proof identities.
   Its total bound was 3,600 seconds; the original compression-stage deadline
   was **03:06:09.295086**, and the total deadline was **03:07:15.241745**.
3. The outer continuation coordinator, stage supervisor and observer were
   interrupted. The last old observer sample was at **02:18:32.766852**.
   The existing prover continued as an orphan with the same PID/birth identity,
   original arguments, process group and checkpoint. Its original supervisor's
   exit code, terminal `wait4` record and successful completion status remain
   **UNKNOWN**. No replacement record was written into that original directory.
4. A new observer started at **02:23:15.417842**, with a **282.650989-second
   observation gap**, **zero new budget**, and the original two deadlines.
   It observed the same existing prover; it did not start a new proof or combine
   assets from the rejected, differently randomized second execution.
5. The final full Succinct was saved and internally verified at
   **02:29:04.990881**. Six separately measured, fresh-process stages completed
   within the original continuation window: original full gate, original
   verifier benchmark, native full replay benchmark, hardened full gate,
   hardened verifier benchmark, and hardened controls. Their return codes are
   all 0, with no timeout or surviving owned process group.

The six fresh stages establish their own observations. They do not restore the
missing original supervisor outcome. The original 90-minute timeout, the
interruption, the observation gap and unknown exact exit settlement remain
engineering limitations even though the saved proof itself is valid.

## Fixed-input measured costs

These are actual repeated measurements of **one saved proof and one dense,
maximum-target input** in the shared container. They are not independent proof
trials or production latency percentiles. Quantiles use nearest rank.

| Operation | Samples | Median | Sample p95 | Sample p99 | Sample max |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original native full replay, including native decode | 1,000 | **0.5543925 ms** | 0.717368 ms | **0.841684 ms** | 2.246435 ms |
| SDK 3.0.3 verify only | 100 | 16.2155545 ms | 20.759946 ms | 21.695171 ms | 22.356775 ms |
| SDK 3.0.3 decode and verify | 100 | 16.3304765 ms | 21.117823 ms | 21.826558 ms | 22.935614 ms |
| SDK 3.0.6 verify only | 100 | 16.5901525 ms | 18.779270 ms | 21.443763 ms | 22.417586 ms |
| SDK 3.0.6 decode and verify | 100 | **16.660953 ms** | 19.409246 ms | **21.576132 ms** | 23.988215 ms |

The comparable primary ratio is hardened **decode-and-verify / native replay**:
**30.05263058** at the medians. Both exclude file I/O. Native replay excludes the
additional experimental journal construction. The separate verify-only ratio
is 29.92492232 and has a different decoding boundary. The receipt/witness size
ratio is **256,886 / 49,188 = 5.222533951**. The common external header is not
counted as a native witness or as an extra mining ticket.

The proof used the existing 8-thread prover configuration. The final fresh
verification stages had `RAYON_NUM_THREADS`, `RUST_LOG` and `RISC0_HOME` unset;
each actual stage declaration retains that environment. All stages shared the
container's 8 CPU / 8 GiB cgroup with other work. These results establish this
experiment's practical failure, not a universal hardware lower bound.

| Observed cost component | CPU seconds |
| --- | ---: |
| Original 90-minute pipeline, including retained prior setup/import/lift records | 33,168.416119 |
| Continuation's completed prefix re-verification | 2.235574 |
| Interrupted continuation compression, observed lower bound | **8,708.640000** |
| Six fresh gates/measurements/controls, actual `wait4` | 7.678947 |
| Recorded continuation preflight Python CPU | 0.31533837 |
| **Combined observed pipeline CPU lower bound** | **41,887.28597837** |

The continuation's old per-PID sampling and the new root/reaped-child sampling
overlap. Their bounds are combined by **maximum**, not addition. Missing
coordinator CPU, observer CPU and unobserved final process-exit accounting are
not invented. The largest observed single-process RSS in the original measured
pipeline was **2,470,932,480 bytes**; it is not an aggregate process-tree peak.

Recorded original-controller/prior durations plus continuation elapsed total
**6,712.315070 seconds**, including **700.173346 seconds** of coordinated pause
and the observation gap. This sum excludes the unmeasured interval between
rounds and is not an isolated end-to-end prover latency. Build costs, security
controls outside this pipeline, and the earlier monolithic one-hour failed
prototype remain separate observations in earlier evidence. They are not
silently converted into another successful independent proof trial.

There is **one independent full proof**. A prover p99 and a production verifier
tail are therefore unestablished. No more proving or optional performance trials
were added to make the result look better.

## Actual positive and negative controls

The hardened suite has exactly **24 total controls: one valid-proof positive
and 23 negative controls**, all matching their expected outcomes, **zero PANIC**.
The final reader checks the exact names, count, expected outcomes and original
bytes/hashes of all 48 header/receipt control assets. Mutations cover malformed
encoding, forbidden Composite/Groth16/Fake tags, the expected header, all public
journal fields, control ID, verifier parameters, hash suite, claim digest and
seal content/length/field encodings. The full archive retains every asset.

The separately retained real-prefix-as-full control uses an actual valid prefix
receipt with the full expected journal. Both full gates reject it for claim
digest mismatch; that record is not a fake-proof or format-only test. Earlier
guest-panic observations remain separate diagnostics, not automatically accepted
as cryptographic negative-proof controls.

The older SDK's metadata-binding observation and the hardened verifier repair
do not imply an arbitrary W1 forgery. Likewise, transparent STARK terminology
does not establish a 128-bit quantum security level. The retained soundness
calculator outputs are component analyses under their stated classical bounds;
they are not a full 59-segment theorem, QROM proof or physical quantum attack.

## Packet layout and independent checking

- [final-readback.json](final-readback.json) records every frozen-asset, source,
  binary, public-statement, control, stage and cost comparison.
- [post-gate-tracked-source.json](post-gate-tracked-source.json) records the
  post-gate byte-level check of **5,502 tracked entries / 706,320,655 bytes** at
  the original clean source. The later evidence commit is not relabelled as the
  runtime-tested source.
- [full-proof](full-proof) contains the actual final receipt, header, input,
  journal, guest ELF, frozen manifest and complete append-only stage log.
- [measurements](measurements) keeps all six fresh stage declarations,
  `wait4` results and original stdout/stderr directly reviewable.
- [runtime-records.zip](runtime-records.zip) retains 493 original runtime/review
  payload members, plus manifest and README; all payload bytes were reopened
  and checked. Intermediate proof and mutant byte assets are in the larger
  archive, rather than being silently claimed to exist in this smaller ZIP.
- [archive-receipts.json](archive-receipts.json) identifies the separate complete
  raw archive: **65,349,319 bytes**, SHA-256
  `5a888ab56f0a656ac26df5caf79a6c46c71b1e53110d189ca1a951591ddb5ac4`,
  **923 payload / 925 total members**, all reopened and hash-verified. It includes
  the original, rejected-second and whole-session-adopted execution checkpoints,
  every original segment and recursive proof, internal Composite, final proof,
  all control assets, and this staged pipeline's retained failures and observers.

After building the pinned hardened verifier from its recorded source and lock,
the saved proof can be independently checked without rerunning the prover:

```sh
trnm-w1-hardened-verifier verify full-proof/header.bin full-proof/succinct.bin
```

The `sources` directory preserves the exact measurement/readback scripts used
in this environment. Their recorded absolute paths identify the original
observations; an independent audit should resolve them to the corresponding
archive members rather than treat a directory name as a security authority.

## Decision

**Full-relation cryptographic prototype: completed. Single-work practical
benefit: failed. Work package 2A: not accepted.** Retain native W1 as the existing
experimental validation path; this result does not qualify it for production
or justify an implicit proof-system fallback. Any later batching or recursive
aggregation proposal must preserve every original relation, original work ID,
required target and admission check, and demonstrate new measured amortized
benefit under a separately declared workload. This experiment establishes no
such future benefit.
