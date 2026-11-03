# Canonical ASCII classification probes — all candidates rejected

These are local component experiments against the helper in source
`6ee97ee8f2955d2d0cd4a451268a906c5aa07584`, tree
`29994c32f554f7f5201bb793a19e54f6616a3354`. **No production Rust source was
changed.** None of these results qualifies the original ARM Node CPU selector,
four-second service, hostile workload, or whole-node throughput.

The [manifest](manifest.json) binds all 21 original source, plan, result and raw
sample files. Each standalone baseline exports the exact existing helper body
with `pub` visibility added for the observer. Each candidate is separate. The
observer compares both implementations with a scalar byte oracle, including
all byte values, block boundaries, paired boundary bytes and deterministic
random inputs. Each built variant passes the same **545,361** oracle cases;
repeated executions of those cases are not additional unique coverage.

## Fixed rules and complete outcomes

Each profile/workload executes 16 ABBA rounds and 64 samples. The main metric is
calling-thread CPU from the actual Linux thread clock. The paired ratio is the
sum of both candidate samples divided by both baseline samples in one round.
With 16 rounds, nearest-rank empirical p95 is the largest round ratio. It is not
a population-tail estimate or a confidence guarantee.

The debug large-string rule requires median <= 0.95 and empirical p95 <= 1.05.
Release and added non-regression workloads require median <= 1.05 and empirical
p95 <= 1.10. All applicable rules must pass. Every plan precedes its own capture;
different implementations' samples are not pooled.

| Candidate and workload | Debug median / p95 B/A | Release median / p95 B/A | Disposition |
| --- | --- | --- | --- |
| One u128 lane, 4,080-byte strings | 0.538942 / 0.625971 | 0.973799 / **1.288290** | Reject release tail |
| Two independent u64 lanes, 4,080-byte strings | 0.457696 / 0.523944 | 0.870572 / 0.945402 | Partial workload pass |
| Two independent u64 lanes, short strings | 0.756670 / 0.870444 | 1.027021 / **1.305466** | Reject candidate |
| Long-only two-lane path, 4,080-byte strings | 0.455057 / 0.545767 | 0.930715 / **1.214567** | Reject release tail |
| Long-only path, 255/256/257/511/512/513-byte boundary mixture | 0.579228 / 0.655120 | 0.892063 / 1.011638 | Partial workload pass |
| Long-only path, short strings | 0.927210 / 1.085794 | 1.045777 / **1.233139** | Reject candidate |

The first implementation classifies sixteen bytes as one u128. The second
uses one sixteen-byte load and two independent u64 lanes, avoiding a cross-word
borrow chain. The third uses that wider path only from 256 bytes and shares the
original eight-byte tail path for shorter inputs. They are different code
candidates. The latter candidates address observed short-input overhead; they
do not erase earlier failed rules.

Each large-string sample contains 2,100 complete calls on 4,080-byte inputs.
Short samples repeat their declared 2,100-string mixture 64 times; threshold
samples repeat theirs 16 times. The six captures retain **768 timed samples**
in total. All planned calls complete. Raw observations, including slow and
outlying samples, remain in the corresponding JSONL files. Compiled executables
are omitted; exact compiler commands and binary digests remain in the results.

## Reproduction and limits

Use Linux with a 64-bit Rust 1.95.0 host toolchain:

```sh
python3 -B evidence/canonical-ascii-probes-20261103/replay.py --verify-only
python3 -B evidence/canonical-ascii-probes-20261103/replay.py \
  --rustc rustc --work-dir /tmp/new-canonical-ascii-probe
```

The first command checks retained file identities and complete sample counts;
it does not execute Rust or turn a rejected experiment into a pass. The second
copies the frozen source into a new directory, compiles and executes both
profiles, and writes fresh observations. It refuses an existing output path.
New timing results describe that new environment and cannot rewrite this
capture's disposition.

These are same-executable comparisons of standalone helpers, with Rust opt-level
0 or 3 and debug information disabled. They are not Cargo workspace builds or
independently built Node comparisons. They measure neither peak RSS nor complete
serialization, validation, hashing, Host checks or confirmation. A faster debug
helper cannot establish a successful original CPU-budget admission. The release
tail failures remain failures even where median or debug results improve.

Keep the production implementation and every original deadline, resource limit,
error, callback, accounting and activation rule. **DRAFT / HOLD / NO-GO** remains.

Original records:

- [Single u128 plan](single-u128/plan.json), [result](single-u128/results.json),
  [debug samples](single-u128/debug-component.jsonl), [release samples](single-u128/release-component.jsonl).
- [Two-u64 plan](two-u64/plan.json), [result](two-u64/results.json),
  [debug samples](two-u64/debug-component.jsonl), [release samples](two-u64/release-component.jsonl).
- [Long-only plan](long-two-u64/plan.json), [result](long-two-u64/results.json),
  [debug samples](long-two-u64/debug-component.jsonl), [release samples](long-two-u64/release-component.jsonl).
