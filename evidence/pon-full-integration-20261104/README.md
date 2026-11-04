# Fixed-combination integration observations

This directory retains source-specific facts for the continuation of Chain
PR #688. It does not qualify a new Chain/Hepta combination or activate a profile.
The sole engineering plan remains
[the development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Original business failures retained

[original-6f-failures.json](original-6f-failures.json) is a denominator-complete
projection of two original GitHub Actions artifacts at source
`6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029`, tree
`76d3b416eccc6a810634062e036f646f22bffc76`:

- [F0 artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41771598282/artifacts/13295252045):
  SHA-256 `b0d584b01e51bda9d5481aeb8c2a430dcf785c7f5eb2357939642291a4dfceca`,
  17,423,749 bytes. All six original four-second confirmations failed the SLO.
  Successful cleanup does not replace the failed business outcome.
- [Three-run artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41771598274/artifacts/13295139319):
  SHA-256 `ac3f2a7bcbe21c6b9943e7c136959df4d09ed485f5ae9bb116294d0df99ac488`,
  56,882,314 bytes. Of 27 planned rounds, 3 confirmed, 9 were observed without
  confirmation and 15 were unobserved. All three confirmations were no-attack
  baseline rounds and took more than 27 seconds from their actual start.

Five of six pressure phases recorded `PUBLIC_REQUEST_DEADLINE`; the remaining
phase was also unconfirmed but had no verifier-error string. Missing rounds are
not deleted, and this projection does not claim that every failure had the same
cause. These newer 24-actor campaigns are distinct from issue #639's retained
16-actor four-second gate. Both original gates remain unchanged.

## Native W1 finite strategy comparison

[w1-fixed-strategy-sensitivity.json](w1-fixed-strategy-sensitivity.json) retains
the exact source/tree, executable digest, raw manifest digest, complete producer
denominators, native verifier outcomes and exact conditional mean-work ratios.
It is an intermediate source observation at
`5ca846a887acbe1fe43e5cf9fc45ac90312a71a0`, not a claim that a later composition
was executed. This local commit contains the Linux x86-64/AArch64 SHA-2 assembly
backend and known-answer tests atop the original `6f458c4f` source.

The original V3 campaign completed all 30 shards (5 classes, 2 targets, reuse
horizons 1/8/64), with 8 actual setup cohorts per fixed strategy. Every raw
artifact hash and unchanged source/binary check was verified. The projection
records 960 cohorts, 23,360 searches and 389,788 attempts across all arms, with no
native semantic alert. Its CPU ratios are local diagnostic observations on a
shared machine. Common preparation, evidence, verification and end-to-end
business costs remain separately reported. No universally cheapest producer,
independent hardware, PQ system, model efficacy or public-service result follows.

The exact original execution command was:

```bash
TRNM_EXPECTED_SOURCE_SHA=5ca846a887acbe1fe43e5cf9fc45ac90312a71a0 \
  python3 scripts/ci/run_w1_false_trace_reuse_v1.py \
  --arch x64 --local --legal-strategy-v3
```

It used the original release profile, Rust 1.95.0, locked dependency graph and
no build-profile overrides. The enclosing receipt retained actual raw source
checks, binary copies and 70 artifact digests. The complete raw run remains
outside this source tree to avoid replacing reproducibility with a large binary
commit. The existing workflow regenerates the raw run for the newly pushed
source; no previous receipt is relabeled.

[derive_observations.py](derive_observations.py) reads the two exact ZIP files
under `readback/chain-6f-{f0,campaign}.zip` and the unchanged local receipt under
`w1-current-source/w1-legal-strategy-v3/`. Run it with that containing directory
as its sole argument. It checks the original artifact identities and every W1
artifact digest, preserves all planned rounds, and derives rational fixed-arm
sensitivities without upgrading any qualification flag. The security-model
interpretation lives in
[work cost and DAA boundaries](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md).

## State, recovery and retention counterexamples

The account-graph cache change was measured against the unchanged clear-all
policy with 510 complete traversals per variant. Every traversal retains the
same current SQL reads, progress callbacks and uncached-oracle result. Each case
contains two cold caches and 100 warm observations; the two prefilled cases
exercise a disjoint new working set after the full cache has been occupied.
The [complete retained evidence archive](lift-cache-evidence.tar.gz) contains
the raw traversals, commands, failures and comparison reader; its SHA-256 is
`34d0779fd302a2b67c59cff608dc00d0e1e96dd89df88b866012c806d9a24908`.
The [method and limitations](lift-cache-README.md),
[comparison](lift-cache-comparison.json) and
[artifact manifest](lift-cache-manifest.json) are available separately. The
integration updates the old inline workflow source pin to the exact new blob;
the earlier correctly rejected stale-pin check remains in that archive.

| Accounts | Unrelated prefill | Original warm p50 / p99, ms | Replacement warm p50 / p99, ms |
| --- | --- | ---: | ---: |
| 1,024 | No | 6.148 / 8.118 | 5.879 / 7.266 |
| 9,216 | No | 422.658 / 521.236 | 245.135 / 299.724 |
| 32,768 | No | 1,582.465 / 1,827.872 | 1,468.463 / 1,678.710 |
| 1,024 | Yes | 7.391 / 14.572 | 6.054 / 9.937 |
| 9,216 | Yes | 433.127 / 513.848 | 243.817 / 319.353 |

These are original debug-profile local graph diagnostics, with descriptive
nearest-rank p99, not an exclusive-host confidence interval, release speedup or
business confirmation. The cache has a fixed 8,192-entry limit per Node and a
compile-time 1-MiB allocation ceiling; the measured software charge is 983,080
bytes per allocated cache. Small graphs can pay more allocation than a partly
filled BTreeMap. Full SQL traversal remains linear, and Host/PQ/whole-State/
network confirmation costs are excluded from this diagnostic.

The [Cell ACK observation](../cell-ack-deadline-20261104/observation.json) retains
three actual failing writer-contention controls and the fixed retention suite
(33 controls) plus the complete Cell library (179 controls), with exact source,
commands and compressed raw logs. Six new native controls cover initial ACK,
lost-ACK retry, reconciliation, schema substitution, post-commit cancellation
and stale ACK versus retirement. The observation belongs to its stated source;
the integration workflow must still execute the composed source.

The [PQ recovery evidence](../pon-pq-system-continuation-20261101/cold-recovery-pin-20261104/README.md)
retains two actual old-method failures and fixed native successes. It preserves
the exact signature-only adapter used to execute the new controls against the
old cold-open body. The mandatory registry has 46 passes and one process control
blocked before business execution by Unix socket `EPERM` in this environment;
two additional process controls are blocked for the same reason. An escalation
was automatically rejected, was not retried, and no socket or deadline bypass
was introduced. The original CI remains responsible for those assertions.
The [effect-root review](../pon-pq-system-continuation-20261101/cold-recovery-pin-20261104/review.md)
enumerates all three protected PNQ2 tables and the larger effect states they do
not cover. It is a source review with executable counterexamples, not an
independent audit or a complete migration certificate.
