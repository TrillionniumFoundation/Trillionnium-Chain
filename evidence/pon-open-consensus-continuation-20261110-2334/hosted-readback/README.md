# Independent readback of hosted da1374a originals

**Readback: PASS. Business and public-consensus qualification: HOLD.** This
2026-11-10 package preserves three original GitHub Actions archives and checks
their existing observations. No native campaign was rerun and no retained ELF
was executed. These results belong to the older source below, not to subsequent
changes on the integration branch.

- Source: `da1374a200022bc14dc2bd325cc9ba29dbcd24ab`.
- Tree: `00479a98dabc6b1fd91a0ceef82ffbdbffb78067`.
- Workflow: [42771007925, attempt 1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42771007925).
- Branch at measurement: `fix/chain-hepta-closure-candidate-20261109-481716`.
- Each recorded source inventory reports 27,660 tracked entries and
  2,527,867,778 tracked bytes, with matching before/after identity. This is a
  verification of retained source receipts; this readback does not claim a new
  full native build or a new execution of that source.

## Original archives

`originals/` contains byte-for-byte ZIPs and the three corresponding artifact
metadata objects read from the GitHub API. Metadata retains the observed expiry
fields; local ZIP retention does not depend on future Actions availability.

| File | Artifact ID | Bytes | Original SHA256 |
| --- | --- | ---: | --- |
| `x64.zip` | 13742695023 | 5,578,450 | `563b273106cd6d123ee42d2a6ba1f6ff41972e41622daf459372b7d50386750a` |
| `arm64.zip` | 13741569215 | 5,557,454 | `57025dd4c0516cfb7d090d140e6bc9b20193773fa639faac9b15254dec12060a` |
| `fresh-service-head.zip` | 13741424505 | 5,823,146 | `50d19f5690bbac21e5a7a6c8e9d6578f26acb57437e77dfde9ba64a231e966de` |

Readback verifies ZIP digests, lengths and CRCs, 74 manifest attachment hashes,
source receipts, retained native binary identities, and the original process
outcomes. The four cost campaigns use release Rust 1.95.0 with the recorded
default build configuration. The x64 and arm64 ELF headers are checked as data.
The exact original Python readers and required configuration are obtained with
`git show` at the source above; their hashes appear in
`readback/independent-readback.json`.

## Cost observations and denominators

Each campaign contains 9 classes × 8 samples × 4 searches: 72 actual prefix
setups, 288 candidates and 573 trial attempts. Default mode has 1,152 verifier
records; full-limb mode has 1,440. Every recorded verifier outcome is
`Transcript`. Complete candidate bytes, hashes, ticket trials and the fixed
record grid are independently reconstructed by the frozen original reader.

**The same deterministic 288 candidate identities recur across both modes and
both architectures.** The replay explicitly checks this shared identity hash;
four campaign records do not constitute 1,152 independent fresh candidates.

The following aggregate ratio is the sum of production-verifier CPU time
divided by the sum of **full attacker cohort CPU time**, not a mean of ratios:

| Architecture / mode | Full attacker CPU (ms) | Production rejection CPU (ms) | Receiver / attacker |
| --- | ---: | ---: | ---: |
| x64 / default | 4.976304 | 113.974639 | 22.903472 |
| x64 / full-limb | 5.799338 | 113.902139 | 19.640542 |
| arm64 / default | 3.764008 | 92.407200 | 24.550213 |
| arm64 / full-limb | 4.655464 | 92.536856 | 19.877043 |

The denominator includes one actual public-prefix validation/serialization
setup reused across four searches, every challenge hash and missed trial,
trial-record construction, and winner-buffer clones. It excludes separately
recorded public-material generation, later buffer destruction, JSONL emission,
and network sends, queues, signatures or storage. The numerator covers native
full-verification calls without a fact cache. These are scoped CPU
microbenchmark observations, not measured public-network amplification or a
fastest-adversary lower bound. Within each architecture both modes use the same
binary; differences in these ratios do not establish an implementation speedup.

## Service failures retained without reclassification

The service run used the original four-second window, 16 attacker workers and
an independent client checking six depth/work confirmations. Both pressure
cohorts accepted all seven honest submissions yet confirmed **0/1** target
transactions inside that window. Baselines confirmed 1/1.

| Cohort | Native exit | Original reader failure | Last history replay | Pressure attack calls |
| --- | ---: | --- | --- | ---: |
| Original | 0 | `CONFIRMATION_TARGET` | index 2, `PUBLIC_REQUEST_DEADLINE` | 319 |
| Fresh challenges | 101 | `FRESH_NATIVE_PROCESS_REQUIRED` | index 0, `PUBLIC_REQUEST_DEADLINE` | 208 |

The original cohort's libtest pass reports observation completion; it does not
turn the business target into a pass. The fresh cohort's panic and exit 101 are
retained under the original reader's exact error. It is not relabeled
`FRESH_BUSINESS_TARGET`, nor credited with post-window confirmation.

The original last page expired in `cpu_wait` after `history_epoch_open`, before
packet work. The fresh last replay reached packet work but not admission:
packet-work CPU 67.316409 ms and wall 1.100883426 s; whole replay CPU
71.003650 ms and wall 1.597569214 s. Its 1,046 nested host-checkpoint calls report
66.335808 ms CPU. Nested phase times must not be added, and wall minus CPU is
not a measurement of lock wait. Detailed rows remain in
`readback/fresh-service-replay-phases.json` and the original archive.

The frozen service reader reproduces both failures and diagnostics. Its fresh
negative-cache readback finds 7/7 baseline and 205/205 pressure relation attempts
started full replay, zero cached rejections and zero exact-fact hits. That
cache-path observation does not establish service success, responsibility
across identities/restarts/receivers, or public network readiness.

## Reproduce the readback

Python 3.10+ and Git are sufficient. Use a repository containing the source
commit; the working tree may have later changes because reader bytes are
selected by commit. The output directory must not already exist. From the
repository root:

```sh
python3 evidence/pon-open-consensus-continuation-20261110-2334/hosted-readback/replay_hosted.py \
  --repo . \
  --source da1374a200022bc14dc2bd325cc9ba29dbcd24ab \
  --archive-dir evidence/pon-open-consensus-continuation-20261110-2334/hosted-readback/originals \
  --output-dir /tmp/pon-da1374a-hosted-readback
```

The script writes unpacked data, frozen reader sources and eight JSON readback
files to the requested output directory. It never invokes Cargo or a retained
binary. `readback/` retains the eight reproduced JSON outputs. `PASS` means
these observations, including the two failures, were reproduced; qualification
and activation fields remain false or `HOLD`.

Check all retained package files from this directory:

```sh
sha256sum -c SHA256SUMS
```
