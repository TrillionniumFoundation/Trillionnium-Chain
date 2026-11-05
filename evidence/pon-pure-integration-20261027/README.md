# Pure PoN integration observations — 2026-10-27

These are observations of identified source commits, not an aggregate release
qualification. The six-item implementation table in the sole development plan
remains authoritative about open blockers.

- `first-ci-failure.json` records the first published source's native/fuzz lock
  mismatch. The failure was retained and the shared dependency versions repaired.
- `local-first-checks/manifest.json` retains the initial checks, including the
  sparse-checkout Markdown failure, missing offline package cache, and the two
  strict Clippy constant-assert errors. The full resolved Cargo graph is retained
  as gzip rather than shortened to a dependency count.
- `repaired-clippy/manifest.json` binds the successful strict all-target,
  all-feature crypto/protocol and node lint runs to source
  `400f034e611073da7259d62b57e2ba3a93904762`. These are lint results, not runtime
  test results and not evidence for an untested later source.

The ingress evidence reader initially could not start in the local sparse
checkout because its tracked gzip fixture was absent. Materializing the existing
tracked evidence directory allowed all eight negative-control tests to execute
and pass; no fixture or rejection predicate was changed to obtain this result.
The focused CI checks the full checkout and executes this reader independently.

For published source `21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`, the CodeQL
exporter run [40476862879](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40476862879)
failed while waiting for exact-source analyses/checks to stabilize within its
1,200-second deadline. Its 16 exporter unit tests and before/after source checks
passed. The retained artifact is
[12722151935](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40476862879/artifacts/12722151935),
with ZIP SHA-256 `866da7a8c28fdacb48f2239d0fc49e518399afe52579f376ab4a4a584fdac267`.
This timeout is not a completed CodeQL security assessment. The required baseline
workflow for that source was still queued at this observation; the additional
focused workflow does not remove or replace any required gate.

## Exact-source native integration completed on d9613853

[Run 40482711707](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40482711707)
completed successfully on source `d96138532b656d767d1ef46f6db86e7effae485e`,
tree `bcf061827dd81cbd4c29378ef53ebac23cd976be`. This is the focused native
workflow, not an aggregate claim that every required repository check passed.
It completed source-contract and negative controls, locked dependency and format
checks, retained crypto/wire tests, all 161 public-ingress tests, two public-task
bootstrap tests, five durable PQ-owner tests, the actual pure-profile CLI test,
and strict Clippy for all three changed native crates and their targets.

All three campaign executables were built before the measured experiments. The
finite rejection-tail campaign, full fixed cost matrix, actual TCP ingress
campaign, their strict readers and final source-byte verification also passed.
The full decoded job log is retained in [the CI manifest](ci-success/manifest.json).
All 29 files from artifact `12724159202` were downloaded, its complete ZIP
SHA-256 was verified against GitHub, and every original file is retained losslessly
under [native-focused-d961](ci-success/native-focused-d961/manifest.json).
Plain files are stored as gzip; already compressed raw streams retain their
original bytes. [Independent local reader reruns](ci-success/root-artifact-recheck.json)
recomputed exactly the same three reports from those downloaded raw streams.
No reader rerun is described as a second native experiment.

The same source's [CodeQL exporter attempt](ci-failures/codeql-d961-observation.json)
timed out after 1,200 seconds while waiting for exact-source analyses/checks.
Its 16 exporter tests and before/after source checks passed; this still is a
failed export and no completed CodeQL assessment. The required baseline and
priority lanes retain their own outcomes; the focused PASS does not replace them.

The required baseline's external-evidence-contract lane also failed on this
source. Its public-readiness suite ran 48 tests with 40 failure reports and
19 errors because durable-schema source controls expected an old unwrapped
DDL/schema-id call pair. The actual source already uses
`shared_snapshot::Layout` wrappers. The store, reader and test files are all
byte-identical at the original `c96022b8` integration base and tested `d9613853`;
this is a retained pre-existing gate failure, not a green overall baseline.
The complete job log and exact baseline comparisons are in
[the failure manifest](ci-failures/manifest.json). Any repair must preserve
strict layout selection and the original negative controls, rather than remove
the schema boundary.

### Complete finite cost and service observations

The hosted long matrix retained all 3,456 cohorts: 1,600 supported cohorts and
1,856 explicitly unsupported combinations. It recorded 605,024 attempts,
80,836 winning verifier calls and 50,764 exhausted searches. Wall time was
425.274 seconds; process user/system CPU was 421.873/3.144 seconds. Repeated
winning calls are not unique new blocks, and shared streams are not independent
samples. All misses, setup costs and unsupported strategies remain visible.
This is a second environment's observation alongside the original local run,
not a replacement for the original timings and source identity.

The hosted TCP experiment lasted 105.539 seconds with two receivers, two
listeners per receiver, four malicious workers and cold budget reopens. There
were 3,057 unique malicious packets, delivered to both receivers for 6,114
actual calls; all were refused as `WORK:Transcript`. The original shared budget
owner and zero-credit cold-start rules were retained.

| Hosted phase | Accepted honest calls / offered calls | Unique honest packets | Honest p99 | Accepted receiver calls/s |
| --- | ---: | ---: | ---: | ---: |
| 15-second baseline | 582 / 582 | 291 | 29.027 ms | 38.706 |
| First 45-second attack | 820 / 820 | 410 | 165.403 ms | 18.185 |
| Second 45-second attack | 832 / 832 | 416 | 155.632 ms | 18.435 |

These are fixed-parent empty candidates on one nonexclusive host. They do not
measure growing-chain TPS or establish WAN, independent-host or arbitrary-Sybil
fairness. Measured malicious receiver dispatch CPU was 23.435 seconds against
11.918 seconds of sender seed, preparation and client CPU, a ratio of 1.966.
Reactor CPU is outside dispatch; full-W1 CPU is nested inside dispatch and must
not be added a second time. No separate transport hashcash was introduced.

The hosted finite rejection campaign retained 83 cases, nine rounds, 747 paired
rows and 2,988 actual calls. Product mutations sample 64 diagonal entries,
including final entry 4095; they do not cover all 4,096 entries. Three false
final-trace-digest byte positions are not three intermediate trace-tile positions.
Each fake-trace case passes the native target before rejection is measured.

| Hosted path / family | Samples | Finite wall p99 | Finite maximum |
| --- | ---: | ---: | ---: |
| Paired valid full verifier | 747 | 0.777370 ms | 1.171586 ms |
| Wrong product, full verifier | 576 | 1.044428 ms | 1.227309 ms |
| Wrong product, product filter then verifier | 576 | 0.035155 ms | 0.042710 ms |
| Correct product, false trace, full verifier | 27 | 0.549134 ms | 0.549134 ms |
| Correct product, false trace, filter then verifier | 27 | 0.720053 ms | 0.720053 ms |

The last two rows preserve the blocker: a public-product fact cannot validate a
trace. Correct-product false-trace packets still trigger the complete native W1
relation. None of these finite maxima is a mathematical or scheduler-independent
upper bound. A real complete-relation certificate needs separate verifier,
late-corruption and global-service measurements before admission can change.

## Reproducible observed source snapshots

[The publication mapping](observed-source-publication.json) preserves the exact
source trees used by the original measurements at reachable immutable commits:

| Original local source | Published identical tree | Measurement scope |
| --- | --- | --- |
| `a26623359d01ba6b9429726f3b05cb2e4145d4e6` | [dcd027ff](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/dcd027ffa0ac1ac77bdfa0da9f13ab8ee43ba2d7) | Original cost and ingress campaigns |
| `bfcc21c08f14685dce27b7e4f99b567f3b6f34f0` | [b1ff52da](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/b1ff52da07618b8bb3506c653fa8c4855c0580c8) | Original finite rejection-tail executable |
| `9e9939b2d9ac97c7172ef141c9920225d2516236` | [5c8cd8bd](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/5c8cd8bd59cd9d8197617239664e66dd8b086baa) | Optimized W1 runtime source snapshot |

These API-created commits are byte-preserving publication mappings, not the
commits checked out at original run start. In particular, the optimized local
W1 attempt began at `576b3864` with dirty runtime files; all 19 runtime file
hashes were subsequently matched to the `9e9939b2` snapshot. That distinction is
retained. An identical source tree does not transfer later test results backward
or turn local execution into a transferable proof.
