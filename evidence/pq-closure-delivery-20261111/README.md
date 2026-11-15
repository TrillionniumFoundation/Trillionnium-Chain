# PQ convergence delivery — HOLD / NO-GO

This continuation composes the reviewed PQ account boundary, complete-key TLS
checks, live provider-history fence, typed V5 Root witness, durable witness
register, hash-purpose inventory, and exact-source CI controls on PR #894. It is
delivered in [draft PR #901](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/901).
Whole-chain PQ qualification and production activation remain **false**.

## Source identities

| Role | Commit | Tree / scope |
| --- | --- | --- |
| Parent, PR #894 | `31543fb6dde565b62b47436e0b1d399b6d0bd772` | Historical parent observations retain this identity |
| Composed runtime checkpoint, C0 | `8add285b6c0a91d8b7812efe2d02c9342f74c91b` | `8aaa486aa4ccd4e41e33241fb4e7e273d3c3d5f6` |
| Native and hosted observation source, C1 | `c09dbbe9921da12db8bf7240a8a95a0e9a789e50` | `f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6` |
| C1 prospective merge | `61589dddd13e7495369aaecad9212668049417c1` | Same tree as C1; distinct source identity |
| Readiness correction, C2 | `0e554f36ffdde3053a5eb1756eb5e526b1935032` | `753cdbad6714f00d8ccb9ddbb47f0fd71280ee62` |

C2 changes three files: the readiness checker, its existing test file while
retaining the same 71 top-level test IDs, and the source-corpus JSON containing
two reviewed blob-pin updates. Every Rust source blob is unchanged
from C1. The corpus is embedded by Node unit-test and example inputs, so C2 is
not classified as an evidence-only revision. Its selected native/Clippy
observations retain C2 separately. The final delivery adds evidence to C2;
previous native or hosted runs are not relabeled as execution of that later
Git identity.

## Concrete changes and retained limits

- M06 account effects, state roots, and fresh/cold/warm Node ownership require
  the existing explicit development-only fields. Missing, null, mistyped, or
  production-like values refuse before effects. An explicitly selected
  classical development profile still performs real test-ledger activity;
  complete deployed PQ account migration remains open.
- Complete canonical ML-DSA SPKI checks and the live provider-history fence from
  #894 remain in place. A public-key identifier alone does not authorize a
  different full key. The live-history fence does not qualify cold restoration
  of every authority together.
- V5 adds a typed witnessed Root owner and a fresh-namespace durable SQLite
  witness register. Pending, anchor CAS, signed acknowledgement, and completion
  retain distinct recovery states. The provider journal remains its V3 consumer;
  this change does not install an independent witness daemon, wire transport,
  M15/effect/FinalUse route, or physical custody arrangement.
- The hash-purpose contract distinguishes 17 uses across 26 bound source/profile
  files: 25 Rust files and one JSON profile binding. Historical commitments and
  roots retain their original strength;
  concrete quantum query/reduction bounds and whole-call-graph coverage remain
  unqualified.
- QROM historical fixtures come from their original Git blobs. Current V1
  refusal, current V2 mapping, and historical success remain separate. The
  gate recomputes complete reports and rejects six retained substitutions that
  the initial composed gate accepted. The original 81-control roster is
  unchanged; separate 8/14 controls require actual named completion.
- The durable readiness checker now binds the reviewed account guard before
  namespace effects. Four subtest mutations reject deletion, commenting,
  ignored refusal, and moving the guard after filesystem effects. The old
  complete-body digest is not a fallback for current source.

## Evidence map

| Package | What it establishes |
| --- | --- |
| [Integration and historical failures](../pq-closure-integration-20261111/README.md) | Immutable original 241-file package; prior source roles, red/green report mutations, and earlier #894 observations |
| [C1 selected static observations](../pq-closure-validation-c09dbbe992/README.md) | Original incomplete run retained, separate resumed completion, exact source snapshots, 577 top-level test/control executions |
| [C1 required gates](../pq-closure-validation-c09dbbe992/REQUIRED_GATES.md) | Separate 55 claim-guard and 77 execution/source-integrity controls, 132 executions |
| [C1 hosted observations](../pq-closure-hosted-c09dbbe992/README.md) | Actual campaign, cross-architecture, fresh-challenge, QROM, SARIF, API-export, and stale-readiness outcomes |
| [C2 cloud observation](../pq-closure-readiness-0e554f36ff/cloud/README.md) | Failed 71-test run with three missing-GNU-time errors; separate 60-test corpus and seven source checks passed |
| [C2 desktop readiness](../pq-closure-readiness-0e554f36ff/desktop/README.md) | 71 actual unique successful IDs with GNU time; original wrapper pathname failure and independent inventory correction preserved |
| [C2 publication](../pq-closure-readiness-0e554f36ff/publication/README.md) | One ordinary push with project hook; failed CLI body update retained separately from successful REST body update and readback |
| [C2 hosted status](../pq-closure-readiness-0e554f36ff/hosted-pending/README.md) | At the recorded observation, required-baseline remained pending and no readiness jobs were returned; no hosted 71-test pass is inferred |
| [Bounded dependency mapping](../pq-closure-dependency-readback-0e554f36ff/README.md) | Seven default-branch alerts concern the old pip `cryptography==41.0.7` pin; C2's exact `50.0.2` pin is outside those seven ranges, without a zero-vulnerability claim |
| [Native observations](../pq-closure-native-observations-20261111/README.md) | Original C1 group with both timeouts preserved; separate remaining-case coverage and the exact C2 embedded-input/Clippy recheck, with independently verified archives |

Counts describe executions, not independent security properties. C1 has
577 + 132 = 709 completed top-level Python test/control executions. The earlier
incomplete command's missing terminal outcome remains unknown. C2's corpus
rerun and readiness observations are not added to a count of unique C1 controls.
Portable evidence verification reads retained bytes and does not rerun a native
workload or attest the host.

Hosted packets are observations at their recorded times. The C1 packet still
had required-baseline work without a terminal observation, and the C2 pending
packet contains no completed readiness jobs. Neither packet represents a final
result for every hosted CI job.

The C1 hosted package's opening reference to “241-control evidence” denotes the
earlier **241-file** integration package. It is not a count of executed controls;
the execution counts above come from named completion records. This clarification
leaves the frozen collector package byte-identical.

Four original raw logs contain captured trailing whitespace or terminal blank
lines. Their [formatting observation](raw-evidence-whitespace-observation.json)
is preserved, and their bytes are not normalized. A new, narrowly scoped
[evidence attribute file](../.gitattributes) applies the repository's existing
immutable-log convention to those four exact new paths. Text diffs remain
available; source formatting rules and all pre-existing C2 Git blobs are
unchanged. The complete delivery checksum list covers the metadata file too.

## Original failures remain binding observations

The C1 three-run campaign completed source/build/startup/finalization and all
economics reports, but all nine phase criteria failed. Each baseline confirmed
one of three rounds; all six attack phases confirmed zero of three rounds with
`PUBLIC_REQUEST_DEADLINE`, and none observed the required credit depletion. The
three baseline verifier-error arrays were empty. The original 30-second phase
window, round count, block depth, and 24 attack actors were retained.

Both architecture cost lanes failed the original four-second confirmation
target under 16-worker pressure despite their five native invariant tests
passing. Both x64 fresh-challenge lanes ran real native processes and exited
101 on the original four-second/six-depth target. Baselines confirmed one
transaction; pressure phases confirmed zero. These results do not identify a
unique performance bottleneck or prove a quantum attack, and successful
observation/artifact retention does not turn them into business passes.

The six local CodeQL lanes completed successfully. Each Rust lane retains 857
raw `rust/hard-coded-cryptographic-value` findings, each Python lane two
`py/redos` findings, and Actions zero. Repeated head/merge results are not summed
as unique issues. The Python locations are unchanged historical evidence
scripts; the bounded source review does not dismiss the findings. The Rust
findings have not all been individually triaged. The separate exact-source API
exporter exhausted 39 actual polls with empty required analyses/checks and
remained incomplete. Local SARIF used `upload: never` and does not satisfy the
Code Scanning API gate.

The [bounded SARIF inventory](CODEQL_FINDINGS_REVIEW.md) identifies 857 distinct
Rust primary locations across 95 files after comparing both lanes' actual URI
tables and regions. Its pathname categories are not exploitability or deployment
classifications. A separate [local source review](CODEQL_SRC_GATES_REVIEW.md)
examines the 101 locations in the remaining `src` category: 98 are within
explicit `#[cfg(test)]` modules. The remaining locations are two fully overwritten
SPKI buffers and one hex-decoding buffer that flows into reveal salt. This does
not prove deployed build exclusion,
all-caller safety, salt randomness or input authentication. All findings remain
unresolved by these bounded reviews; no suppression or alert dismissal occurred.

The original C1 desktop group completed all 27 commands with unchanged source
and provider bytes. Thirteen native targets passed completely, covering 66 of
the 97 planned native executions. The 14-case provider target timed out at
1,200 seconds after four named successes; the 17-case V5 witness target timed
out at 1,200 seconds after six named successes. Both received the owned process
group's SIGTERM and exited -15. Their partial results are separate from the
66 complete-target successes. The 12-case durable V5 target passed completely.
All selected Node account, settlement, complete-key TLS, QTX1 recovery, and
distinct-invalid-work targets passed. Strict workspace/all-target/all-feature
Clippy also exited zero. The original group remains unsuccessful.

The retained original archive has 90 members. An independent read verified all
27,912 tracked file entries, representing 20,796 distinct Git blob identities
and 2,554,106,689 bytes across those entries, by recomputing the referenced
content SHA-256 values against the original before/after source records. This
verifies the recorded source bindings; it does not attest the host or the
execution itself.

Separate C1 observations completed the ten remaining Provider cases and eleven
remaining witness V5 cases, with the original binaries, one test thread and
unchanged 1,200-second native limits. Their full source and Provider observations
closed unchanged. The [coverage calculation](../pq-closure-native-observations-20261111/C1-COVERAGE.json)
records 97 distinct successful names across the three groups: 66 + 10 original
partial + 21 later subset names. Both original aggregate success flags remain false;
the later observations do not establish their original aggregate time budget.

The separate C2 native group completed all 14 commands successfully, including
eight Node cases: four account-scope cases, one settlement case, and three
complete-key TLS identity cases. Strict workspace/all-target/all-feature Clippy
also passed with warnings denied. Its before/after source records cover the
same 27,912 entries and 2,554,108,569 bytes, and its Provider records match. The
test and development build profiles remain unoptimized with debug information;
no workload deadline or profile was relaxed. The 51-member C2 archive and both
portable evidence checks are retained in the native packet. Those results
belong to C2, while the original C1 aggregate and hosted failures remain binding.

## Qualification obligations still open

| Layer | Outstanding qualification |
| --- | --- |
| Accounts | All deployed entry paths, account/profile migration, recovery and historical authorization |
| Root and recovery | Independent custody, freshness outside the common-restore domain, post-restore challenge entropy, real witness/effect adoption, operational restoration and power-loss evidence |
| Transport | Every public/WAN/recovery path, peer identity, key/certificate lifecycle, and recovery operation |
| Commitments | Old roots and historical commitment migration; complete coverage of each actual hash purpose |
| Work and consensus | Quantum work costs, DAA/timestamp/chainwork composition, and original service/adversary-budget qualification |
| Lifetime composition | Complete shared query accounting, concrete reductions and assumptions, and an actual whole-chain failure-probability budget |

The fixed reversible W1 oracle and the source/control results do not provide a
quantum-mining theorem. Unknown bounds remain unknown. No whole-chain PQ or
PQ-128 product claim, production activation, main merge, or self-approval is
part of this delivery.
