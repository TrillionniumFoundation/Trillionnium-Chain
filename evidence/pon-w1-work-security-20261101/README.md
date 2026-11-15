# PoN W1 work-security local evidence: 2026-11-01

**Scope: local native source-module observations, with separate Cargo graphs.**
These records are not complete-workspace execution, public-service acceptance,
independent-hardware evidence, a work-cost lower bound or production approval.
Hosted CI for the integration candidate is **pending** at packaging time.

The checkout was restored as a source-only sparse candidate. Historical evidence
was not fully restored, and the complete original workspace graph and full
repository test suite were not executed for these captures. The baseline commit
`cea95fb44d8152a0eb1138727619fcced056f496` identifies the parent checkout;
working-tree candidate changes were measured through their retained source
hashes. It is not an assertion that the parent commit contains the new example
or experimental verifier. Do not relabel these captures with a later commit.

## Subsequent integration overlay

Both local captures occurred **before** the subsequent upstream integration of
`acd8f79f2dcc22ecdee1d1a5fd88d619d06f37c9`. Their original manifests continue to
record baseline `cea95fb44d8152a0eb1138727619fcced056f496` and the actual measured
source hashes; no manifest or raw capture has been retagged as an execution on
the newer composite source.

That upstream overlay changes cache wrong-length rejection, State encoding reuse
and metadata. It does not change the measured `pon_work.rs` default full-verifier
or new campaign example bytes. The campaign directly invokes the four primitive
verifiers and does not call the work-fact cache. This unchanged measured call path
does not qualify the entire updated module, cache, node or integrated workspace.
Any modified ancillary-source hashes in the original inventory remain historical
observations. The newly composed full source still requires its own actual CI;
these cache-free captures are not final whole-module or whole-project validation.

## Retained observations

Both captures use the fixed nine diagnostic material classes, eight samples per
class, four independent searches per actual public-prefix preparation, target
`7f` followed by 31 `ff` bytes, seed zero and a 4,096-attempt ceiling. They acquire
no honest proof. Each contains **72 real setups, 288 searches, 573 hash attempts,
288 complete forged candidates and 1,152 native verification calls**. Every
production, reference, existing-limb and experimental-column-limb call returns
`Transcript`. No malformed or unexpected acceptance was suppressed.

The actual machine reports AMD EPYC 9V74, x86_64, Linux kernel 6.18.57. Both builds
use Rust 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`, LLVM 22.1.2), release
profile, on the same local host. They are not independent host observations.
Thread CPU and wall timestamps are observations, not hardware or execution
attestations. Normal allocation, scheduling and CPU-frequency variation remain.

Each number below is the sum of native rejection CPU divided by the sum of
**all actual attacker cohort CPU** for that class. Each class denominator keeps
all eight actual setups and four searches per setup, including every failed
hash attempt, challenge derivation, trial hex/retention and winning-buffer clone.
The final row divides aggregate CPU totals; it is not an average of ratios.

The interval excludes separate material generation, subsequent retained-buffer
destruction, JSONL evidence output and network sending. Hex/trace retention is
not a necessary attack cost. Hash midstate reuse, longer preparation reuse,
avoiding evidence allocations, different algorithms and different hardware may
cost less. No public-network amplification, network fanout, admission/lease
binding, queue fairness, honest confirmation latency or model utility is measured.

### Trial 1: original local module graph

[Original manifest](trial-1/manifest.json) and [raw capture archive](trial-1/campaign.jsonl.xz).
The measured graph uses serde 1.0.229 and serde_json 1.0.154. This first observation
is retained unchanged, including its graph distinction and limitations.

| Material class | Production | Reference | Existing limb | Experimental column-limb |
|---|---:|---:|---:|---:|
| periodic-dense-fixture | 28.620051 | 30.348505 | 23.383669 | 26.662567 |
| full-rank-field | 33.896554 | 38.544687 | 28.108569 | 31.300267 |
| zero | 39.830586 | 43.453557 | 30.950400 | 36.563454 |
| identity | 38.755084 | 40.126284 | 30.754387 | 35.233417 |
| rank-one | 31.899587 | 31.441975 | 26.670878 | 28.734172 |
| sparse-diagonal | 25.265804 | 26.614985 | 20.534591 | 23.292636 |
| continuity-maintenance-v1 | 27.687769 | 30.445059 | 22.609709 | 25.367624 |
| one-zero-left-rank-one | 15.279228 | 15.868723 | 13.693640 | 15.794185 |
| one-zero-right-rank-one | 27.686186 | 28.679633 | 21.999643 | 25.638768 |
| **Aggregate of all measured CPU** | 27.625466 | 29.323928 | 22.624791 | 25.736126 |

### Matching direct dependencies: frozen second local module graph

[Original manifest](matching-direct-deps/manifest.json) and
[raw capture archive](matching-direct-deps/campaign.jsonl.xz).
The frozen second graph uses the repository's direct versions of serde 1.0.228,
serde_json 1.0.149, sha2 0.10.9, hex 0.4.3, rustix 1.1.4 and thiserror 1.0.69.
It still has eight transitive-version differences: bitflags, cfg-if, libc,
memchr, proc-macro2, quote, unicode-ident and zmij. Exact versions are listed in
the original manifest. `original_lockfile_matched` and
`original_workspace_graph_verified` remain false. This directory name does not
claim a complete match to the original lockfile or Cargo graph.

| Material class | Production | Reference | Existing limb | Experimental column-limb |
|---|---:|---:|---:|---:|
| periodic-dense-fixture | 34.583429 | 31.612724 | 25.016003 | 28.699773 |
| full-rank-field | 37.996280 | 36.228742 | 29.961670 | 32.237382 |
| zero | 49.338283 | 46.699034 | 38.004886 | 41.243817 |
| identity | 51.438391 | 50.379886 | 38.943118 | 40.925471 |
| rank-one | 43.665799 | 44.653862 | 34.229549 | 38.818984 |
| sparse-diagonal | 28.328367 | 29.440276 | 23.783353 | 26.305963 |
| continuity-maintenance-v1 | 29.557985 | 29.649471 | 24.012103 | 27.490954 |
| one-zero-left-rank-one | 27.724330 | 28.508138 | 23.576836 | 26.155770 |
| one-zero-right-rank-one | 26.392872 | 27.910164 | 21.611521 | 24.806216 |
| **Aggregate of all measured CPU** | 35.508018 | 35.183599 | 28.063682 | 31.104868 |

The second capture's aggregate experimental-column-limb CPU is about 12.4% below
production, but about 10.8% above the already-existing limb verifier. This does
not justify promoting the experimental implementation. The default production
verifier remains unchanged, and the observed rejection-cost asymmetry remains.
The first capture and the second capture are both retained; neither is selected
to hide a slower result, and neither is an adversarial cost bound.

The historical 6.86–7.90 primitive ratios used different source, hardware,
challenge recipes and workload/cost construction. They cannot be directly
compared with these two captures as a regression, improvement or public-network
attack multiplier. Their original raw records must remain unchanged.

## Source, binary and harness identity

Both captures record 40 repository source-file SHA-256 identities before and
after the native campaign, with no observed change. The measured W1 source hash
is `91d7ccb4ea0ac710e0e207a765779b1f02fddb703be92cf1cb7df1c300632798`;
the measured example hash is
`8caba498365709777e6320c4ccc5f1e13a08ac450855de306b17b5844bff5135`.
The manifests retain the actual invocation paths, compiler observation, CPU
affinity, source inventories, native exit status and original reader result.
These before/after checks cover the native execution interval; they are not a
complete original-workspace build-provenance or continuous-immutability proof.

| Capture | Original ELF SHA-256 | Preserved harness identity |
|---|---|---|
| Trial 1 | `0eab111d3918b7b30e228d3982b501d61e03dc65e2240d611517bfa214ab8617` | Original top-level Cargo manifest and lockfile; reader identity observed only after capture |
| Matching direct dependencies | `8d389c401095fc184b6564b237c10843e4ab7cbe49502bc38fa0049e6c5ff03c` | Original top-level, crypto and protocol Cargo manifests, crypto wrapper, lockfile, source-before snapshot; before/after configuration and reader hashes |

**Trial 1 has missing original harness artifacts.** Its crypto dependency
Cargo manifest, crypto `lib.rs` wrapper and protocol dependency Cargo manifest
were not captured as standalone artifacts. They have not been recreated from
later versions or substituted with the second trial's files. The retained
original top-level manifest/lock and original measured ELF remain available.
`reader-observed-after-capture.json` records its limited after-capture observation;
it does not assert that a before-capture reader hash was taken.

The second capture preserves the actual wrapper/configuration files. Its
repository-source symlinks are not archived as replacement source files: the
actual source identities are listed in the original manifest and correspond to
the measured repository files. Both original ELF executables are retained with
lossless XZ compression; they are not rebuilt or stripped substitutes.

## Archive verification and reader scope

[INDEX.json](INDEX.json) records every packaged file's relative path, byte size
and SHA-256. For both native JSONL and ELF XZ archives it also records the
decompressed size and SHA-256. The index intentionally does not hash itself.
Any subsequently added validation logs or CI receipts need separate index
entries. Original manifests, stderr, harness files and existing raw XZ captures
were copied byte for byte. Full 30 MB JSONL files are not added directly to Git.

For example, extract and inspect the second raw capture outside the checkout:

```sh
pon_receipt_dir="$(mktemp -d)"
xz --decompress --stdout evidence/pon-w1-work-security-20261101/matching-direct-deps/campaign.jsonl.xz > "$pon_receipt_dir/campaign.jsonl"
python3 scripts/pon_w1_false_trace_reuse_reader_v1.py "$pon_receipt_dir/campaign.jsonl"
```

Reader exit zero means complete internally consistent records. The reader
reconstructs matrices, task/challenge/trace/ticket hashes, complete forged bytes,
coverage and timing nesting. It does not execute W1 or authenticate the native
verdict, clocks, binary provenance or hardware. The original manifests' `PASS`
values describe only their documented local module observation. They do not
change any hardness, public-service, resource-fairness or production flags.

The separately owned [campaign specification](../../docs/development/specs/pon/W1_FALSE_TRACE_ACTUAL_REUSE_V1.md)
and [complete-workspace runner](../../scripts/ci/run_w1_false_trace_reuse_v1.py)
define the hosted execution path. The newly hardened hosted runner was not used
for these local module captures; its future execution receipts must remain
separate. Keep all original bytes and failures. Complete-workspace and hosted
x64/ARM CI status remains **pending** until its actual execution is reviewed.

## Integrated source checks and adversarial reader review

The continuation preserves upstream `acd8f79f2dcc22ecdee1d1a5fd88d619d06f37c9`.
After that integration, the exact-source W1 module harness passed **98 tests**,
the original native fuzz-semantic target passed **6 tests**, and the module
plus its test targets passed strict Clippy. The entire workspace's formatting
check passed. These are recorded in
[the local validation receipt](validation/LOCAL_VALIDATION.json); the original
workspace graph was not built by that module harness.

The new cost reader has 16 controls and its runner has 26. The new service
successor has 12 controls; the original native reader's 86 controls and Host's
20 controls also pass. Existing CI contract controls (95), source-integrity
negatives (34), PQ source negatives (34) and original V2/V3 cost reader controls
(32/19) remain passing in their stated component scopes. The current PQ source
corpus still reports HOLD; no cryptographic or network acceptance flag changes.
Changed Markdown link paths were checked against the complete Git tree plus
candidate additions. This is not a full sparse-checkout repository-truth pass.

An actual locked-workspace attempt exited 101 because local `ml-dsa` registry
input is unavailable. The configured shell proxy also refused connections.
The retained [failure log](validation/full-workspace-locked-attempt.log) is not
replaced with a dependency downgrade, stub, altered lockfile or claimed workspace
success. The GitHub workflow is the separate complete-workspace execution owner.

Independent adversarial review found and corrected flaws in the newly added
service evidence reader before publication. It could initially accept missing
business/History/observer records, trust an overlap boolean despite all attacks
falling outside the four-second window, or accept impossible nested CPU totals.
The fresh reader now reuses the original complete phase validation and rejects
each counterexample. It checks disjoint construction subintervals against their
enclosing measurement and each worker's construction plus client-call CPU
against that same worker's total. Another worker's surplus cannot repair a
contradiction. Both new hosted runners bind the explicit workflow-selected SHA;
internally consistent measurements of a different clean commit are refused.

## What remains unproved

The unchanged required-target chainwork rule and complete W1 verification do not
establish a lower bound on the cheapest legal solving strategy. Nor does correct
rejection establish economical rejection. An attacker may omit this experiment's
trace-retention overhead, reuse SHA-256 midstates or retain its public material
for longer than four searches. These captures are concrete implementations, not
a worst-case upper bound on verifier amplification or a lower bound on attacker
cost. Hardware/key counts cannot be substituted for effective adversarial work.

The explicit fresh service test creates a different header challenge for every
attempt, preserves every miss and network refusal, and must reach at least one
actual `WORK:Transcript` rejection. Its original four-second, sixteen-worker,
six-depth confirmation criteria, Host limits and original repeated-packet test
remain. Neither test was executed in this local module environment; no current
service success is inferred from Python tests or a configured CI job. A passing
finite Host run would still leave public WAN fairness, sustained fresh-identity
churn, cheapest-work assumptions and model utility as separate obligations.

The experimental column kernel is retained for reproducible comparison. The
production entry, original ticket, PNH1/PNW1 bytes, work weight and resource policy
are unchanged. A future succinct relation or different work statement needs its
own version, full statement binding and soundness/cost review; proof randomness
must not manufacture additional lottery tickets. Current qualification remains
**HOLD**.
