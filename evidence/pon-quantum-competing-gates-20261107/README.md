# PoN competing schedules, service costs and preprocessing — research / HOLD

This continuation extends the previous four-gate experiment with two scheduled
honest arrivals during private search, explicitly reserved service architectures,
and an exact-key classical preprocessing cache. The native regression failures
retained in the previous experiment are repaired. All four general quantum
qualification gates remain **HOLD**.

## Frozen implementation and validation

The implementation was committed before these observations:

- Commit: a56889a54aac5f14141bb45fb602141dd6a37645.
- Tree: b4e64c82d2646b9f32124feb510edc3349a375d0.
- Complete source inventory: 11,030 tracked files; SHA-256
  a1f7fa55fccc079391b874a86b2bdd5ae667615777aa305ad355d55b66c99424.
- Native ELF: 105,447,528 bytes; SHA-256
  dd00fb09345d78f28d45a8f431355c2eb5503f2729a3dd88409eb6356d8206dd.
- The executed ELF was selected from this successful Cargo build's unique
  compiler-artifact record. The retained target cache was reused; this is not a
  clean-room reproducible-build or fully calibrated toolchain claim.

The validation driver checked every tracked file's bytes, mode and Git identity
before and after every command, rejected all extra files including ignored
files, and bound the existence and identity of external Cargo configuration.
Native source inventories and the five raw competition inputs are additionally
bound through the producer, Python verifier and receiver replay.

| Actual validation | Outcome |
| --- | --- |
| Python test groups | 696 passed |
| Full Node library outer suite | 1,250 passed, 0 failed, 37 ignored |
| Root-role and sealed-file targeted groups | 6/6 and 7/7 passed |
| Explicitly executed native bridge tests | 4 passed, each checked by exact name |
| Main locked/offline Cargo graph, formatting and strict all-target/all-feature Clippy | Passed |
| Fuzz complete graph in independent cache | 149 packages / 149 nodes; locked online and offline metadata byte-identical |
| Repository links, distributed inventory, CI integrity and PQ source pins | Passed |
| Original 18-cell and new 54-cell reports; cache observation and independent verification | Executed successfully |

Two wrapper/cache observations require explicit reconciliation. The original
47-command driver result remains **FAIL**, unmodified: its outer-suite parser
rejected four Rust summaries, and its first optional fuzz metadata command
returned exit 101. The native Node process itself returned exit 0. An independent
checker subsequently matched all 1,287 outer test names and outcomes to this
same ELF's complete and ignored inventories, recognized the six groups of
thirteen legitimate child-process invocations, and consumed every nonempty log
line. The three successful child summaries are not added to the 1,250 outer
passes. The original log, rejected row, checker, inventories and supplemental
PASS are all retained.

Separately, the fuzz cache lacked arbitrary 1.4.2, jobserver 0.1.35 and
libfuzzer-sys 0.4.10. A new cache copied 133 checksum-verified archives and fetched
only those three locked packages. All 136 registry archives match Cargo.lock;
online/offline complete metadata SHA-256 is
23b657df105e61da8535390ff9a5659be1313027148345a56796788bdcfd68de.
No fuzz campaign was run. The prior cache, original failure and main result were
not rewritten.

The evidence-only child commit changes this evidence directory and the sole
development plan. The execution claims refer to the implementation SHA above;
attaching evidence does not imply another execution at the child commit.

## Four gates

| General gate | Additional evidence in this continuation | Remaining evidence |
| --- | --- | --- |
| Complete machine cost and error accounting | Common whole-plan allocation plus three explicit service reservations; initialization/readout ports, auxiliary patches, control cores/memory, retries, complete candidate/proof/publication costs and conditional error accounting | Real hardware calibration, compiled physical layout, measured control/decoding services, full energy/capital costs and execution guarantees |
| Cheapest legal implementation and amortization | 54 declared service configurations alongside the original 18; exact-key LRU observations retain complete proofs, misses, overhead and independent checks | All legal algorithms, caches and cross-challenge preprocessing; a minimum-cost lower bound and equal real total quantum/classical resources |
| Native valid adversarial execution | Independent receiver, private and honest producers; fresh honest blocks arriving while private search proceeds; real native admission/DAA/timestamp/chainwork/tip and reopen checks | QPU execution and calibrated clocks, stochastic live honest mining, responsive network propagation and attacker/competitor strategy adaptation |
| Mixed quantum/classical consensus reasoning | Eight complete finite certificates; distinct transient-replacement and horizon-survival events; fixed visible-prefix policies and labelled future-schedule/census advice | Arbitrary quantum algorithms, timestamp/abort/restart policies, long DAA evolution and general settlement security |

Quantum hardware execution, physical calibration, minimum attacker cost,
real resource equality, quantum mining qualification and production activation
remain false. Adding a provenance/coverage manifest cannot promote those flags.

## Actual native competition

The initial public history ends at height 16 with cumulative work 37. Every run
then freshly produces honest heights 17 and 18 with work 44 and 51. Both
predeclared schedules have a four-second **modeled** horizon:

- Early arrivals: 1 and 3 seconds.
- Late arrivals: 2.5 and 3.5 seconds.

The honest producer follows an isolated public view until the horizon. It does
not restart on a private publication. Equal-work ties retain the receiver's
current selected tip; at simultaneous modeled events, the honest arrival is
applied first. These are conditional, offline event schedules, not measured
live-network arrival times or a responsive mining network.

| Run family, for each schedule | Private completed checks | Private outcome | Ever replaced public branch | Private active at horizon |
| --- | ---: | --- | --- | --- |
| Quantum q0, fixed seed 9 | 0 | Modeled initialization is censored | No | No |
| Quantum q1, fixed seed 9 | 0 | Modeled initialization is censored | No | No |
| Classical uniform q0, fixed seed 9 | 2 | Nonces 7 and 5 both miss | No | No |
| Observer-advice classical path, early arrivals | 2 | Legal nonces 6 then 1, publication completes | No | No |
| Observer-advice classical path, late arrivals | 2 | Legal nonces 6 then 1, publication completes | Yes, temporarily | No |

There are eight runs: six fixed-seed samples and two separately labelled advice
controls. Across them the native execution freshly checked eight private
candidates, including four misses; produced sixteen honest blocks in seventy-two
attempts, including fifty-six misses; and verified all eight authenticated
reopens. Failure attempts and complete proof bytes remain in flushed ledgers.

The late advice control publishes at exactly 1101031/500000 = 2.202062 model
seconds. Its height-16 block ties work 37; its height-17 child reaches work 44
and replaces the public branch. At 2.5 seconds the honest height-17 block ties
44 and does not replace the selected private tip. At 3.5 seconds honest height
18 reaches 51 and is selected. Every run ends with selected work 51.

That sequence is a native conditional witness of **temporary** replacement.
The advice control was selected using the offline census and is not a successful
random mining sample. The fixed-seed samples produced no replacement. These
observations do not reproduce a live quantum attack or establish settlement
safety.

## Finite probability statements

All eight finite certificates are COMPLETE. The classical graphs contain
29 states under early arrivals and 34 under late arrivals; the declared quantum
graphs contain three states.

| Declared implementation and schedule | Ideal probability of ever replacing | Ideal probability of private survival at four seconds |
| --- | ---: | ---: |
| Classical uniform q0, early arrivals | 0 | 0 |
| Classical uniform q0, late arrivals | 1/64 | 0 |
| Declared serial quantum lifecycle, either schedule, q0/q1 | 0 | 0 |

The late classical risk is the probability of the legal two-nonce path in the
two-attempt class: (1/8)(1/8) = 1/64. The seed-9 run still missed. The finite
optimizer may use future-schedule and census advice; the fixed policy sees only
the already-visible public prefix. The action class is non-preemptive and
excludes arbitrary mid-action measurement, abort, restart and public-branch
switching.

The additive fault coupling bounds private-machine faults only, conditional on
exact honest packets, arrival schedule and receiver transitions. It does not
bound honest production, receiver or network faults. A zero ideal probability
with a positive conditional fault upper bound is not zero real-world risk.

An independent reduced 16-nonce review covered 29 cases, 458 state visits, 1,117
state/actions, 2,992 transition edges, tie/deadline boundaries and visible-prefix
checks. Its reduced-domain probabilities are separate from the native
eight-nonce results above.

## Service-architecture comparison

The 54 cells are the product of three initialization/readout configurations,
two predicates, P=1/2/4 processors and q=0/1/2 iterations. The four-second
horizon, declared noise/error assumptions and physical-qubit cap of 10^16 are
fixed. Additional ports reserve auxiliary patches, control cores, memory and
resource-time; they do not become free service capacity.

| Initialization/readout ports | q0 cells completing within the model horizon | q>0 cells completing within the model horizon |
| --- | ---: | ---: |
| 1 / 1 | 0 of 6 | 0 of 12 |
| 1024 / 8 | 6 of 6 | 0 of 12 |
| 65536 / 64 | 6 of 6 | 0 of 12 |

All 54 cells satisfy their declared construction bounds; twelve complete both
declared checks and the full reserved delivery plan. For those twelve q0 cells,
full plans take approximately 2.392684–2.492972 seconds at 1024/8 and
1.119264–1.121060 seconds at 65536/64. All 36 positive-q cells are censored
within this horizon. The original eighteen-cell comparison still has zero
timely completions. The new interval comparison leaves thirty undominated cells;
this is not a minimum-cost proof.

q0 retains the conditional quantum machine's lifecycle costs but uses no Grover
iterations. The native competition above retains its original serial service
configuration; the faster service cells are a separate comparison and are not
silently substituted into its action set. Single-task delivery probabilities
are also distinct from fork-replacement probabilities. All architecture
calibration states remain MISSING_EXTERNAL_EVIDENCE.

## Classical cache and complete cost observations

Each capacity starts with an empty application cache and processes the same
sixteen native fixture candidates in nonce-major order. Full raw keys bind the
A/B matrices and arithmetic parameters or the exact framed SHA prefix.
Every candidate still rebuilds noise, low-rank offsets, ordered trace, trace
hash, ticket and complete proof. Independent full scalar-relation checks and
native fixture byte comparisons cover all forty-eight generated proofs.

| Resident key/value payload cap | AB computed / reused | Cache hits / misses | Payload peak | Producer CPU seconds | Independent verifier CPU seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 B | 16 / 0 | 0 / 96 | 0 B | 0.892916545 | 0.737719838 |
| 4096 B | 16 / 0 | 15 / 25 | 2369 B | 0.883944293 | 0.736936351 |
| 262144 B | 1 / 15 | 30 / 10 | 51547 B | 0.728497688 | 0.736248540 |

Each row retains sixteen complete proofs: two target hits and fourteen target
misses, with no noise exhaustion or execution-stage failure in this run.
Each row still executes 4096 noise hashes, 1,048,576 low-rank multiply/add
pairs, 4,194,304 ordered-trace multiply/add pairs and serializes 787,008 proof
bytes. Cache lookup misses, target misses and failed execution stages are
different ledger categories.

The journal contains 194 events covering all 96 begun and completed stages.
Combined producer/verifier CPU time is 4.716263255 seconds; the internal observer
uses 6.275263428 CPU seconds, including 1.559000173 seconds of additional
observation overhead. Outer command receipts also include startup, imports,
final report writing and process exit.

These are descriptive timings from a fixed order in a shared process and OS
environment. They do not establish unbiased speedups, worst-case guarantees,
equal quantum/classical resources or a quantum advantage. The cap counts
resident key/value payload only, excluding object/allocator/transient overhead.
The process RSS high-water value is not per-capacity exclusive memory. This
classical reuse does not prove a reduced reversible oracle cost.

## Regression repairs and preserved observations

Canonical role-key parsing now accepts only the canonical role keys and detects
duplicates before insertion, including inside tagged envelopes. Signed messages
and the stored v1 serialization remain unchanged. The sealed object is reopened
read-only through its held descriptor and handed off with the reserved fd number
and CLOEXEC preserved. Full object identity, timestamp and seal checks remain
active. The original two failures and earlier frozen source remain available in
the [previous evidence](../pon-quantum-four-gates-20261107/README.md).

The archives retain development-test and disk-write failures, independent-review
harness mistakes, the original driver rejection, the original fuzz cache
failure, and their explicit resolutions. The main execution's 37 ignored tests
are not counted as passes; the four bridge experiments were separately executed
by exact name.

## Publication and reproduction

The implementation and previous evidence were pushed through the existing
HeptaRuntime Mac/local GitHub channel using the existing authorized account.
The native regression used the existing Linux ROG environment through that
runtime. Bounded discovery did not locate a directly callable Colab/Kaggle
adapter in the currently exposed channel; no provider availability, quota,
GPU execution or QPU execution is inferred from that observation.
Exact blob, tree and commit identities were checked; the update was non-forced
and its ref/tree were read back. The original branch's draft-PR request returned
422 claiming an existing PR, while subsequent bounded REST/GraphQL queries
returned no readable matching PR. Those responses are retained as an unresolved
API inconsistency; no PR number is inferred from them.

Reproduce execution from the implementation commit, with the declared Rust
1.95.0 / OpenSSL 3.5.9 environment, complete locked dependencies and an external
fresh evidence directory. The retained driver gives the exact commands and
environment identities. The independent outer-suite checker explains how to
read nested libtest output without changing the original execution record.

The [finite model note](../../formal/pon-nakamoto-v1/FINITE_QUANTUM_CONSENSUS.md)
and [machine/reuse note](../../formal/pon-nakamoto-v1/MACHINE_SERVICE_AND_REUSE.md)
define the declarations, refusal controls and limitations. This short-horizon
experiment does not reproduce the long difficulty trajectory considered by
[Bailey and Sattath](https://arxiv.org/abs/2403.08023), or establish the
distributional assumptions needed for a general hybrid query lower bound.

## Evidence files

- [combined-validation.json](combined-validation.json)
- [frozen-validation.tar.xz](frozen-validation.tar.xz)
- [frozen-validation.tar.xz.index.json](frozen-validation.tar.xz.index.json)
- [full-source-identity.json](full-source-identity.json)
- [fuzz-graph-result.json](fuzz-graph-result.json)
- [machine-cache-summary.json](machine-cache-summary.json)
- [machine-compact-readback.json](machine-compact-readback.json)
- [native-compact-readback.json](native-compact-readback.json)
- [native-competition-summary.json](native-competition-summary.json)
- [native-test-elf.json](native-test-elf.json)
- [original-driver-result.json](original-driver-result.json)
- [preparation-receipt.json](preparation-receipt.json)
- [preparation-script.py](preparation-script.py)
- [prepared-file-index.json](prepared-file-index.json)
- [publication/a568-import-anchor.json](publication/a568-import-anchor.json)
- [publication/a568-manifest.json](publication/a568-manifest.json)
- [publication/a568-requests.json](publication/a568-requests.json)
- [publication/a568-result.json](publication/a568-result.json)
- [publication/b455-result.json](publication/b455-result.json)
- [publication/manifest.json](publication/manifest.json)
- [publication/pr-422-response.json](publication/pr-422-response.json)
- [publication/pr-422-stderr.txt](publication/pr-422-stderr.txt)
- [publication/pr-readonly-README.md](publication/pr-readonly-README.md)
- [publication/pr-readonly-summary.json](publication/pr-readonly-summary.json)
- [supplemental-validation.tar.xz](supplemental-validation.tar.xz)
- [supplemental-validation.tar.xz.index.json](supplemental-validation.tar.xz.index.json)
- [whole-node-inventory-result.json](whole-node-inventory-result.json)
- [manifest.json](manifest.json): SHA-256 and length of every evidence file, self-excluded.
- [finalization-observations.json](finalization-observations.json): retained evidence-formatting refusal and its resolution.
