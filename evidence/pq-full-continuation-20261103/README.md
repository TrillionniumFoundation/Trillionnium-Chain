# PQ component continuation evidence — 2026-11-03

**Status: HOLD / UNQUALIFIED.** All four hosted W1 research lanes have verified
raw evidence. All four hosted network/witness lanes passed 45 required controls
and strict Clippy. Complete Node regression passed on x64 head and actual merge
(897 passed, 0 failed, 22 ignored each); ARM head and actual merge each failed two
original CPU-budget controls (895 passed, 2 failed, 22 ignored). The hosted
workflow therefore failed. Main's 27 passing and 18 failing witness selectors
and X230's 2400-second complete-library timeout remain retained. X230 separately
passed all 45 controls and strict Clippy. Paired Hepta changes are published.
These component observations do not close any whole-chain qualification gate.

This record belongs to the existing
[sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [six-gate claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md).
It grants no production, whole-chain PQ, consensus, WAN or deployment qualification.

## Source identity and snapshot boundary

| Item | Identity |
| --- | --- |
| Chain code commit | [12fe5f2c1f19704fe7eb635dede6839ed8b1e91e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/12fe5f2c1f19704fe7eb635dede6839ed8b1e91e) |
| Code tree | `c44112da731e3f958e55eb024e5762d6723ea2c9` |
| Parent Chain commit | `1c7e8ab7cd6a321cad4e6c7f7e8a197d7b3be14c` |
| Hosted PR base | `2e72a989d001cf51bd0aed0e1401526e45db31f1` |
| Actual hosted prospective merge | `0357031364787574cb7058b05329aa2e2730f947` |
| Main witness patch SHA-256 | `e90562a3bb770a969c4ddd3c44b6353715668a22c9129f0121655ba9b5fb291c` |

The code commit is published on the existing Chain #683 branch. This evidence
record and the sole-plan entry follow separately; their addition changes the
repository tree without retroactively changing a native run's source identity.
Each native archive identifies its own modified source and command configuration.
The separate component runs, X230's successful integrated 45-control run and
the four hosted research-verifier lanes remain distinct observations. The
actual prospective merge has parents `[2e72a989d001cf51bd0aed0e1401526e45db31f1,
12fe5f2c1f19704fe7eb635dede6839ed8b1e91e]`; its tested tree equals the head tree
listed above. The completed hosted matrix establishes the results below for
that code, including its failures; it does not establish complete four-lane
Node regression acceptance. The later evidence-only commit is not the commit
under which these native executions ran.

## Changes under review

Ordinary PNQ2 admission retains the fresh external-witness guard and permission
reads in one SQLite IMMEDIATE transaction when no pending request expires.
An actual expiry still commits retirement, publishes the new epoch, and
obtains a fresh guard before admitting the next request. The original 43
required controls remain, with two exchange-count/state/reopen controls added.
The original 250 ms witness exchange bound and live-request deadlines remain.

The [isolated W1 verifier](../../formal/pon-nakamoto-v1/w1_hardened_verifier/README.md)
now selects one explicit SDK 3.0.6 profile for complete-proof verification and
the recursion-only diagnostic:

- Hash suite: `poseidon2`.
- Verifier-parameter digest:
  `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`.
- Existing control root, full image and journal verification retained.
- Unknown suites, disallowed `sha-256` / `blake2b`, and mismatched parameter
  metadata rejected; matching metadata still requires actual cryptographic
  verification, with no retry under another profile.
- Original prover segment limit 18 remains distinct from the retained SDK
  control root's maximum of 22.

The existing PQ workflow defines separate research-verifier jobs for
head/prospective-merge and x64/ARM, using fixed real inputs. Its native witness
lane requires all 45 selectors with `--all-features`. The four research-verifier
lanes have completed with checked raw evidence. The network/witness lanes also
completed; required controls passed, while complete ARM Node suites retained
the original CPU-budget failures below.

## Recorded validation

| Scope and configuration | Observed result | Boundary |
| --- | --- | --- |
| Main: isolated W1 verifier, Rust 1.95.0, release build | Four unit tests passed; real complete succinct STARK verified; 26 controls passed; real prefix lift verified; locked graph, format and strict Clippy passed | Local component validation; Cargo.toml and Cargo.lock unchanged |
| Main: witness, existing test profile, default features | 45 selectors executed: 27 passed, 18 failed | Failed acceptance run; does not cover the workflow's all-feature configuration |
| X230: prepared integration, static checks | All 11 static checks passed | Source/configuration checks; no native behavioral qualification |
| X230: combined code tree, original test profile, default features | All 45 native selectors passed; every original `check_required_native_test.py` check returned 0; eight recorded source-file hashes were unchanged before/after | Actual integrated control execution, including both new count/state/reopen controls; preserves the separate main-host failures |
| X230: complete Node library and Clippy | Library reached the 2400-second orchestration limit, exit 124; strict Node Clippy passed in 98.03 seconds; aggregate job failed | No completed library total or acceptance; timeout is not classified as a native assertion failure |
| X230: original implementation with two new controls | Ordinary admission failed at the intended count assertion: `[1,1,2]` versus `[1,2]`; expiry control passed | Expected negative experiment; eight fixed source hashes restored |
| Hosted W1 research verifier, head/prospective-merge × x64/ARM | All four lanes completed successfully; complete raw artifacts independently read back as described below | Completed isolated proof-component evidence; no Node consensus or whole-chain qualification |
| Hosted required network/witness controls, head/actual merge × x64/ARM | All four lanes passed all 45 exact selectors with `--all-features`; 180 individual records checked | Original 43 controls retained; zero ignored required controls |
| Hosted complete Node library, x64 head and actual merge | Each: 897 passed, 0 failed, 22 ignored | Original ignored tests remain explicit |
| Hosted complete Node library, ARM head and actual merge | Each: 895 passed, 2 failed, 22 ignored; both failures return `PUBLIC_MUTATION_CPU_BUDGET` | Original capacity controls failed; hosted workflow failed |
| Hosted strict Node Clippy | All four original commands exited 0; raw receipt/log identities matched | Does not override native regression failures |
| Paired Hepta continuation | Both new controls failed on original production files; fixed package passed 136 tests, zero skipped/retries; build, original strict fix/Clippy, format and diff passed | Separate package execution; historical 133/134 CI failure not causally attributed to this fix |
| Paired Hepta V5 binding | 51 source tests and 32 diversity tests passed; actual source verifier validated all 42 file rows; qualification flags stayed false | Published Chain code/tree bound; V1–V4 historical pins unchanged |

### W1 proof evidence

The 26 complete-receipt controls preserve the original 24 and add the two
recognized-but-disallowed hash-suite selections. The actual verifier produced
one acceptance and 25 rejections, with no panics. The separate real prefix-lift
diagnostic accepted while explicitly reporting `complete_w1_claim=false` and
`consensus_admission=false`. A prefix lift does not establish a complete W1 proof.

The retained positive inputs are:

| Input | SHA-256 |
| --- | --- |
| `evidence/pon-w1-complete-succinct-20261028/full-proof/header.bin` | `7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f` |
| `evidence/pon-w1-complete-succinct-20261028/full-proof/succinct.bin` | `ca4d3c9f5159b7001abae7491604cadbbbfa97c0f93d90d5943e48936813ca2b` |
| `evidence/pon-w1-verifier-hardening-20261028/real-lift-0000.bin` | `d2b06a1feca2d15e8dc5741b43f481a82c32d7d3dab01e413d357012467093d3` |

The proof archive preserves the exact tested source, command records, raw
results, original inputs, all control assets, binary identity and payload
manifest. It also preserves the earlier shared-cache wait cancellation and
the failed offline-cache probe. These setup observations remain distinct from
the later successful isolated-cache validation.

### Hosted W1: complete four-lane artifact readback

For run `41628135456`, attempt 1, the following completed jobs were matched to
their original artifacts, downloaded in full, and checked against GitHub's
reported ZIP sizes and SHA-256 digests:

| Lane | Job ID | Artifact ID |
| --- | --- | --- |
| x64 head | 125890592176 | 13226234301 |
| x64 prospective merge | 125890591419 | 13226169545 |
| ARM head | 125890592077 | 13226363199 |
| ARM prospective merge | 125890591942 | 13225943961 |

All four archives contain 82 entries, preserved byte-for-byte: 328 artifact
entries in total. Readback checked each lane's 12 command receipts against the
actual command arguments, raw log sizes and SHA-256, successful exit/status,
runner architecture, run/attempt, and matching source identities before and
after execution. The existing source checker recorded the full tracked
worktree: 6,831 entries and 782,174,381 bytes. Actual checkout output and the
GitHub commit objects independently agree on the head, real merge and tree.

Each lane's raw output establishes four executed unit tests with zero failed,
ignored or filtered, actual verification of the retained full receipt, all 26
named controls with one acceptance and 25 rejections and no panics, verification
of the real prefix lift, and passing locked graph, formatting and strict Clippy.
Each control's saved header and receipt bytes were hashed against its result
row. Full/lift input identities, SDK, hash suite, parameter digest and claim
limits were checked. These are repeated verifications of the same retained
proof input, not four independent proof-generation trials.

The hosted payload archive below retains every extracted artifact entry, raw
job logs, API snapshots, relevant exact-commit source files, readback code,
summaries and a file manifest. All four original ZIPs were downloaded in full
and checked against their official sizes and SHA-256; their metadata and digests
are retained, while this package does not duplicate the ZIP containers. All 328
artifact files are preserved byte-for-byte. Its 359 payload files were hashed
again after packaging. The uploaded artifacts do not include compiled verifier
binaries, so no hosted binary-digest claim is made. The proof acceptance records
continue to report consensus admission false, and prefix-lift acceptance keeps
the complete-W1 claim false. This completed research result does not erase any
main-host witness failure or close any whole-chain gate.

### Hosted network/witness: final artifact readback

All four final artifacts from [run 41628135456](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41628135456)
were downloaded and matched to their original ZIP identities. Each retained
all 166 early artifact files byte-for-byte and added exactly the four Node/Clippy
receipt and log files. Readback checked all 180 required-control records,
exact selectors, all-feature configuration, original test profile, execution
checks and source identity before/after. The final archive retains all 680
artifact files, original ignored lists and early/final byte comparisons.

| Lane | Job ID | Required controls | Complete Node library | Strict Clippy |
| --- | --- | --- | --- | --- |
| x64 head | 125890591823 | 45 passed | 897 passed / 0 failed / 22 ignored | Exit 0 |
| x64 actual merge | 125890592046 | 45 passed | 897 passed / 0 failed / 22 ignored | Exit 0 |
| ARM head | 125890592233 | 45 passed | 895 passed / 2 failed / 22 ignored | Exit 0 |
| ARM actual merge | 125890592092 | 45 passed | 895 passed / 2 failed / 22 ignored | Exit 0 |

Each outer suite enumerated 919 tests; nested subprocess totals were not added
again. Both ARM failures are the unchanged tests:

- `store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner`
- `store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator`

Both fail at `store/detached_admission/tests.rs:724:31` while unwrapping
`Error { code: Some(PublicMutationCpuBudget), kind: Capacity,
message: "PUBLIC_MUTATION_CPU_BUDGET", source: None,
request_history_budget: false }`.

| Original control | ARM head total CPU / remaining credit (ns) | ARM merge total CPU / remaining credit (ns) |
| --- | --- | --- |
| Custom genesis over eight MiB | 2765746800 / -54352177 | 2691608328 / -8132888 |
| Authenticated large parent | 2765182320 / -38860982 | 2686729680 / -4927962 |

The original burst is 2000000000 ns and refill is 250000000 ns per second.
Each record reports `authenticated_backend=true`, final
`native_result=Err(PUBLIC_MUTATION_CPU_BUDGET)`, and `live_refused=true`.
An earlier `original_dispatch_result=Ok` does not make the final outer result
successful. No budget was increased or failure reclassified as an environment
exception. Expected injected panics elsewhere in the logs are not additional
suite failures; the final totals and named failure lists are authoritative.

### Main-host witness failures and its uncompleted count controls

The main witness run's 18 failures are classified by their observed records:

| Observed failure | Count | Native labels |
| --- | ---: | --- |
| `PQ_WITNESS_DEADLINE`, including deadline errors instead of a later intended refusal | 15 | 05, 08, 11, 12, 13, 14, 22, 25, 26, 31, 33, 37, 39, 43, 44 |
| Connection reset by peer | 2 | 34, 36 |
| Assertion `service.commit_uncertain` failed | 1 | 41 |

In native-41, Current succeeded, but the later Advance error was consumed by
`.is_err()`; the retained output does not identify that error or prove SQLite
COMMIT was reached. The false uncertainty flag is retained without inventing
the missing cause.

The baseline record named `baseline-extra-current-negative` exited 101 on the
first ordinary admission at `store/pq_rollback_witness/tests.rs:907`, with
`PQ_WITNESS_DEADLINE`. It did not reach the exchange-count assertion and
therefore does not demonstrate the intended count-negative result.

In the main-host run, both new controls also failed before their intended assertions:

- `native-43`: ordinary admission failed at the first admission, line 907.
- `native-44`: the expiry control failed at its first admission, line 941,
  before reaching the expiry transition and count/state/reopen checks.

The main-host run does not establish the new behavior under the unchanged budget.
The raw failures must remain attributable to their exact source, profile and
feature selection. No latency improvement, original-budget closure or
successful witness qualification is inferred from the reduced source-level
exchange path.

### X230 integrated control execution

The combined code tree `c44112da731e3f958e55eb024e5762d6723ea2c9` passed all
45 selectors on X230 using the original test profile and default features.
Each selector also passed the original `check_required_native_test.py` execution
check with return code 0. The eight recorded source-file hashes were identical
before and after the commands.

Both new controls reached and passed their actual assertions: ordinary admission
observed Current/CAS `[1, 2]`, retained pending replay observed Current `[1]`, and
expiry retirement followed by a fresh admission observed `[1, 2, 1, 2]`, with
the associated state, epoch and cold-reopen checks. The unchanged exchange and
request deadlines remained in force.

The complete library command then reached its 2400-second orchestration limit
and returned 124. Its last recorded progress was in the original capacity
regression after the 65536-key case; it has no completed suite total. Strict
Node Clippy subsequently passed in 98.03 seconds. Job
`1a1a12385cc-96a-6d73` terminated with failure and complete retained output.
This timeout is an orchestration outcome, not a native assertion or library pass.

A separate baseline restored only original `pq_network.rs` from
`1c7e8ab7cd6a321cad4e6c7f7e8a197d7b3be14c`, retaining the two new tests.
Ordinary admission exited 101 at its intended assertion, observing `[1,1,2]`
where the fixed contract expects `[1,2]`. The actual-expiry control exited 0
with its four exchanges, epoch, checkpoint and cold-reopen assertions.
The old ordinary test stops at its first count assertion; its later pending
replay count was not measured. The fixed run independently observed replay
`[1]`.

All eight fixed source hashes were restored and verified after the baseline.
The fixed binary identity was preserved before rebuilding the baseline; the
target directory subsequently held the baseline binary. No execution of that
cached binary is presented as a fixed-source run. These results do not erase
main-host failures, establish a latency distribution or change the earlier
main-host deadline into a demonstrated count-negative result.

### Paired Hepta write ownership and V5 binding

Published [Hepta commit a7c523f366de3aaf9bce923be885ad275d0ecc22](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/a7c523f366de3aaf9bce923be885ad275d0ecc22),
tree `070d61d7525d55938aa2d6ddcdbf666a138b3125`, reserves SQLite write ownership
with `BEGIN IMMEDIATE` before mutation snapshots. Read-only transactions retain
deferred reads. New controls hold an independent writer, verify the same pinned
mutation waits then succeeds after release, retain reader availability and check
replay does not append another effect. WAL/FULL, maximum five connections,
original five-second busy timeout, existing concurrent provider-effect test and
retry policy remain unchanged.

With original production files, both new controls failed on both original
nextest attempts with `writer returned before release: Ok(Err(Unavailable))`.
The fixed package passed 136 tests with zero skipped/retries. Build, the original
`just fix -p codex-hepta-automation --locked -- -D warnings`, format and diff
passed with source unchanged. This establishes the new controls; it does not
recover the historical 133/134 CI error or prove its cause.

V5 binds Chain `12fe5f2c1f19704fe7eb635dede6839ed8b1e91e` and tree
`c44112da731e3f958e55eb024e5762d6723ea2c9`. Its 42 file rows are unchanged;
the applicable source commit/tree binding changes. Its manifest SHA-256 is
`2a706d08ecc1e92b4844662e16441a4342ac8e49dba9d5aae212a4a93bf8bc21`.
The 51 source tests, 32 diversity tests and actual 42-file CLI verification
passed with production flags false. V1–V4 historical bindings remain.

The private [native validation record](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a7c523f366de3aaf9bce923be885ad275d0ecc22/evidence/pq-effect-owner-20261103/native-validation.json)
retains 35 lossless raw items, independently decoded and checked (350540 raw
bytes). It is 192305 bytes, SHA-256
`e4e287c9bd4ceb19e6d54221f19b127a62bc92f772221f31e1bbc81e113fb417`.
Native package execution and subsequent V5/workflow metadata validation remain
separate observations; they do not establish a same-source complete paired
deployment or production acceptance run.

### Paired Hepta hosted observations (2026-11-03 12:53:43 UTC)

[Native pair run 41634290628](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/41634290628)
tested Hepta head `a7c523f366de3aaf9bce923be885ad275d0ecc22` and actual merge
`f561bfafef1171db955a886227de698e49609913`. All four effect-recovery artifacts
were downloaded and their ZIP identities and raw log sizes/hashes checked.
Every lane actually ran 136 AutomationStore tests: 136 passed, zero skipped and
no retries. Original lost-ack and both new contention controls each passed.

| Lane | Effect-recovery job | AutomationStore | Selected HTTP owner/recovery |
| --- | --- | --- | --- |
| x64 head | 125911419103 | 136 passed / 0 skipped | 6/6 selected controls passed |
| x64 actual merge | 125911419153 | 136 passed / 0 skipped | 6/6 selected controls passed |
| ARM head | 125911419034 | 136 passed / 0 skipped | 6/6 selected controls passed |
| ARM actual merge | 125911419056 | 136 passed / 0 skipped | 6/6 selected controls passed |

Each HTTP invocation selected one control and reported one passed, 238 outside
the selector; this is not a zero-skipped whole-Agentd-package result. Four
Cell-host-v2 lanes and two native Windows ledger lanes completed with successful
step statuses. Four PQ policy-renewal lanes in
[run 41634290706](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/41634290706)
also completed successfully. FinalUse PQ component-observation workflow
`41634290700` was skipped, not passed.

Four historical pair lanes failed step 30, `Require paired native pressure and
complete state convergence`, with
`{"passed":false,"failures":["CONFIRMATION_TARGET"]}` and exit 1. Their 97 wrapper
controls and five named native cases passed before the business confirmation
gate failed; steps 32–62 were skipped. Those lanes used historical Chain
`c16507147b65285ea94dead22d3b93c5db7295af` (merge
`d1b8ae970bb5e014b6feaa49030823e1d8228c90`), not the V5 Chain source. Their failure
cannot be assigned to `12fe5f2` or borrowed as V5 acceptance evidence.

At this timed snapshot Cell-installed-host-v3 was still at checkout; its
current-Chain preflight, installed controls, startup/History recovery and pressure
cases had not completed. The complete paired workflow has no successful combined
acceptance result. Hosted private logs remain private.

## Evidence archives

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| [pq-frozen-verifier-20261103-4502-evidence.tar.xz](pq-frozen-verifier-20261103-4502-evidence.tar.xz) | 533964 | `1f3f05acf83c6a86aa52c49d0facd3adac03feef2a7c6b3d18ab786cb03a9f3f` |
| [main-witness-validation-20261103.tar.xz](main-witness-validation-20261103.tar.xz) | 28168 | `3d35f44f42323be9d8d4202e5cc519f9b71bb9bd1e10a9f0fa6b6350c6f8239c` |
| [x230-integrated-validation-20261103.tar.xz](x230-integrated-validation-20261103.tar.xz) | 114396 | `4f08ef7627e9df0563b801b89389c14dd2f5b476f6ee172e9c943a63276ff902` |
| [x230-witness-baseline-negative-20261103.tar.xz](x230-witness-baseline-negative-20261103.tar.xz) | 24184 | `ab8bf3d24a3bf9e5458c9e23fed678821e3377ff805722aeb4847afd1172dc1b` |
| [hosted-w1-four-lane-41628135456-payloads.tar.xz](hosted-w1-four-lane-41628135456-payloads.tar.xz) | 381240 | `3a4d964d5966f6b0157d51ab2c7f0de9f46503fb012028c4d444ebe186418b15` |
| [hosted-controls-payloads-41628135456.tar.xz](hosted-controls-payloads-41628135456.tar.xz) | 192020 | `28d552413182760c340d803b4d6b3e6d21bf511c5fa852914ce0b4139618f385` |
| [hosted-final-payloads-41628135456.tar.xz](hosted-final-payloads-41628135456.tar.xz) | 632272 | `7a5492a55e04acd2d64fe00134d9c12c5ed50887cba98aea098e928e6c3af986` |

The proof archive has 109 payload entries plus its manifest; payload hashes were
checked after packaging and after transfer. The witness archive retains the
main-host validation evidence, including failed outcomes. Archive hashes identify
the retained observations; they are not acceptance certificates. X230 integrated
evidence preserves 218 payload files plus its manifest. Baseline evidence retains
the negative assertion, successful expiry and source restoration. Hosted early/
final archives retain 664/680 original artifact files respectively, including
exact overlap, failures and original ZIP identities; duplicate ZIP containers
are omitted. Payload manifests were checked after packaging. Private Hepta raw
source and logs remain in the private repository.

## Remaining qualification

All six whole-chain gates and PN0–PN6 remain HOLD / UNQUALIFIED. The witness
still covers its original three PNQ2 tables under independent external-state
assumptions. It does not cover all Chain/Hepta state or establish a deployed
monotonic trust service.

The older statement that all ordinary Hepta FinalUse consumers remain classical
is incomplete for the paired candidate: the protected explicit PQ route already
exists in the parent Hepta source. Untagged classical authority and incomplete
governance, release, recovery and key-custody coverage remain. This continuation
does not introduce that existing route or perform automatic migration.

The explicit proof profile does not supply a quantum Fiat–Shamir/FRI/recursion
soundness argument, a PQ-128 claim, quantum-mining/fork-choice analysis, production
consensus admission or practical benefit over native W1. Complete authorization
coverage, migration and rollback semantics, original capacity/History/business
budgets, independent deployment/WAN/fault evidence and authorized activation
remain open. Current build or test observations must not be pooled across
sources, features, machines or repositories into same-configuration acceptance.
