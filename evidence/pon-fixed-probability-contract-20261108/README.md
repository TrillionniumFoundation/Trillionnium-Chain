# Fixed-probability cost-contract research — 2026-11-08

**Status: HOLD_NO_GO.** This archive records executable research, exact finite-model
certificates, a complete MU1 reuse control, and a branch-bound native work-schedule
candidate. It does not establish an all-algorithm cost lower bound, install a new
consensus profile, or qualify production, quantum resource cost, confirmation
risk, or a public network. All such qualification flags remain false.

The governing documents are the
[fixed-probability cost contract](../../docs/protocol/pon-nakamoto-v1/details/FIXED_PROBABILITY_COST_CONTRACT_V1.md),
[branch-schedule research specification](../../docs/protocol/pon-nakamoto-v1/details/BRANCH_WORK_SCHEDULE_RESEARCH_V1.md),
and the repository's sole
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## 1. Immutable source identity

The final tested executable source is:

| Identity | Value |
| --- | --- |
| Final tested commit | `103cdf67108a667d8570388f9dd402210c160157` |
| Final tested tree | `6910f1838a5801f7c0e6d0c5de544a4c3161713e` |
| Integration merge | `ae90d186b79a9269bdb7d9ac8dfc0bcf7e5bfe0c` |
| Integration first parent | `8d5389748873dad6e296d17f2ff20483b5afa5bc` |
| Integration second parent | `b16bae2824e6c8236ef2011fc93a74df3ac7f039` |
| Initial materialized candidate | `747a7169fae3bc27618e267eef8a5a03701bb6f3` |

Use [final-tested-source.json](final-tested-source.json) for the immutable source
record, [exact-source-qa-final.json](exact-source-qa-final.json) for the QA result,
and [final-native-checks.json](final-native-checks.json) for native commands and
outcomes. The before/after records,
[final-source-identity-before.json](final-source-identity-before.json) and
[final-source-identity-after.json](final-source-identity-after.json), delimit the
source identity of the validation run. An earlier candidate's successful check
is not substituted for a check on the final source.

An archival commit containing this README and raw outputs may have a different
Git tree. The tested-source claim above identifies the executable snapshot; it
does not claim that every later archival commit was itself rebuilt and tested.

## 2. Contributions and their exact scope

### 2.1 A machine-readable contract bound to actual MU1 source

The [contract data](../../formal/pon-nakamoto-v1/fixed_probability_contract_v1.json)
and [contract reader](../../formal/pon-nakamoto-v1/fixed_probability_contract.py)
bind the declared work profile to the existing
[MU1 relation](../../formal/pon-nakamoto-v1/MANDATORY_UNITS_RELATION_V1.md):

- The inclusive aggregate target is `2^252 - 1`. Its density is `p = 1/16`
  **under the independent uniform terminal-oracle assumption**; this is not a
  proof that the implemented SHA-256 construction satisfies that assumption.
- The relation permits one through eight complete, ordered PNW1 units and uses
  the research credit `16u`.
- The actual context fields, relation-parameter digest, and four relation-source
  hashes are checked. These pins do not authenticate a complete process, build
  graph, host, or every legal implementation.
- The cost experiment requires at least one distinct valid result with
  probability at least one half and counts unsuccessful work as well.
- Batching, shared and low-rank work, cached products, preprocessing, public help,
  all competing forks, unsuccessful or unpublished attempts, restart/profile
  state, proof/encoding grinding, quantum subsets, state preparation,
  uncomputation, variable-time search, parallelism, and retained quantum state
  remain in the required adversary scope.

**All 16 actual cost points remain unknown:** eight scales for each of the
classical and quantum classes retain `lower=null`, `upper=null`, and
`status=unproved`. A successful source-binding check does not fill these entries.
A measured implementation cost is not substituted for a minimum over legal
algorithms, and the contract does not turn a declared proof reference into a
verified theorem.

The 288 finite subset controls enumerate an eight-element domain to check the
inside/outside winner-mass conditions used by the normalization diagnostic.
The displayed classical and quantum cost ratios follow assumed
inverse-density and inverse-square-root laws. They are not exact finite-Grover
success costs, an implemented quantum W1 miner, or a lower bound for every legal
subset strategy.

### 2.2 Exact simultaneous credit feasibility

[Credit feasibility](../../formal/pon-nakamoto-v1/CREDIT_FEASIBILITY_V1.md) and its
[implementation](../../formal/pon-nakamoto-v1/credit_feasibility.py) decide the
finite declared envelope inequalities

```text
s(u) U_chi(v) <= Gamma_chi s(v) L_chi(u)
```

for every ordered pair, including self pairs. Exact rational multiplicative
Bellman-Ford returns either a common positive schedule or a directed cycle
whose multiplier product is strictly below one. The result verifier checks
the original inequalities or independently reconstructs the contradiction.

The 1,309 finite credit-model comparisons concern this declared envelope
problem. Feasibility does not prove that a supplied cost envelope is true;
infeasibility of a conservative envelope does not prove that the unknown
actual optimum admits no schedule. The synthetic two-scale example using
`u in {1,16}` is a mathematical diagnostic: `u=16` is outside MU1 V1's allowed
range and is not an added native or MU1 work scale.

### 2.3 Automatically synthesized lifecycle potentials

[Additive lifecycle synthesis](../../formal/pon-nakamoto-v1/AMORTIZED_COST_POTENTIAL_V1.md)
adds an exact solver to the prior stateful research. With fixed credit weights,
resource price, initial-potential caps, and a finite non-refillable eta ledger,
it checks every declared action against

```text
E[credit + Phi(next) - Phi(state) - kappa cost - eta_debit] <= 0.
```

It returns a checked nonnegative potential or exact nonnegative Farkas
multipliers giving a strict algebraic contradiction. An incomplete bounded
search returns `unknown`; nonconvergence is not reported as infeasibility.
Stopping does not award the remaining potential as extra credit. A restart
cannot refill the eta ledger or silently create a new initial allowance.

The new controls include paid cross-scale cache conversions, batch discounts,
preparation retained after stochastic failure, prefilled starts, duplicate
credit, and adaptive stopping. Independently implemented finite oracles compare
1,600 deterministic models against a complete integer grid and 2,025 stochastic
models against exact two-state interval conditions: **3,625 models in total**.
These check feasibility and the least potential without reusing the solver's
basis enumeration as their oracle.

A finite-model expectation certificate is not an all-algorithm W1 reduction or
a chain-security tail bound. The earlier
[stateful exponential-potential interface](../../formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md)
remains a separate obligation, including joint residual quantum state. Its
6,156 conditional cases are retained checks of that earlier model, not 6,156
new native mining experiments.

### 2.4 A concrete complete-MU1 proof-reuse control

The [reuse probe](../../formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py)
loads a previously recorded complete two-unit fixture and a separately pinned
PMH1 expected context. The verifier does not obtain its expected context by
trusting the submitted packet. See
[actual-mu1-reuse/report.json](actual-mu1-reuse/report.json) for the retained
21-predicate result, input pins, output manifest, and source identities.

The original context has nonce 24 and receives research credit 32. Regeneration
under that unchanged context produces identical proof and packet bytes, ticket,
and identity; a duplicate adds zero credit. The hybrid changes the global nonce
to 26, retains the entire first unit proof, and actually recomputes the second
unit using the existing prepared-matrix implementation.

The hybrid's outer aggregate ticket really wins. Its new second unit passes
complete scalar W1 verification and reuses the prepared `A,B,AB` prefix. The
stale first unit fails on the changed challenge with `TRANSCRIPT`; full MU1
verification and its research counter both refuse with `W1_TRANSCRIPT`. The
counter remains at 32.

This is a literal whole-proof reuse control on actual MU1 bytes. It does not
show that every new valid unit must perform the reference implementation's
operations. Legal product caches, context-specific nonce banks, shared traces,
batching, and quantum strategies remain in the lifecycle cost obligation. The
probe runs the complete scalar verifier, not a new native process, and claims
no mapping from its operation path to a universal physical cost bound.

### 2.5 Native C0/C1 branch-schedule research and independent packet replay

The [Rust component](../../trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs)
and [native tests](../../trillionnium/crates/trnm-pon-node/tests/research_work_schedule.rs)
reconstruct a bounded genesis-to-parent path, derive the anchor from that
branch, and bind the profile/anchor identity. C0 keeps a fixed target for the
whole study window. C1 implements integer ASERT over full 256-bit targets; its
activation block retains the preceding rules, and subsequent timestamps must
be nondecreasing and strictly above MTP11.

The required target is independent of the candidate timestamp and local
current time. The local clock only changes `Eligible`/`DeferredUntil`; historical
target and work remain unchanged. Work is the existing
`floor(2^256 / (T+1))`, accumulated with checked 512-bit arithmetic.

The 12 native tests retain 14 new complete W1 packets, seven for each backend.
Their proof inventory is not a count of total mining attempts or a cost bound.
The exports are:

- [PNH1 report](native-final/pnh1-authenticated/report.json) and
  [PNH1 independent reader output](final-12-pnh1-authenticated-reader.stdout.txt).
- [PGH2 report](native-final/pgh2-growth/report.json) and
  [PGH2 independent reader output](final-12-pgh2-growth-reader.stdout.txt).

The [independent reader](../../scripts/pon_branch_work_schedule_reader.py)
recomputes packet identities and challenges, branch ancestry, profile and
anchor digests, targets, MTP, and work from the complete bytes. PGH2 retains its
full challenge domain and account-witness commitment. Every complete scalar
W1 transcript/product is replayed, including the time-rejected packet.

A new-target proof passes the research verifier while the original Node refuses
it with `TARGET`; this is policy isolation. The separate backward-time control
has the correct target, a valid complete W1 proof, and a timestamp above MTP,
then fails specifically at `SCHEDULE_TIME_NONDECREASING`. An old proof failing
against a new target is not used as evidence that the time rule was fixed.

The reader does not reexecute native admission, cold reopening, account-state
transitions, or growth-account proofs. Those remain externally recorded native
observations. An externally recorded report digest pins the observations and
packet identities; it does not authenticate source or host provenance.

**C0/C1 here concern the existing target-based work relation.** Fixed-probability
MU1 and its research `16u` credit still have no native weight/identity or DAA
bridge. This archive does not silently combine target-based ASERT with an
activated variable-u MU1 consensus rule.

## 3. Validation ledger

Unless a row says otherwise, completed results below refer to source
`103cdf67108a667d8570388f9dd402210c160157`. The JSON records retain exact commands,
exit status, and source identity. Distinct kinds of counts are not added into
one purported security-test total.

| Check | Result | Scope/count |
| --- | --- | --- |
| New fixed-probability contract suite | PASS | 16 test methods; includes 288 finite subset controls |
| New credit-feasibility Python suite | PASS | 31 test methods; 1,309 finite credit-model comparisons |
| New additive-potential suites | PASS | 40 methods: 34 component controls and 6 independent methods; 3,625 model comparisons |
| New Python methods, combined | PASS | **87 = 16 + 31 + 40** |
| Actual MU1 reuse probe | PASS | 21 predicates; independent pinned expected context and full scalar verification |
| New native branch schedule | PASS | 12 tests; 14 retained complete W1 packets across PNH1/PGH2 |
| New PNH1 reader controls | PASS | 9 tests against the corresponding export |
| New PGH2 reader controls | PASS | 9 tests against the corresponding export |
| Retained joint-consensus native controls | PASS | 2 native tests; 114 complete packets per backend |
| Retained joint PNH1 reader | PASS with recorded skip | 22 run, including 1 skipped; the skip is not counted as a pass |
| Retained joint PGH2 reader | PASS | 22 passed |
| Existing work-scale suite | PASS | 24 tests |
| Existing stateful-tail exercise | PASS | 6,156 conditional finite cases |
| Source-integrity controls | PASS | 43 tests |
| CI source-execution controls | PASS | 77 tests |
| Project-boundary controls | PASS | 16 tests |
| CI workflow-contract controls | PASS | 111 tests |
| Repository canonical source/inventory gate | PASS | 1,202 Rust files, 4,320 local links, 26 workspace members; not the entire runtime test suite |
| Locked main Cargo graph | PASS | 26 workspace members / 180 resolved packages |
| Locked fuzz Cargo graph | PASS | 1 workspace member / 147 resolved packages |
| Lockfile preservation | PASS | Lockfiles unchanged |
| Formatting | PASS | Recorded formatting gate |
| Source whitespace | PASS | Source check only; raw-output whitespace retained |
| Retained consensus arithmetic checks | PASS | 10 tests |
| Retained legacy/reorganization checks | PASS | 5 tests |
| Retained readback checks | PASS | 6 tests |
| Strict Clippy | PASS | Recorded `--workspace --all-targets --all-features -- -D warnings` gate |
| Final post-run source identity | PASS | Commit `103cdf67108a667d8570388f9dd402210c160157` unchanged; identity record contains 17,888 entries / 1,787,971,327 bytes |

The post-run identity entry/byte counts describe the recorded identity inventory;
they are not counts of files or bytes in this evidence archive. The archive's
own manifest records its final artifact inventory.

**Coverage exclusions:** this campaign did not run the complete workspace test
suite or the complete `native_node` target. It does not cover or resolve the two
previously recorded failures from the
[#794 joint audit](../../docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md).
A source, graph, or formatting pass does not close those runtime observations.

## 4. The old joint counterexample remains a regression

The retained original-profile experiments are archived separately:

- [PNH1 joint observation](retained-joint-native/pnh1-authenticated/joint-daa.json).
- [PGH2 joint observation](retained-joint-native/pgh2-growth/joint-daa.json).

Each backend's 114 complete W1 packets is replayed under its original rules.
The `height 64 / work 793` branch still defeats the `height 65 / work 130`
branch, with the retained cold-reopen observation. This preserves the earlier
reachable joint timestamp/DAA/work result; it does not establish free mining,
a profitable double-spend, or the cost of any optimized attack.

Keeping this old-profile result is deliberate. The new research checks do not
rewrite historical target calculations, reset earlier credit, or relabel an
old-proof target mismatch as a successful timestamp repair.

## 5. Failed observations and corrections are retained

### Source inventory and its control assertion

An initial source-inventory check failed because these three Rust source paths
needed registration in the merged candidate:

- [src/research_work_schedule.rs](../../trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs).
- [tests/research_work_schedule.rs](../../trillionnium/crates/trnm-pon-node/tests/research_work_schedule.rs).
- The already-existing upstream [tests/history_stage_diagnostic.rs](../../trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs).

The first two belong to the new research component. The third matches upstream
blob `0ad34d092863dd32c5e9793daa618a91cd6c15f8` in parent
`8d5389748873dad6e296d17f2ff20483b5afa5bc`; registering it is not a claim that this
continuation authored that upstream test.

An initial control assertion expected two missing registrations and observed
three. That failed assertion is retained along with the corrected registration
and final canonical/inventory result. The passing final run does not erase the
initial failures or change their recorded source scope.

### Additive-potential input-soundness defects

Independent review of an uncommitted draft found that one-shot iterators could
be consumed during validation, allowing a positive-credit zero-cost loop to be
misreported as feasible. Delimiter-based constraint labels could also collide,
and Boolean/integer model names were not rejected consistently.

The final source first validates exact containers, record types, names and
rational values before any consuming traversal. Constraint labels use canonical
JSON arrays of their components. Component and independently authored regression
controls now reject the malformed inputs and verify the corrected certificates.

**The exact source hash of the uncommitted pre-fix draft was not retained.**
There is no preserved fixed-executable record for that draft, so the archive
does not claim a replay of a pinned old executable. It
records the review findings, the current negative controls, and the final tested
source that contains the fixes.

Raw evidence whitespace has not been normalized or cleaned. Source whitespace
checks passed; raw runner output and its formatting remain part of the retained
observation.

## 6. Reproduction

Use the immutable tested source and the recorded toolchain/environment. From
that repository root, run the project preflight before builds or edits:

```sh
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_credit_feasibility.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_fixed_probability_contract.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_amortized_cost_potential*.py' -v
python3 formal/pon-nakamoto-v1/fixed_probability_contract.py
python3 formal/pon-nakamoto-v1/amortized_cost_potential.py --compact
python3 formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py --check
```

The MU1 probe's optional `--out NEW_DIR` requires a new directory and reruns the
same full verification. Do not overwrite this archive to repeat the experiment.
The credit solver requires an explicit declared-envelope input; the actual MU1
contract's unknown cost points are not a solvable real-cost instance.

For native candidate regeneration, choose a fresh output directory and retain
the emitted report digests separately from the generated files:

```sh
TRNM_WORK_SCHEDULE_RESEARCH_DIR=/absolute/new/branch-schedule-evidence \
  cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test research_work_schedule -- --test-threads=1 --nocapture
```

To replay this archive, substitute the externally recorded digest literals from
the run records for `EXTERNAL_PNH1_DIGEST` and `EXTERNAL_PGH2_DIGEST` below. Do not
manufacture a supposedly independent expected digest from the file being checked.
The reader must import its dependencies from the same merged source tree; a
prior session's `PYTHONPATH` is not part of the reproduction contract.

```sh
python3 scripts/pon_branch_work_schedule_reader.py \
  --raw-dir evidence/pon-fixed-probability-contract-20261108/native-final/pnh1-authenticated \
  --report-sha256 EXTERNAL_PNH1_DIGEST
python3 scripts/pon_branch_work_schedule_reader.py \
  --raw-dir evidence/pon-fixed-probability-contract-20261108/native-final/pgh2-growth \
  --report-sha256 EXTERNAL_PGH2_DIGEST
python3 scripts/ci/test_pon_branch_work_schedule_reader.py \
  --raw-dir evidence/pon-fixed-probability-contract-20261108/native-final/pnh1-authenticated \
  --report-sha256 EXTERNAL_PNH1_DIGEST -v
python3 scripts/ci/test_pon_branch_work_schedule_reader.py \
  --raw-dir evidence/pon-fixed-probability-contract-20261108/native-final/pgh2-growth \
  --report-sha256 EXTERNAL_PGH2_DIGEST -v
```

For the retained joint experiment, consensus/legacy/reorganization selectors,
strict Clippy, dependency-graph and source/CI gates, use the exact invocations
and environments recorded in [final-native-checks.json](final-native-checks.json)
and [exact-source-qa-final.json](exact-source-qa-final.json). A focused rerun does
not reproduce unexecuted workspace targets or resolve a retained failure outside
its selected scope.

## 7. Remaining scientific and integration obligations

The primary scientific gate remains an actual resource lower envelope that
survives every legal preparation, cache, batch, task-selection, subset, and
retained-state strategy. It needs a justified initial classical/quantum state
budget and a compositional multiwinner tail, not only a mean first-winner cost.
Public work and publicly available models must be accounted for without
charging another participant's historic cost to each miner.

The native integration gate remains an explicitly versioned work identity,
credit/weight, and DAA bridge with both admission owners, activation, fork and
reorganization handling, availability, and cold recovery on one fixed source.
The present target-based C1 candidate does not supply that bridge for MU1.

Real Cell output quality, utility, negative-transfer checks, and local-owner
adoption remain separate from consensus work credit. A correct `NoUpdate` result
is not a failed mining obligation, and chain settlement does not grant local
installation authority. None of the results in this archive changes those
boundaries or promotes a qualification flag.

## 8. Archive integrity and provenance

[artifact-manifest.json](artifact-manifest.json) records SHA-256 and byte length
for every other file in this archive; the manifest excludes itself. Raw logs,
including failed observations and their original whitespace, and complete packet
bytes are copied without text normalization.
[archive-code-preservation.json](archive-code-preservation.json) records the
comparison with the tested source: every pre-existing tracked mode and Git object
is unchanged, and new paths are confined to this evidence directory.
[archive-links.json](archive-links.json) records the added README's local-link
check. These integrity checks do not authenticate the operator host.

The new report digests were retained from the native runner before independent
replay:

| Backend | SHA-256 of report.json |
| --- | --- |
| PNH1 | `e3fd4c236991529124ab5a493c31c0559694403aa57ec570267f8ac7ad0fec6d` |
| PGH2 | `5a80454acc7f899d3440bdfdda2a7856df5030c3bf7ba089e96abe8a405add04` |

[tool-versions.json](tool-versions.json), [provider-validation.json](provider-validation.json),
and [final-native-binaries.json](final-native-binaries.json) identify the observed
toolchain, existing OpenSSL provider, and native test binaries used. The OpenSSL
3.5.9 provider was already installed; this task checked its actual binary/static
library hashes, ML-DSA-65 sign/verify, and wrong-message rejection, and did not
rebuild it. Build-cache reuse is permitted and is not represented as a fresh
toolchain build or host attestation.

[failed-process-observations.json](failed-process-observations.json) retains
the complete tool-read stdout/stderr for early patch, merge, and inventory
assertion failures. [launch-reconciliation.json](launch-reconciliation.json)
separately records an unavailable launch whose absence was reconciled before
retry; it is not a successful check.
[development-review-findings.json](development-review-findings.json) records the
uncommitted input-soundness findings without inventing a retained pre-fix source.
[implementation-files.json](implementation-files.json) identifies this
continuation's source delta after the integration/research merge.
