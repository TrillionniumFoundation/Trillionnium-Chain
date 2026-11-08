# Constructed W1 search under a finite deadline

Status: **Draft / HOLD**. Base source:
`7a98f27f99abccc28da2f1f3cc60bdaa2eca4890` (PR #755).
This is a research continuation on the existing integration lineage.

## Scope of this source change

- Repair zero-iteration identity and the exact `1/4`, `1/2` and `3/4` Grover
  probability periods. The original
  floating-point implementation could assign a positive probability to an
  impossible measurement; exact rational reference controls retain that failure.
- Reject physical decompositions claiming more nonempty T layers than T gates;
  this is input coherence, not a universal minimum implementation cost.
- Add a literal-domain finite-horizon executor that retains partial preparation,
  iterations, readout, full candidate checks, proof and propagation costs.
  Completion at the deadline is inclusive; incomplete delivery earns no success.
- Bind actual full and restricted W1 constructions to the same declared
  physical-model envelope, all processors and predeclared schedule. Restricted
  phase membership and full legal acceptance remain separate. A measured legal
  winner may pass the full checker even when its phase was unmarked.
- Preserve source identities, complete scenario inventories, exact resource
  inputs, deterministic replay and refusal controls. Register the new tests in
  the existing repository-truth job without weakening its original commands.

The complete mathematical and cost contract is in
[QUANTUM_DAA_RESEARCH.md](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md).

## Frozen validation

The public implementation was committed before a complete new validation run:

```text
commit e31e4e1122c1f88c72025b507d5706a0dc96fbd7
tree   9ba43628c3004950f4d79392301dba306adb5a1f
```

Each of the four main validation groups checked all 10,977 tracked files against
that commit before and after execution. Their inventory SHA-256 is
`294697b43d9760b5cb092d280b44c37105f504a25b7b1acaee9153d3c3982a76`.
This evidence-only continuation does not represent a later composed tree as
having run the same suites again.

Ordinary HTTPS Git push had no credential in the shell. Publication through the
connected GitHub API preserved all 17 changed blob IDs and the complete source
tree, but generated a different commit ID. All main suites, the campaign,
independent controls, fuzz metadata and Clippy were therefore actually rerun on
the public commit above. [publication.json](publication.json) records this source
transition. The original local `aa46f285` and evidence `f22c513a` history remains
available in the historical archive's Git bundle, with the published #755 commit
as prerequisite. Fresh-clone replay of the primary campaign uses the public
commit and does not depend on importing that historical bundle.


| Check on frozen source | Observed result |
| --- | --- |
| Quantum, W1, reversible, DAA and bounded-campaign tests | 341 passed: 153 + 105 + 17 + 11 + 36 + 19 |
| Source-integrity negative tests | 43 passed |
| CI contract tests | 106 passed |
| PQ integration tests | 38 passed; 688 source pins retained |
| Repository and distributed-source checks | Passed; committed-clean source, 26 workspace packages, 1,275 Rust files and 3,579 local links |
| Main full locked/offline Cargo dependency graph | Passed |
| Cargo formatting | Passed |
| Workspace/all-targets/all-features Clippy with `-D warnings` | Passed |
| Fuzz full locked/offline dependency graph | Passed on the public commit using the previously checksum-verified isolated cache; 149 packages, including 136 registry packages; no fuzz execution |
| Independent finite-horizon controls | 22 passed on the frozen commit |
| Independent construction control groups | 10 passed on the frozen commit |
| Campaign generation and full replay | Both passed on the frozen commit |

The first local validation at `aa46f285` encountered a missing fuzz cache;
its original Rust aggregate remains **FAIL** and its separate cache-repaired
metadata pass is retained in the historical archive. The public-commit fuzz
metadata above is a new execution, not a relabelled old receipt.

On the public commit, an initial Rust wrapper failed before invoking Cargo
because `TRNM_PQ_OPENSSL` was not exported. The next attempt passed full main
metadata and formatting, but Clippy failed because the remaining OpenSSL values
were shell variables rather than exported process environment. That attempt's
`rust-rerun/result.json` remains **FAIL**. Exporting the existing OpenSSL 3.5.9
values fixed the environment; only strict Clippy was repeated, with complete
before/after source checks, and passed. Both failed attempts and the successful
supplement are retained. No source, lockfile, dependency version or test gate was
changed to repair the environment.

The full Rust runtime test suite was not rerun, and this package does not claim
remote CI completion. The 22 independent controls and 10 control groups are
reported separately, not added to the unit-test total. Earlier development
observations also include 120 full-state amplitude comparisons and 137 deadline
ledger cases; these are not relabelled as executions at the frozen commit.

Local Rust lint used Rust/Cargo 1.95.0 and OpenSSL 3.5.9, a dedicated target
directory, two build jobs, and disabled debug symbols and incremental compilation.
The successful Clippy log is retained. These static checks do not establish
provider parity or runtime performance.

## What the campaign actually observed

The source-bound [campaign.json](campaign.json) contains 16 predeclared model
runs. Its SHA-256 is
`1734edb20d26881f126b7bdb53b2df1171dbde238cacce32bc01245e0c9b6154`.

| Offline census | Fixed contexts | Candidate evaluations | Full legal winners | Restricted phase marks | Scalar-verified native PNW1 winner proofs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native shape, low two nonce bits | 5 | 20 | 5 | 5 | 5 |
| Reduced shape, low four nonce bits | 5 | 80 | 34 | 7 | 0 |

The 20 and 80 counts are evaluations across contexts. They are not globally
distinct nonce integers or independent tasks. The native census checks only four
numeric nonce values per context, not a full 64-bit nonce space. Its five winner
proofs are offline scalar observer work, not online quantum proof generation or
native block admissions.

| Model outcome | Runs | Meaning |
| --- | ---: | --- |
| `delivered` | 8 | Every successful run used zero Grover iterations, then assumed candidate-check, proof and propagation clocks |
| Deadline during first iteration | 4 | No Grover iteration, measurement or candidate check completed in these runs |
| Empty-domain schedule exhausted | 4 | Each run retained 16 failed candidate checks and charged template reuse, switch and revisit costs |

Across all runs there are 24 completed model measurement batches and 84 model
candidate checks. **Completed Grover iterations, online generated proofs and
native blocks admitted are all zero.** The eight delivery observations do not
demonstrate quantum acceleration or satisfaction of the native four-second
acceptance profile.

Full legal acceptance and phase membership are deliberately separate. If the
restricted marked set has size `s`, the full valid set has size `f`, and the
domain size is `N`, then for `s < N` the ideal measured candidate acceptance is
`p_phase + (1 - p_phase) * (f - s) / (N - s)`. A legal unmarked candidate can
therefore pass the full checker. The independent controls check this against
explicit state amplitudes rather than assuming every unmarked candidate fails.

## Retained evidence

- [qualification.json](qualification.json) records exact scope, counts and
  remaining false qualification flags.
- [frozen-validation.tar.xz](frozen-validation.tar.xz) contains all original
  public-source command logs, before/after identities, retained Rust environment
  failures and the successful supplement, independent controls, campaign
  interpretation review and the executed validation driver.
- [development-observations.tar.xz](development-observations.tar.xz) retains
  pre-fix numerical failures, the physical-model acceptance failure, earlier
  controls, the first local frozen validation and their original source identities.
  Its Git bundle preserves the corresponding original local commits. The files named
  `prepared-frozen-*` are prepared plans, not execution receipts.
- [manifest.json](manifest.json) hashes the delivered files. Each archive also
  has a `MEMBERS.json` listing all other members and their hashes.

The original special-angle failure produced 73 failing subcases in three test
methods; the later zero-iteration controls produced 11 failing subcases in two
test methods. These are retained regression observations, not extra independent
mining trials. The historical `constructed-01` and `constructed-02` observations
both used the same post-fix physical-model source and are repeats of ten control
groups; neither is evidence of a pre-fix failure. An independent reviewer's
initial processor count above the existing cap was refused and retained before
the review was corrected within the existing cap.

## Reproduction

Replay the campaign from a checkout of the exact implementation commit above.
Pass the absolute path to this evidence directory's `campaign.json`; a later
evidence-only checkout is not the original committed source identity.

```sh
python3 formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py --verify /absolute/path/to/campaign.json
```

For a new observation, run from that repository root; output paths must not
already exist:

```sh
python3 formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py --observe /tmp/w1-bounded.json
python3 formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py --verify /tmp/w1-bounded.json
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_*search.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1/experiments -p 'test_w1_bounded_search_campaign.py' -v
```

The campaign uses explicit illustrative classical and physical inputs, not
measurements. Its four-second analysis horizon is not native service acceptance;
its qubit cap does not represent available hardware. Source-bound replay is not
external execution attestation or a proof of schedule precommitment. Online
proofs generated and native blocks admitted are both zero.

## Remaining qualification gates

The original `quantum_oracle_resources.py` incomplete-input demonstration keeps
`complete_quantum_cost=null`. A separate constructed, fixed-context upper-bound
budget does not justify filling an unknown generic W1 input or setting an
attacker lower-bound flag. The most economical legal implementation remains an
independent research problem.

The current experiment still lacks calibrated fault-tolerant hardware,
end-to-end machine error accounting, measured preprocessing/reuse economics,
accepted native work under equal real budgets, native-valid costed adversarial
evaluation of Bailey–Sattath-style schedules and a justified mixed
quantum/classical consensus security argument. Physical feasibility and consensus
security remain distinct questions. Failure to reproduce a profitable attack, or
failure of an illustrative expensive construction to finish one iteration, does
not establish security. Native target, accumulated work and fork choice are
unchanged. All quantum-mining and activation qualification flags remain false.
