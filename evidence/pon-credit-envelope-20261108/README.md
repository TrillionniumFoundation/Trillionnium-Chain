# Classical/quantum cost contract evidence

Date: 2026-11-08, UTC. Overall qualification: **HOLD**.

This packet records the finite public-credit decision, normalized probability
and complete stationary-renewal cost checks. All numerical cost inputs are
declared mathematical examples. None is a measured or proved minimum W1 cost.

## Source and scope

Development began from `b66e66d2465258d808c0f56ff851123306d4bdb4` in a separate
checkout. Publication is prepared against the current integration candidate
`8d5389748873dad6e296d17f2ff20483b5afa5bc` on
`fix/chain-six-axis-performance-20261103`. Final retained runtime and hosted
observations must identify the exact source they actually executed. Tests on
the development checkout do not establish the integrated checkout's result.

The earlier work-scale and stateful-tail contracts belong to a separate published
research branch. They are cited by immutable links, not imported into this
integration. Retained commands below name suites actually present in the
integration base.

The source-first candidate contains this initial receipt index. Completed
execution observations are appended only after the isolated runtime has
actually run them. A pending check is not a PASS.

## Reproduction

Run from a complete checkout, with a new output directory outside that checkout:

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/ci/run_credit_envelope_checks.py --output-dir /tmp/pon-credit-envelope-new-run
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_candidate_check_clock.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_restricted_oracle.py' -v
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/ci/test_ci_contract.py
```

The [pinned roster](../../formal/pon-nakamoto-v1/credit_envelope_test_roster_v1.json)
contains named methods, not an inflated count of loop iterations. The runner
requires registered, started and successful names to agree; skips and expected
failures are rejected. Its reports identify the exact selected file bytes.
The [hosted workflow](../../.github/workflows/pon-credit-envelope.yml) additionally
verifies every tracked source entry before and after execution for both the
head and GitHub's prospective merge, including its ordered parents and tree.

## Established finite mathematics

- Cost curves admit exact simultaneous scale neutrality iff their ratio is
  constant over the complete compared scale set.
- With two exact cost curves, the smallest worst efficiency spread is the
  square root of the range ratio of the two costs. The geometric-mean credit
  attains it as a mathematical diagnostic; it is not a native chainwork change.
- A finite rectangular envelope has a robust credit at tolerance rho iff its
  multiplicative constraint graph has no cycle with product below one.
- Exact negative-cycle examples include `9/16` and the three-scale `8/9`;
  the latter is not detected by checking two-scale cycles alone.
- Normalized sampling distinguishes domain retention from success density.
  Repeated-unit, setup, failure, restart and success-only costs stay separate.

## Gates that remain open

Actual W1 bounds covering all legal classical and quantum strategies, warm
adaptive portfolios, complete joint initial state, a mixed honest/attacker
process, native fork-failure reduction, lifetime budgets and original resource/
WAN acceptance remain unproved or unqualified. Honest-node observations do not
bound hidden adversarial resources. Finite tests and a verified cost table do
not set work, consensus, post-quantum or production qualification to true.

See the [project audit](../../docs/protocol/pon-nakamoto-v1/details/CLASSICAL_QUANTUM_COST_AUDIT_20261108.md)
and [full theorem contract](../../formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md).


## Completed runtime observations: initial failures and repaired source

Current tested source: `7201ce80bd0acba128c71ffd851b18c219c8b992`. Current tested tree: `43e46a0c64ab3b9369b7a54d0b7ef8aa3103da96`.
Initial source: `57511355b9dfb1fc02c90eb0713fd8e95263a662`; initial tree: `5d7a4f2e01e1b0712a7319cc230191043039ffa6`.
Both descend from integration base `8d5389748873dad6e296d17f2ff20483b5afa5bc`. The repaired source is the direct
child of the initial source and changes only the generated native inventory.

The [current complete execution](runtime-current/validation-summary.json) has
**17/17 stages passed**, including complete-source guards before and after,
13 repeated original stages and two individually named distributed-pipeline
tests. The [final job status](runtime-current/runtime-job-status.json) records
`succeeded`, exit 0, complete durable output and no timeout. The actual
[repair and validation driver](review-observations/orchestration/repair_validate_credit.py)
and [original driver](review-observations/orchestration/apply_validate_credit.py)
are retained with their exact reviewed bytes.

| Exact-source check | Result | Observed detail |
| --- | --- | --- |
| source-before | PASS | Exit 0; original stdout/stderr retained |
| preflight | PASS | Exit 0; original stdout/stderr retained |
| finite-math | PASS | 77 pinned distinct methods; retained reports verified |
| candidate-clock | PASS | 6 named methods |
| restricted-oracle | PASS | 12 named methods |
| source-integrity | PASS | 43 named methods |
| ci-contract | PASS | 107 named methods |
| repository-check | PASS | Exit 0; original stdout/stderr retained |
| inventory-check | PASS | Exit 0; original stdout/stderr retained |
| cargo-graph | PASS | 26 packages; locked and offline |
| cargo-graph-all-features | PASS | 26 packages; locked and offline |
| rust-format | PASS | Exit 0; original stdout/stderr retained |
| rust-clippy | PASS | Exit 0; original stdout/stderr retained |
| retained-native-work | PASS | 135 passed; 0 failed; 0 ignored |
| distributed-source-scope | PASS | 1 passed; 0 failed; 0 ignored |
| distributed-resume-identity | PASS | 1 passed; 0 failed; 0 ignored |
| source-after | PASS | Exit 0; original stdout/stderr retained |

The current complete tracked-source receipts before and after are identical:
15000 entries and 1652493618 bytes.
The inner [77-method roster outcomes](runtime-current/finite-math/test-outcomes.json)
bind selected mathematical sources; the outer source receipts independently
bind the complete worktree. Neither source identity alone nor fixture loop
iterations count as executed named tests. The [credit readback](runtime-current/finite-math/credit-envelope-verified.json)
checks the credit inequalities or negative-cycle witness. The
[normalized-cost readback](runtime-current/finite-math/normalized-search-verified.json)
recomputes fixed-example arithmetic using the same implementation; it is not
an independent implementation, a W1 attack, or a resource lower bound.

### Initial run remains an observed failure

The [unaltered first summary](runtime-initial-57511355b/validation-summary.json)
retains all 17 initial stages, including **inventory-check FAIL** and
**rust-clippy FAIL**. Its [initial job status](runtime-initial-57511355b/runtime-job-status.json)
is `failed`, exit 1. All original raw files are copied byte for byte; the later
success does not rewrite either initial failure.

| Exact-source check | Result | Observed detail |
| --- | --- | --- |
| source-before | PASS | Exit 0; original stdout/stderr retained |
| preflight | PASS | Exit 0; original stdout/stderr retained |
| finite-math | PASS | 77 pinned distinct methods; retained reports verified |
| candidate-clock | PASS | 6 named methods |
| restricted-oracle | PASS | 12 named methods |
| source-integrity | PASS | 43 named methods |
| ci-contract | PASS | 107 named methods |
| repository-negative | PASS | 50 named methods |
| project-boundary-negative | PASS | 16 named methods |
| repository-check | PASS | Exit 0; original stdout/stderr retained |
| inventory-check | FAIL | Exit 1; original stdout/stderr retained |
| cargo-graph | PASS | 26 packages; locked and offline |
| cargo-graph-all-features | PASS | 26 packages; locked and offline |
| rust-format | PASS | Exit 0; original stdout/stderr retained |
| rust-clippy | FAIL | Exit 101; original stdout/stderr retained |
| retained-native-work | PASS | 135 passed; 0 failed; 0 ignored |
| source-after | PASS | Exit 0; original stdout/stderr retained |

The initial `repository-negative` 50-method and `project-boundary-negative`
16-method passes belong **only to `57511355b9dfb1fc02c90eb0713fd8e95263a662`**. They were not rerun on the
repaired head. Their original outputs and explicit
[historical reuse declarations](runtime-current/validation-spec.json) remain
separate from the current 17-stage table.

The inventory failure came from one already-tracked integration source,
`trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs`, missing from the generated inventory. The
[repair record](runtime-current/inventory-repair.json) and
[exact seven-line diff](runtime-current/inventory-repair.diff) retain the cause,
unchanged generator, matching ripgrep/Git enumeration, seven added lines and
zero removals. This second source commit only repairs that generated inventory;
it changes no miner or consensus logic.

Initial all-feature Clippy reached E0599 for `PKey::private_key_from_seed`
without the repository-pinned provider environment. The original diagnostics
in `pq_account_native.rs` and its included `pq_account_owner.rs` remain in
[initial Clippy stderr](runtime-initial-57511355b/rust-clippy.stderr.log).
The later run explicitly binds the original OpenSSL 3.5.9 preparation receipt
and native artifacts before and after execution. This is not a claim that the
inventory caused the Clippy failure or that all post-quantum behavior is qualified.

### Provider preparation and cancelled transport

The [successful original-script receipt](provider-current/observations/pq-provider/provider.json)
and [public build log](provider-current/observations/pq-provider/build-and-smoke.log)
retain the fixed OpenSSL 3.5.9 preparation. The official release asset is
53279637 bytes and SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`. Thirteen HTTP range parts were
assembled and the complete original pin was checked; the original preparation
script checked its copied archive again. The
[transport summary](provider-current/transport-summary.json),
[complete archive check](provider-current/archive-verification.json) and
[setup result](provider-current/setup-result.json) retain these separate steps.
No dependency version or source pin was changed. The
[selected provider before](runtime-current/selected-provider.json) and
[after](runtime-current/selected-provider-after.json) are identical.

The earlier provider download was **CANCELLED**, exit -15, while downloading.
Its [public log](provider-initial-cancelled/build-and-smoke.log) and
[explicit cancellation status](provider-initial-cancelled/runtime-job-status.json)
are retained separately. It is not a preparation or smoke-test pass.
Only the named public provider receipts and logs are retained. No runner tree,
smoke directory, PEM, private key, installed library, executable, or source
archive is copied into this evidence packet.

### Earlier development refusals also remain separate

The 109-method local prefix run had one failure for an inherited GSC2 mutation's
specific diagnostic. Its [recovered excerpt](runtime-initial-57511355b/development-observations/ci-prefix-initial-failure.log)
is explicitly an excerpt, not reconstructed full raw output. The guard order
was corrected; [subsequent complete local output](runtime-initial-57511355b/development-observations/ci-prefix-final.log)
is retained separately. The first remote apply check failed before source was
written; its [original refusal](runtime-initial-57511355b/development-observations/runtime-apply-initial-failure.json)
remains. Three-way integration retained existing integration CI lines, as
recorded in [patch validation](review-observations/development-ci-merge/patch-validation.json).

The intermediate mixed checkout's 107-method run had 104 successes and three
missing-file errors for `test_useful_cell_execution_v2.py`. Its
[complete original output](review-observations/development-ci-merge/latest-ci-contract.log)
and [scope summary](review-observations/development-ci-merge/final-merge-summary.json)
are preserved. The integrated 107-method successes in the runtime tables are
separate actual executions. Ten [footer-control fixtures](runtime-initial-57511355b/development-observations/retained-footer-controls.json)
remain fixtures and are not added to the 77-method roster.

### Qualification and publication boundary

Finite mathematics and the listed current engineering checks are **PASS**;
overall security qualification remains **HOLD**. Actual W1 minimum costs,
all-strategy and adaptive-portfolio bounds, mixed CP/CG/CQ, lifetime budgets,
hidden adversarial resources, original WAN acceptance and production activation
are not established by these observations.

This subsequent commit only retains evidence. Its complete non-evidence Git
entries must match the current tested source exactly. Publication and hosted
head/prospective-merge checks retain their own source identities; no prospective
merge execution is attributed to either runtime table. The
[receipt index](receipt-index.json) binds every retained raw file by size and
SHA-256 and preserves both terminal states.
