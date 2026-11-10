# PoN open-consensus continuation — 2026-11-10

Status: **HOLD_NO_GO**. This continuation repairs evidence acceptance and
retained evaluation checks, preserves adverse native observations, and makes
the relevant original artifacts independently replayable. It does not qualify
open consensus, useful model production, public service liveness, quantum
security or external-effect recovery.

The integration parent is `da1374a200022bc14dc2bd325cc9ba29dbcd24ab`, tree
`00479a98dabc6b1fd91a0ceef82ffbdbffb78067`, on the existing
`fix/chain-hepta-closure-candidate-20261109-481716` candidate, PR
[#847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847).
The sole plan remains the
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
No stored schema, signed domain, W1 relation, lottery/chainwork formula, original
four-second service target, resource budget or activation policy is changed.

## Source changes and their limits

### Fixed V4 lifecycle records

The [reader](../../scripts/pon_w1_lifecycle_cost_v4.py) previously accepted a
canonical but mislabeled or substituted material if its task hash was updated.
It also allowed specialized supported producer/material pairs to become
unsupported, and checked losing proof hashes for syntax and cross-producer
agreement without deriving the hash from the declared material and trace.

The reader now binds A/B and task to the frozen material recipe, checks all 117
producer/material support decisions (59 supported), and derives every proof
digest, including losing trials, from the canonical proof prefix and trace.
The final added controls expose 76 failing subtests against the parent reader;
the fixed 15 test methods pass. An earlier 121-failure run also contained 45
overly specific error-code expectations and is retained separately, not counted
as 121 distinct acceptance defects.

The fixed reader also successfully replays the original native V4 complete and
SIGTERM journals published in `c2297ad53fef1d9b552e657cfd205d583c91980d`.
Those observations were executed at source
`11791e2da79b69322271be2cffe03725165151d1`, not at this continuation.
All 105 archived files match their original manifest. The complete journal has
23,069 records, 936 cohorts, 1,888 verified searches, 3,848 completed attempts,
3,776 verifier calls and 288 canonical candidates. Both new readbacks equal
their historical readbacks byte for byte. The interrupted run remains
`INCOMPLETE`, with unknown unfinished resource cost rather than zero cost.

This is a consistency and compatibility result. It does not authenticate the
historical machine execution, replay every native transcript, establish the
cheapest legal strategy, or turn a measured cost into a lower bound.
See the [cost validation package](validation/cost/README.md).

### Retained native evaluation closures

The parent quorum path skipped the closure checks applied to classic
evaluations. Two controls using the existing signed fixture fail against the
parent: substituting a canonical `records_digest` still allowed adoption, and
adoption at height 56 still succeeded after setting `closed_height` to 57.

The [quorum validator](../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs)
now checks the exact retained 20-field closure, immutable plan/context binding,
historical score/evidence and counters, frozen denominator, exclusion bounds,
and all four false authority claims. Consumption rejects a closure later than
the caller's height. Hydration and adoption both run the checks. The final
regressions cover replacements, every field deletion and legal historical
closure followed by additional conflicts; the existing 17 signed cross-language
vectors retain their expected bytes.

The existing schema lacks conflict insertion heights. When a nonempty
historical conflict subset has subsequently grown, the validator cannot always
derive the historical subset or independently authenticate its digest. It also
does not independently authenticate cross-candidate exclusions or closure time.
Authenticated state roots and ancestry remain required. These are semantic
retained-state controls, not a demonstrated forged block or a new governance
authority. See the [protocol limits](../../docs/protocol/pon-nakamoto-v1/details/NATIVE_EVALUATION_QUORUM_V2.md).

### Test and CI fidelity

The parent full node test run retained 1,358 passing tests, one failure and 39
ignored tests. Its cancellation fixture observed four CPU reservations instead
of the expected three. The owner lock prevented native work, but a cancelled
worker could return and dequeue the third request before the reactor observed
that socket's shutdown. The fixture now observes the queued cancellation
before releasing either dispatched worker. All original no-work, later-success,
individual settlement and total CPU assertions remain. No production policy
or implementation changes in `public_v3.rs` are made.

The original hosted legal and factorial example tests actually passed 13 and
11 tests; the workflow still expected 8 and 6. Its retained History suite also
passed 33 with one intentionally ignored subprocess fixture, versus the old
expectation of 28 and one. The gate now requires the complete legal/factorial
example name sets, rejects missing, duplicate, failed, filtered or ignored
example observations, and retains the existing kernel and History controls.
Negative gate tests pass 9/9. Replaying the original logs makes the corrected
gate pass; the original hosted workflow remains a failed historical run.

The generated distributed inventory is refreshed for the already present
custody V2 configuration. Only the ten already-pinned, actually changed curated
source entries are rebound; the corpus retains 1,079 exact source blobs and all
refusal flags.

## Independent original hosted readback

The [hosted package](hosted-readback/README.md) retains three original ZIPs,
their API metadata, exact SHA-256 checks, all 74 manifest attachment checks,
source/process identity readback, complete recalculation and a portable replay
script. These artifacts belong to the parent source and Actions run
[42771007925](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42771007925).
No retained ELF was executed in this readback.

### False-trace rejection CPU

| Architecture / producer mode | Attacker cohort CPU ns | Production rejection CPU ns | Ratio |
| --- | ---: | ---: | ---: |
| x64 / default | 4,976,304 | 113,974,639 | 22.903471934 |
| x64 / full-limb | 5,799,338 | 113,902,139 | 19.640541558 |
| arm64 / default | 3,764,008 | 92,407,200 | 24.550213496 |
| arm64 / full-limb | 4,655,464 | 92,536,856 | 19.877042546 |

Each campaign uses nine material classes, eight samples and four searches per
sample: 288 candidates and 573 actual trials. All four campaigns repeat the
same deterministic 288-candidate set. They do not yield 1,152 distinct
candidates. Every fake candidate is rejected as `TRANSCRIPT`. Each campaign
has 288 production-verifier calls. Default and full-limb modes retain 1,152 and
1,440 verifier observations across four and five paths respectively; those
totals include reference/alternative paths as well as production.

The denominator includes actual prefix setup, all four reuse searches, misses,
hashing, record construction and winner cloning. It excludes material
generation, buffer destruction, evidence JSON output, network traffic, service
queues and signing. Each ratio's numerator sums only the 288 production-path
calls in that row; the other verifier paths are excluded. This is a measured
native microbenchmark ratio, not whole-service
amplification, a minimum attack cost or evidence of accepted fake work.

### Original four-second service failures

| Native observation | Baseline confirmations | Pressure confirmations | Pressure Submit replies | Original failure classification |
| --- | ---: | ---: | ---: | --- |
| Original | 1/1, 3.005164411 s | 0/1 | 7/7 accepted | `CONFIRMATION_TARGET` |
| Fresh verifier process | 1/1, 3.099049148 s | 0/1 | 7/7 accepted | `FRESH_NATIVE_PROCESS_REQUIRED` |

The original native process exited zero but the acceptance reader rejected it.
The fresh native process exited 101, so its process failure classification is
preserved. A successful Submit reply is not independently confirmed business
goodput. No deadline, resource limit or confirmation target is relaxed.

The last History replay in both pressure phases records
`PUBLIC_REQUEST_DEADLINE`. The original third-page history epoch open records
92.2 ms before its first CPU-wait checkpoint reaches deadline, with no packet
work entered. The fresh first-page packet work records 67.316409 ms CPU and
1.100883426 s wall time. Its enclosing client replay records 71.003650 ms CPU
and 1.597569214 s wall time, including 1,046 nested Host checkpoints totaling
66.335808 ms CPU. These nested measurements must not be added. Wall time minus
CPU time is not a measured lock-wait duration.

The fresh cache data records full replay for all 7 baseline and 205 pressure
lookups, with zero exact facts found, cached rejections returned or incomplete
lookups. These observations identify where the original runs stopped; they do
not establish a unique contention cause or authorize a performance claim for
the new source.

## Validation provenance

| Validation | Retained outcome | Scope |
| --- | --- | --- |
| V4 reader negative controls | Parent 76 failing subtests; fixed 15/15 methods pass | Python reader consistency |
| Existing fixed-material reader | 32/32 pass | Retained matrix recipe controls |
| Native CI gate controls | 9/9 pass | Log acceptance, including negative rosters |
| CI contract controls | 177/177 pass | Existing repository workflow contracts |
| Native quorum regression harness | Parent two regressions fail; final 9/9 pass | Includes 17 existing signed vectors |
| MVCC library tests | 153 pass, 0 fail, 9 ignored | Existing library suite; no all-features claim |
| MVCC strict Clippy | Pass | `--all-targets -- -D warnings` |
| Public V3 targeted native tests | 59 pass, 0 fail, 0 ignored; 1,263 filtered | Includes the repaired cancellation fixture; not a full node suite |
| Source-integrity negative tests | 43/43 pass | Existing tracked-source and source-fence controls |
| Curated corpus negative tests | 59/59 pass | Existing cross-branch source contract |
| Curated corpus check | `HOLD_NO_GO`, 1,079 source blobs | All production and activation refusals retained |

The [quorum logs](validation/quorum/README.md) preserve the initial two-test
failure reproduction separately from the final expanded harness. The
[original CI provenance](validation/original-ci/provenance.json) binds the six
unmodified job logs to their original URLs. The
[observed source snapshot](validation/source/observed-working-source.json)
records file hashes for the working-source controls; it is not a whole-tree
execution certificate. Exact committed validation is reported separately and
must not borrow an old-source success.

### Completed validation of the committed source

The retained [static manifest](validation/committed-fcc3/static/manifest.json)
and [native manifest](validation/committed-fcc3/native/manifest.json) bind the
actually executed commands to commit
`fcc3c86631c4fb5a1be59ba6da49d9d98d560761`, tree
`dcbeaec3ae9cf300c10223f12ae9890e05285b22`. Both final manifests report `PASS`
and `source_consistent=true`; every command verifies the raw committed source
before and after execution.

| Exact committed-source group | Actual outcome |
| --- | --- |
| Source and Python controls | All 12 listed commands pass: preflight, locked/offline Cargo graph, format, repository links, generated inventory, 177 CI-contract tests, 43 source-integrity tests, 59 corpus negatives, corpus check, 15 V4 reader tests, 32 material-reader tests and 9 native-gate tests |
| Public V3 native tests | 59 passed, 0 failed, 0 ignored, 1,263 filtered |
| MVCC default-feature library/integration tests | 259 passed, 0 failed, 9 ignored, 0 filtered, across 17 harnesses; the feature-gated OpenSSL account harness reports zero tests |
| Strict workspace Clippy | `--workspace --all-targets --all-features -- -D warnings` passes |

The [effective-version observation](validation/committed-fcc3/toolchain.json)
records Rust 1.95.0 and Cargo 1.95.0 using the same explicit runtime paths.
`--all-features` belongs to Clippy here, not to the runtime test commands.
The later publication extension changes only this evidence directory, including
the diagnostic collector's intermediate-state label; it does not change native
sources, tests, the Cargo graph or protocol/configuration inputs. The executed
manifests retain their exact `fcc3` source identity. They do not certify a later
whole-tree CI run or turn any qualification flag on.

The [committed validation runner](validation/verify_committed.py) uses the
existing `ci_observation` raw-source fence before and after every command. Run
it only from a clean committed checkout with the pinned toolchain and prepared
dependencies. Outputs must be new directories outside that checkout:

```sh
python3 evidence/pon-open-consensus-continuation-20261110-2334/validation/verify_committed.py \
  --repo "$PWD" --expected-head "$(git rev-parse HEAD)" \
  --group static --output /tmp/pon-continuation-static
python3 evidence/pon-open-consensus-continuation-20261110-2334/validation/verify_committed.py \
  --repo "$PWD" --expected-head "$(git rev-parse HEAD)" \
  --group native --output /tmp/pon-continuation-native
```

The native group includes all default-feature MVCC library/integration targets,
the selected Public V3 tests, and strict workspace/all-target/all-feature
Clippy. Listing those commands is not an assertion that they have already
passed at any other source; their source-bound manifests retain actual outcomes.
Only a final `manifest.json` can report completion. `progress.json` is an
intermediate observation and now remains `RUNNING` until a failure is observed;
it never grants completion even when its last command has returned. The
[service diagnosis](service-diagnosis.md) distinguishes observed phases from
unmeasured causes and describes the remaining bounded diagnostic work.

## Open obligations

| Proposition or boundary | Still required |
| --- | --- |
| Real task demand | Independent authorization, actual resources and payment, and genuine receiver demand |
| Correct computation and delivery | Complete relation coverage and actual receiver verification/use; declared records alone are insufficient |
| Net model benefit | Frozen independent future tasks, held-out evaluation, and all failed attempts/training costs |
| Consensus work cost | Cheapest legal strategies, shared preparation, caches, multi-target amortization, abandonment, GPU/ASIC and quantum resources |
| Public rejection liveness | Identity/connection/restart/receiver-wide resource responsibility and the unchanged failed four-second business gate |
| Joint consensus | DAA, timestamps, credited work, changing participation, congestion, hidden ancestry and classical/quantum strategies in one security model |
| Evaluation governance | Collusion, shared controllers, copied models, holdout contamination and fabricated demand |
| External effects | Target-side idempotency, durable non-rewinding journals, reconciliation and explicit `Unknown` handling for the same operation |

At the tested source, the
[fixed-probability contract](../../formal/pon-nakamoto-v1/fixed_probability_contract_v1.json)
still has 16 actual classical/quantum points with `lower=null`, `upper=null`
and `status="unproved"`; the [scope readback](validation/committed-fcc3/scope.json)
retains those fields and the false evaluation authority flags. Historical V4's
one-half target density cannot fill the MU1 contract's one-sixteenth terminal
probability cost points.

Existing durable same-operation, pending/`Unknown`, reopen and liability
components are retained. The remaining external-effect obligation is their
combination with actual provider/payment/resource evidence, a production
adapter, an effect sink and an authenticated reorganization feed. Verifiable
provider declarations alone do not prove a real external action or compensation;
see the [native effect-readback limits](../../docs/security/PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md).

No public-prefix, chain-growth, chain-quality or six-confirmation failure bound
is established by this continuation. Synthetic joint models and local semantic
controls do not supply those proofs. All business, release, whole-chain and
activation qualification gates remain denied.
