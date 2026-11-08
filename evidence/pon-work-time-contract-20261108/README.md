# Work profile, branch time and joint-cost observations

## Decision and source

**HOLD_NO_GO.** The executable research controls pass on the source below.
They do not qualify native consensus, all-algorithm cost bounds, deployment,
positive payment or a real Hepta evolution.

| Identity | Value |
| --- | --- |
| Source actually executed | `2141962ea7b9a1498acbd99acfdfe123335f613c` |
| Executed source tree | `a7e3ae9d9a4f6efa5950de6763be20ba5f3b19b5` |
| Parent baseline, PR #794 | `b16bae2824e6c8236ef2011fc93a74df3ac7f039` |
| Unchanged native subtree | `bf84f89b235adfcffcb0d3540c22c120f4031e13` |
| Frozen baseline entries / bytes | 1,747 / 27,613,671 |
| Work contract digest | `6d71aced74e18bcb025653ba0f03efc8475d014de04ed4563f2ba3545b213ed7` |
| PR | [#805](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/805) |

This evidence is attached after the tested source commit. Its attachment commit
is not retrospectively called the execution source. The full catalog records
the tested HEAD, checks all listed source bytes against it, and records empty
uncommitted source lists both before and after. The surrounding baseline
contract separately verifies its complete frozen native/formal/config roster.

## Actual results

| Control group | Unique named controls | Result |
| --- | ---: | --- |
| Frozen work profile and source contract | 19 | PASS |
| Temporal reference and integer DAA | 31 | PASS |
| Cost envelope and lifetime arithmetic | 29 | PASS |
| Full-verifier legal optimization catalog | 25 | PASS |
| Integrated required roster | **104** | **104 PASS, 0 fail, 0 skip** |

The 18 pinned ASERT vectors are cases inside one named test; the 1,296 bounded
integer comparisons are cases inside another. They are not extra named tests.
Separately repeated or independently reviewed tests are not added to 104.

The fresh catalog and a separate process replay both passed. Their fixed
24-cohort experiment retains 96 complete attempts and 24 actual first-tile
cancellations. Original targets accept 57 candidates and reject 39. The 39
misses additionally undergo explicitly labelled maximum-target diagnostic
relation replay; that replay does not turn them into accepted work. The
experiment also records 33 withheld hits, 57 completed attempts after the
first hit, and 24 local bank extractions.

These are matched deterministic candidates repeated across three strategies,
not 57 independent mining successes. There are zero native admitted blocks.
No Python thread speedup, quantum device result, minimum cost lower bound,
complete physical bill or real network publication is claimed.

The cost runner joins both model inputs to the actual raw baseline profile
SHA-256. The current model returns `HOLD_MISSING_BOUNDS`: 12 endpoints remain
unknown. The synthetic paid-preparation example returns `INFEASIBLE`, with
minimum expected joint credit `7/2` exceeding its declared cap `3`.
Its batch condition is independently specified for the same model window;
it is not inferred from fixed-confidence cost. `failure_budget` remains null.

## Evidence index

- [Execution and raw artifact hashes](source-run/execution.json)
- [All required, started and successful test identities](source-run/named-controls.json)
- [Full test log](source-run/tests.log)
- [Before](source-run/contract-before.json) and [after](source-run/contract-after.json) frozen-source checks
- [Full catalog](source-run/catalog.json) and [incremental partial records](source-run/catalog.json.partial.jsonl)
- [Generation outcome](source-run/catalog-generate.stdout) and [separate replay outcome](source-run/catalog-replay.stdout)
- [Current cost model](source-run/cost-envelope-current-hold.json) and [paid-batch counterexample](source-run/cost-envelope-counterexample.json)
- [Machine-readable qualification](qualification.json)
- [Source publication manifest](source-publication-manifest.json)
- [Independent review record](independent-review.json)
- [Prepublication static command results](prepublication-static/summary.json)

All raw stdout and stderr, including empty successful stderr and the failed
whole-repository check, remain present. `execution.json` hashes every other
file in its execution directory. `SHA256SUMS.json` covers the attachment's
remaining files, including this index; it does not hash itself.

## Retained failure and test scope

The prepublication project-boundary controls passed 16 tests and the existing
source-integrity controls passed 43. Those run before the source commit and
retain their own limited scope in the raw summary. They are not native tests.
Preflight, distributed-source inventory and CI-contract checks also passed.

The local checkout omits historical evidence blobs. Its whole-repository
checker exited 2 with the original error:

```text
Repository check failed: broken link docs/README.md -> ../evidence/pon-v1/README.md
```

This failure is retained in
[raw stderr](prepublication-static/repository-full-check.stderr).
Local `rustc` and `cargo` were unavailable, and no local native binary was
executed. Original #794 native failures are not replaced by these Python
controls. The old native timestamp rule is not upgraded by the new separate
temporal namespace.

The dedicated GitHub workflow separately checks the exact PR head and its
actual prospective merge using full checkouts and before/after tracked-source
receipts. Hosted status, source identities and artifact readback must be read
from the corresponding run; this attachment does not predeclare a hosted pass.

## Reproduction and continuation

Create a checkout at the exact source commit above before replaying this
catalog. Keep the report at an external absolute path and run:

```sh
python formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py --replay /absolute/path/to/catalog.json
```

The reader deliberately rejects replay as evidence for another HEAD, including
a later evidence-only commit. For a new source, produce a fresh observation:

```sh
python scripts/ci/run_work_time_contract_v1.py --output-dir /absolute/new/output-directory --campaign
```

The output directory must be new and outside the source tree. Exact timing
values are observations of that environment, not portable cost guarantees.

The [seven-package integration record](../../docs/protocol/pon-nakamoto-v1/details/WORK_TIME_COST_INTEGRATION_20261108.md)
and the [single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
contain the actual remaining obligations. In particular: native temporal
admission and recovery wiring; a mandatory variable-work relation; classical
and quantum all-algorithm envelopes; joint CP/CQ/CG and lifetime bounds; one
same-source/resource WAN/recovery/payment iteration; and actual independently
evaluated, protected Hepta adoption, loading and next-task use remain open.
