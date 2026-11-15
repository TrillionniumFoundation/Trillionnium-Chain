# Four separate proposition evidence view V1

Status: reviewable research adapter, **HOLD**. This is a read-only view over
existing observations, not a new funding, payment, evaluation, adoption or
consensus owner. Its namespace is `pon-four-propositions-evidence-view-v1`.

The four propositions are computation correctness, genuine commissioned demand,
usefulness after complete costs, and proportional resource cost for every allowed
winning strategy. No one of them establishes another. This adapter checks the
consistency and supplied identities of existing evidence, and keeps the missing
external and mathematical premises visible.

## Implemented scope

`four_propositions_v1.py` reuses these existing modules:

| Source | What this view actually executes | What that does not establish |
| --- | --- | --- |
| `demand_evidence.py` | Replay original canonical signed bundles through `DemandEvidenceBook.observe`; compare each exact composition observation and final book snapshot. | Actual escrow/payment, customer independence, motivation or data rights. |
| `work_utility.py` | Replay supplied attempt/cost/verification/adoption/reorganization events through `UniqueUsefulOutputAccounting`; compare every reconstructed event and final snapshot. | Truthful physical meters, actual consumer use, durable complete lifetime history or positive net benefit. |
| `upgrade_policy.py` | Replay original frozen plans, paired rows, signed receipts, cancellation, canary and proposal actions; compare the complete original observation. | Fresh/independent sampling, authentic costs, causal adoption or general future efficacy. |
| `work_profile_contract_v1.py` | Read its original `definition()` and `QUALIFICATION`; preserve the original `b16bae…` historical contract identity. | Current source verification, raw W1 proof verification, all-algorithm resource lower bounds or native admission. |

The historical `check_contract` is deliberately **not** executed on the current
tree, and its baseline or source roster is not changed. The new reader checks
17 specified source/configuration blobs from reviewed reference commit
`e2a02f9271b49f146e70806c8a66e161b5973971`. These are reader-source checks;
they do not authenticate a loaded process, the producer's execution or the
complete runtime environment.

## Input and review pins

The executable API is `project(value, pins, source_root=repository_root)`.
`value` and `pins` are separate JSON objects. The accepting reviewer must obtain
pins independently of the delivered evidence. They are still declarations, not
a new trust authority.

Input schema `pon-four-propositions-evidence-input-v1` has exactly:

- `schema`, `source_commit`, `binding`, `resource_units`;
- `demand`, `utility`, `upgrade`, each either the complete supported record or `null`.

`binding` has exactly `context`, `parent`, `inputs`, `output_spec`,
`output_content`, `task_content`, `qualified_work`, `evaluation_protocol`,
`work_profile`, `cost_unit`. Digests are canonical lower-case SHA-sized strings;
`cost_unit` may be null when no upgrade is replayed. This version requires the
original `pon-matmul-transcript-64-v1` profile. A binding hash is a label
association: the view does not derive semantic equivalence between a utility
task-content hash, demand inputs/output specification and an evaluation window.
The output therefore states `cross_proposition_semantic_binding_authenticated=false`.

Review-pin schema `pon-four-propositions-review-pins-v1` has exactly `schema`,
`source_commit`, `input_sha256`, `binding_sha256`, `demand`, `upgrade`.
SHA-256 input and binding identities use sorted, compact, ASCII JSON. Duplicate
keys, floats, NaN/infinity, unknown top-level fields and type aliases refuse.
Changing the declared source against its independent pin refuses. Matching it
does not prove execution: `execution_source_provenance_authenticated=false`.

Demand pins retain original owner keys, common-control registry root, bonus cap
and record limit. Each supplied action contains its complete original bundle,
expected contract/anchor, observation height and exact original observation;
the enclosing record also contains the original book snapshot. This bounded
view accepts up to 64 supplied task observations, without security-reward-book
events. Such events require their own extension; they must not be dropped from
a claimed snapshot. The target context, parent, inputs, output specification,
qualified-work identity, evaluation protocol and delivered output must agree.

Utility records contain original initial branch, required stages, limits,
complete supplied events and snapshot. Reconstructed event bytes must match,
including order, retained reorganization history and all supplied retries.
Distinct source/partition/function labels leave the original canonical output
deduplication unchanged. Unknown GPU measurements remain null. Memory peaks are
maximum reported operation peaks; cumulative wall time is not parallel elapsed
time. Reference operation counts are not physical resource lower bounds.

Upgrade pins retain owner key, alpha, proposal cap, attempt limit and the selected
target attempt. Original `begin`, `evaluate`, `cancel`, `canary`, `propose`
actions supply their actual inputs and receipts. All supplied prior attempts
are replayed; the selected target's context, parent, candidate, evaluation
protocol and cost-unit digest must agree with the view's binding. The original
reader owns all net-benefit/e-value arithmetic. Resource counters are never added
to score units, and no second cost conversion formula is introduced.

## Results and limits

Each proposition has its own `observation_state` (`MISSING` or `OBSERVED`),
`proven=false`, `facts` and `unresolved_obligations`. `OBSERVED` identifies a
supplied, replayed observation; it is not a proof or production qualification.
The Sybil slot requires a nonempty reported-cost history to be `OBSERVED`, and
its `all_algorithm_cost_bound` remains null. A container without actual events
does not count as an observation. There is no aggregate `PASS` field.

Signed claims of complete/correct delivery remain signed claims; this view does
not accept raw W1/AIR/STARK proofs. A future proof adapter must bind the precise
verified relation separately and cannot promote demand, utility or Sybil status.

`NoUpdate` retains the original reason. A completed, fulfilled no-gain evaluation
may retain its agreed service/evaluation fee. An upgrade cancellation, timeout
or execution-failed `NoUpdate` is not a completed evaluation. The view neither
equates no gain with a service failure nor invents improvement from a fee.

The full supplied history is checked; omitted real attempts and joint restoration
of all owners cannot be detected. Source/signature/hash checks do not certify
external truth, rights, independence or global completeness. Payment, adoption,
consensus-credit and production authorization fields are all false.

## Execution

```sh
python3 formal/pon-nakamoto-v1/four_propositions_v1.py \
  --input /path/to/evidence.json --pins /path/to/review-pins.json
python3 formal/pon-nakamoto-v1/four_propositions_v1.py \
  --input /path/to/evidence.json --pins /path/to/review-pins.json \
  --check-view /path/to/previous-view.json
python3 formal/pon-nakamoto-v1/test_four_propositions_v1.py -v
```

`--source-root` selects an explicit reviewed checkout; the default is the current
repository when integrated under `formal/pon-nakamoto-v1`. The CLI writes only to
stdout. Exit zero means supplied observations and the optional previous view
were reproduced. It does not grant any of the four propositions. A source change
requires review and a deliberate versioned reader update, never automatic pin
refresh. Tests use the original signed synthetic fixtures and state that scope.

Malformed nested containers or missing indexed event fields produce the stable
`FOUR_INPUT_SHAPE` refusal; existing semantic errors retain their original code.
CLI failures write only to stderr, emit no JSON view, and exit nonzero.
