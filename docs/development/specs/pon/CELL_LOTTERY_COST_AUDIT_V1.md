# Cell computation and lifecycle cost qualification V1

This conformance increment belongs to the existing
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md). It uses
the current [stateful Cell V2 relation](USEFUL_CELL_RELATION_V2.md) and leaves
its original arithmetic, source guard, verifier and native acceptance rules
unchanged. The [replay](../../../../formal/pon-nakamoto-v1/cell_lottery_cost_audit_v1.py)
and [controls](../../../../formal/pon-nakamoto-v1/test_cell_lottery_cost_audit_v1.py)
are deliberately not a cost-hardness certificate.

## What the executable observation establishes

The admitting fixture loads the retained public-source model and two actual
source-corpus rows, fixes its independent expected context before proving, and
uses two fixed nonces, 0 and 1. It calls the unchanged complete W1 prover for
each tile. Both complete five-tile witnesses pass the original V2 verifier with
the same entire output and successor state. All five denoised products are
equal, while all five nonce-dependent transcripts differ. Replaying the first
witness also verifies again; the computation verifier has no operation-spend
authority. The three accepted calls execute fifteen full W1 verifications.

This is an actual reference execution on retained model/input bytes, with an
all-ones target to avoid mining search. It is not a new training experiment,
real customer demand, production Node admission, measured mining advantage,
an independent Hepta Encoder, or an ordinary owner adoption.

The same run requires three original defensive rejections:

- Changing a tile's nonce while keeping its proof fails `TRANSCRIPT`.
- Adding JSON whitespace to the witness fails `V2_WITNESS_CANONICAL`.
- Changing the consumer-retained parent fails `EXPECTED_PARENT_CONTEXT`.

The observation distinguishes reusable useful values from the cost of a fresh
legal transcript. It does **not** say that the transcript can be generated for
free. In this relation the product returned by denoising is the unchanged
matrix product, whereas the challenge enters the noise and cumulative trace.
Any minimum-cost proof must account for the cheapest complete legal way of
producing that trace, all reusable products, setup and losing attempts.

The packing contains 15 active output rows, two requests and tile widths
`64,64,64,64,1`. That is 7,710 dense useful-product positions, compared with
1,310,720 positions in five padded `64 x 64` dense products. These are algebraic
shape counts only. Neither is a measured resource bill or lower bound for the
complete noisy relation. No speedup is inferred from their ratio.

## Six obligations and the actual defensive boundary

| Obligation | Existing control and executable evidence | Still required for consensus credit |
| --- | --- | --- |
| New nonce after one useful computation | V2 challenge binds contract, state, tile task, index and u64 nonce; nonce-only alteration fails full replay. The new observation has equal complete products and different legal transcripts. | A lower bound for the complete nonce-dependent legal relation including product reuse, incremental algorithms, preprocessing and shared state. |
| Claimed units with partial recomputation | V2 reconstructs all five material tiles and verifies every full transcript, complete products, state, model and segment dataflow. | An amortized cost inequality over all legal algorithms; five valid tiles or nominal arithmetic positions are not five independently paid work units. |
| Proof/signature/padding alternatives | Canonical JSON, fixed proof length, field encoding and tile padding are checked. The reference ticket hashes challenge plus trace, not an enclosing signature. | A joint analysis of every admitted representation and randomness source in the actual eventual consensus composition. Reference serialization control alone is not that theorem. |
| Preselect an output commitment before obtaining a witness | The cheap W1 precheck is explicitly insufficient; V2 invokes the full original verifier. Existing precheck tests retain this distinction. | Joint soundness and work-cost bounds for late witness search; a deterministic full-replay check is not a physical-work lower bound. |
| Reuse across parent/profile/version | Independent expected context, new version domains and segment identities stop invalid cross-context substitution. The pure verifier permits re-verification. | A durable owner of credit nullifiers and a common lifecycle account across contexts, private branches, restart and recovery. Hashing a fresh context does not itself charge a new computation. |
| Easy inputs, models and parameters | Frozen model bytes, source replay, policy, feature mask, numeric semantics and expected context are checked. Sparse/padded/low-rank lawful inputs remain possible. | A cost statement uniform over every allowed choice, or a narrower independently admitted work profile with its own proof. Public model training costs cannot be charged anew per nonce. |

The existing conformance suites are
[V2 execution](../../../../formal/pon-nakamoto-v1/test_useful_cell_execution_v2.py),
[V2 relation](../../../../formal/pon-nakamoto-v1/test_useful_cell_relation_v2.py),
[V2 segment/context controls](../../../../formal/pon-nakamoto-v1/test_useful_cell_relation_v2_adversarial.py),
[source binding](../../../../formal/pon-nakamoto-v1/test_useful_cell_source_guard_v2.py),
and [W1 precheck](../../../../formal/pon-nakamoto-v1/test_work_precheck.py).
The new replay does not claim to rerun every case in those suites; the final
validation record names the commands actually executed.

`max_attempts <= 4096` is a limit on the reference prover call. The verifier
admits a canonical u64 nonce; it does not restrict all legal strategies to
4,096 attempts. Similarly, `work_attempts` reports that prover's own attempts.
It is not an authenticated inventory of an adversary's failed, abandoned,
unpublished, helper or historical computations.

## Cost and payment composition

The [finite lifecycle game](../../../../formal/pon-nakamoto-v1/LIFECYCLE_COST_GAME_V1.md)
provides an exact conditional certificate within an enumerated resource model.
It is not an implementation of the missing all-algorithm reduction for this
Cell. The [service settlement adapter](SERVICE_WORK_SETTLEMENT_V1.md) keeps a
fulfilled service, model improvement and consensus work as different outcomes.
Successful reference verification cannot select a qualified work profile or
increase chainwork. Neither module activates a consensus rule.

The older [selected nonce-bank study](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/09fbc0f45151a68a1bf205641171840fbf309882/formal/pon-nakamoto-v1/selected_nonce_bank_research/THEOREMS.md)
is evidence that an immediate-decision policy class can omit legal retained
selectors. It concerns a selected local-product relation, not this cumulative
W1/Cell V2 relation. Its fixed-oracle prices, iid-ticket theorem and actual SHA
observations retain their separate scopes; no result is imported as Cell cost
qualification.

## Reproduce without qualification promotion

```sh
python3 -B formal/pon-nakamoto-v1/test_cell_lottery_cost_audit_v1.py -v
python3 -B formal/pon-nakamoto-v1/cell_lottery_cost_audit_v1.py
```

Retain the source and artifact identities returned by the report. The original
frozen source commit must be readable for source replay; unavailable historical
objects cause refusal and must not be replaced with a successful mock. A local
cost experiment that closes a listed gap needs its own original source,
complete resource accounting and qualification evidence. The six general cost
obligations, native work qualification and production activation remain open.
