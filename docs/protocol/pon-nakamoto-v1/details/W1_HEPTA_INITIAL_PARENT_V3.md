# Hepta initial neural parent: source boundary v3

This is a source-bound refinement of [the v2 qualification review](W1_HEPTA_QUALIFICATION_V2.md)
within O06 and the [sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It is not a new installer, grant, execution receipt or product qualification.
The inspected Hepta source is `de133b601e133917cbe1ae03efb3a2ffc06dcd4a`;
historical execution observations retain their own commits and failures.

## The initial-parent dependency is more specific than an evaluated child

The original selection owner already implements
[`SelectedInitialSmolLmMaterialV1`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/codex-rs/hepta-learning-artifacts/src/selected_initial_smollm.rs).
`VerifiedArtifactSelectionV1::load_initial_smollm_material` consumes an original
verified selection, checks the fixed profile, immutable selector validity window,
known revocation, common owner trust and fresh authenticated CURRENT, and then
loads the original selected candidate. Every `with_current` read rechecks these
conditions and monotonic observed time. Failure or panic makes that material
object unavailable. There is no public constructor, clone, serialization or
installation conversion for this type.

The exact
[initial-material validator](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/codex-rs/hepta-learning-artifacts/src/initial_smollm_genesis.rs)
requires the fixed generation-one, no-predecessor Parameters shape, exact
canonical safetensors header, and positive-zero F32 bytes for every A and B
factor. This authorizes selected adapter bytes only. An initial parent need not
be a previously improved child; requiring that would make the first parent
circular. Later evaluated children retain the original efficacy, lineage and
selection requirements.

The immutable
[fixed profile](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/codex-rs/hepta-learning-artifacts/profiles/smollm2-initial-positive-zero-v1.profile)
names the following expected identities. Reading these constants does not prove
that this session downloaded, measured, loaded or ran the associated model.

| Item | Expected identity |
| --- | --- |
| Upstream | `HuggingFaceTB/SmolLM2-135M-Instruct@12fd25f77366fa6b3b4b768ec3050bf629380bac` |
| Upstream model SHA-256 | `5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c` |
| Upstream model bytes | `269060552` |
| FP32 backbone index root | `c320c094769446c21d7e4a33795d7f9310b5e4c8ca5a6fecca40207b1f735b7c` |
| Tokenizer files root | `a1883207efeacecee399f4dc699d2b547eb2d6ddb7500522933ed76c1521fb93` |
| Target contract | `2bb480a2becd44b7f4e4b03e557e270ed92a4bb952e0a634562d23d7f0f97e46` |
| Adapter layout | 30 layers, q/v projections, rank 4, input 576, output 576 or 192, alpha 8 |

## The inspected ordinary host lacks the initial-only composition

[`load_neural_evaluated_published`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/codex-rs/hepta-agentd/src/neural_cognitive_ranker.rs)
requires an evaluated candidate with its genuine eligible predecessor and
matching lineage, registry and compatibility pin. The
[`prepare_smollm_neural_agentd_v1` host](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/codex-rs/hepta-infer-worker-host/src/smollm_cognitive_host.rs)
loads that product-qualified process bootstrap before composing the original
inference and FinalUse owners. That route does not consume the initial material
type. Its ordinary compatibility digest also has a different meaning from the
fixed initial profile digest, so a cast or substituted digest is not a valid
composition.

The existing Hepta
[end-to-end contract](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/de133b601e133917cbe1ae03efb3a2ffc06dcd4a/docs/lane-e/END_TO_END_LEARNING_SEQUENCE.md)
already identifies the missing work: retain real main-weight and forward
measurement, compose a distinct initial-only constructor and ordinary task
context, and then use unchanged eligible-child, CURRENT, cold-recovery and
three-round upgrade owners. This review follows that existing responsibility;
it does not introduce another model-selection authority or another product gate.

## Concrete implementation and execution obligations

The missing initial-only constructor must own the opaque selected material and
keep the original fresh CURRENT/expiry/revocation checks on every ordinary use.
It must bind the actually measured backbone, tokenizer, target layout and
adapter bytes to the same inference owner and ordinary cognitive context.
Generation-one initialization must remain distinguishable from evaluated
beneficial-child installation. No fabricated evaluator receipt or initial
efficacy claim is needed or permitted to bridge those two roles.

The host must obtain the actual protected owner inputs and original FinalUse
authorization, execute a genuine ordinary task, and retain its selected-parent,
CURRENT and model readback before that parent supplies training/evaluation
lineage. Recovery, revocation, stale-CURRENT and loss-of-owner cases must preserve
the same unavailable outcome. Only then can the original controlled three-cycle
mechanism exercise actual training, evaluation, explicit update/no-update,
settlement, cross-node retrieval, permitted adoption and later ordinary use.

Public or previously seen engineering tasks remain permitted by the existing
controlled-mechanism contract. An unchanged-parent/no-update cycle is a real
mechanism result when its executed and unexecuted stages are accurately recorded;
it is not a beneficial release or successful new-artifact installation. The
separate efficacy and public independent-operation obligations retain their own
evidence requirements.

## Verdict

The original owner-selected initial material is implemented in the inspected
source. Its ordinary initial-only host composition and joined execution evidence
are not established by the existing evaluated-child path. O06 remains open.
This increment does not modify the Hepta repository, mint owner inputs, install a
model, claim a new training execution, or promote historical hardware results to
the current source.
