# Actual training, NoUpdate, model loading and Cell material transfer

These are original observations from isolated CPU research runs on 2026-11-08.
They establish actual model execution and actual bounded Cell transport for the
recorded operations. They do not establish independent evaluation, public
discovery, long-term custody, payment, production FinalUse or activation. The
complete system qualification remains **HOLD_NO_GO**.

The actual candidate regressed: the incumbent answered three of four frozen
public questions correctly, while the candidate answered one. The candidate's
separate next-task probe also answered incorrectly. The subsequent controlled
NoUpdate run retains the complete incumbent, executes a new next task using that
incumbent and reads its exact response after starting another worker process.
No model efficacy gain is claimed.

## Distinct operations and freeze boundaries

| Operation | Original runtime job on `ai395` | Actual work and observed result |
| --- | --- | --- |
| `chain-learning-d9fb-20261108` | `1a1bc40c500-138b0-129` | Explicit new bootstrap followed by two actual 10-step training generations. Generation 2 loads the exact generation-1 adapter. |
| First-generation comparison and candidate probe | `1a1bc482607-138b0-162` | Eight evaluation forwards, one new generation-2 next-task forward, a new worker process and exact replay. Parent 3/4, candidate 1/4; next-task answer `no` is incorrect. |
| `learning-d9fb-retain-v2` | `1a1bc4fbecb-138b0-196` | A fresh 10-step training execution, eight evaluation forwards, strict NoUpdate, one new retained-parent next-task forward, cold exact replay and idempotency/budget refusals. |
| `learning-d9fb-cell-gen1-v1` | `1a1bc796e67-138b0-2b8` | Native Cell packing/serving/fetching of the actual retained adapter and two companion files, followed by real loading from the receiver directory, a new forward and exact replay in another process. |

The first run freezes its input files, public questions and evaluation profile
before training, but explicitly declares `none-research-load-only` as its
adoption rule. Its candidate probe is not an authorized adoption decision.
The second run freezes the strict rule and all four questions before **its own
fresh training**: accept only if candidate correct-count exceeds parent
correct-count; otherwise retain the complete parent. Previous tasks and outcomes
were already exposed. It is a controlled replay, not a prospective or independent
evaluation. All original first-run observations remain unchanged.

The original frozen plans are
[initial](initial/training/frozen-plan.json) and
[controlled NoUpdate](no-update/frozen-decision-plan.json).
The latter plan's recorded time precedes the
[actual training command](no-update/training-command.json), and its digest is
bound by the [decision](no-update/decision.json).

## Exact model and material identities

The original public trainer closure is fixed to Chain
`c96022b897c1235fdbdbfcfa32764403511c6aab`. The existing SmolLM2-135M-Instruct
material set, tokenizer and complete adapter contract are checked by that
trainer and the original Hepta weight worker. The exact Python executable is
`23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5`.
The worker entry-point digest is
`10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0`;
its package digest is
`1cfcb4997e86e1e9dee51f4a1b80b19439232344abce8d60d2e52cd624bd25d7`.
Raw open responses retain dependency versions, material preflight, thread limits,
model identity and source pins. Private worker source is not included here.

| Material | Exact identity |
| --- | --- |
| Retained generation-1 adapter commitment | `e1a9ce940c9d4b04bb827490708604178d4e2391e7afd81a3ca63008389d1e53` |
| Retained safetensors file, 933,544 bytes | `a946c2cd7073092e607fb5ee3fd9b2dc78053ba5dc3d357a0a27c273ebbf95e2` |
| Candidate generation-2 adapter commitment | `6d3ad4295d628df7e5d0927f9044f46dd4375511b2788eeb1606a2cb6d48aa34` |
| Candidate next-task output, 197,579 bytes | `9f3f1a4e39a680934feffa9cc624f28160b69a5b6c2abd6b47dd522f60eda96a` |
| Retained next-task output, 197,579 bytes | `5b803dad6abdaaf5e732496b85f3c1d90440bf06975375513b0350a16d11ff22` |

Both initial LoRA files are retained. The controlled replay produces the same
candidate bytes deterministically, with a different actual training receipt and
operation; its candidate file is not duplicated. This equality does not make the
two executions one operation. The two retained-parent task operations also have
different request identities and actual worker processes, even though their
same-input deterministic output bytes agree.

The output artifacts contain all 49,152 original vocabulary logits, input IDs,
attention mask, two raw action logits and the original Q32 scores. The incumbent
next-task scores are `[162879406080, 162451603456]`; the candidate scores are
`[155978448896, 156542484480]`. The replay verifier checks these bytes and their
prediction ordering. Raw evaluation rows preserve all four questions and both
models' answers. Evaluation tensor bodies other than the next-task outputs are
not duplicated in this export.

## Cold readback scope

The initial candidate worker changes from PID 131731 to 131756. The retained
parent worker changes from 140436 to 140490. Original stdio request/response
transcripts, normal controlled-EOF exits, session ledgers and original responses
are retained. Reusing the original request returns exactly the same response;
changing its content produces `IDEMPOTENCY_CONFLICT`; another forward exceeds
the original `FORWARD_BUDGET`. The retained close response still reports one
forward example. This is a source-bound persisted worker-budget observation,
not external hardware invocation instrumentation.

These operations are research worker execution. The separate native learning
coordinator bridge has a new source, operation and evidence namespace. No older
actor fixture or these model receipts are relabelled as a completed production
learning-owner iteration.

## Actual native Cell transfer

The executable was built independently from fixed #807 source
`0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`, tree
`80170d240fbaba258a98f1b90d81a58724002b77`, using the original locked offline
Cargo graph. [Original build receipt](cell-build-original.json) records the
command and executable digest
`f4110b8a9126133303fdee34ed586018ab266433f0ee20d5650c8d6968a54427`.
The 3,865,848-byte executable was transferred to the model device and checked
there before execution.

The original native pack/serve/fetch/verify commands transfer the actual
`artifact.safetensors`, `target-contract.json` and `wrapped-adapter.json` into a
new receiver store. There are **1,011,315 payload bytes, 17 downloaded chunks,
three connections, zero cached chunks and zero rejected responses**. Every
receiver file matches the sender hash. The provider has a fixed 12-second
lifetime; each fetch keeps its original 3-second deadline and bounded cache,
request, connection and response budgets.

The worker then loads the transferred retained model from `replica/`, executes
a new next task and reopens the same session in another actual process
(PID 162308 → 162322). The full response replays exactly. The transport is
same-device loopback with one operator. This does not show independent operators,
public discovery, long-term hosting, full base-weight transfer or production
CURRENT binding. The two original SQLite database images are omitted; their
size and hash remain in the export manifest.

## Replaying the preserved evidence

Run from the repository root:

```sh
python3 evidence/smollm-same-iteration-20261108/verify_originals.py
```

The verifier pins the three original export manifests and checks all **233
original files** (105 initial, 94 NoUpdate, 34 Cell). It checks the exact executed
runners, generation ancestry, actual receipt-to-artifact references, pre-training
freeze order, the regression and NoUpdate decision, original response replay,
negative controls, full next-task tensor bytes and native Cell payload accounting.
It is an offline byte/identity replay, not a new model execution or independent
attestation. The real-model runners require the existing pinned model and worker
materials on an authorized research host; no full base weights or private
repository checkout is published here.

The raw source measurements and cost events are preserved. Supported-operation
FLOP counts are not complete-system work measurements, and these runs do not
establish a cheapest-work lower bound, net compute benefit or model generality.
