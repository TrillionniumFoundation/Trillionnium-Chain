# Context-bound consumer decisions: explicit offline supplement

Owner: the existing M11 model-window/evaluation boundary. Implementation:
`formal/pon-nakamoto-v1/model_consumer_context.py`. This adds no trainer, journal,
model installer, ledger rule or independent-operator authority. It is opt-in;
historical V1/V2 receipts, domains and calling paths retain their meaning.

## Why the additional relation exists

A V2 consumer signature binds exact consumer/model/task/output/score/decision
bytes, not the exposure window directly. Rebinding caller-supplied lineage rows
to a different self-consistent series therefore does not change the signed V2
receipt. V2 deliberately claims key possession and structural relations, not
context-bound installation or independent evaluation. A later consumer use may
also satisfy V2 although the next generation was already registered.

The stronger causal claim needs an additional statement signed by BOTH of the
same consumer/controller keys, naming the exact completed window. The original
six-key uniqueness and strict signature checks remain mandatory. This does not
make those six keys independently administered organizations.

## Exact additional bytes

Each of exactly three envelopes has only `statement`, `consumer_signature` and
`controller_signature`. The statement has only:

| Field | Required meaning |
| --- | --- |
| schema | `pon-model-consumer-context-v1` |
| ordinal | Exact integer 1, 2 or 3; boolean aliases reject |
| window | Existing exposure-window identity, including context and previous link |
| run_plan | Exact run-plan digest retained by that window |
| assessment | Exact completed evaluation-receipt digest retained by that window |
| receipt | Exact V2 consumer-decision receipt digest pinned by the generation |

All four digests are exactly 64 lowercase hexadecimal characters. Both signatures
are exactly 128 lowercase hexadecimal characters. Let J be sorted-key ASCII JSON
of the statement, with no spaces, ensure_ascii=True and allow_nan=False. The
signed 32-byte message is SHA256 of:

    b"TRNM-MODEL-CONSUMER-CONTEXT-V1\0" || LE32(len(J)) || J

`context_signing_message` implements these bytes and validates their closed
shape. Calling it grants no authority and does not validate the supplied facts.
Neither signature covers a final three-window history that did not yet exist at
the time of the first use: each signs its own already-completed window only.

## Verification and integration boundary

The public `verify_context_bound_prospective_decisions` takes the same externally
pinned history, generation rows, V2 receipts and V2 attestations as the existing
signed V2 verifier, plus the three context envelopes. It first runs that COMPLETE
existing verifier. Then every statement must equal its derived window/plan/
assessment/receipt context and both existing keys must verify its new message.
For the first two rows, declared `used_at` must be strictly before the next
window's `registered_at`. Existing V2 already requires use after its own completed
window. An improved candidate may still remain `no_update` under a valid V2
`safety_hold`, withdrawal, resource or selection reason.

Any failure returns no aggregate result. Rehashing history, lineage or unsigned
context metadata cannot replace either signature. The existing evaluator and
consumer owners must explicitly obtain these statements and call this entry;
adding this verifier does not automatically install it in Agentd or activate
public model rewards. The caller must keep its trusted history pin and actual
current owner/withdrawal authority independently of the submitted material.

The output asserts only context signatures and DECLARED causal use order. Actual
installation, new consumer benefit, clock authenticity, hidden-window exclusion,
independent control, prospective acceptance, reward eligibility and production
remain unaccepted. No synthetic fixture is a real learning generation.

## Executable regressions

`test_model_consumer_context.py` checks canonical bytes, strict bounds, signatures,
consistent metadata substitution, role failures, causal edges and no partial
result. Its integration class uses the actual existing model-window fixtures and
V2 verifier, including resealed cross-series replay, old-domain rejection,
zero-gain refusal and improved-but-held candidates. Fixtures are explicitly
synthetic. The existing priority workflow runs the unchanged window suite and
this complete suite on both architectures and both head/main-merge selections;
source verification, original pressure/native model/state campaigns and failure
retention remain unchanged. CI wiring is not a claim that CI has passed.
