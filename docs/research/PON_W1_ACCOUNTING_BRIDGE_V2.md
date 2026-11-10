# W1 exact-content accounting bridge V2

Status: **HOLD / NO-GO**. This is a read-only bridge for the fixed
`pon-matmul-transcript-64-v1` relation. It supplies no payment, adoption,
consensus-credit or production authority. Historical V1 roots, records,
signatures and reader behavior retain their original meaning.

## Input and API

[four_propositions_w1_v2.py](../../formal/pon-nakamoto-v1/four_propositions_w1_v2.py)
exposes `derive_binding(relation, *, source_root=None)` and
`project(value, pins, *, source_root=None)`. The helper verifies and derives
roots for new records; it has no reviewer pins or native authentication.
`project` independently pins the supplied statement and proof digest, checks
the derived accounting fields, and replays the original V1 accounting view.

The input schema is `pon-four-propositions-w1-input-v2`, with `relation` and
`accounting_input`. A relation contains exactly `challenge`, `target`, `task`
and `proof_hex`. The first three are canonical lowercase 32-byte hex values;
the proof is exactly 49,188 bytes in canonical lowercase hex. The review-pin
schema is `pon-four-propositions-w1-review-pins-v2`, with `input_sha256`,
`statement`, `proof_sha256` and the original `accounting_pins`. JSON rejects
duplicate keys, floating-point numbers, unknown fields and oversized inputs.

The pinned scalar `work_oracle.py` performs full transcript and product
verification before accounting replay. Passing a ticket filter is insufficient.
The verifier is explicitly scalar; a native-backend environment variable cannot
switch it. The local Python runtime remains trusted.

## Derived bindings

The descriptor fixes 64-by-64 row-major matrices, modulus 4,294,967,291,
canonical little-endian u32 scalars and the original PNW1 proof encoding.
`H` below is the existing framed hash and the descriptor uses canonical JSON.

| Accounting field | Derivation after complete verification |
| --- | --- |
| `inputs` | Original W1 task digest of the exact A and B bytes |
| `work_profile` | Fixed `pon-matmul-transcript-64-v1` |
| `task_content` | Fresh `w1-accounting-task-content-v2` domain over descriptor, A and B |
| `output_spec` | Fresh `w1-accounting-output-spec-v2` domain over descriptor |
| `output_content` | Fresh `w1-accounting-output-content-v2` domain over output specification and verified product bytes |
| `qualified_work` | Fresh `w1-accounting-qualified-work-v2` domain over exact challenge/target/task statement and proof SHA-256 |

All six fields must equal the supplied accounting binding. Roots apply to new
V2 records; this bridge does not reinterpret an old signed delivery.

The existing `unique-useful-output-v1` key uses context, derived task content
and derived output content. Different challenges over identical A/B therefore
keep the same key in the same context while retaining distinct qualified-work
identities and all reported attempt costs. Different A/B remain distinct even
when their products coincide. This is exact-byte accounting within the fixed
profile and context, without global semantic-equivalence or novelty claims.

## Report and verification scope

The output schema is `pon-four-propositions-w1-view-v2`. A successful report
records `VERIFIED_SUPPLIED_W1_RELATION`, exact matrix-content binding and the
original accounting view. It does not authenticate a native block header,
parent-derived target, Node admission, physical execution or execution-source
provenance. The original four propositions remain `proven=false`; real demand,
independent full-cost net benefit and all-algorithm Sybil hardness remain open.
All authority fields remain false and `all_algorithm_cost_bound` remains null.

The [regressions](../../formal/pon-nakamoto-v1/test_four_propositions_w1_v2.py)
cover full scalar verification, all six bindings, exact-content reuse across
challenges, distinct inputs with a coincident product, independent review pins,
strict input/report handling, source drift and unchanged authority boundaries.
Synthetic matrices and accounting fixtures do not qualify native execution,
real customers, model efficacy or a physical resource lower bound. The suite is
registered exactly once after V1 in the original protocol-contract CI lane.

```bash
python3 formal/pon-nakamoto-v1/four_propositions_w1_v2.py \
  --input input.json --pins pins.json --check-view prior-view.json
python3 formal/pon-nakamoto-v1/test_four_propositions_w1_v2.py -v
```

CLI exit zero means that the supplied relation and accounting view reproduce;
it grants no new qualification or external-effect authority.
