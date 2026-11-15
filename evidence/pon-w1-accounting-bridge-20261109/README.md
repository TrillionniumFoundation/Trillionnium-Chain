# Fixed W1 relation and exact-content bridge vectors

Status: **HOLD / NO-GO**. These are deterministic synthetic scalar fixtures,
not native Node, real-customer, model-efficacy or Sybil-cost qualification.
Base: `e96fff2f06e433932ed889676f2bf46e76e3eb3e` (PR #841).

Both matrices are 64 by 64 in row-major order over modulus 4,294,967,291.
A is the identity and B's flattened entry i is 17i+3. Thus the exact product
is independently known to equal B. Challenge 1 is 32 bytes of 0x01; challenge
2 is 32 bytes of 0x02. Both use the all-0xff target. This diagnostic target
does not model native difficulty or establish any work-cost bound.

Each `challenge-N-input.json` contains the full PNW1 transcript proof and
original V1 accounting events under fresh V2-derived content roots.
`challenge-N-pins.json` independently selects the statement and proof digest;
the accompanying `challenge-N-view.json` is the scalar/V1 replay result.
The trust placed in these reviewer pins is local to this supplied experiment.
It does not authenticate a native header or a parent-derived target.

`exact-vector.json` retains literal expected roots. The two statements have
distinct qualified-work commitments and identical task/output content and
unique-output keys. Each accounting fixture contains two reported attempts,
eight cost records and two consumer observations, with one unique adopted
output, CPU cost 80 ns in its synthetic meter, and unknown GPU cost. These
numbers exercise accounting, and are not benchmark measurements.

Reproduce each view from the repository root:

```bash
python3 -B formal/pon-nakamoto-v1/four_propositions_w1_v2.py \
  --input evidence/pon-w1-accounting-bridge-20261109/challenge-1-input.json \
  --pins evidence/pon-w1-accounting-bridge-20261109/challenge-1-pins.json \
  --check-view evidence/pon-w1-accounting-bridge-20261109/challenge-1-view.json
python3 -B formal/pon-nakamoto-v1/test_four_propositions_w1_v2.py -v
```

The original V1 files, signatures and meaning are unchanged. Test coverage
includes exact vectors, independently known product bytes, non-unique products
from different inputs, actual scalar rejection of corrupted proofs, fresh
signed synthetic demand composition, independent pins and all six content
bindings, cost preservation, and refusal of invented authority.

Local development used a partial checkout with many historical tracked
artifacts absent. Scoped Python tests do not establish a complete tracked-byte
or repository-link check. Full-source, native, hosted-head and prospective-merge
qualification must retain their own execution identity and result. Missing
historical files must never be staged as deletions.

The four original propositions remain independently unproved. In particular,
the full supplied W1 relation and exact matrix binding do not authenticate real
demand, prospective net benefit, all permitted strategy costs, or production.
