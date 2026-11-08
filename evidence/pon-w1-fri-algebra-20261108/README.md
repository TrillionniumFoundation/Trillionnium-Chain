# Fixed W1 seal algebra replay evidence

This packet continues exact source
`2e5150c41484a8b3196b33de2e997794145edd7c`. It adds the fixed numerical mixed
AIR, DEEP, FRI folding and terminal equations to the historical transcript and
opening replay. No historical evidence file, original helper or production
verifier is replaced.

See the [technical review](../../docs/security/W1_FRI_ALGEBRA_REPLAY_20261108.md)
and [executable replay](../../scripts/w1_fri_algebra_replay.py).

## Source material

* `algebra-source-supplement.json.gz` is a deterministic gzip container holding
  the complete generated recursion `poly_ext.rs` and `core/ntt.rs` from RISC
  Zero commit `8c215e2f4ccdd935f0517bf05d90f1ae032840a9`. It is 70,636 bytes,
  SHA-256 `f649c85ff3775c275d3b7f891e4866ecea13a17ac5225eae8b359ec464051f86`.
  Every member has its byte length, SHA-256, Git blob SHA-1 and exact source URL.
* [Source provenance](source-provenance.json) records direct GitHub retrieval
  and the generated AIR's match to the earlier retained crate-member hash.
  A fresh complete crate download/build is not claimed.
* The 24-file historical upstream snapshot remains at
  [its original path](../pon-w1-qrom-implementation-20261107/README.md).
* Upstream source is Apache-2.0 and retains its complete copyright/license
  headers; the complete license is retained as
  [LICENSE-RISC0](../pon-w1-qrom-semantics-20261107/LICENSE-RISC0).

## Scope

All 12,359 generated operations are executed numerically. The actual mixed
AIR equality, 50 computed DEEP goals, 150 incoming FRI value comparisons and
50 terminal comparisons agree. The 50 DEEP links are included in the 150 FRI
comparisons. There are 201 compared algebraic equalities, not 251 independent
checks. Fresh transcript/Merkle replay is a prerequisite.

The [tests](../../scripts/ci/test_w1_fri_algebra_replay.py) include independent
arithmetic and interpolation implementations plus targeted fault injection.
Fault-injected captured values are not accepted malformed receipts.

Only fixed-input numerical qualifications may become true. Complete receipt
verification, language/VM semantics, all-program recursion, knowledge
extraction, QROM, complete W1/PQ, production and consensus admission remain
false; full security bounds and unconditional security bits remain null.

The generator refuses zero DEEP divisors, whereas upstream defines
`inverse(0)=0`. Every divisor in this fixture is nonzero. That stricter audit
restriction is explicitly retained, and no universal accepted-language
equivalence follows from this packet.

Reproduce with a new output filename:

```sh
python scripts/w1_fri_algebra_replay.py --output /tmp/w1-fri-algebra-new.json
python -m unittest scripts.ci.test_w1_fri_algebra_replay -v
```

## Executed validation and independent comparison

The [local validation record](local-validation.json) retains 47 distinct new
successful named controls, the 69 rerun predecessor controls, 43 source
integrity negative tests and 16 project-boundary tests. Repeated exploratory
runs are not added to those counts. The
[pinned roster](required-tests.json) lists every new test identity; its
registered, started and successful sets agree in
[the completion record](local/named-controls.json).

The fresh [algebra report](local/algebra-replay.json) is compared against a
fresh [register-expanded review](local/independent-review.json), using a
[separate comparison command](../../scripts/ci/w1_fri_algebra_report_check.py).
All 50 DEEP values, 150 outgoing fold values, 50 terminal results and 300
nonzero divisor identities agree. The reviewer computes individual register
terms and does not import the new combo-batched algebra code. Its
[source](review/recompute_register_deep.py) and
[independent review](independent-algebra-review.json) are retained.
The generated AIR left-hand-side interpreter is reviewed against the fixed
opcode semantics; the register-expanded script independently computes only
the check-polynomial side of that equality.

The first comparison attempted to hash denominator arrays in numerical combo
order; the independent register walk encounters combo 1 before combo 0.
[The ordering observation](review/comparison-order-review.json) is preserved.
The corrected comparator checks explicit query/combo identities and then
hashes the declared traversal order. Review additionally reproduced boolean
identity aliases in the initial comparator. The
[failed negative run](review/comparison-negative-before-fix.json) and
[successful corrected run](review/comparison-negative-after-fix.json) remain
separate; strict integer types and canonical field words are now required.

The local repository check still fails on an unmaterialized historical
archive. Its [original output](local/repository-check.log) is retained.
The [listed source/input hashes](source-candidate.json) do not claim a full
local checkout, native Cargo run or complete receipt verification.
The [new workflow](../../.github/workflows/pon-w1-fri-algebra.yml) separately
requires exact complete head and prospective-merge worktree identities before
and after execution. At the time of the local record, hosted observations are
pending; later results must have their own source-bound readback.

Run the complete named controls and independently check completion:

```sh
python scripts/ci/w1_fri_algebra_controls.py run --output /tmp/w1-algebra-controls-new
python scripts/ci/w1_fri_algebra_controls.py check --output /tmp/w1-algebra-controls-new
python evidence/pon-w1-fri-algebra-20261108/review/recompute_register_deep.py --output /tmp/w1-register-review-new.json
python scripts/ci/w1_fri_algebra_report_check.py /tmp/w1-fri-algebra-new.json --review /tmp/w1-register-review-new.json --output /tmp/w1-algebra-scope-new.json
```

All eight full proof interfaces remain open. The complete security obligation
count is still zero; the complete bound and unconditional project security
bits are null. The newly checked numerical subclaims do not promote those
separate mathematical or production decisions.
