# Versioned useful-Cell integer relation

This specification belongs to the existing
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
`pon-useful-cell-int257-v1` is a bounded research relation for the existing
public-source integer router. It binds an entire read-only decision to its
admitted task, inputs, state and verifier. It does not change native W1 consensus,
authorize an owner action, install a model or grant a reward.

Implementation and controls:

- [Reference relation](../../../../formal/pon-nakamoto-v1/useful_cell_relation_v1.py)
- [Exact scalar numeric profile](../../../../formal/pon-nakamoto-v1/useful_cell_numeric_v1.py)
- [Relation rejection controls](../../../../formal/pon-nakamoto-v1/test_useful_cell_relation_v1.py)
- [Numeric and decision counterexamples](../../../../formal/pon-nakamoto-v1/test_useful_cell_numeric_v1.py)
- [Reproduction driver](../../../../formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py)
- [Existing complete-operator packing](SHARED_CELL_WORK_V1.md)

## Statement and independently retained context

The intended statement is

\[
R_v(T,s_{\mathrm{before}},y,s_{\mathrm{after}},w)=1.
\]

The executable verifier additionally requires consumer-retained `expected`
context and a verifier clock. An internally consistent contract supplied by a
producer is insufficient. `expected` contains exactly `contract_id`,
`program_sha256`, `parameters_sha256`, `before_state`, `consumer`, `allowed_use`
and `candidate_artifact`. The caller must retain these independently of the
downloaded contract, witness and verification report. Reconstructing them from
the producer's message would remove the external binding.

The canonical contract has seven substantive bindings, plus its schema and
explicit research scope:

| Binding | Frozen contents and executed check |
| --- | --- |
| Model | Artifact hash, integer-model schema and source commit; source extractor, research adapter, base/delta head, router and prequantized artifact identities. The actual model bytes and all five matrices are checked. |
| State | Cell ID, unsigned generation, before-state commitment and model artifact. Before-state must equal external expected state; the only allowed transition is exact read-only equality. |
| Inputs | Frozen Git source, allowed evaluation partition, complete ordered rows digest, ordered member IDs, source paths, normalized-content digests and feature digests. Every supplied row must match actual source replay. |
| Numeric | The fixed signed-integer profile, scales, bounds, bias coordinate, overflow policy, reduction order and field decoding. A committed unsupported numeric label is rejected. |
| Decision | Three-expert argmax, base plus selected delta, lowest frozen index for expert/class ties, STOP disabled, abstention disabled and inference randomness forbidden. |
| Output use | Class mapping, consumer, allowed-use string, deadline, request ID and candidate artifact. Consumer/use/artifact must match the independent expected context. |
| Proof | Relation/verifier identities, program and parameter digests, source-manifest digest, underlying W1 profile, challenge domain, target and per-tile nonce rule. |

The admitted mapping is `M00`, `M04`, `M10`. STOP and abstention outputs are false
for every row because this version explicitly disables both operations. This is
a complete decision for this fixed profile, not an implementation of arbitrary
Hepta stopping, routing or state mutation. A different policy needs a separately
specified relation and tests.

## Upstream features are reproduced, not asserted

The `encoder` component is the existing
[source-token hash extractor](../../../../formal/pon-nakamoto-v1/experiments/model_loop.py),
not a trained Hepta Encoder. The reference verifier actually reruns that source
producer against the model's frozen Git commit. It checks the complete selected
rows against the reproduced rows, including source task ID, path, normalized
content hash, partition, inventory-derived label and all 257 feature values.
Caller-supplied `source_verified` or `trusted` flags cannot replace this work.

The producer selects public Rust snippets using the pinned inventory and source
rules, normalizes them, hashes bounded tokens into 256 signed clipped counts and
adds the final bias value 8. The content digest identifies the normalized snippet;
the frozen commit, path and source-task construction bind its original source.
This replays feature provenance. It does not rerun training or establish that
the inventory labels are independent ground truth.

Only `consumer`, `evaluation_a` or `evaluation_b` rows are admitted, with one
partition per batch and no duplicate task IDs. Batch size is 1 through 64. The
replay subprocess disables Git replacement objects and lazy fetching, has a
bounded time/output allowance, and refuses unavailable source. Its small cache
stores immutable replay bytes keyed by source commit and program identity; it
does not cache a caller-supplied validity assertion.

Consequently `upstream_verified=true` is restricted to the frozen public-source
extractor. `ordinary_hepta_encoder_verified` remains false. A different Encoder
requires its actual relation or an explicitly authenticated upstream trust
boundary; a features-only calculation is insufficient.

## Exact numerical interpretation

The existing artifact contains five `3 x 257` matrices: base, router and three
expert deltas. Each artifact coefficient is an integer in `[-32767, 32767]`;
each feature is an integer in `[-8, 8]`, with coordinate 256 fixed to 8. Boolean,
floating-point and out-of-range inputs are rejected. The scales are coefficient
1024, feature 8 and output 8192. Outputs remain raw integers: inference performs
no rescaling, rounding, saturation or runtime quantization.

The independent scalar reference accumulates exact signed integers in ascending
feature order and returns all 15 product rows, selected routes, three logits per
request and predictions. Its model schema validation reuses
[model_contract.py](../../../../formal/pon-nakamoto-v1/model_contract.py); its
arithmetic does not call that module's inference function or NumPy. The tiled
consumer's results must agree with this reference for every product, including
unselected experts, as well as routes, logits and predictions.

For an odd modulus, a conservative integer dot-product bound is

\[
B=dM_xM_w+|b|,\qquad 2B<p.
\]

`checked_signed_bound` constructs this expression with exact integers and rejects
an unsafe bound. It must not replace the condition with `B < p // 2`: for
`p=97`, `B=48` is valid because `96 < 97`, while `B=49` is invalid. Canonical
residue 49 decodes to -48 under that modulus, demonstrating the ambiguity if the
bound is ignored. `centered_decode` rejects noncanonical residues; decoding alone
does not prove that an intended integer calculation was in range. Alternate
small odd moduli are arithmetic test parameters, not negotiated work profiles
or a primality certification.

This relation fixes W1's `p = 4,294,967,291`. Its single-matrix bound is

\[
257\cdot8\cdot32767=67,368,952.
\]

The bias is already the final feature coordinate, so no additional bias term is
added here. Merging base and selected delta can double a coefficient to 65,534;
the resulting logit needs the separate bound

\[
257\cdot8\cdot65534=134,737,904.
\]

Both satisfy the strict doubled comparison with the fixed modulus. Reusing only
the single-matrix bound for a merged output would be incorrect. The implementation
rejects unsafe ranges and never repairs them by wrapping or saturation.

`compare_behavior` reports numeric errors, route agreement and STOP agreement
separately, with exact rational numerator/denominator pairs. Its counterexamples
show that mean absolute error `1/200000` can change a lowest-index route and error
`1/100000` can cross a STOP threshold. Fraction-valued diagnostics do not add
fractional or floating-point inference support. No average-error threshold
automatically grants decision agreement, calibration, OOD or old-task retention.

## Five complete W1 verifications under a new enclosing identity

Packing reuses the existing complete-operator implementation: 15 weight rows,
all batch members and feature widths `64, 64, 64, 64, 1`, with explicit zero
padding. The witness contains the integer model, source rows and five ordered
entries, each carrying its tile index, nonce and actual PNW1 proof bytes.

The enclosing challenge is domain-separated by
`useful-cell-int257-v1/challenge` and binds the complete contract ID,
before-state digest, material task ID, tile index and unsigned nonce. Each
contract ID commits to its target, output use and frozen parameters. Substituting
a task, model, generation, batch order, consumer or numeric rule cannot retain
the original enclosing identity.

The reference verifier checks material bytes, then executes full
[work_oracle.verify](../../../../formal/pon-nakamoto-v1/work_oracle.py) for every
tile: transcript, product and target. A precheck, returned JSON status or matching
matrix output alone is insufficient. Only verified product bytes reach the
consumer, which checks canonical field values, coverage, padding and signed
bounds before executing the decision and comparing the independent scalar result.

This is a new research relation around unchanged W1 arithmetic and encoding.
It is not a native Node acceptance path or a replacement W1 consensus profile.
The reference prover and verifier perform the complete work; no succinct proof,
zero-knowledge property, proving speedup or end-to-end cost benefit is established.

## State, time and authority limits

`before_state` contains exactly `cell_id`, `generation`, `state_root` and
`model_artifact`. The candidate artifact equals the model used by this read-only
request. `after_state` must equal `before_state` exactly. A new generation,
updated root or replacement artifact is refused. The root is an externally
supplied commitment matched against expected state, not an independently
reconstructed native owner database.

The verifier checks its clock before verification and again after full source,
work, numeric and output checks. Acceptance requires
`start_ms <= finish_ms <= deadline_ms`, with exact unsigned integer clock values.
The default clock uses current wall time. A test clock is an explicit verifier
dependency, never a witness field. The completion check rejects a late result;
it is an acceptance fence, not preemptive cancellation of the work calculation.

This pure verifier does not authenticate owner authority, prove a live
generation has remained current, consume a request ID, persist replay nullifiers,
install artifacts or settle payments. Repeating the same valid statement can
verify again before its deadline. A real consumer must authenticate current
context and atomically check and consume any one-use authorization at its own
state/effect boundary. An `allowed_use` match records the agreed use; it is not
proof of the consumer's subsequent behavior.

## Source, program, parameter and runtime identity

`current_identity()` hashes the enumerated relation/numeric/model/source/work
modules and configuration files. `program_sha256` commits to that source
manifest, actual execution parameters and runtime version record: Python
implementation/version/optimization, Unicode database, NumPy and cryptography.
`parameters_sha256` commits to the fixed
relation, numeric/decision/scope profiles, existing wire parameters, W1 profile,
challenge and nonce rules, tile widths and limits. The source identity is checked
again after freezing, proving and verification to reject observed source drift.

At import, the verifier captures the source bytes. It checks loaded module
origins, compares already loaded function code against compilation of those
bytes, and checks public constants using a bounded AST interpreter for literal
containers, names and integer arithmetic. This catches disk edits after import,
preloaded stale functions, and stale numeric-profile constants or expressions.
It never executes arbitrary initializers to manufacture a successful identity.
Changing source requires restarting the process and freezing fresh context.

These are the actual listed source hashes and runtime version strings. They do
not attest every interpreter, native library or operating-system binary. The
verifier runs inside the consumer's trusted local execution boundary.

Contract JSON must be canonical and at most 64 KiB; witness JSON must be canonical
and at most 1 MiB. Duplicate keys, extra fields, unsupported versions and numeric
aliases are refused. A code change changes the program digest and requires fresh
expected context. Changing shape, numerical semantics, accepted decision rules,
challenge derivation or work trajectory additionally requires a new relation
namespace and separate behavior and work-security evidence.

## Reproduction and acceptance scope

Run from the repository root. The relation controls require the existing tracked
model/evaluation material and its frozen Git source to be available. The numeric
controls need no trained fixture or NumPy. Missing source is a refusal, not a
synthetic replacement.

```bash
bash scripts/project-preflight.sh
PYTHONPATH=formal/pon-nakamoto-v1 python -m unittest -v \
  test_useful_cell_numeric_v1 test_useful_cell_relation_v1
python formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py \
  --out /tmp/trnm-useful-cell-v1-new-run --batch-size 64
```

Choose a new output path for each driver invocation. The driver's default target
is `7f` followed by 31 `ff` bytes; it performs real bounded nonce search and full
verification. Its deadline is frozen from actual current time plus 600 seconds.
Unit controls may instead use a maximal target and explicit test clock to
exercise deterministic boundaries; they are not a mining-cost observation.
The commands define reproducible work and do not themselves claim a passed run.

The driver also verifies the saved witness in a fresh process and replays the
existing frozen consumer/evaluation quality protocol. Its admission context is
an explicitly local fixture; independent process execution is not independent
administration. A consumer can explicitly supply separately retained context:

```bash
python formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py \
  --verify-dir /tmp/trnm-useful-cell-v1-new-run \
  --expected /path/to/consumer-retained-expected.json
```

This command uses the actual current clock. An expired original request must be
rejected; a new experiment needs a new contract, not an extended old deadline.

A successful reference report retains `owner_authorization_verified=false`,
`ordinary_hepta_encoder_verified=false`, `succinct_proof=false`,
`work_security_qualified=false`, `production_qualified=false` and
`public_reward_eligible=false`. BF16 equivalence and model-behavior preservation
remain unestablished; calibration, OOD and old-task retention remain unqualified.
Relation correctness does not erase a prior failed quality or cost observation.

## Primary-source comparison: Pearl PIP-3

[PIP-3 at commit `9dacf7fb6c5fdcec95323d45cdd75fe0083499ff`](https://github.com/pearl-research-labs/pips/blob/9dacf7fb6c5fdcec95323d45cdd75fe0083499ff/PIPS/pip-0003.md)
is explicitly a Draft consensus proposal. It changes the useful operation to
FP8 E4M3 quantization and multiplication with FP32 accumulation and a peeling
correction. It acknowledges that its useful output need not match ordinary
multiplication bit-for-bit, while requiring verification to reproduce the
declared Hopper/Blackwell computation bit-for-bit. Device identity is committed.

PIP-3 assigns certificate version 3 and describes activation as a consensus hard
fork that rejects versions 1/2 thereafter. Its stated security assumption is
that multiplication of quantized low-rank matrices is as hard as multiplication
of general matrices of the same dimensions. That is an assumption, not a result
established by this repository. The proposal also identifies verification
tolerance as a potential grinding surface.

At the pinned commit, prequantization details and Jackpot Policy remain TBD;
the reference implementation is promised but not linked, and test vectors,
experiments and deployment remain TBD. Its model-accuracy assertion is not a
reproduced experiment here. These distinctions motivate separate numeric,
behavior and work-security qualification when this project changes a work
relation; they do not supply those qualifications.
