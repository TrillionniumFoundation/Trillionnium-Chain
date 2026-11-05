# Shared real model materials and complete W1 output consumption

This is a bounded research experiment under the existing PN1/PN3 work plan. It
does not register a task, activate a work profile, grant FinalUse, install a model,
or authorize a payment. The native relation remains
`pon-matmul-transcript-64-v1`, with the original field, transcript, ticket and proof
encoding. Existing V1/V2/V3 cost campaigns keep their original inputs and exits.

## The missing connection

The existing public-source routing experiment trained real integer parameters,
but its work observation multiplied only the first 64 of 257 feature coordinates.
The modern legal-strategy and false-transcript experiments selected fixed
synthetic material classes. Neither observation answered whether a complete
normal model operator could consume the same W1 outputs studied by the attacker.

The new consumer uses the existing model loader, source-corpus generator,
evaluation bundle and ordinary inference reference. It introduces no trainer or
new reward owner. Its source tasks remain retrospective public Rust function
ownership classification, not an LLM, an independent future window or an ordinary
Hepta deployment.

## Complete arithmetic and exact signed decoding

The model contains a base, a router and three expert deltas. Each is 3 by 257,
with integer coefficients bounded by 32,767 and features bounded by 8. All five
matrices are packed into 15 rows. Up to 64 frozen corpus examples form the columns of
the input. Five canonical W1 material pairs cover feature widths
`64, 64, 64, 64, 1`; the last coordinate includes the existing bias. Remaining
rows, columns and inner coordinates are explicit zero padding.

Each tile product is decoded to its centered signed representative before the
five partial products are added as ordinary integers. The conservative bound
`257 * 32767 * 8 = 67,368,952` is strictly below half the field modulus
`4,294,967,291`. The consumer also checks input-specific absolute bounds, canonical
field values, exact padding and complete tile coverage. Router selection and
lowest-index argmax ties then follow the existing model contract.

No floating-point model is silently mapped to these integer semantics. A real
BF16/FP16 model needs an independently specified and measured numeric contract.

## Shared native observation

Implementation:

- [Native fixed-material experiment](../../../../trillionnium/crates/trnm-crypto-primitives/examples/pon_shared_material_v1.rs)
- [Complete model consumer](../../../../formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py)
- [Same-material security supervisor](../../../../scripts/ci/run_shared_material_security_v1.py)

The native process reads exactly 32,768 bytes: 4,096 canonical little-endian u32
words for A followed by the same for B. Target and seed are explicit. One actual
preparation survives all requested searches. The two separately selected
`full-limb` and `transposed` arms use the same challenge sequence, retain every
attempt from completed searches, and materialize successful PNW1 bytes. They are two observed
implementations, not a proof that no cheaper legal algorithm exists.

Both the full native verifier and the independently coded scalar reference must
accept the same proof and agree on the typed product. The output handoff copies
only `VerifiedWork.product()`. Failed verification never hands off product bytes.
The consumer additionally checks the native record sequence, frozen inputs and
outputs against the existing scalar inference and an ordinary NumPy int64 path.
Record parsing is not a cryptographic substitute for executing the pinned native
binary.

The explicit `--attack-controls` mode uses the identical A/B bytes to construct
target-hitting false transcripts without acquiring a valid proof. It retains
both raw verifier refusals and a one-slot arithmetic-fact cache sequence: cold,
warm, another challenge, return after eviction, and owner destruction/recreation.
This last observation is in-process volatile state loss, not durable node restart
or public service recovery. Cache controls never establish current authority.

## Cost denominators

The ordinary control may cache `base + delta` and compute the router plus only
the selected expert: `6 * 257 * batch_size` multiply-adds. The W1 packing computes
all five matrices: `15 * 257 * batch_size`, including unselected expert work.
Five padded W1 products contain `5 * 64^3` multiply-add positions before counting
challenge encoding, transcript hashing, correction, failed searches or verification.
The report retains all three counts. Inactive expert outputs and padding are not
credited as useful demand.

For a 64-request batch the ordinary required arithmetic occupies about 7.53% of
the padded product positions. Packing all five matrices occupies about 18.82%.
These are geometry calculations, not measured speedups or work-security bounds.

The baseline reports reusable preparation, first execution, warm samples and a
separate scalar check. Native rows retain thread CPU and monotonic wall clocks,
setup, every attempt from completed searches, each verifier, typed copying and evidence output overhead.
The external supervisor retains child CPU, local pipe bytes, process elapsed
time, failures and partial output. Cumulative child RSS is labelled as a high-water
observation; it is not additive memory across children. Diagnostic reference
verification and evidence serialization are visible separately from the producer
and one native verifier.

An interrupted search can have unobserved internal attempts: its search record
is emitted on completion. Retained process cost and an output prefix are not
a complete internal attempt ledger for a process killed during that search.

Repeated challenge cycles over the same task produce one distinct application
batch, regardless of the number of winning proofs. They may measure actual setup
reuse but never create additional useful-output credit. Local pipes do not measure
WAN propagation, energy, node admission, block confirmation or physical recovery.
Shared-host samples cannot qualify the original isolated hardware envelope.

## Reproduction

Run the repository preflight first. Use a new output directory for every attempt.

```bash
bash scripts/project-preflight.sh
cargo build --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_shared_material_v1
python3 formal/pon-nakamoto-v1/experiments/model_loop.py --mode run \
  --source FROZEN_SOURCE_COMMIT --out /tmp/frozen-model-inputs
```

Read the independently retained bundle hash from that producer's result, then:

```bash
python3 formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py \
  --model /tmp/frozen-model-inputs/model.json \
  --tasks /tmp/frozen-model-inputs/consumer.json \
  --evaluation-bundle /tmp/frozen-model-inputs/evaluation-bundle.json \
  --bundle-hash EXPECTED_BUNDLE_HASH --replay-source \
  --runner /absolute/path/to/pon_shared_material_v1 \
  --target-index 0 --cycles 1 --max-attempts 4096 \
  --arithmetic full-limb --out /tmp/new-complete-model-observation
```

Replay the same frozen input with `--arithmetic transposed` into a different
directory. Repeat both arms with target index 1, retaining every run. Then use
the completed full-limb consumer directory for the matching target:

```bash
python3 scripts/ci/run_shared_material_security_v1.py \
  --material-dir /tmp/new-complete-model-observation \
  --runner /absolute/path/to/pon_shared_material_v1 \
  --target-index 0 --cycles 4 --max-attempts 4096 \
  --out /tmp/new-same-material-security-observation
```

The supervisor binds the original material, seed, target and binary, executes
the actual native attack controls and retains every tile's process result.
Its raw-verifier-to-attacker ratio divides measured native refusal CPU by
the attacker's prefix setup plus both complete false-trace searches. Cache
paths, cache setup/recreation and whole child CPU remain separate measurements.
Keep these costs separate from the normal consumer run. Neither experiment
establishes an adversarial minimum cost or an isolated public-service budget.

The existing `settle_model.py` recomputes the frozen evaluations in a separate local check.
Failure to meet its declared benefit rules must retain `not_adopted` and zero
model reward. This controlled development refusal does not establish independent
administration, an untouched future window or funded production settlement.

## Decisions this experiment can support

A correct full output with a negative cost result is a useful counterexample to
an efficiency claim. It can motivate a separately versioned rectangular/grouped
relation, after fixing real shapes, numeric semantics, microbatch deadlines,
weight/activation/router commitments and legal fast algorithms. Such a new
relation cannot inherit W1 qualification or replace W1 as an implementation tweak.

Transparent v2 proof generation, actual saved-receipt negative controls and full
end-to-end proof cost remain separate. Correct model arithmetic, cheapest legal
work, affordable hostile verification, public service, beneficial future updates
and payment authorization are different acceptance decisions.

The [2026-11-05 frozen observation](../../../../evidence/pon-shared-material-v1-20261105/README.md)
records four complete-operator runs, two same-material attack runs and the actual
model refusal. Its negative cost results and current v2 setup block remain part
of the result; successful numerical execution does not erase them.

## Separate rectangular/grouped research profile

`pon-routed-int257-grouped-research-v0` is a **design identifier only**, not an
implemented or activated work relation. Its initial business fixture is the
existing 64-request integer routing batch. The router shape is `3 x 257` by
`257 x 64`; after deterministic routing, each selected expert uses a cached
`base + delta` matrix of shape `3 x 257` and its `257 x b_e` request group,
where the three group sizes sum to 64. Empty groups require no multiplication.
The complete five-matrix `15 x 257` product remains a correctness reference,
not the useful-work denominator of the grouped design.

An independently specified relation must commit to the model version, exact
integer weights, all ordered input requests including the bias coordinate,
router outputs, lowest-index tie rule, group membership/order, result and
request-set identity. Changing numeric representation or any commitment,
challenge or transcript requires a fresh version and new qualification.
The existing bound applies to each original matrix. Merged base-plus-delta
coefficients need their own doubled bound (`134,737,904` for a full output),
canonical signed encoding and, where inputs are not trusted, a range proof.

Batch size 64 is a measured fixture, not a production batching policy. No real
request arrival trace or deadline was supplied by this corpus; microbatch
waiting time and p95/p99 completion deadlines therefore remain unresolved
business inputs. They must be fixed before accepting a batching speedup.

Challenge construction and its resistance to legal fast algorithms are also
unresolved, rather than inherited from W1. The evaluation must include model
preprocessing amortized over its actual lifetime, sparse/low-rank inputs,
cached merged experts, request reuse and batched algorithms. A transcript
design that removes useful sparsity or creates surplus expert work must debit
that work. Initial correctness can be checked by the ordinary exact integer
operator; moving to a full proof or a service dispute window requires separate
proof-cost and trust assumptions. No new challenge domain is registered here.

## Complete decision relation

The separately versioned [useful-Cell relation](USEFUL_CELL_RELATION_V1.md)
now wraps this exact packing with consumer-retained contract/state/use context,
mandatory frozen-source feature replay, fixed numerical and decision semantics,
and five complete reference W1 verifications. Its new challenge domain belongs
to the enclosing research relation; this original native W1 profile is unchanged.
The grouped relation above remains a design and acquires no qualification from
that reference verifier.
