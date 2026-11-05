# Revision 16 bounded integer model evolution

This is an explicit development context selected by
`--evaluation-policy native-public-evaluation-quorum-dev-v2` and
`--model-profile linear-model-evolution-dev-v5`. It addresses the previously
unreachable router and base in the native integer model loop. It does not activate
production, arbitrary model code, independent governance, independently administered evaluation data,
prospective efficacy or Hepta execution authority.

The sole implementation plan remains the
[AI native blockchain development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Ownership and compatibility

M00 owns the bounded ILF3 codec in
[integer_evolution_v3.rs](../../../../trillionnium/crates/trnm-protocol/src/integer_evolution_v3.rs).
M06 owns actual parent resolution, integer computation, duplicate admission,
complete models and application of releases in
[model_evolution_v5.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/model_evolution_v5.rs)
and [pon_executor.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
Native Node uses the existing signed transaction, PNW1, state commitment, store,
fork activation and observation paths. No second model registry or activation
journal is introduced.

The existing ILF2/tag23, ILM2, revision 15 evaluation policy and model V3/V4
configuration bytes are retained. Tag24 is refused in those historical contexts;
tag23 and legacy hash-only tag6 are refused in the new context. The new family,
network, parameters, evaluation policy hash and plan are distinct. Opening a store
with an incompatible profile is refused. This is an explicit successor devnet,
not a hot migration of an existing chain.

Configuration owners are
[model-evolution-v5.json](../../../../config/pon/model-evolution-v5.json),
[model-family-evolution-v3.json](../../../../config/pon/model-family-evolution-v3.json)
and [public-evaluation-model-evolution-v5.json](../../../../config/pon/public-evaluation-model-evolution-v5.json).
The last file retains the revision 15 quorum algorithm and unchanged evaluation
record schema, and independently commits the new model allowlist and genesis
revision. Existing evaluation record storage is reused under the distinct chain
context; changed model/update/evidence schemas use fresh namespaces below.

## Executable model and graph

The model has five signed integer matrices of shape 3 by 257: base, router, and
three expert delta matrices. A nonempty three-bit mask enables a subset of the
three existing experts. For each fixed input vector, the router selects the
enabled expert with the largest router dot product, breaking ties by the lowest
enabled index. Logits are the base dot product plus the selected expert delta
dot product. Class ties use the lowest class index.

This makes router, base and expert weights reachable from the real zero genesis.
It also makes a bounded graph update executable: changing the mask changes which
experts can route an input. It does not add or remove matrix dimensions, load
arbitrary operators, authorize code, represent arbitrary topology, or implement
a distributed transformer. Graph generalization remains a separate design task.

The complete ILM3 artifact is exactly 7,758 bytes:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `ILM3` |
| 4 | 2 | Version 3, little endian |
| 6 | 32 | Model family hash |
| 38 | 8 | Little endian u16 values 1024, 3, 257, 3 |
| 46 | 1 | Enabled-expert mask, 1 through 7 |
| 47 | 1 | Reserved byte, exactly zero |
| 48 | 7,710 | Five row-major matrices of signed little endian i16 |

Every coefficient must be in -32767 through 32767. The complete artifact is
hashed with domain `integer-linear-model-artifact-v3` and retained in eight
1,024-byte maximum chunks under `linear-model-v3:<artifact>:`. Exact metadata,
chunk lengths, complete decoding, family and artifact hash are checked on load.
The genesis is the complete zero model with mask 7. Historical empirical control
weights are imported into this fresh family and encoding with mask 7; they remain
controls rather than becoming the current model.

## ILF3/tag24 contract

The signed envelope retains the existing 2,048-byte transaction bound. Its tag24
payload consists of a 242-byte prefix and zero through three operations:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `ILF3` |
| 4 | 2 | Version 3, little endian |
| 6 | 1 | Resulting enabled-expert mask |
| 7 | 1 | Operation count, zero through three |
| 8 | 2 | Scale label 1024, little endian |
| 10 | 224 | Family, parent reference, parent artifact, candidate artifact, normalized update ID, contribution ID, allocation root |
| 234 | 8 | Submission round, little endian |
| 242 | Variable | Ordered operations |

Each operation has a one-byte target, a one-byte rank, then row-major B followed
by row-major A. Targets are base 0, router 1, expert0 2, expert1 3 and expert2 4.
Targets must be strictly increasing and distinct. Each rank is one or two; the
sum of ranks is at most three. B is 3 by rank, A is rank by 257. Factors are signed
little endian i16 in -32767 through 32767. Maximum payload is 1,808 bytes and
maximum envelope is 1,967 bytes. Truncation, trailing bytes, reordered/duplicated
targets, invalid rank/mask and the forbidden i16 minimum are refused.

Joint updates are necessary for an actual path from zero genesis: independently
training a disabled or unrouted expert would have no native gain, and a router
change alone cannot improve zero expert weights. A rank-one router update and a
rank-two expert update fit in one transaction and can improve a real candidate.

Admission loads the actual branch current model. A release reference resolves to
its stored complete artifact; a producer-supplied hash cannot substitute for that
model. For each operation, M06 computes B times A with checked i64 products and
accumulation. The scale is a numeric contract label; no division, approximation,
quantization or rounding is introduced. Every resulting delta and every
parent-plus-delta coefficient must lie within -32767 through 32767.

Every listed operation must have a nonzero complete delta. A zero-operation
graph change is admissible only if it changes the complete model. A complete
no-op is refused even when its factor representation differs. Mask-only changes
still face native empirical evaluation and the positive-gain release gate.

The base fee is 240 development units plus the existing byte fee. The same
candidate/history bounds, deadlines, signature checks, nonce and fee owner apply.
This fee is a development policy value, not a measured production cost model.

## Normalization and identity

`integer-linear-model-update-v3` commits network, parameters, family, actual parent
reference and artifact, round, and complete resulting ILM3 bytes. Algebraically
equivalent factor bases, ranks, authors or allocation roots therefore cannot
mint another update in the same current-parent/round window. Admission stores
`linear-update-v3:<update>` metadata, and rechecks the retained complete artifact
when rejecting duplicates. A marker retains its artifact until the window ends,
even if a contribution is removed. Markers and complete models remain ordinary
branch state and roll back with branch activation.

This is normalization of the declared complete model. It does not prove general
function equivalence between distinct tensor arrangements, equal predictions on
all possible inputs, or independent training provenance.

The fresh `integer-evolution-contribution-v3` domain commits the author, network,
parameters, family, parent, complete candidate, normalized update and round. The
allocation root is excluded from this identity to avoid a self-leaf hash cycle.
It remains in the signed ILF3 payload. Native release verifies the exact signed
allocation root against the candidate identity, admitted owner and native score.
Submitting a different root cannot overwrite an admitted contribution or bypass
the normalized duplicate marker.

## Evaluation, attribution and adoption

Native evidence reuses the exact 25 public retrospective rows, four historical
controls, fixed admitted development sources, intake caps and funded source
budget caps from [model-evidence-v3.json](../../../../config/pon/model-evidence-v3.json).
An optional [owner-pinned task-window manifest](MODEL_TASK_WINDOWS_V1.md) replaces
the selected task rows at precommitted activation rounds. Parent, candidate and
the same four full control models are all replayed on those selected rows.
Every candidate and parent is a complete loaded model; no producer predictions
or claimed score are accepted. The score remains positive accuracy improvement
over the maximum of actual parent and all historical controls, multiplied by
1,000,000 and divided by the row count with integer truncation.

Changed evidence is independently bound with schema
`native-integer-model-evidence-record-v5`, domain
`native-model-empirical-record-v5`, namespace `model-evidence-v5`, source namespace
`model-source-v5` and source-root-work domain `native-model-source-root-work-v5`.
The record binds the evolution policy and resulting enabled-expert mask. Existing
plan, dataset, actual parent and round bindings remain mandatory.

The installed four controlled development keys use the retained quorum rule:
exclude the author, keep the frozen denominator, require two matching
native-checked reveals out of three eligible keys, and recheck actual signed
equivocation at adoption. Hash-only appeals remain bounded audit records.
They do not provide a veto. Independent evaluator ownership is not established.

V5 releases have exactly one allocation leaf: the adopted candidate itself,
its admitted owner, and its exact positive native score. Tag8 rejects a different
candidate, multiple leaves, a different score/root, stale parent, incomplete
evaluation, lost objective quorum, or zero gain. It then applies the ordinary
funded release, source budget reservation and `model:current` update. Repeated
adoption, fee replay and candidate overwrite keep their existing native checks.

Historical V4 remains available for its separately specified two-to-four-component
same-slot exact composition and leave-one-out allocation. V5 does not inherit or
claim arbitrary cross-target composition attribution. Extending that attribution
requires a separately versioned complete-model composition contract and tests.

## Verification and limits

The native M06 regression in
[model_evolution_v5.rs](../../../../trillionnium/crates/trnm-mvcc-fee/tests/model_evolution_v5.rs)
deliberately memorizes the installed public rows. It uses actual signed tag24,
native commit/reveal/closure and tag8, and exercises this sequence:

1. Zero genesis has 3 of 25 correct. A joint router/expert1 candidate has 24 of 25,
   beats the strongest control at 19, and is adopted with score 200,000.
2. A base update plus expert-mask change loads that actual release and reaches
   25 of 25. It is adopted with score 40,000.
3. A further mask change with identical predictions has score zero, receives no
   model promotion and cannot publish a release.

This closes the prior reachability defect. It also preserves the evidence that a
fixed public benchmark saturates. A new round number does not add new data.

The independently implemented
[Python oracle](../../../../formal/pon-nakamoto-v1/model_evolution_oracle.py)
generates [fixed vectors](../../../../formal/pon-nakamoto-v1/vectors/model-evolution-v5.json).
Rust compares exact context hashes, ILF3 bytes, full ILM3 bytes, normalized update,
contribution and release identities against those vectors. Historical revision15
evidence/composition context identities are also retained in the fixture. Python
checks mask behavior, tie order, arithmetic boundaries, no-ops and factor aliases.
It does not authenticate signatures or replace native state execution.

Run the focused selectors from `trillionnium/`:

```sh
cargo test --locked -p trnm-protocol --test integer_evolution_v3
cargo test --locked -p trnm-mvcc-fee --test model_evolution_v5
cargo test --locked -p trnm-pon-node --test evolution_cli
```

From the repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_model_evolution_oracle.py -v
```

The Node selector includes actual CLI profile separation and durable reopen, and
one real PNW1 tag24 admission with transaction membership observation. The M06
test supplies evaluation heights directly; it does not itself establish PoN work
security across those heights. Node observations remain nonfinal and carry no
adoption, reward or execution authority.

## External task windows and remaining data-owner boundary

The ordinary CLI/Settings/Config path now accepts an optional bounded signed
manifest with an explicit exact-byte hash and data-owner public-key pin. It
reconstructs full source contents and features, verifies content snapshot revisions
and task roots, and selects the window by frozen submission round. The manifest,
owner and complete activation schedule enter the new chain context. Candidate
authors have no task-root selector. See the
[task-window contract](MODEL_TASK_WINDOWS_V1.md) for exact fields and refusal rules.

Without this optional input, the historical 25 rows and exact original V5 context
remain unchanged. The window conformance fixture uses 12 newly authored controlled
source texts, six per window, and ordinary native admission/evaluation/adoption.
It establishes the external loading path, not independent governance, prospective
generalization or production eligibility. `task_window` evidence identifies an
active external window; the retained `fresh_dataset_activation` qualification flag
remains false because no production prospective data source is certified.

Later manifests select an explicit different genesis context. Updating a running
chain needs a separately specified data-owner activation/migration mechanism;
source integrity alone does not provide truthful labels or data availability.
Private Hepta DecisionCells and local execution authority remain governed by their
separate handoff and revocation owners.
