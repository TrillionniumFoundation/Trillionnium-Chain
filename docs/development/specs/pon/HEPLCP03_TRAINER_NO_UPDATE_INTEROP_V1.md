# HEPLCP03 trainer NoUpdate interoperability

This reader extension consumes the explicit `TrainingNoUpdateV2` observation
from fixed Hepta source `f97f3c90ac1ac3d5171fd9f25b3e34431f44a367`.
It preserves Chain integration source `df927b6ffaecff293b9e9428e3ba516f47cd101a`
and incorporates the original business/economics/NextUse reader from
`d9ef94f34339c8f76591fa54c14724c54805af36` (#855), whose common ancestor is
`e2a02f9271b49f146e70806c8a66e161b5973971`.

The change closes a concrete readback incompatibility. The old Chain reader
accepts the original initial and Dataset cuts, then rejects all three native
HEPLCP03 cuts with `LEARNING_CHECKPOINT_VERSION`. The original Rust coordinator
and codec now provide a separately retained, reproducible engineering vector.
This vector is not an ordinary task, optimizer run, independent consumer or
Hepta FinalUse observation. All existing authority and qualification gates
remain closed.

## Exact wire and transition contract

The initial commitment and receipt signing domains remain unchanged:
`hepta.learning.iteration-checkpoint.v2\0` and
`hepta.learning.iteration-observation.v1\0`. The new checkpoint magic is
`HEPLCP03`; its presence is equivalent to an actual tag-8 observation in the
receipt sequence. HEPLCP03 without tag 8 and HEPLCP02 with tag 8 are refused.
HEPLCP01 and unknown versions remain refused.

Tag 8 encodes, in this exact order:

| Field | Encoding |
| --- | --- |
| observation | one byte, 8 |
| reason | one byte, 0 (`QuantizedWeightsUnchanged`) |
| retained bundle | 32-byte digest |
| Dataset | 32-byte digest |
| original update rule | 32-byte digest |
| training steps | little-endian u64 |
| training milliseconds | little-endian u64 |

The valid path is Experience (0), Dataset (1), TrainingNoUpdateV2 (8), Selection
(5), and RetainedModelNextUse (7). Tag 8 belongs to the original generator at
Training; it binds the retained baseline, exact prior Dataset and positive,
originally bounded work counters. It creates no candidate and moves directly
to the independent selector. It does not fabricate an Evaluation or Proposal.
The retained use must name the same original principal/agent/Cell, a distinct
run, the selected retained bundle, committed step and task-owner publication.
Unknown reasons, failed/pending tasks, wrong actors, forged stage order, quota
violations and relabelled cutovers cannot become a completed NoUpdate result.

## Original Root scope is mandatory

The checkpoint does not contain FrozenLearningScopeV2. Every HEPLCP03 use join
therefore requires a separately pinned original schema-2 Root profile. Its
initial checkpoint, complete request, owners, scope binding and original update
rule must agree with the retained receipt chain. Rehashing every receipt after
changing the rule still fails against this independent profile pin.

The existing schema-2 layout and Cell/Organ scope limits remain those documented
in [the original scope contract](CELL_LEARNING_SCOPE_JOIN_V1.md). This change
does not accept a Model scope or infer another Root profile version. Matching a
caller-provided profile proves structural agreement; it does not authenticate
Root custody, preregistration or actual equality of quantized model weights.

The first-use and completion CLIs accept paired `--root-profile` and
`--root-profile-sha256` inputs. The scoped completion CLI retains its existing
mandatory profile interface. Business bindings v2 add `root_profile` as a sixth
material, with the same operation and source-pair fields and a separate SHA-256
pin. Both selected and completed checkpoints must be HEPLCP03, and the declared
Root envelope must be schema 2. The business CLI takes `--root-profile` and
obtains its pin from the bindings file. V1 business bindings still require
HEPLCP02; neither version silently upgrades the other.

## Versioned reports and preserved old bytes

| Material | Existing HEPLCP02 schema | HEPLCP03 schema |
| --- | --- | --- |
| first use | iteration-use-review-v2 | iteration-use-review-v3 |
| completion | completed-use-review-v1 | completed-use-review-v2 |
| scoped completion | scoped-completed-use-review-v1 | scoped-completed-use-review-v2 |
| business bindings | business-bindings-v1 | business-bindings-v2 |
| business report | business-review-v2 | business-review-v3 |

All names above carry the `trnm-cell-learning-` prefix. New reports explicitly
record `training_disposition=quantized_weights_unchanged`, no trained candidate,
null evaluation/proposal dispositions and a null candidate artifact byte count.
Null is not an asserted zero physical cost. The reader does not recompute the
optimizer or compare tensors: `quantized_weights_unchanged_verified=false`.

The historical adopt-v1 and no-update-v9 completed reports and #855 business
reports are reproduced byte for byte from their unchanged original input and
bindings bytes. The old tag-6/tag-7 Rust signing vectors remain exact.
`SAME_ORIGINAL_ACTOR_DISTINCT_RUN_ONLY` remains the only accepted actor relation;
it does not satisfy the independent-consumer gate.

## Validation and remaining qualification

[The retained evidence](../../../../evidence/heplcp03-interop-20261111/README.md)
contains five original Rust codec cuts, every original receipt signing payload,
88 source blob identities, the isolated harness and lockfile, baseline refusal,
retained failed observations and current control results. Synthetic complete
readback controls use a zero signature and explicit fixture identities. They
exercise parser relations and are labelled accordingly.

No production Rust source, workspace dependency, consensus rule, settlement
path or execution permission is changed. Reader success retains `DENY_ALL`,
`NOT_EXPORTED`, `HOLD_NO_GO`, `independent_consumer_verified=false`,
`hepta_final_use_accepted=false`, and `production_activation=false`. Ordinary
work, real training/no-change determination, signed custody, independent B/C,
publication/withdrawal and actual daemon/Root cold recovery require their own
original observations.
