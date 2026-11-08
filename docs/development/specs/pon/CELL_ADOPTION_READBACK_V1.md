# Cell learning-use readback review v1

Status: engineering material review; **HOLD_NO_GO** for a complete real-model
evolution cycle. This reader adds no installer, training runner, authority
issuer, settlement adapter, or alternate model owner.

## Purpose and original ownership

The [ordinary-host handoff](CELL_ORDINARY_HOST_HANDOFF_V2.md) distinguishes
completed transport, protected installation, and actual native use. A download,
an ELF probe, an `EXEC_REQUESTED` record, or a successful chain submission cannot
replace the original owner's next-task observation.

`scripts/cell_adoption_readback.py` consumes the serialize-only
`hepta.agentd.learning-use-readback.v1` produced by the original Hepta generation
actor. The actor uses its existing `read_next_use` / `read_updated_next_use`
paths, finds the original successful receipt through `receipt_for_intent`, and
reads the generation journal observation. Export does not run another model
step, consume another grant, install a model, or advance a learning checkpoint.
It refuses a changed journal cut and rechecks current permission after
serialization. The exported value itself carries `DENY_ALL` authority and
`NOT_EXPORTED` current permission.

The Python reader checks public structure and independently pinned relations.
It does **not** authenticate the host or issuer, verify a FinalUse signature,
recover current permission from a past witness, or authorize another operation.
Its successful result still says `qualification: HOLD_NO_GO`.

The optional [original learning-iteration join](CELL_LEARNING_ITERATION_JOIN_V2.md)
adds separately pinned HEPLCP02 checkpoint and frozen-request inputs through
this same CLI. It preserves this v1 readback relation and all authority limits.
The combined report verifies request/receipt/selection binding, not the time
or authenticity of independent freeze custody or a completed production loop.

## Exact bytes and independent expectations

The outer object contains exactly `schema`, `payload_json`, and
`payload_digest`. The payload commitment is SHA-256 of
`hepta.agentd.learning-use-readback.v1\0` followed by the exact UTF-8 payload
string. Native manifest, publication, and receipt commitments likewise use
their original embedded JSON bytes. Reformatting or sorting these native
structures changes their commitments.

The CLI requires both the complete readback SHA-256 and a separately retained
expectations file with its own SHA-256. The expectation schema is
`trnm-cell-learning-use-expectations-v1`. It pins the disposition, learning
operation and decision cut, source run/receipt/artifact/bundle, complete current
and previous manifests, next task/input/frontier, original intent, owner
checkpoint, publication, successful receipt, state partition, optional reset
receipt, generation, and writer epoch.

`intent_digest` is an expectation commitment over
`hepta.agentd.learning-use-intent.v1\0` plus the compact original intent in its
native field order. It binds **all** intent fields, including predecessor and
deadline. It is not the native worker-request digest: the export omits full
predecessor snapshot, input bytes, and admission time needed to recompute that
request. The report therefore keeps `request_digest_recomputed: false`.
The original journal's `receipt_for_intent` remains responsible for exact
original-intent equality before returning its committed receipt.

Production expectations must come from the independently retained original
supervisor/qualification context. Deriving expected values from a producer's
submitted JSON only demonstrates self-consistency. The repository's four
positive fixtures deliberately use fixture-derived expectations, labelled as
engineering fixtures; they are not trusted deployment pins.

## Relations checked

The reader requires exact fields, bounded regular-file input, duplicate-free
JSON, integer byte arrays, valid original identifier syntax, and the relevant
native nonzero and resource bounds. Booleans and floats cannot alias integers.
Unknown schemas and added authority claims are refused.

For both dispositions it checks the next task and run, principal/agent/cell
continuity, incremented generation and writer epoch, complete manifest binding,
state partition, predicted empty genesis checkpoint, original learning
publication operation, current observation, original first input, committed
successful receipt, and pending output against committed prefix bytes.

The original publication's public grant/request/scope/payload relations and
dispatch witness are recomputed. Native epoch, nonce, identifier and five-minute
maximum grant-window rules are enforced. This is a structural consistency
check; current revocation, trusted issuer enrollment, and signature verification
remain with the original authority owner. A copied valid-looking witness is
not a portable permission token.

| Disposition | Required model relationship | Required next-task evidence |
| --- | --- | --- |
| `retained_model` | Same complete parent manifest and bundle; no model-reset receipt | Original same-model task publication and successful receipt under the retained model |
| `adopted_model_reset` | Exact original parent plus a different complete candidate manifest and bundle | Original published reset receipt and successful receipt under the candidate |

A legal NoUpdate is a completed selection outcome when the candidate does not
justify replacement. It must retain the parent model; changing only a display
label, selecting an unproven candidate, or inventing a reset receipt is rejected.
These native fixtures test the use relationship. They do not establish that
any real candidate improved under an independent evaluation.

## Pending output, ACK, stop, and cost

The exported observation preserves pending request/output and original cost
records. A pending output chunk is not an ACK. A later ACK may change the owner
checkpoint without changing the earlier successful step receipt. The reader
does not require those two distinct cuts to have identical digests.

`terminal_episode_observed` requires model stop and absence of both pending
request and pending output. Neither output delivery nor episode termination
proves that the learning iteration completed. The report always keeps
`full_learning_iteration_completed: false`.

Cost task/source identities must agree between the original step receipt and
generation observation. The cost source identifies the metering convention;
it need not equal the backend source digest. Preserving these records does not
establish complete pricing, charge finality, or settlement.

## Acceptance obligations that this reader cannot discharge

| Required real-world link | Required original evidence / owner |
| --- | --- |
| Actual parent and lawful training | Complete parent closure, authorized training inputs and original training execution |
| Independent evaluation and NoUpdate | Frozen comparison policy, original evaluator result, and verified separation from training/selection control |
| Complete candidate publication | Exact full version closure, original release decision and publication authority |
| Actual settlement and confirmation | Original accounting/chain records with the required confirmation rule satisfied |
| Cold-node acquisition | Original complete closure transfer to the intended consumer, with exact content identities |
| Current permission | Original owner check at the actual operation; never the exported past witness alone |
| Protected install and real model load | Qualified protected-installed profile and original model owner's loading result |
| Next task uses the selected version | Original task/intent, complete manifest, successful receipt and current owner observation |
| Independent control and collusion resistance | Independently sourced controller records and the original actor-to-control association |

[Seven-role control review](CELL_CONTROL_SEPARATION_V1.md) covers task publisher,
trainer, evaluator, version selector, storage, release-key custodian, and
consumer. It merges common control transitively and rejects required
separation conflicts. Increasing node processes or signing keys does not
increase the number of independent controllers. Complete submitted materials
still do not exclude concealed common control.

The signed learning campaign and separate control roster also need an original
actor-to-controller binding. The current composition exposes this missing
association explicitly. Matching a campaign identifier and source pair is
insufficient to establish it.

## Reproduction and interpretation

Run the actual captured fixture checks with:

```sh
bash scripts/project-preflight.sh
python3 -B scripts/test_cell_adoption_readback.py -v
```

For an independently retained readback and expectations:

```sh
python3 -B scripts/cell_adoption_readback.py \
  --readback /absolute/readback.json \
  --readback-sha256 "$READBACK_SHA256" \
  --expected /absolute/expectations.json \
  --expected-sha256 "$EXPECTATIONS_SHA256"
```

The test corpus requires all four original native exports: retained/adopted
each before and after ACK. Missing fixtures fail rather than skip. Mutations
are negative parser controls, never replacement native positive evidence.
The historical real SmolLM training/download/64-forward result is retained as
a negative input: it is useful research evidence and is not a native FinalUse
export. Historical and current runs must not be spliced into one purported
end-to-end evolution cycle.

The evidence index is
[`evidence/cell-adoption-20261108/README.md`](../../../../evidence/cell-adoption-20261108/README.md).
Successful parsing cannot change `native_origin_authenticated`,
`grant_signature_verified_by_this_reader`, `current_permission_exported`,
`independent_control_accepted`, `real_model_training_verified`,
`physical_installation_accepted`, `settlement_verified`,
`hepta_final_use_accepted`, or `production_activation` to true.
