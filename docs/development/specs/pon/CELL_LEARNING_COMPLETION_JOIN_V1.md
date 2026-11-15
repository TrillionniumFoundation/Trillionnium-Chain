# Original native completed-learning checkpoint join V1

Status: engineering evidence review; **HOLD_NO_GO**. This is a read-only
continuation of the [Selection-cut join](CELL_LEARNING_ITERATION_JOIN_V2.md),
not a new learning owner, checkpoint codec, signed domain or admission route.

## Original inputs and exact continuation

The reader consumes five separately pinned materials:

| Material | Meaning |
| --- | --- |
| Selection checkpoint | Original `HEPLCP02` bytes after the original Selection receipt |
| Completed checkpoint | Original `HEPLCP02` bytes after that coordinator recorded its actual NextUse observation |
| Native readback | Original serialize-only actor envelope at acknowledged next-task use |
| Frozen request and owners | Separately supplied frozen expectations already required by the Selection reader |
| Expected native context | Independently supplied operation, manifest, publication, checkpoint and task context |

The CLI requires every file and every SHA256 pin. A pin proves equality with the
supplied commitment; it does not authenticate the source or establish pre-dispatch
custody. The API retains the prior reader's caller-owned trust boundary for the
already decoded frozen and expected context.

`scripts/cell_learning_completion_join.py` first executes the original Selection
reader, including the native-use reader. It then decodes and replays both original
native checkpoints with the existing bounded codec. The completed checkpoint
must preserve the request, complete owner map, initial head, and every original
receipt object. It must append exactly one original NextUse receipt. Its replay
must have no remaining stage, and its last predecessor must equal the Selection
head.

The final observation must equal the observation reconstructed from the validated
original actor readback. This equality includes the actual state partition,
complete retained or adopted bundle, checkpoint, selection, committed step and
retained publication or adopted cutover receipt. A receipt whose attacker has
recomputed every hash remains unacceptable when any observed binding differs.
The original stage, actor, predecessor, time, budget and frozen-profile checks
remain active.

## ACK and completion boundaries

This review profile requires both pending work and pending delivery to be absent.
A pending output cannot satisfy this profile even if another supplied checkpoint
claims a final receipt. The profile preserves both `RetainedModelNextUse` and
`NextUse`, and does not rewrite NoUpdate into candidate adoption.

`acknowledged_use_observed` reports the drained original use. `model_stop_observed`
and `terminal_episode_observed` retain the original readback values separately.
Neither ACK nor a complete structural receipt chain establishes actual training,
model efficacy or model STOP.

The report uses the new namespace `trnm-cell-learning-completed-use-review-v1`.
Its structural facts are `original_receipt_prefix_preserved`,
`native_receipt_chain_complete`, `final_next_use_matches_original_actor` and
`acknowledged_use_observed`. Its authority remains `DENY_ALL`; current permission
is `NOT_EXPORTED`. `full_learning_iteration_completed`, native-origin
authentication, pre-dispatch custody, signature verification, independent control,
complete costs, real training, physical installation, settlement, Hepta FinalUse
and production activation remain false.

## Original fixture collection

The Hepta companion at
`34eacaec1c94032f4980807e4a6f7c3516a7dafc` uses its existing production codec to
encode the actual completed coordinator from two existing actor tests. It first
reopens that checkpoint through the same codec and verifies the original native
readback's Selection head and absence of pending delivery/work. The native actor
and cold-recovery assertions remain in their original tests.

`scripts/capture_cell_learning_completion.py` captures four Selection/readback
pairs and two completed checkpoints from the original stdout. It records exact
JSON slices with byte offsets, unpadded-base64 checkpoint bytes, and every file
hash. It refuses missing, duplicate, malformed, mismatched or incomplete export
rosters. It does not encode a positive checkpoint or infer a native pass from a
marker. Its frozen contexts and expectations are expressly fixture-derived.
`--native-source` records a claimed source reference and does not authenticate it;
source integrity and native test execution are separate evidence.

See the [run record and retained failures](../../../../evidence/cell-learning-completion-20261108/README.md).
The ordinary CI retains both head and prospective-merge lanes, all original
native and reference commands, and adds thirteen continuation controls. The
positive cases use original native bytes. Test encoders construct negative
mutations only.

## Remaining owner obligations

A full real iteration still needs the same actual training output, frozen
qualified evaluation, original artifact and selection admission, material-loaded
runtime, next-task observation, original effect/payment reconciliation and current
permissions to agree under their owning contracts. This reader cannot supply
missing owners or transfer authority from a downloaded model, a successful probe,
a fixture signature or an acknowledged output.
