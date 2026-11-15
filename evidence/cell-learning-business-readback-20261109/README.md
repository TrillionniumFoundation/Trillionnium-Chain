# Learning and business readback — retained input and qualification boundary

**DENY_ALL / HOLD_NO_GO.** This continuation adds a read-only composition and
keeps real client, independent evaluator/consumer, physical cost, external funds,
Hepta FinalUse and complete failure/reorganization recovery unqualified.

The [contract](../../docs/development/CELL_LEARNING_BUSINESS_READBACK_V1.md)
describes the exact input, new application mappings and remaining obligations.

## Original bytes and retrospective bindings

The two [bindings files](bindings/) were created for retrospective structural
readback from the original five input files in each case. They have no native
economic observations and make no pre-registration, independent-custody or
authenticated-execution claim. They do not alter the older source/receipt files.

| Case | Bindings SHA-256 | Original receipt count |
| --- | --- | --- |
| [adopt-v1](bindings/adopt-v1.json) | `8ba561db51a2808a3d6a4ebcc684436cbb3619c94387c0f3939eadc34b7c88a8` | 7 |
| [no-update-v9](bindings/no-update-v9.json) | `56821f43e6af00c0e7eeb21a1e965628333a0522b9833491f9e1f5bfac897bd6` | 6 |

Original Hepta executed code/tree:
`edf03ecb8a814a0f5e86b1d6a752aeac80b1a978` /
`c7588a07d20310059d4016559fa550d397b7eb09`.
Original Chain reader executed code/tree:
`9129e65b3255439593e44a0ba39578f220c27087` /
`3362f33fc1eb16bb1aa168f237065e4d15252bcc`.
Original evidence was delivered at
`e798d7125724d4b9f98c24d00cc80031f2eab4a9`.
This implementation continues #835 at
`e2a02f9271b49f146e70806c8a66e161b5973971` /
`86d2014b560659106b3af6e6c19e1f82a290a60e`.
None of these identities is relabelled as a new model execution.

The original plan states independent evaluation is false and prior tasks and
outcomes were exposed. A correct structural Selection does not prove useful
improvement, and a distinct next run does not prove an independent consumer.

## Repeatable validation

The [collector](../../scripts/ci/run_cell_learning_business_readback.py) requires
an actual checked-out Git HEAD matching `--expected-head`. On that source it
runs the unchanged adoption/iteration/completion suites, the two new structural
suites and the selected existing CI contract class. It then invokes the new
reader on both original cases and compares the completion subreport to the
archived stdout bytes. It preserves every command exit and raw output.

```bash
python3 scripts/ci/run_cell_learning_business_readback.py \
  --expected-head "$(git rev-parse HEAD)" \
  --output /tmp/cell-learning-business-readback-new-run
```

The output directory must not exist and must be outside the source checkout.
The dedicated workflow runs the original full tracked-source verifier before and
after these commands, then uploads outputs even after failure. The workflow is
additional scoped validation; it replaces no required gate.

Local selected-source observations, preparation failures and subsequent hosted
records are separate evidence. An initial materialization added a terminal LF
to seven unchanged reader/test files; it was detected, retained as a separate
observation, corrected to the original Git blob bytes and rechecked. An initial
new test expected the wrong original diagnostic name (`MAGIC` instead of
`VERSION`); the original parser already refused the input and was not changed.
Missing-dependency and temporary storage/environment failures are retained as
preparation observations, not counted as successful tests.

All paid-schema controls are explicitly synthetic. Native development units are
not independent customer payments. No new training, native payment, deployment,
independent consumption or real-world recovery is performed by this change.
