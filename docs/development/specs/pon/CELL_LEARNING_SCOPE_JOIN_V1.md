# Scoped Root profile and completed-learning evidence join

This read-only reader accepts the Root profile layout from one fixed Hepta
source candidate: [`71738345326b98d88b738250d2b84ecbcb466eb8`](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5509).
It adds the original frozen component scope to the existing HEPLCP02
selection, completed checkpoint and acknowledged next-use join. A successful
review retains `DENY_ALL`, `HOLD_NO_GO` and `FinalUse=false`; it grants no new
execution, installation, settlement or production authority.

## Fixed source identity

The following files were read at that exact Hepta commit. Git blob identifiers
below are source identities, not hashes of loaded daemon binaries.

| Source path | Git blob |
| --- | --- |
| `codex-rs/hepta-agentd/src/authority_host_learning_profile.rs` | `b666322db02f013624fdee71984111fe749f3142` |
| `codex-rs/hepta-learning-artifacts/src/learning_iteration_scope.rs` | `77d15d44a21eb06d0d8e2d8e726810d887da6e64` |
| `codex-rs/hepta-learning-artifacts/src/learning_iteration_types.rs` | `bcd18a4618af0702b7e1ea456fa0b849b8f9ee01` |
| `codex-rs/hepta-learning-artifacts/src/learning_iteration_digest.rs` | `657876c890e90c3b72989e445450cd4f2b2e807e` |
| `codex-rs/hepta-agentd/src/learning_iteration_checkpoint_codec.rs` | `de82aec060a9f89b223849abba3948d7c7cfb41b` |

That single source includes the request's frozen `evaluation_profile`, the
`hepta.learning.iteration-checkpoint.v2\0` initial commitment, HEPLCP02, and
schema-2 Root scope transport. It is not a combination of live branch tips.

## Accepted original JSON layout

The top-level field set is exactly `schema_version`, `identity_digest`,
`writer_proof_digest`, `initial_snapshot`, and `update_scope`.
`schema_version` must be the integer 2. The nested `update_scope` object has
exactly `update_scope`, `update_rule`, and `binding`; its first value must be
the string `cell` or `organ`.

The earlier `b8e8c6e82abc1479c573f61a5e17d28d581e6cad` Root layout used the
nested key `scope`. This reader refuses that layout, mixed old/new keys,
unknown or duplicate keys, and incorrect scalar or collection types. It does
not infer an evaluation profile for HEPLCP01 or migrate an original record.

The caller supplies the retained Root profile bytes and their independently
frozen SHA-256. `initial_snapshot` must be canonical unpadded base64 for the
exact empty HEPLCP02 checkpoint. Its complete request, owner set, operation
identity and initial head must match the existing completion inputs.

The scope binding is SHA-256 over the exact concatenation of:

1. `hepta.learning.frozen-update-scope.v2\0`;
2. the 32-byte initial head;
3. the single byte 1 for Cell or 2 for Organ;
4. the 32-byte original update-rule digest.

Every retained Training candidate must have that original update rule. It may
change `heads`, `calibration`, `composition`, and the selected scope's adapter.
Every other component, including the opposite adapter, must equal the complete
incumbent. A later NoUpdate decision does not remove this check. These are
component-digest restrictions; they do not prove an actual tensor update mask.

## Validation and evidence boundaries

The unit corpus is copied unchanged from Chain
`e2a02f9271b49f146e70806c8a66e161b5973971` under
`evidence/hepta-real-native-adoption-20261108/chain-reader/`. Tests pin all 12
original files for `adopt-v1` and `no-update-v9`. The Root profile objects in
these tests are explicitly synthetic parser fixtures. Combining those fixtures
with historical checkpoints does not establish that the selected Hepta
candidate exported them or executed a complete ordinary daemon operation.

The [selected candidate's execution records](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/qualification/cell-common-20261109-e1c98/CURRENT.json)
separate three source roles:

| Role | Commit |
| --- | --- |
| Historical native suite, actual model and Root component execution | `f070113bb61cda492d2668b3afbbcda13e11fa52` |
| Subsequent formatting and strict-lint maintenance | `dde0c36ef2b90af37f5cdafe7dca0c7572585b09` |
| Fixed source and evidence delivery selected here | `71738345326b98d88b738250d2b84ecbcb466eb8` |

The historical component results are not a complete ordinary daemon run on
the selected delivery commit. The later delivery also has its own limited CI
results; those results retain their actual suite scope. This reader neither
transfers execution evidence between commits nor fills missing P0 deployment
inputs from test fixtures. Selected ordinary-daemon binary, model, loader and
evaluator originals remain unestablished and must stay null in the integration
lock until supplied and independently checked.

In particular, matching a caller-provided profile does not authenticate the
Root writer or prove that the profile was retained before training. The report
therefore explicitly keeps `root_profile_origin_authenticated=false` and
`tensor_update_mask_verified=false`. All authority and completeness limits
from `cell_learning_completion_join.py` remain unchanged.
