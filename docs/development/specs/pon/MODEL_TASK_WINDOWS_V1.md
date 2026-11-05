# Owner-pinned external task windows for V5

This optional input extends the unpublished
[revision16 integer evolution context](MODEL_EVOLUTION_V5.md). A node can load
complete external task material through its ordinary startup path, pin its exact
bytes and data owner, verify the owner's signature, and precommit a deterministic
activation schedule. Candidate authors cannot choose the dataset root that will
score a transaction. Default V5 without this input and all historical profiles
retain their exact context identities.

This is startup configuration of an explicit development chain. It is not a hot
update mechanism for a running chain, permissionless data governance, a guarantee
of truthful labels, or an independent/prospective efficacy certificate.

## Ordinary entrypoint and pins

The three additional CLI options are required together:

```sh
trnm-pon-node status --development --store /absolute/dev-store \
  --evaluation-policy native-public-evaluation-quorum-dev-v2 \
  --model-profile linear-model-evolution-dev-v5 \
  --model-task-windows /absolute/signed-windows.json \
  --model-task-windows-sha256 <exact-file-sha256> \
  --model-data-owner <expected-ed25519-public-key>
```

The operator independently pins both the public key and complete file SHA256.
A public key supplied inside a self-signed file is insufficient without the
matching explicit local pin. The file is public task material, not an execution
script or private signing key. Missing flags, mismatched exact bytes or owner,
bad signatures, unsupported profiles and invalid task material are refused before
a new store is opened.

The manifest hash, canonical manifest identity, owner, owner revision and entire
activation/root schedule enter parameters and the evaluation plan. The complete
file hash also enters the network label, including when `--genesis-time` is used.
Genesis commits the resulting network, parameters and initial state. A store
cannot be reopened with omitted, modified or incompatible manifest settings.

The typed Config and Settings constructors use the same pinned input and parser
as the CLI. Cloning a Config retains an immutable shared validated task schedule;
it does not reload a mutable file or accept new task bytes during evaluation.

## Manifest schema and deterministic source revision

The exact schema is `native-model-task-windows-manifest-v1`. Unknown fields and
duplicate JSON fields are refused. Fields are schema, feature profile, owner,
positive owner revision, source repository, source class, windows and signature.
Source class is either `controlled-source` or `external-source-unqualified`.
Neither value asserts independent administration or model benefit.

The manifest is at most 1 MiB and contains one through eight windows. Each window
has `activate_round`, `source_revision`, `tasks_root` and three through 32 task
inputs. Activation rounds must be strictly increasing and fit the existing
128-block generation arithmetic. Every task has exactly source path, complete
content SHA256, hexadecimal ASCII source bytes, and class label 0, 1 or 2.
All three labels must occur in a window. Source paths must be strictly ordered,
unique, relative, at most 256 bytes and free of empty/dot/traversal segments.
Source snippets are nonempty ASCII without NUL, at most 8,192 bytes each.

Here `source_revision` has a precise reproducible meaning: SHA256 of canonical
JSON containing the source repository and ordered included source paths/content
hashes. It is a content snapshot revision. It is not an unchecked assertion that
a remote Git commit was fetched or authenticated. Complete payloads let any node
recompute every content hash and that snapshot revision. A future input requiring
full repository membership needs an additional explicit Git/tree provenance
contract.

The signature domain `native-model-task-windows-owner-v1` commits the model family
and canonical manifest excluding its signature field. The canonical signed
manifest also receives domain `native-model-task-windows-manifest-v1`. Exact file
SHA256 remains a separate pin, so even differently formatted file bytes require
an explicit matching operator configuration.

## Native feature reconstruction and task roots

The feature profile is
`signed-ascii-token-hash-256-clipped8-plus-bias-v1`. M06 finds ASCII identifiers
`[a-zA-Z_][a-zA-Z_0-9]*`, lowercases them, excludes tokens beginning with `trnm` and
the exact tokens `m00`, `m04`, `m10`, then takes the first 1,024 retained tokens.
SHA256 gives the LE16 coordinate modulo 256 and a sign from bit zero of byte two.
Counts accumulate as integers and are clipped to -8 through 8 after accumulation.
The final 257th feature is bias 8.

The candidate author supplies no feature vectors or predictions. A task identity
commits family, source repository, verified source revision, source path, complete
content hash, label and derived integer features under
`native-model-task-window-row-v1`. The task root commits the complete canonical
ordered task rows under `native-model-task-window-tasks-v1`. A declared root that
differs from this reconstruction is refused.

Duplicate task roots and duplicate complete source contents are refused across
the entire schedule. Contents of the original 25 historical rows are also
excluded. Changing an epoch, path, revision label or owner field cannot turn
identical content into a new scheduled dataset. These checks prevent simple
reuse; they do not prove semantic independence or stop an authorized data owner
from choosing a favorable, biased or mislabeled benchmark.

## Activation and native replay

For a submission round, M06 selects the last precommitted window whose activation
round is no greater than that round. Before the first activation it uses the
historical 25-row material and identifies that selection explicitly. The last
window remains active until another scheduled window. No transaction contains a
task-window selector or a replaceable dataset root.

Candidate, actual parent and all four historical control models are replayed on
the same selected rows. The frozen quorum plan binds the selected task root in
its generation context; reveals bind the actual native evidence digest and score.
The evidence also records manifest identity, owner/revision, source revision,
activation round and source class. Later scoring and adoption resolve the original
submission round, preserving the frozen material across later height changes.

The new plan domain `native-integer-model-task-windows-plan-v1` commits the existing
V5 plan, manifest identity, exact file hash and owner. The existing positive-gain
gate, controlled evaluator quorum, known-source budgets and self-allocation rule
remain mandatory. A new task window does not grant Hepta action authority or
invalidate local revocation history.

## Conformance evidence and remaining boundary

[The independent Python fixture](../../../../formal/pon-nakamoto-v1/model_task_windows_oracle.py)
contains two groups of six newly authored source snippets. Each full payload,
content snapshot revision, feature vector, task root and real Ed25519 owner
signature is reproducible. The
[signed input file](../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.manifest.json)
and [expected task vectors](../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.json)
are retained for native comparison. Their source class is `controlled-source`;
labels and trained candidate parameters deliberately exercise the acceptance
mechanics. They provide no prospective benefit claim.

The native regression must traverse the ordinary pinned Config/Settings/CLI path,
actual signed candidate admission, native evaluation and release adoption at the
activation boundary. Negative coverage includes missing pins, byte substitution,
wrong owner/signature, source hash/revision mismatch, wrong root, activation
reordering, repeated data, incompatible reopen and an attempted cross-window
evidence reveal. The no-window V5 and historical revision15 fixed vectors continue
to guard compatibility.

The optional schedule closes a data-loading interface gap. A production system
still needs independently administered data owners, prospective task collection,
availability and withdrawal policies, privacy/label review, adversarial evaluation,
and an explicitly versioned mechanism to accept a later schedule on an existing
chain. Every node joining this development context must retain or obtain the exact
pinned manifest itself. A task root alone is not data availability.
