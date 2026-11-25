# Artifact-bound paired evaluation and attempted cost

This development profile extends the existing released-pair evaluation. It does
not dispatch training, grant FinalUse, settle a real customer payment, or change
the original E1–E6 budgets. Current native authority and production holds remain.

## Identity versions

| Hepta loop identity | Chain request / delivery | Dependency observation |
| --- | --- | --- |
| `hepta.paired-learning.loop-identity.v1` | `trnm-isolated-bound-paired-evaluation-request-v2` / `delivery-v2` | Installed package versions only |
| `hepta.paired-learning.loop-identity.v2` | `trnm-isolated-bound-paired-evaluation-request-v3` / `delivery-v3` | Installed package versions and verified declared artifact bytes |

The complete v2 loop identity retains its parent, candidate, data exposure,
router, model runtime, evaluation, release and native-consent commitments. Its
implementation additionally contains `runtime_artifacts` and changes
`dependency_identity_kind` to `verified_runtime_artifacts_v1`. The artifact
manifest uses schema `hepta.paired-learning.runtime-artifacts.v1` with exact
fields `schema`, `roots`, `files`, `inventory_sha256`, and `total_bytes`.

Roots are sorted, unique, nonoverlapping portable relative paths. Each file has
exact fields `path`, `sha256`, and integer `size`; the sorted file list is hashed
using the same canonical JSON as the loop. Limits are 256 roots, 65,536 files,
16 GiB of file bytes, and 32 MiB of canonical manifest bytes. Traversal, symlinks,
special files, duplicate paths, empty roots, and observed changes during hashing
are refused. All files below a selected directory must be listed, including
unlisted files added after the snapshot. Directory traversal uses descriptor-relative
no-follow opens, so replacing a parent with a symlink cannot redirect a child read.
Live verification refuses platforms without these operations; directory depth is
limited to 128. Retained manifest validation is independent of these platform APIs.

`prepare-bound` accepts both identity versions. For v2, the operator must set
`TRNM_DEV_RUNTIME_ARTIFACTS_ROOT` to the actual installed material root at prepare
and execute time. This local path is not part of the portable signed identity.
The reader recomputes the snapshot and checks that every installed distribution
file for torch, transformers, peft, tokenizers, and safetensors resolves into the
verified inventory. An unrelated copied bundle cannot satisfy this check. Both
before and after evaluation, the live reader also compares interpreter bytes,
Python identity, selected package versions, evaluator files and Chain sources.
The new Chain source roster includes the artifact verifier itself.

This checks declared files and selected installed distributions. It does not
establish transitive dependency, import-hook, native-loader, operating-system or
driver closure, nor immutability after verification. Thus
`runtime_closure_complete` remains false. Retained readback validates commitments
without pretending to reobserve a historical environment. v1/v2 readbacks must
match their loop version; old artifacts are never relabelled.

## Failed evaluation costs

The existing paired and historical evaluator paths now create
`EVALUATION_ATTEMPT.json` under schema `trnm-evaluation-child-attempt-v1`. It binds
an exclusive `EVALUATION_STARTED.json` intent, the original admission bytes,
command commitment, child outcome, exact stdout
and stderr digests, wall time, and waited-child CPU delta. A nonzero child exit
retains its measured attempt before the original exception is raised. Recording
failure does not hide that original exception. A failed launch records unknown
execution, and a second attempt cannot overwrite or reexecute the first.
Intent and output reservations occur before entering the terminal recorder. An
existing intent or output collision blocks dispatch without writing a competing
terminal receipt. An interrupted intent with no terminal receipt remains unknown.

Successful new `COST.json` documents use their respective `cost-v2` namespace and
bind the attempt receipt. Verification checks the successful child outcome,
original intent, admission, counters and raw logs. Only the explicit cost-v1/v2
namespaces are accepted, and the cost family must match the actual admission.
Artifact-bound request-v3 requires cost-v2 and cannot downgrade to historical
cost-v1. Historical cost-v1 records remain
readable without acquiring this new evidence. Child exit zero is not itself a
successful evaluation, adoption, output acknowledgement or authorized delivery;
the existing subsequent checks remain required.

The clock excludes receipt persistence and pipeline stages outside the evaluated
child. `RUSAGE_CHILDREN` is a process-wide waited-child delta and does not isolate
unrelated concurrent children. A killed recorder may leave no receipt; missing
cost stays unknown. Diagnostic search, failed candidates elsewhere, feature
construction, training, transmission, adoption, energy and monetary expense are
not reconstructed here. `cost_completeness_verified` remains false.

## Verification scope

The `test_dev_*.py` suites cover original retained readbacks, artifact admission,
byte mutation, namespace downgrade, copied-bundle refusal, symlinks and malformed
manifests, plus real lightweight child success/failure and missing-cost behavior.
The package metadata in artifact controls is synthetic. These are engineering
controls, not extra training, independent users, frozen scientific trials, paid
operations or production qualification.
