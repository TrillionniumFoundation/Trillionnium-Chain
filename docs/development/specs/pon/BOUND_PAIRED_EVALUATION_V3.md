# Artifact-bound paired evaluation

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


## Verification scope

The identity and retained-readback suites cover original v1 records, v2 artifact
admission, actual byte mutation, namespace downgrade, unrelated copied bundles,
symlinks and malformed manifests. A parent directory is actually replaced at a
leaf-file open; the descriptor-relative reader refuses without opening the
external file. Missing safe filesystem operations refuse before file access.
The package metadata in these controls is synthetic; no model is executed.

The native funded-evaluation driver selects the exact request and delivery schema
from the independently retained original loop identity, compares the complete
identity and retained pin, and rejects unknown versions. The new native namespace
selector test still requires validation on the same source. Python tests do not
certify native execution, real users, FinalUse, adoption or payment.

Attempt-cost accounting remains a separate dependent increment. This identity
change does not establish complete costs, authorize another frozen trial, or
qualify artifact-bound request-v3 for production.
