# Final source rebinding and remaining gates

This is the integration handoff for the root agent. It is **not** a passing
qualification report. The current GitHub PR still tests
`b683714cdd5ba241c16c335a81aebc12c1581902`; local ports and observations must not
be described as that remote source or as the final composed source.

## Order of operations

1. Finish semantic composition, standalone lock reconciliation, selected source
   inventory, and pinned Rust 1.95 formatting. Preserve the current signed
   domains, explicit versioned profiles, budgets, false qualification flags,
   source reader refusals, and all required selectors.
2. Run `python3 scripts/refresh_distributed_source_inventory.py`, inspect its
   diff, then `python3 scripts/refresh_distributed_source_inventory.py --check`.
   This generator is mechanical **after** the active source set is reviewed.
   My inventory refresh includes three new outbound sources and 22 already
   selected source files absent from the older generated inventory. Reconcile
   against Cell and Node additions rather than replacing their rows.
3. Freeze and publish the reviewed implementation checkpoint. GitHub
   `create_commit` may produce a different SHA from the local commit. Use the
   actual returned/published checkpoint for current-source declarations and
   independently read it back. Never substitute an unpublished local SHA.
4. On the exact full checkout, run the read-only planner:

   ```bash
   GOMAXPROCS=2 python3 plan_source_rebindings.py \
     --root /absolute/path/to/the/full/composed/checkout \
     --declared-source-checkpoint FULL_PUBLISHED_SHA \
     --output /absolute/new/output/rebinding-plan.json
   ```

   The script creates only a new report. It computes candidate hashes with the
   selected readers' digest functions where applicable. It does not attest to
   publication, add semantic coverage, rewrite a manifest, or alter a gate.
5. Review changes in the order below, commit the metadata delta, then run the
   actual head and prospective-merge qualification against that final commit.
   A metadata commit is not evidence that the native code ran.

## Exact files and allowed mechanical changes

| Owner | Current files | Required update and boundary |
| --- | --- | --- |
| Root dependency register | `config/pon/pq-root-dependency-register-v3.json`; `scripts/ci/pq_root_dependency_register.py` | After reviewing the dependency/owner changes, update `source_files_sha256` and `REVIEWED_SOURCE_SNAPSHOT_SHA256` using `source_snapshot_digest`. If the review context changes, update `review_base_revision` and `REVIEW_BASE` together with an explicit review record. Preserve roles, domains, original operational caps and all unknown lifetime terms unless independently reviewed. |
| Authority effects | `config/pon/pq-authority-effects-v1.json`; `scripts/ci/pq_authority_effect_register.py` | Review new/changed routes first. Update the declared file map and `REVIEWED_SOURCE_LOCK_SHA256` using `source_lock_digest`. Keep `source_revision` / `SOURCE_REVISION` coherent. New source paths, route ownership, authentication and effect semantics are not mechanical hash updates. |
| Hash-use contract | `config/pon/hash-use-contract-v1.json`; `scripts/ci/hash_use_contract.py` | Update source byte counts and SHA-256 values, then `REVIEWED_SOURCE_MAP_SHA256 = sha(canonical(source_files))`. Preserve `REVIEWED_SEMANTICS_SHA256` when all non-source-map fields are unchanged. Changing the review revision or any encoding/domain/game/primitive/use is a semantic change and needs a new reviewed semantics digest. Added outbound request-domain hashing needs an explicit scope decision; the existing inventory does not claim exhaustive call-graph coverage. |
| PQ corpus | `config/pon/pq-cross-branch-corpus-v1.json`; `scripts/ci/check_pq_research_integration.py` | `pinned_blobs` uses the Git blob ID: SHA-1 of `b"blob " + decimal_length + b"\0" + bytes`, not raw-file SHA-1. Reconcile new active paths against the selected scanner and required-path sets, then refresh actual current blobs. Preserve the six original `upstream_heads`, source-composition ancestry, old observations and false acceptance assertions. A whole-file search/replace of old commit hashes is incorrect. |
| Joint lifetime composition | `config/pon/pq128-lifetime-composition-v2.json`; `scripts/ci/pq_lifetime_composition.py` | After serializing the updated root register, update its `input_manifests.root.sha256` and the matching `INPUTS` literal. Keep the actual declared-revision semantics coherent. Preserve the legacy input identity if its bytes are unchanged. Do not turn missing probability bounds or query budgets into numbers, add incompatible bounds, or infer custody independence. |
| W1 current lifetime | `config/pon/w1-lifetime-current-source-v2.json`; `scripts/w1_lifetime_current_observation.py` | Recompute only the selected rows' `bytes` and `current_sha256`. Derive the exact ordered changed path list against the retained `historical_sha256`, then update `changed_paths` / `CHANGED`, current checkpoint / `CURRENT`, and `CONTRACT_SHA256` together. Keep the 20-path scope and its limits. Preserve the historical reader, historical checkpoint and historical hashes. |
| W1 current QROM mapping | `config/pon/w1-qrom-implementation-current-v2.json`; `scripts/w1_qrom_current_implementation_audit.py` | Refresh reviewed current `project_files` and `local_path_closure.files`, source checkpoint / `SOURCE`, exact `CHANGED` set, and `CONTRACT_SHA256`. Review the path dependency graph, all Rust files, literal data includes and absent build inputs before extending the closure. Preserve the selected project roster. Helpers, historical contracts/readers, saved proof files, upstream snapshot, image/control/parameter identities and unknown soundness fields remain exactly historical. |

The planner intentionally does **not** invent new source census members, routes,
cryptographic use categories, crate roots, include owners or proof obligations.
Those require semantic review. It reports a missing file rather than deleting a
pin. Its source checkpoint argument remains an unauthenticated declaration
until the root agent verifies the canonical published commit.

## Immutable historical material

Keep the original W1 historical reader and contract; the exact QROM job from
`0c830e0be8939ce80c8443c9ad68021b87343a00`; original proof bytes, failed logs,
run/artifact identities and source maps. Current-source correspondence is a
separate record. The current QROM closure reader intentionally records the
reviewed lock difference; it must not rewrite the historical semantics report
or weaken its exact one-field correspondence.

Retain the original and supplemental QROM test rosters and their exact counts.
Do not auto-discover a smaller passing set. If a newly reviewed current test is
added, update its versioned roster and exact workflow digest/reader controls as
one reviewed change; do not alter an immutable historical roster.

## Remaining verification

After metadata serialization, run the selected `inspect`/CLI readers and their
negative suites for root dependency register, authority effects, hash use,
joint lifetime composition, W1 current lifetime, current QROM mapping and PQ
cross-branch integration. Also run the source inventory `--check`, project
boundary/source integrity, repository/link checks and the closed CI contract.
The required lanes remain:

- `repository-truth`
- `protocol-contract`
- `fuzz-smoke`
- `external-evidence-contract`
- `rust-baseline`, with both successful exact-source quality and runtime shards

Keep their prospective-merge counterparts and required native source recorders.
The PQ workflow additionally requires both runners and both source kinds, the
original 52 + 11 controls, checkpoint ownership, new outbound 9 + one E0308
boundary, current TLS roster, and retained release-authority controls. A passing
source scanner or zero-test subprocess cannot replace native execution.

For this resource-constrained local host, use `CARGO_BUILD_JOBS=1`,
`GOMAXPROCS=2`, `--offline --locked` and explicit `+1.95.0` when a local Cargo
operation is necessary. Avoid duplicate full native builds. Local OpenSSL
3.5.7 results remain preliminary; the hosted qualification uses pinned 3.5.9.

## Fresh remote failures inspected

Run `43410672728` still tests the original b683 source. Exact decoded logs are
retained in `remote-current/`.

- Job `131886963850` (`rust-baseline`) correctly fails fan-in because the
  runtime shard failed; source identity before/after and artifact retrieval
  succeeded. The quality shard succeeded.
- Runtime job `131836000387` reports 11 passed / one failed in `operator_actors`:
  the shared strict key parser rejects the validly encoded weak identity point
  before the actor wrapper and returns `ACTOR_KEY`, while the old test expected
  `ACTOR_WEAK_KEY`. The narrow test repair proves the fixture's decoded weakness,
  requires the helper's exact weak-key refusal and the actor's exact error, and
  separately checks noncanonical encoding. Production acceptance is unchanged.
  Final native execution of this repaired test is still required.
- Repository job `131836000179` fails the dependency register on the stale
  `trillionnium/Cargo.lock` hash: four failures and one error. This belongs to
  the final reviewed register rebinding above.
- Protocol job `131835999888` was cancelled after several successful component
  runs. The complete lane is not a pass.
- Cross-architecture x64 job `131836000183` reports a prepared native binary
  followed by child exit 1; its Host cleanup and source guards succeeded.
  The job-level log does not expose the failing child's exact assertion, so
  this remains an unresolved original observation pending its retained child
  artifact or the final exact-source run. Do not attribute it to the full-name
  CI assertion repair without that evidence.
