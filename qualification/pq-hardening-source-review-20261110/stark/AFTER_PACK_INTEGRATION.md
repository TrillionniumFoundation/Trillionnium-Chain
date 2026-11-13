# Supplemental integration instructions

Preparation only. The final reviewed Rust bytes and source checkpoint must be
supplied by the integrating owner. No final candidate or hosted/native pass is
claimed here. All qualification remains HOLD.

## Fixed inputs and patch order

The base is `da1374a200022bc14dc2bd325cc9ba29dbcd24ab`. The original STARK package
imports its new route material from
`06c3d24cc4fc05011e04951d30f066c057394836` (#857), preserving the separate
literature basis `e2a02f9271b49f146e70806c8a66e161b5973971`.

1. Run the existing project preflight in the complete candidate checkout.
2. Integrate the three reviewed source changes, including the 10 full files and
   `shared-integration.patch` from the original `stark-integration.tar.gz`.
3. Apply **only** `after-pack.patch` for the supplements. It applies after the
   original shared patch. The earlier `integration-stark-roster.patch` is an
   intermediate artifact and must not also be applied.
4. Finish the selected Rust formatting and source review before choosing final
   fingerprints. Do not rewrite unrelated source merely to make pins pass.

```sh
git apply --check /absolute/path/to/after-pack.patch
git apply /absolute/path/to/after-pack.patch
```

The original shared patch was applied successfully to exact downloaded da1374
files. The supplemental patch also passed `git apply --check` against that
after-pack state. Neither operation modified the original archive.

## What the supplement adds

The existing checker now independently requires the four quantum model and
test files, in addition to the 10 STARK files from the original package.
The test file has separate literal STARK and quantum rosters; neither roster
is generated from the checker's set. It tests omission from required paths,
omission from pins, omission from both, and altered bytes under an old pin.

The actual `repository-truth` lane now runs, in this order, after
`test_pq_chain_claim_guard.py` and before the current W1 mapping controls:

```sh
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
```

The command checker and independent CI tests enforce the order, exactly one
invocation, original arguments, foreground completion, and failure propagation.
The negative cases include deletion, duplication in either lane, relocation,
commenting out, `if false`, suppressed errexit, `|| true`, and `&`.
All previous CI checks and required command groups remain in place.

## Two specific outer bindings need maintenance

The final source changes affect these existing bindings:

| Reviewed source | Existing outer binding | Allowed pin change |
| --- | --- | --- |
| `trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs` | `config/pon/pq128-source-lock-v1.json.files` | This one SHA-256 value |
| `formal/pon-nakamoto-v1/quantum_daa_model.py` | `scripts/w1_lifetime_ledger.py.SOURCE_PINS` | This one SHA-256 value |

The source-lock revision must equal
`config/pon/pq128-lifetime-budget-v1.json.experiment.source_revision`.
The ledger's `SOURCE_BASE` must identify a real commit containing all 20
selected source blobs: the existing named test reads them from Git and compares
them byte for byte. A source checkpoint followed by a child binding/report
commit is therefore required; a self-referential final commit ID is not used.

After the source-only checkpoint exists, run the supplied preparer from outside
the repository, using the **reviewed final network digest**. The quantum DAA
digest is fixed in the preparer to the reviewed numeric patch:
`1cc69a5d58350ce0ffcc21f7030473f7be9e5a9baeea024da0f589447dcd14b7`.

```sh
python3 -I /absolute/path/to/rebind_reviewed_outer_pins.py \
  --root /absolute/path/to/complete-candidate \
  --source-commit FINAL_REVIEWED_SOURCE_CHECKPOINT \
  --expected-pq-network-sha256 REVIEWED_FINAL_NETWORK_SHA256 \
  --output /absolute/path/to/new-outer-binding-review
```

The preparer requires HEAD to equal the source checkpoint, verifies da1374
ancestry without replacement refs or lazy fetch, checks all 31 distinct
selected paths as Git regular blobs and working files, and refuses any source
difference outside the two paths above. It also requires the exact original
five binding/input/report files before planning changes. It never guesses a
new source digest from arbitrary working bytes.

It writes an external `outer-pins.patch`, `REVIEW.json`, and before/after bytes.
It does not write the checkout. The patch has exactly four outputs:

1. The one source-lock pin plus its source revision.
2. The budget experiment's matching source revision.
3. The one ledger source pin plus `SOURCE_BASE`.
4. The recomputed **current** lifetime report.

The new report is computed from a temporary copy of checked input bytes. It
must exactly equal the original report except for five source-survey leaves:
the source checkpoint, the DAA digest in two places, its byte count, and its
source-anchor line. The arithmetic, counterexamples, all unknown quantities,
and the complete independent-acceptance object must remain exactly equal.
The preparer checks the resulting patch for applicability before returning.

```sh
git apply --check /absolute/path/to/new-outer-binding-review/outer-pins.patch
git apply /absolute/path/to/new-outer-binding-review/outer-pins.patch
```

The input `project-input.json` remains byte-identical. The historical
`evidence/pon-w1-lifetime-20261107/` records and fixed historical
`w1-qrom-current-source-observation-v1.json` profile must not be repinned. That
profile intentionally names its original ledger bytes and historical refusal;
it is not the current successor's acceptance report.

Current prose in `docs/security/PQ128_LIFETIME_BUDGET_V1.md`,
`docs/security/W1_LIFETIME_AND_INDEPENDENT_ACCEPTANCE_20261107.md`, and
`evidence/pon-w1-lifetime-current-20261109/README.md` names the prior mapping.
Add the new reviewed mapping and label the previous mapping accurately once
the real checkpoint/digests are known. Preserve the historical paragraphs and
receipts. The fixed `66b706...` assertion in `test_ci_contract.py` belongs to an
old Cell doctest failure receipt; it is unrelated and must remain unchanged.

## Current QROM map does not contain these changed sources

The existing 137-file `local_path_closure` in
`w1-qrom-implementation-current-v2.json` contains six roots: the hardened and
v2 verifier crates, guest-v2, relation, crypto-primitives, and protocol. It
contains no `trnm-pon-node` or TLS source, no quantum Python model, no CI script,
and no documentation or sole plan. The current three patch groups therefore
do not require a new QROM current-map source base or digest merely because
those files change.

If an additional reviewed change actually enters that map, its independent
outer bindings also need review: the current audit's `CONTRACT_SHA256` and
`SOURCE`; `pq-proof-profile-binding-v1.json.mapping_contract` bytes/digest; and
the STARK route registry's current-map source row plus frozen 19-input roster
digest. The proof-profile workflow pins a descriptor digest as well. Do not
alter any of them unless the corresponding mapped input actually changes.

## Inventory and corpus last

The distributed-source generator enumerates `.rs`, `.json`, and `Cargo.toml`
under `trillionnium/crates` and `config`, plus the workspace manifest/lock and
its own output path. The original package already adds the two new STARK JSON
entries. Run its check and review the exact file-list diff if it needs a
refresh; the generator does not review new paths for you.

```sh
python3 scripts/refresh_distributed_source_inventory.py --check
# Only when a reviewed added/removed path requires regeneration:
python3 scripts/refresh_distributed_source_inventory.py
git diff -- trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs
```

The original corpus has 1,079 pins and 987 required paths. All 10 STARK paths
and all four quantum model/test paths were absent. Add those 14 literal paths
to both `required_paths` and `pinned_blobs`. The sole plan, existing shared
files, corpus test file, identity files, source lock, budget, ledger and current
lifetime report were already pinned; update their pins only if their final
reviewed bytes actually changed. Additional new joint documentation should be
handled explicitly in the same reviewed path list.

Corpus pins are **40-hex Git blob SHA-1 identities**, not file SHA-256:

```sh
git hash-object --no-filters -- reviewed/path
```

The equivalent calculation is
`SHA1(b"blob " + decimal_byte_length + b"\0" + raw_file_bytes)`.
There is no corpus `--rebind` option in the fixed checker. Do not regenerate
all 1,079 values or accept a whole-tree scan as the review decision. Use a
literal reviewed delta with each expected old and expected new blob ID, reject
unexpected changes, preserve all unlisted pins and provenance/qualification
fields, and union the 14 required additions. Recheck the entire corpus after
the selective edit. The corpus cannot pin its own final bytes recursively.

## Required checks in the complete final tree

```sh
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_pq_lifetime_budget.py
python3 scripts/ci/pq_lifetime_budget.py
python3 -B -m unittest discover -s scripts/ci -p test_w1_lifetime_ledger.py -v
python3 -B scripts/w1_lifetime_ledger.py \
  --input evidence/pon-w1-lifetime-current-20261109/project-input.json \
  > /absolute/path/to/fresh-lifetime-observation.json
cmp evidence/pon-w1-lifetime-current-20261109/project-report.json \
  /absolute/path/to/fresh-lifetime-observation.json
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/check_ci_contract.py
python3 scripts/refresh_distributed_source_inventory.py --check
```

The existing QROM closure workflow already invokes the unchanged 19 named
ledger tests and compares the current lifetime report. Those test IDs and the
closure roster digest do not need changes when only the reviewed source pins
and current report are maintained. Existing historical rejection controls
remain required. Native Rust/provider tests, whole-checkout identity checks,
and hosted head/prospective-merge lanes remain separate final integration work.
