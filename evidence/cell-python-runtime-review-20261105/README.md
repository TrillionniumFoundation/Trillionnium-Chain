# Cell Python runtime: independent import review, 2026-11-05

## Scope and status

These are actual lightweight Python import observations from an independent
review of the in-progress Chain/Hepta runtime binding. The review loaded no
model, produced no model Ready, invoked no native Rust admission guard and ran
no large build. It grants no installation, FinalUse, GPU, immutable-runtime or
production qualification claim. The integrating owner must retain the final
combined-source and native pre-spawn gate results separately.

The base Chain checkout was `6ee529046d295e3175f09112492abee373f1f54c`. The helper
was changing during review; the receipts identify the exact helper digest
observed in each run. A historical green receipt is not acceptance of the
eventual combined commit. No original failure was replaced by a later result.

## Retained observations

| Evidence | Actual observation | Interpretation |
| --- | --- | --- |
| [Original red observations](original-red-observations.json) | A real temporary `.dist-info` is discoverable before the original import guard and raises `PackageNotFoundError` afterward. The same record retains the first startup ZIP canary. | Replacing `PathFinder` without forwarding `find_distributions` breaks metadata discovery. The original ZIP observation is preserved separately from later work. |
| [Metadata green](metadata-green.json) | The real distribution reports `1.2.3` both before and after the updated guard. | Independent recheck of the metadata forwarding fix at the recorded helper digest only. |
| [Source versus bytecode](bytecode-source.json) | The ordinary loader executes a poisoned timestamp-matched `.pyc` (`pyc`); the guard executes the pinned source (`raw`). | Actual source bytes, rather than the ambient valid cache file, determine execution in this control. |
| [Project shadows and sources](project-shadow.json) | Script-directory `hashlib.py` and `json.py` canaries do not execute. An undeclared formal-directory `torch.py` is rejected before execution. Actual copied sources produce the expected source-pin projection. | The observed 13 host source names, 12 inherited source pins and 8 Python source paths agree. This is an import/identity control, not model loading. |
| [Startup ZIP](startup-zip.json) | A copied real interpreter is unchanged, and the declared venv/stdlib inventory is unchanged, but a sibling `python312.zip/hashlib.py` executes before Python-side admission. | Static startup search inputs outside those two inventory trees require native pre-spawn checks. |
| [Startup `._pth`](startup-underscore-pth.json) | An executable-side `python3.12._pth` introduces a module directory; the original worker's top-level `import hashlib` executes its canary while the declared inventory remains unchanged. | `-I -S -B` alone does not exclude this observed startup input. A native guard must refuse the layout before Python starts. |
| [Ready field shape](ready-field-shape.json) | All 13 names in the Python Ready constructor match the Rust Ready fields. | Static structure comparison only; no actual Ready was emitted. |
| [Withdrawn hypothesis](withdrawn-alternate-venv.json) | Changing a second venv's `home` did not execute that home's ZIP canary on this interpreter. | The tentative alternate-venv bypass inference was explicitly withdrawn. It is not a finding. |

The ZIP and `._pth` probes directly start Python with
`-I -S -B -X pycache_prefix=<absent-private-path>` and invoke the original worker
with `--help`. Their canaries write a temporary marker and raise an exception.
They do **not** call the new Rust guard. Continued canary execution in these
direct-launch probes must not be described as a failure of a later native
pre-spawn fix. No native guard green is claimed in this directory.

The first ZIP run counted 998 inventory files; the later separately identified
run counted 1,031. Each receipt asserts equality within its own before/after
pair. The two counts are not merged into a single environment observation.

## Source identities and preservation

| Observation | Helper SHA-256 |
| --- | --- |
| Original metadata failure | `8cbb3074e40b6c0df9018ea991fbb8de4fd800371bc31188a8dac5782ce29773` |
| Original startup ZIP canary | `6f63a6564e06ba39f68f11bc5717867adf2a0735815d48306a8f69b1b1a8cc55` |
| Metadata green, bytecode, project, repeated ZIP and `._pth` observations | `650927fe80d3d9b07689261a861b06878cf76488ad4b6571be25dfb5ecebe855` |

Worker and Rust-profile digests are retained where the original observations
recorded them. [Provenance](provenance.json) records the original receipt hashes
and the changes made while packaging this directory. Seven retained receipts
are byte-for-byte copies. Only the `._pth` receipt's traceback path prefixes
were replaced with `<CHAIN>` and `<TEMP>`; its observation values remain
unchanged. No installed environment, runtime snapshot or model bytes are copied.

The two reproduction scripts were adapted from the actual review runners for
repository-relative defaults and explicit, create-only output. Their original
runner digests are preserved. They execute the helper in the selected checkout
and report its observed digest; they do not synthesize the historical bug when
run against a later fixed helper. The earliest two helper byte snapshots were
not retained here, so their original red receipts are historical observations,
not a claim that this directory alone contains those exact earlier sources.

## Reproduce against a selected checkout

Run from the Chain repository root using CPython and a fresh output parent:

```sh
CELL_REVIEW_OUTPUT="$(mktemp -d)"
python3 -I -S -B evidence/cell-python-runtime-review-20261105/import_review.py metadata --output "$CELL_REVIEW_OUTPUT/metadata"
python3 -I -S -B evidence/cell-python-runtime-review-20261105/import_review.py bytecode --output "$CELL_REVIEW_OUTPUT/bytecode"
python3 -I -S -B evidence/cell-python-runtime-review-20261105/import_review.py project --runtime-root /path/to/hepta --output "$CELL_REVIEW_OUTPUT/project"
python3 -I -S -B evidence/cell-python-runtime-review-20261105/import_review.py zip --output "$CELL_REVIEW_OUTPUT/zip"
python3 -I -S -B evidence/cell-python-runtime-review-20261105/underscore_pth_review.py --output "$CELL_REVIEW_OUTPUT/underscore-pth"
```

`--chain-root` optionally selects another Chain checkout. Project mode requires
an explicit Hepta checkout; it does not silently omit the cross-repository
source-name comparison. Each `--output` path must not already exist. New
receipts go there, so reruns cannot overwrite the historical evidence here.

The recorded interpreter was CPython 3.12.14. ZIP and `._pth` probes create a
temporary copy of the real interpreter and a temporary venv-style layout with
a link to its existing stdlib; they remove that temporary layout afterward.
They leave the installed interpreter, either checkout and all model files
untouched. A different interpreter/build may select startup paths differently;
use the observed fields, not the script's exit code, to assess its result.

Each subprocess has a ten-second timeout. File enumeration and hashing are
cooperative and do not have a separate whole-run hard deadline. The original
interpreter copy was 30,894,944 bytes. The controls need no network, model
weights, Torch inference or GPU; the `torch.py` file is only a refusal canary.

## Remaining boundaries

The original snapshot capture code collects all absolute-path entries from
`/proc/self/maps` and merges them into `files`, rather than selecting only
executable mappings. Thus an already mapped shared libpython is covered by
that code path. The observed interpreter here was a standalone ELF with no
libpython mapping, and no actual cold-runtime snapshot was available for this
review. This is not a dynamic-libpython acceptance run.

Native dynamic-loader resolution, concurrent path replacement and immutable
namespace ownership remain separate from these observed-byte checks. Complete
model semantics, ordinary model execution/use, device ownership and independent
runtime qualification are not established by this evidence.
