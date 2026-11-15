# Reproduce the same-material cost observation

The raw archive is bound by [archive.json](archive.json). The measured source is
`eeedfe33f9c7cd27a1855b865e7faa458047dcd1`, not a later integration commit.
The archive contains `campaign-v2/`, both `security-v2-t*/` directories,
`frozen-inputs/`, the strict readback and scenarios, audit records, original
algebra inputs, the exact release binary, validation logs and a measured-source
file hash manifest. Obtain the source from the repository at the named commit
for imports, review and dependency resolution.

All examples assume the current directory is the pinned repository and
`TRNM_COST_ARCHIVE_DIR` is the absolute path to an extracted archive. Output
directories/files must not already exist. Do not overwrite the retained records.

## 1. Verify the retained bytes

Check the ZIP's SHA256 and size against `archive.json` before extraction. The ZIP
contains `payload-manifest.json`; verify every listed payload after extraction:

```bash
export TRNM_COST_ARCHIVE_DIR=/absolute/path/to/extracted-archive
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
root = Path(os.environ['TRNM_COST_ARCHIVE_DIR']).resolve()
manifest = json.loads((root / 'payload-manifest.json').read_text())
for row in manifest['files']:
    path = root / row['path']
    data = path.read_bytes()
    assert len(data) == row['bytes']
    assert hashlib.sha256(data).hexdigest() == row['sha256'], row['path']
print('Verified', len(manifest['files']), 'payload files')
PY
```

The manifest does not hash itself. The outside ZIP commitment covers it. Hash
consistency and local clock consistency do not authenticate a remote operator.

## 2. Read all retained cases without native execution

Use the pinned source's strict reader. The final exit 2 is expected because the
31-case set deliberately includes a failed, uncredited batch:

```bash
python3 - <<'PY'
import json, os, subprocess
from pathlib import Path
root = Path(os.environ['TRNM_COST_ARCHIVE_DIR'])
plan = json.loads((root / 'campaign-v2/plan.json').read_text())
command = ['python3', 'scripts/ci/shared_material_cost_v2.py']
for case in plan['cases']:
    command += ['--run', str(root / 'campaign-v2' / case['name'])]
command += ['--scenario-json', str(root / 'cost-scenarios-v2.json'),
            '--out', str(root / 'fresh-readback.json')]
result = subprocess.run(command)
assert result.returncode == 2
report = json.loads((root / 'fresh-readback.json').read_text())
assert report['status'] == 'incomplete_local_observations'
assert len(report['runs']) == 31
assert sum(r['status'] == 'complete_consistent_observation'
           for r in report['runs']) == 30
assert report['qualification'] is False
assert report['full_system_cost'] is None
PY
```

Fresh readback embeds the new local directory locations, so it need not be byte
identical to the original readback. Mathematical identities, raw costs, refusal
status and qualification fields must agree.

The standalone summary program uses only Python's standard library and retained
JSON. With the original retained readback its output is byte-reproducible even
after moving the input files to an unrelated directory:

```bash
python3 "$TRNM_COST_ARCHIVE_DIR/evidence/summarize.py" \
  --cost-readback "$TRNM_COST_ARCHIVE_DIR/cost-v2-all-readback.json" \
  --campaign-dir "$TRNM_COST_ARCHIVE_DIR/campaign-v2" \
  --security-report "$TRNM_COST_ARCHIVE_DIR/security-v2-t0/report.json" \
  --security-report "$TRNM_COST_ARCHIVE_DIR/security-v2-t1/report.json" \
  --audit-controls "$TRNM_COST_ARCHIVE_DIR/audit-notes/cost-v2-actual-controls.json" \
  --audit-log "$TRNM_COST_ARCHIVE_DIR/audit-notes/cost-v2-actual-controls.log" \
  --out "$TRNM_COST_ARCHIVE_DIR/fresh-summary.json"
```

The actual-v2 negative controls are:

```bash
python3 scripts/ci/test_shared_material_cost_v2.py \
  --actual-run "$TRNM_COST_ARCHIVE_DIR/campaign-v2/paired-r0-t0-full-limb-dense" -v
python3 formal/pon-nakamoto-v1/test_shared_cell_operator_v1.py
python3 scripts/ci/test_shared_material_security_v1.py
python3 scripts/ci/test_shared_material_campaign_v2.py
```

## 3. Execute a new, separately identified campaign

Use a clean checkout on an allowed `fix/chain-...` branch at the measured commit.
Keep the archive and all new outputs outside the repository. The driver refuses
dirty source, drifted inputs or a changed binary. It writes the complete case plan
before starting and retains every failed process.

```bash
bash scripts/project-preflight.sh
export CARGO_TARGET_DIR=/absolute/path/to/shared-cost-target
CARGO_BUILD_JOBS=1 cargo +1.95.0 build --locked --release \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_shared_material_v1
export TRNM_COST_RUNNER="$CARGO_TARGET_DIR/release/examples/pon_shared_material_v1"
export TRNM_COST_NEW_CAMPAIGN=/absolute/path/to/new-campaign
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
python3 scripts/ci/run_shared_material_campaign_v2.py \
  --model-dir "$TRNM_COST_ARCHIVE_DIR/frozen-inputs" \
  --bundle-hash 0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5 \
  --runner "$TRNM_COST_RUNNER" --repetitions 3 \
  --out "$TRNM_COST_NEW_CAMPAIGN"
```

The original build used the existing dependency cache with `--offline`; omit
that option only when dependencies must be fetched. Release optimization flags
were not changed. Tests used one job, debuginfo zero and incremental compilation
disabled; those test-only settings must not be confused with measured release
settings. Every timing rerun is a new observation, not a reproduction of exact
nanosecond values or a performance qualification.

Run the same-material attacks on the new campaign with the same binary:

```bash
python3 scripts/ci/run_shared_material_security_v1.py \
  --material-dir "$TRNM_COST_NEW_CAMPAIGN/paired-r0-t0-full-limb-dense" \
  --runner "$TRNM_COST_RUNNER" --target-index 0 \
  --cycles 4 --max-attempts 4096 --out /absolute/path/to/new-security-t0
python3 scripts/ci/run_shared_material_security_v1.py \
  --material-dir "$TRNM_COST_NEW_CAMPAIGN/paired-r0-t1-full-limb-dense" \
  --runner "$TRNM_COST_RUNNER" --target-index 1 \
  --cycles 4 --max-attempts 4096 --out /absolute/path/to/new-security-t1
```

The attacks explicitly use dense preparation, full-limb arithmetic, one verifier
and the v1 observation namespace. They consume the v2 consumer's same material
files, not a different attack-only synthetic workload.

## 4. Recompute the algebra audit

The audit script requires a clean repository at the measured commit and the
retained original v1 winner logs. It does not execute a new native benchmark:

```bash
python3 "$TRNM_COST_ARCHIVE_DIR/audit-notes/recompute_transcript_prefix_factorization.py" \
  --input-root "$TRNM_COST_ARCHIVE_DIR/prior-v1-algebra-inputs" \
  --repo "$PWD" --output /absolute/path/to/fresh-algebra-audit.json
```

Check all 2,560 tile-word hashes and the five complete trace hashes. The generic
four-term schedule and the narrower bias-tile candidate have explicit counted
operations and exclusions. Their mathematical validity is not a measured CPU
speedup and does not prove a global minimum work cost.

## Original gates remain unchanged

The research driver uses a 60-second per-child observation timeout and a
360-second outer observation bound. These are instrumentation bounds, not a
replacement for the original 0.25 CPU / 2 GiB / four-second / 16-hostile-work /
depth-six service gate. This campaign does not grant that qualification, model
adoption, network-wide validation coverage, funded settlement or activation.
