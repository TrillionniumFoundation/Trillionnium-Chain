#!/usr/bin/env bash
# Use the existing consolidated native target and timeout owner, not a second suite.
set -euo pipefail
parent="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}"
export TRNM_CI_RECEIPT_DIR="$parent"
root="$parent/from-zero-native"
test ! -e "$root"
test ! -L "$root"
mkdir -p "$parent"
mkdir "$root"
# These runner checks move with the native invocation into the existing protocol lane.
python3 scripts/ci/test_run_from_zero_service.py > "$root/owner-tests.log" 2>&1
python3 scripts/ci/test_check_from_zero_service.py > "$root/accounting-tests.log" 2>&1
# Only committed public inputs; never credentials, runtime state or host files.
git archive --format=tar.gz HEAD trillionnium scripts config docs formal/pon-nakamoto-v1 > "$root/source.tar.gz"
rustfmt --edition 2021 --check trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs > "$root/format.log" 2>&1
cargo fetch --locked --manifest-path trillionnium/Cargo.toml > "$root/fetch.log" 2>&1
cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test maintenance_paired_conformance --no-run --message-format=json \
  > "$root/build.jsonl" 2> "$root/build.stderr"
python3 - "$root" <<'PY'
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
root = Path(sys.argv[1])
rows = [json.loads(line) for line in (root / 'build.jsonl').read_text().splitlines()]
executables = [row['executable'] for row in rows
               if row.get('reason') == 'compiler-artifact'
               and row['target']['name'] == 'maintenance_paired_conformance'
               and row.get('executable') and row['profile']['test']]
if len(executables) != 1:
    raise SystemExit('expected exactly one freshly compiled integration test')
target = root / 'maintenance_paired_conformance'
shutil.copyfile(executables[0], target)
target.chmod(0o755)
identity = {
    'schema': 'from-zero-native-build-v1',
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
    'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
    'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
    'source_sha256': hashlib.sha256(Path(
        'trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs').read_bytes()).hexdigest(),
    'source_archive_sha256': hashlib.sha256((root / 'source.tar.gz').read_bytes()).hexdigest(),
    'compiled_only': True,
}
(root / 'build.json').write_text(json.dumps(identity, indent=2) + '\n')
PY
# The existing owner preserves failures, exact names, original 600s deadlines,
# owned process-group cleanup and source/log/native-report identity checks.
python3 scripts/ci/run_from_zero_service.py
python3 scripts/ci/check_from_zero_service.py "$parent/from-zero-service/native/report.json" > "$root/accounting.json"
