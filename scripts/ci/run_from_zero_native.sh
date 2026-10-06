#!/usr/bin/env bash
# Called by the existing protocol-contract lane, for both head and merge trees.
# Retain the newly compiled executable and every individual execution result.
set -euo pipefail
root="${TRNM_CI_RECEIPT_DIR:-${RUNNER_TEMP:-/tmp}/trnm-ci-$$}/from-zero-native"
test ! -e "$root"
test ! -L "$root"
mkdir -p "$(dirname "$root")"
mkdir "$root"
cargo test --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test public_v3_from_zero --no-run --message-format=json \
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
               and row['target']['name'] == 'public_v3_from_zero'
               and row.get('executable') and row['profile']['test']]
if len(executables) != 1:
    raise SystemExit('expected exactly one freshly compiled integration test')
original = Path(executables[0])
target = root / 'public_v3_from_zero'
shutil.copyfile(original, target)
target.chmod(0o755)
identity = {
    'schema': 'from-zero-native-build-v1',
    'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
    'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
    'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
    'source_sha256': hashlib.sha256(Path(
        'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs').read_bytes()).hexdigest(),
    'compiled_only': True,
}
(root / 'build.json').write_text(json.dumps(identity, indent=2) + '\n')
PY
failed=0
for name in \
  caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct \
  from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection \
  from_zero_service_shares_cpu_with_honest_work_and_reopened_owner
do
  if TRNM_PUBLIC_V3_FROM_ZERO_DIR="$root/service" \
    "$root/public_v3_from_zero" "$name" --exact --nocapture --test-threads=1 \
    2>&1 | tee "$root/$name.log"; then
    python3 scripts/ci/check_required_native_test.py "$root/$name.log" \
      --test "$name" > "$root/$name.execution.json" || failed=1
  else
    failed=1
  fi
done
exit "$failed"
