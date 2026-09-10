#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
python3 "$root/scripts/ci/check_native_consensus_only.py"
python3 - "$root" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
workflow = (root / ".github/workflows/trnm-required-baseline.yml").read_text()
assert "check_native_consensus_only.py" in workflow
assert "runs-on: ubuntu-24.04" in workflow
assert "pull_request:" in workflow
print('{"schema":"trnm-native-ci-truth-v1","result":"PASS"}')
PY
