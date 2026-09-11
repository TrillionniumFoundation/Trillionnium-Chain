#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scanner="$repo_root/scripts/validate_workflow_script_refs.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-python.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT
mkdir -p "$fixture_root/.github/workflows" "$fixture_root/scripts"

cat >"$fixture_root/.github/workflows/coverage.yml" <<'YAML'
name: isolated Python and shell reference fixture
on: workflow_dispatch
jobs:
  references:
    runs-on: ubuntu-latest
    steps:
      - run: |
          python3 ./scripts/check.py
          bash ./scripts/run.sh
          python3 ./scripts/check.py
YAML
cat >"$fixture_root/scripts/check.py" <<'PY'
raise SystemExit(0)
PY
cat >"$fixture_root/scripts/run.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 600 "$fixture_root/scripts/check.py"
chmod 700 "$fixture_root/scripts/run.sh"

run_case() {
  local label="$1" expected_exit="$2" expected_missing="$3" expected_non_exec="$4" expected_status="$5"
  local actual_exit=0
  rm -f -- "$fixture_root/summary.json"
  (
    cd -- "$fixture_root"
    WORKFLOW_ROOT=.github/workflows \
      WORKFLOW_SCRIPT_REF_STRICT=1 \
      WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$fixture_root/summary.json" \
      bash "$scanner"
  ) >"$fixture_root/scan.log" 2>&1 || actual_exit=$?
  if [[ "$actual_exit" != "$expected_exit" ]]; then
    cat "$fixture_root/scan.log" >&2
    echo "[workflow-ref-python][FAIL] $label: exit=$actual_exit expected=$expected_exit" >&2
    exit 1
  fi
  python3 - "$fixture_root/summary.json" "$label" "$expected_missing" "$expected_non_exec" "$expected_status" <<'PY'
import json
import sys

path, label, missing, non_exec, status = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    summary = json.load(stream)
expected = {
    "workflow_root": ".github/workflows",
    "strict_mode": 1,
    "workflow_count": 1,
    "workflow_file_count": 1,
    "script_ref_total_count": 3,
    "script_ref_count": 2,
    "non_dot_script_ref_total_count": 0,
    "non_dot_script_ref_count": 0,
    "empty_ref_count": 0,
    "missing_count": int(missing),
    "non_exec_count": int(non_exec),
    "status": status,
}
for key, value in expected.items():
    actual = summary.get(key)
    if type(actual) is not type(value) or actual != value:
        raise SystemExit(f"{label}: {key}={actual!r}, expected {value!r}")
PY
}

# Interpreter-driven Python references require existence, not an executable bit.
[[ ! -x "$fixture_root/scripts/check.py" ]]
run_case python_without_execute_bit 0 0 0 ok

# The duplicate reference must still produce exactly one missing-file finding.
rm -- "$fixture_root/scripts/check.py"
run_case missing_python_is_a_strict_failure 1 1 0 fail

cat >"$fixture_root/scripts/check.py" <<'PY'
raise SystemExit(0)
PY
chmod 600 "$fixture_root/scripts/check.py" "$fixture_root/scripts/run.sh"
run_case shell_without_execute_bit_is_a_strict_failure 1 0 1 fail

echo "[workflow-ref-python] PASS cases=3"
