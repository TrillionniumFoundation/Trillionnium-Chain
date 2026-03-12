#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/validate_workflow_script_refs.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] missing executable gate: $GATE" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/.github/workflows" "$TMP_DIR/scripts"
cat >"$TMP_DIR/.github/workflows/test.yml" <<'YAML'
name: test
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: scripts/example.sh
YAML
cat >"$TMP_DIR/scripts/example.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo ok
SH
chmod +x "$TMP_DIR/scripts/example.sh"

REL_SUMMARY="tmp/workflow-ref-summary.json"
STRICT_OUT="$TMP_DIR/strict.out"
if (
  cd "$TMP_DIR"
  WORKFLOW_SCRIPT_REF_STRICT=1 \
  WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$REL_SUMMARY" \
  "$GATE"
) >"$STRICT_OUT" 2>&1; then
  echo "[FAIL] strict workflow ref gate should fail on non-dot script refs" >&2
  cat "$STRICT_OUT" >&2 || true
  exit 1
fi

if ! grep -Fq 'workflow script refs should prefer ./-prefixed paths' "$STRICT_OUT"; then
  echo "[FAIL] expected non-dot warning banner in strict run" >&2
  cat "$STRICT_OUT" >&2 || true
  exit 1
fi

if ! grep -Fq 'scripts/example.sh' "$STRICT_OUT"; then
  echo "[FAIL] expected offending non-dot ref in strict output" >&2
  cat "$STRICT_OUT" >&2 || true
  exit 1
fi

if ! grep -Fq '"non_dot_script_ref_count": 1' "$TMP_DIR/$REL_SUMMARY"; then
  echo "[FAIL] summary missing non-dot script ref count" >&2
  cat "$TMP_DIR/$REL_SUMMARY" >&2 || true
  exit 1
fi

if ! grep -Fq '"status": "fail"' "$TMP_DIR/$REL_SUMMARY"; then
  echo "[FAIL] strict summary should report fail status for non-dot script refs" >&2
  cat "$TMP_DIR/$REL_SUMMARY" >&2 || true
  exit 1
fi

WARN_OUT="$TMP_DIR/warn.out"
(
  cd "$TMP_DIR"
  WORKFLOW_SCRIPT_REF_STRICT=0 \
  "$GATE"
) >"$WARN_OUT" 2>&1

if ! grep -Fq 'status=warn strict_mode=0' "$WARN_OUT"; then
  echo "[FAIL] non-strict workflow ref gate should warn on non-dot script refs" >&2
  cat "$WARN_OUT" >&2 || true
  exit 1
fi

echo "[PASS] workflow_script_ref_strict_non_dot_guard_test"
