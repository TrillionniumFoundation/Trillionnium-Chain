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

mkdir -p "$TMP_DIR/.github/workflows" "$TMP_DIR/scripts" "$TMP_DIR/trillionnium/scripts"
cat >"$TMP_DIR/.github/workflows/test.yml" <<'YAML'
name: test
on:
  push:
    paths:
      - scripts/example.sh
      - trillionnium/scripts/example.sh
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/example.sh
YAML
cat >"$TMP_DIR/scripts/example.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo ok
SH
cat >"$TMP_DIR/trillionnium/scripts/example.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo ok
SH
chmod +x "$TMP_DIR/scripts/example.sh" "$TMP_DIR/trillionnium/scripts/example.sh"

REL_SUMMARY="tmp/workflow-ref-summary.json"
OUT="$TMP_DIR/out.log"
(
  cd "$TMP_DIR"
  WORKFLOW_SCRIPT_REF_STRICT=1 \
  WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$REL_SUMMARY" \
  "$GATE"
) >"$OUT" 2>&1

if ! grep -Fq 'status=ok strict_mode=1' "$OUT"; then
  echo "[FAIL] strict workflow ref gate should stay green when only trigger path globs use non-dot refs" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

if ! grep -Fq 'non_dot_script_ref_count=0' "$OUT"; then
  echo "[FAIL] trigger path globs should not be counted as non-dot executable refs" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

if ! grep -Fq 'script_ref_total_count=3' "$OUT"; then
  echo "[FAIL] expected both trigger path globs and the run-step ref to be scanned" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

if ! grep -Fq 'script_ref_count=3' "$OUT"; then
  echo "[FAIL] expected three unique script refs in output" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

if ! grep -Fq '"non_dot_script_ref_count": 0' "$TMP_DIR/$REL_SUMMARY"; then
  echo "[FAIL] summary should record zero non-dot executable refs for trigger path globs" >&2
  cat "$TMP_DIR/$REL_SUMMARY" >&2 || true
  exit 1
fi

if ! grep -Fq '"status": "ok"' "$TMP_DIR/$REL_SUMMARY"; then
  echo "[FAIL] summary should remain ok for trigger path glob exemption case" >&2
  cat "$TMP_DIR/$REL_SUMMARY" >&2 || true
  exit 1
fi

echo "[PASS] workflow trigger path globs stay exempt from non-dot executable ref guard"
