#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-empty-summary-schema.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

EMPTY_DIR="$TMP_DIR/empty-target"
mkdir -p "$EMPTY_DIR"
SUMMARY="$TMP_DIR/summary.json"

QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY" bash "$SCRIPT" "$EMPTY_DIR" >"$TMP_DIR/stdout.log"

python3 - <<'PY' "$SUMMARY"
import json, sys
summary = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
required = {
    'ts_utc': str,
    'target_dirs_csv': str,
    'target_dir_count': int,
    'script_count': int,
    'git_head': str,
    'file_manifest_sha256': str,
    'skip_shellcheck': int,
    'bash_n_elapsed_sec': int,
    'shellcheck_status': str,
    'shellcheck_version': str,
    'shellcheck_elapsed_sec': int,
    'total_elapsed_sec': int,
    'status': str,
}
for key, typ in required.items():
    if key not in summary:
        raise SystemExit(f'missing key: {key}')
    if not isinstance(summary[key], typ):
        raise SystemExit(f'wrong type for {key}: {type(summary[key]).__name__}')
if summary['script_count'] != 0:
    raise SystemExit(f"expected script_count=0, got {summary['script_count']}")
if summary['shellcheck_status'] != 'skipped':
    raise SystemExit(f"expected shellcheck_status=skipped, got {summary['shellcheck_status']}")
if summary['status'] != 'warn-empty':
    raise SystemExit(f"expected status=warn-empty, got {summary['status']}")
if summary['bash_n_elapsed_sec'] != 0 or summary['shellcheck_elapsed_sec'] != 0:
    raise SystemExit('expected zero elapsed sub-phase counters for empty target set')
print('ok')
PY

echo "[PASS] quick gate empty summary keeps deterministic evidence schema"
