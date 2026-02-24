#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-scripts}"
SKIP_SHELLCHECK="${QUICK_GATE_SKIP_SHELLCHECK:-0}"
SUMMARY_PATH="${QUICK_GATE_SUMMARY_PATH:-}"
START_EPOCH="$(date -u +%s)"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "[quick-gate][FAIL] target directory not found: $TARGET_DIR" >&2
  exit 2
fi

if [[ "$SKIP_SHELLCHECK" != "0" && "$SKIP_SHELLCHECK" != "1" ]]; then
  echo "[quick-gate][FAIL] QUICK_GATE_SKIP_SHELLCHECK must be 0 or 1 (got: $SKIP_SHELLCHECK)" >&2
  exit 2
fi

if [[ "$SKIP_SHELLCHECK" != "1" ]] && ! command -v shellcheck >/dev/null 2>&1; then
  echo "[quick-gate][FAIL] shellcheck not found in PATH (set QUICK_GATE_SKIP_SHELLCHECK=1 for syntax-only local run)" >&2
  exit 2
fi

mapfile -t FILES < <(find "$TARGET_DIR" -type f -name '*.sh' -print | LC_ALL=C sort)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[quick-gate][WARN] no shell scripts found under $TARGET_DIR"
  if [[ -n "$SUMMARY_PATH" ]]; then
    mkdir -p "$(dirname "$SUMMARY_PATH")"
    cat >"$SUMMARY_PATH" <<EOF
{
  "target_dir": "${TARGET_DIR}",
  "script_count": 0,
  "skip_shellcheck": ${SKIP_SHELLCHECK},
  "status": "warn-empty"
}
EOF
  fi
  exit 0
fi

echo "[quick-gate] target_dir=$TARGET_DIR"
echo "[quick-gate] script_count=${#FILES[@]}"

audit_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

bashn_start="$(date -u +%s)"
for f in "${FILES[@]}"; do
  bash -n "$f"
done
bashn_end="$(date -u +%s)"

echo "[quick-gate] bash -n passed"
echo "[quick-gate] bash_n_elapsed_sec=$((bashn_end - bashn_start))"

shellcheck_elapsed=0
shellcheck_status="skipped"
if [[ "$SKIP_SHELLCHECK" == "1" ]]; then
  echo "[quick-gate][WARN] QUICK_GATE_SKIP_SHELLCHECK=1 -> shellcheck skipped"
else
  sc_start="$(date -u +%s)"
  shellcheck -S error "${FILES[@]}"
  sc_end="$(date -u +%s)"
  shellcheck_elapsed="$((sc_end - sc_start))"
  shellcheck_status="passed"
  echo "[quick-gate] shellcheck -S error passed"
  echo "[quick-gate] shellcheck_elapsed_sec=${shellcheck_elapsed}"
fi

end_epoch="$(date -u +%s)"
total_elapsed="$((end_epoch - START_EPOCH))"

if [[ -n "$SUMMARY_PATH" ]]; then
  mkdir -p "$(dirname "$SUMMARY_PATH")"
  cat >"$SUMMARY_PATH" <<EOF
{
  "ts_utc": "${audit_ts}",
  "target_dir": "${TARGET_DIR}",
  "script_count": ${#FILES[@]},
  "skip_shellcheck": ${SKIP_SHELLCHECK},
  "bash_n_elapsed_sec": $((bashn_end - bashn_start)),
  "shellcheck_status": "${shellcheck_status}",
  "shellcheck_elapsed_sec": ${shellcheck_elapsed},
  "total_elapsed_sec": ${total_elapsed},
  "status": "ok"
}
EOF
  echo "[quick-gate] summary_json=${SUMMARY_PATH}"
fi

echo "[quick-gate] total_elapsed_sec=${total_elapsed}"
