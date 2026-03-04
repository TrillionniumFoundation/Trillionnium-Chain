#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_ROOT="${WORKFLOW_ROOT:-.github/workflows}"
SUMMARY_PATH="${WORKFLOW_SCRIPT_REF_SUMMARY_PATH:-}"
STRICT_MODE="${WORKFLOW_SCRIPT_REF_STRICT:-0}"
START_EPOCH="$(date -u +%s)"

if [[ "$STRICT_MODE" != "0" && "$STRICT_MODE" != "1" ]]; then
  echo "[workflow-ref][FAIL] WORKFLOW_SCRIPT_REF_STRICT must be 0 or 1 (got: $STRICT_MODE)" >&2
  exit 2
fi

if [[ ! -d "$WORKFLOW_ROOT" ]]; then
  echo "[workflow-ref][FAIL] workflow directory not found: $WORKFLOW_ROOT" >&2
  exit 2
fi

mapfile -t WORKFLOW_FILES < <(find "$WORKFLOW_ROOT" -type f \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort)
if [[ ${#WORKFLOW_FILES[@]} -eq 0 ]]; then
  echo "[workflow-ref][FAIL] no workflow files found under: $WORKFLOW_ROOT" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

refs_file="$TMP_DIR/refs.txt"
missing_file="$TMP_DIR/missing.txt"
non_exec_file="$TMP_DIR/non_exec.txt"

: >"$refs_file"
: >"$missing_file"
: >"$non_exec_file"

for wf in "${WORKFLOW_FILES[@]}"; do
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    printf '%s\n' "$ref" >>"$refs_file"
  done < <(LC_ALL=C grep -Eo '\./scripts/[[:alnum:]_./-]+\.sh' "$wf" || true)
done

mapfile -t SCRIPT_REFS < <(LC_ALL=C sort -u "$refs_file")

echo "[workflow-ref] workflow_count=${#WORKFLOW_FILES[@]}"
echo "[workflow-ref] script_ref_count=${#SCRIPT_REFS[@]}"

if [[ ${#SCRIPT_REFS[@]} -eq 0 ]]; then
  echo "[workflow-ref][WARN] no ./scripts/*.sh references found in workflows"
fi

for ref in "${SCRIPT_REFS[@]}"; do
  path="${ref#./}"

  resolved=""
  if [[ -f "$path" ]]; then
    resolved="$path"
  elif [[ -f "trillionnium-rust/$path" ]]; then
    resolved="trillionnium-rust/$path"
  fi

  if [[ -z "$resolved" ]]; then
    printf '%s\n' "$ref" >>"$missing_file"
    continue
  fi

  if [[ ! -x "$resolved" ]]; then
    printf '%s -> %s\n' "$ref" "$resolved" >>"$non_exec_file"
  fi
done

missing_count="$(wc -l <"$missing_file" | tr -d ' ')"
non_exec_count="$(wc -l <"$non_exec_file" | tr -d ' ')"

if [[ "$missing_count" != "0" ]]; then
  echo "[workflow-ref][WARN] missing script references:" >&2
  cat "$missing_file" >&2
fi

if [[ "$non_exec_count" != "0" ]]; then
  echo "[workflow-ref][WARN] referenced scripts without executable bit:" >&2
  cat "$non_exec_file" >&2
fi

end_epoch="$(date -u +%s)"
status="ok"
if [[ "$missing_count" != "0" || "$non_exec_count" != "0" ]]; then
  if [[ "$STRICT_MODE" == "1" ]]; then
    status="fail"
  else
    status="warn"
  fi
fi

if [[ -n "$SUMMARY_PATH" ]]; then
  mkdir -p "$(dirname "$SUMMARY_PATH")"
  cat >"$SUMMARY_PATH" <<EOF
{
  "workflow_root": "${WORKFLOW_ROOT}",
  "strict_mode": ${STRICT_MODE},
  "workflow_count": ${#WORKFLOW_FILES[@]},
  "script_ref_count": ${#SCRIPT_REFS[@]},
  "missing_count": ${missing_count},
  "non_exec_count": ${non_exec_count},
  "status": "${status}",
  "elapsed_sec": $((end_epoch - START_EPOCH))
}
EOF
  echo "[workflow-ref] summary_json=${SUMMARY_PATH}"
fi

if [[ "$status" == "fail" ]]; then
  exit 1
fi

echo "[workflow-ref] status=${status} strict_mode=${STRICT_MODE} elapsed_sec=$((end_epoch - START_EPOCH))"