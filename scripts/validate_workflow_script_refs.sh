#!/usr/bin/env bash
set -euo pipefail

# Normalize locale/timezone-sensitive behavior so workflow reference scans and
# summary evidence remain reproducible across local/CI runner environments.
export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LC_COLLATE="${LC_COLLATE:-C}"

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

if [[ -n "$SUMMARY_PATH" && -d "$SUMMARY_PATH" ]]; then
  echo "[workflow-ref][FAIL] WORKFLOW_SCRIPT_REF_SUMMARY_PATH points to a directory: $SUMMARY_PATH" >&2
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
  done < <(LC_ALL=C grep -Eo '(\./scripts|scripts|trillionnium-rust/scripts)/[[:alnum:]_./-]+\.(sh|py)' "$wf" || true)
done

total_script_ref_count="$(wc -l <"$refs_file" | tr -d ' ')"
mapfile -t SCRIPT_REFS < <(LC_ALL=C sort -u "$refs_file")

echo "[workflow-ref] workflow_count=${#WORKFLOW_FILES[@]}"
echo "[workflow-ref] script_ref_total_count=${total_script_ref_count}"
echo "[workflow-ref] script_ref_count=${#SCRIPT_REFS[@]}"

audit_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

git_head=""
if command -v git >/dev/null 2>&1; then
  git_head="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
fi

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

  if [[ "$resolved" == *.sh && ! -x "$resolved" ]]; then
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
  "ts_utc": "${audit_ts}",
  "workflow_root": "${WORKFLOW_ROOT}",
  "strict_mode": ${STRICT_MODE},
  "workflow_count": ${#WORKFLOW_FILES[@]},
  "workflow_file_count": ${#WORKFLOW_FILES[@]},
  "script_ref_total_count": ${total_script_ref_count},
  "script_ref_count": ${#SCRIPT_REFS[@]},
  "git_head": "${git_head}",
  "missing_count": ${missing_count},
  "non_exec_count": ${non_exec_count},
  "status": "${status}",
  "elapsed_sec": $((end_epoch - START_EPOCH))
}
EOF
  echo "[workflow-ref] summary_json=${SUMMARY_PATH}"
fi

echo "[workflow-ref] status=${status} strict_mode=${STRICT_MODE} elapsed_sec=$((end_epoch - START_EPOCH))"

if [[ "$status" == "fail" ]]; then
  exit 1
fi