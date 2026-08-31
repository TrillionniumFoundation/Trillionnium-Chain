#!/usr/bin/env bash
set -euo pipefail

# Normalize locale/timezone-sensitive behavior so workflow reference scans and
# summary evidence remain reproducible across local/CI runner environments.
export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LC_NUMERIC="${LC_NUMERIC:-C}"
# Mirror the workflow locale envelope so local reference scans and workflow
# runners sort/log consistently even when tools honor per-category locales.
export LC_COLLATE="${LC_COLLATE:-C}"
export LC_TIME="${LC_TIME:-C}"
export LC_CTYPE="${LC_CTYPE:-C}"
export LC_MESSAGES="${LC_MESSAGES:-C}"
export LC_MONETARY="${LC_MONETARY:-C}"
export LC_MEASUREMENT="${LC_MEASUREMENT:-C}"
export LC_PAPER="${LC_PAPER:-C}"
export LC_ADDRESS="${LC_ADDRESS:-C}"
export LC_NAME="${LC_NAME:-C}"
export LC_TELEPHONE="${LC_TELEPHONE:-C}"

# Mirror CI's deterministic file-mode contract so local summaries/artifacts do
# not drift from workflow runs when scripts create files/directories.
UMASK_VALUE="${UMASK:-022}"
if [[ ! "$UMASK_VALUE" =~ ^[0-7]{3,4}$ ]]; then
  echo "[workflow-ref][FAIL] UMASK must be a 3- or 4-digit octal value (got: $UMASK_VALUE)" >&2
  exit 2
fi
umask "$UMASK_VALUE"

WORKFLOW_ROOT="${WORKFLOW_ROOT:-.github/workflows}"
SUMMARY_PATH="${WORKFLOW_SCRIPT_REF_SUMMARY_PATH:-}"
STRICT_MODE="${WORKFLOW_SCRIPT_REF_STRICT:-0}"
START_EPOCH="$(date -u +%s)"

json_escape() {
  local s=${1-}
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

if [[ "$STRICT_MODE" != "0" && "$STRICT_MODE" != "1" ]]; then
  echo "[workflow-ref][FAIL] WORKFLOW_SCRIPT_REF_STRICT must be 0 or 1 (got: $STRICT_MODE)" >&2
  exit 2
fi

if [[ -e "$WORKFLOW_ROOT" && ! -d "$WORKFLOW_ROOT" ]]; then
  echo "[workflow-ref][FAIL] workflow root is not a directory: $WORKFLOW_ROOT" >&2
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
non_dot_refs_file="$TMP_DIR/non_dot_refs.txt"

: >"$refs_file"
: >"$missing_file"
: >"$non_exec_file"
: >"$non_dot_refs_file"

for wf in "${WORKFLOW_FILES[@]}"; do
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    while IFS= read -r ref; do
      [[ -n "$ref" ]] || continue
      printf '%s\n' "$ref" >>"$refs_file"
      # Only require ./-prefixed refs for executable workflow invocations.
      # GitHub trigger path globs are repo-relative patterns, where retaining
      # plain scripts/... or trillionnium/scripts/... is expected.
      if [[ "$ref" != ./* ]] \
        && ! printf '%s\n' "$line" | LC_ALL=C grep -Eq "^[[:space:]]*-[[:space:]]*['\"]?(scripts|trillionnium/scripts)/"; then
        printf '%s\n' "$ref" >>"$non_dot_refs_file"
      fi
    done < <(printf '%s\n' "$line" | LC_ALL=C grep -Eo '(\./trillionnium/scripts|\./scripts|scripts|trillionnium/scripts)/[[:alnum:]_./-]+\.(sh|py)' || true)
  done <"$wf"
done

total_script_ref_count="$(wc -l <"$refs_file" | tr -d ' ')"
non_dot_script_ref_count="$(wc -l <"$non_dot_refs_file" | tr -d ' ')"
mapfile -t SCRIPT_REFS < <(LC_ALL=C sort -u "$refs_file")
mapfile -t NON_DOT_SCRIPT_REFS < <(LC_ALL=C sort -u "$non_dot_refs_file")

echo "[workflow-ref] workflow_root=${WORKFLOW_ROOT}"
echo "[workflow-ref] workflow_count=${#WORKFLOW_FILES[@]}"
echo "[workflow-ref] script_ref_total_count=${total_script_ref_count}"
echo "[workflow-ref] script_ref_count=${#SCRIPT_REFS[@]}"
echo "[workflow-ref] non_dot_script_ref_total_count=${non_dot_script_ref_count}"
echo "[workflow-ref] non_dot_script_ref_count=${#NON_DOT_SCRIPT_REFS[@]}"

audit_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

git_head=""
if command -v git >/dev/null 2>&1; then
  git_head="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
fi

if [[ ${#SCRIPT_REFS[@]} -eq 0 ]]; then
  echo "[workflow-ref][WARN] no workflow script references found in workflows (expected ./scripts, scripts, or trillionnium/scripts .sh/.py refs)"
fi

empty_ref_count=0
if [[ ${#SCRIPT_REFS[@]} -eq 0 ]]; then
  empty_ref_count=1
fi

echo "[workflow-ref] empty_ref_count=${empty_ref_count}"

for ref in "${SCRIPT_REFS[@]}"; do
  path="${ref#./}"

  resolved=""
  if [[ -f "$path" ]]; then
    resolved="$path"
  elif [[ -f "trillionnium/$path" ]]; then
    resolved="trillionnium/$path"
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

if [[ "$non_dot_script_ref_count" != "0" ]]; then
  echo "[workflow-ref][WARN] workflow script refs should prefer ./-prefixed paths for repo-root determinism:" >&2
  cat "$non_dot_refs_file" >&2
fi

end_epoch="$(date -u +%s)"
status="ok"
if [[ "$missing_count" != "0" || "$non_exec_count" != "0" || "$non_dot_script_ref_count" != "0" || "$empty_ref_count" != "0" ]]; then
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
  "ts_utc": "$(json_escape "${audit_ts}")",
  "workflow_root": "$(json_escape "${WORKFLOW_ROOT}")",
  "strict_mode": ${STRICT_MODE},
  "workflow_count": ${#WORKFLOW_FILES[@]},
  "workflow_file_count": ${#WORKFLOW_FILES[@]},
  "script_ref_total_count": ${total_script_ref_count},
  "script_ref_count": ${#SCRIPT_REFS[@]},
  "non_dot_script_ref_total_count": ${non_dot_script_ref_count},
  "non_dot_script_ref_count": ${#NON_DOT_SCRIPT_REFS[@]},
  "empty_ref_count": ${empty_ref_count},
  "git_head": "$(json_escape "${git_head}")",
  "missing_count": ${missing_count},
  "non_exec_count": ${non_exec_count},
  "status": "$(json_escape "${status}")",
  "elapsed_sec": $((end_epoch - START_EPOCH))
}
EOF
  echo "[workflow-ref] summary_json=${SUMMARY_PATH}"
fi

echo "[workflow-ref] status=${status} strict_mode=${STRICT_MODE} elapsed_sec=$((end_epoch - START_EPOCH))"

if [[ "$status" == "fail" ]]; then
  exit 1
fi
