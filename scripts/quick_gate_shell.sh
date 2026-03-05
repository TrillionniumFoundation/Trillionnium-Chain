#!/usr/bin/env bash
set -euo pipefail

# Normalize locale/timezone-sensitive output so local and CI runs produce
# consistent summary artifacts for replay/rollback evidence.
export TZ="${TZ:-UTC}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

if [[ $# -eq 0 ]]; then
  TARGET_DIRS=("scripts")
else
  TARGET_DIRS=("$@")
fi

SKIP_SHELLCHECK="${QUICK_GATE_SKIP_SHELLCHECK:-0}"
SUMMARY_PATH="${QUICK_GATE_SUMMARY_PATH:-}"
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

if [[ "$SKIP_SHELLCHECK" != "0" && "$SKIP_SHELLCHECK" != "1" ]]; then
  echo "[quick-gate][FAIL] QUICK_GATE_SKIP_SHELLCHECK must be 0 or 1 (got: $SKIP_SHELLCHECK)" >&2
  exit 2
fi

if [[ -n "$SUMMARY_PATH" && -d "$SUMMARY_PATH" ]]; then
  echo "[quick-gate][FAIL] QUICK_GATE_SUMMARY_PATH points to a directory: $SUMMARY_PATH" >&2
  exit 2
fi

if [[ "$SKIP_SHELLCHECK" != "1" ]] && ! command -v shellcheck >/dev/null 2>&1; then
  echo "[quick-gate][FAIL] shellcheck not found in PATH (set QUICK_GATE_SKIP_SHELLCHECK=1 for syntax-only local run)" >&2
  exit 2
fi

mapfile -t NORMALIZED_TARGET_DIRS < <(printf '%s\n' "${TARGET_DIRS[@]}" | awk 'NF {print}' | LC_ALL=C sort -u)

if [[ ${#NORMALIZED_TARGET_DIRS[@]} -eq 0 ]]; then
  echo "[quick-gate][FAIL] no target directories provided" >&2
  exit 2
fi

for target_dir in "${NORMALIZED_TARGET_DIRS[@]}"; do
  if [[ ! -d "$target_dir" ]]; then
    echo "[quick-gate][FAIL] target directory not found: $target_dir" >&2
    exit 2
  fi
done

mapfile -t FILES < <(
  for target_dir in "${NORMALIZED_TARGET_DIRS[@]}"; do
    find "$target_dir" -type f -name '*.sh' -print
  done | LC_ALL=C sort -u
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[quick-gate][WARN] no shell scripts found under target directories: ${NORMALIZED_TARGET_DIRS[*]}"
  if [[ -n "$SUMMARY_PATH" ]]; then
    mkdir -p "$(dirname "$SUMMARY_PATH")"
    cat >"$SUMMARY_PATH" <<EOF
{
  "target_dirs_csv": "$(json_escape "$(IFS=,; printf '%s' "${NORMALIZED_TARGET_DIRS[*]}")")",
  "target_dir_count": ${#NORMALIZED_TARGET_DIRS[@]},
  "script_count": 0,
  "skip_shellcheck": ${SKIP_SHELLCHECK},
  "status": "warn-empty"
}
EOF
  fi
  exit 0
fi

echo "[quick-gate] target_dirs=${NORMALIZED_TARGET_DIRS[*]}"
echo "[quick-gate] target_dir_count=${#NORMALIZED_TARGET_DIRS[@]}"
echo "[quick-gate] script_count=${#FILES[@]}"

audit_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

git_head=""
if command -v git >/dev/null 2>&1; then
  git_head="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
fi

manifest_sha256=""
if command -v sha256sum >/dev/null 2>&1; then
  manifest_sha256="$(printf '%s\n' "${FILES[@]}" | sha256sum | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  manifest_sha256="$(printf '%s\n' "${FILES[@]}" | shasum -a 256 | awk '{print $1}')"
fi

bashn_start="$(date -u +%s)"
for f in "${FILES[@]}"; do
  bash -n "$f"
done
bashn_end="$(date -u +%s)"

echo "[quick-gate] bash -n passed"
echo "[quick-gate] bash_n_elapsed_sec=$((bashn_end - bashn_start))"

shellcheck_elapsed=0
shellcheck_status="skipped"
shellcheck_version=""
if [[ "$SKIP_SHELLCHECK" == "1" ]]; then
  echo "[quick-gate][WARN] QUICK_GATE_SKIP_SHELLCHECK=1 -> shellcheck skipped"
else
  shellcheck_version="$(shellcheck --version | awk '/version:/ {print $2}')"
  sc_start="$(date -u +%s)"
  shellcheck -S error "${FILES[@]}"
  sc_end="$(date -u +%s)"
  shellcheck_elapsed="$((sc_end - sc_start))"
  shellcheck_status="passed"
  echo "[quick-gate] shellcheck -S error passed"
  echo "[quick-gate] shellcheck_elapsed_sec=${shellcheck_elapsed}"
  echo "[quick-gate] shellcheck_version=${shellcheck_version}"
fi

end_epoch="$(date -u +%s)"
total_elapsed="$((end_epoch - START_EPOCH))"

if [[ -n "$SUMMARY_PATH" ]]; then
  mkdir -p "$(dirname "$SUMMARY_PATH")"
  cat >"$SUMMARY_PATH" <<EOF
{
  "ts_utc": "${audit_ts}",
  "target_dirs_csv": "$(json_escape "$(IFS=,; printf '%s' "${NORMALIZED_TARGET_DIRS[*]}")")",
  "target_dir_count": ${#NORMALIZED_TARGET_DIRS[@]},
  "script_count": ${#FILES[@]},
  "git_head": "$(json_escape "${git_head}")",
  "file_manifest_sha256": "$(json_escape "${manifest_sha256}")",
  "skip_shellcheck": ${SKIP_SHELLCHECK},
  "bash_n_elapsed_sec": $((bashn_end - bashn_start)),
  "shellcheck_status": "$(json_escape "${shellcheck_status}")",
  "shellcheck_version": "$(json_escape "${shellcheck_version}")",
  "shellcheck_elapsed_sec": ${shellcheck_elapsed},
  "total_elapsed_sec": ${total_elapsed},
  "status": "ok"
}
EOF
  echo "[quick-gate] summary_json=${SUMMARY_PATH}"
fi

echo "[quick-gate] total_elapsed_sec=${total_elapsed}"
