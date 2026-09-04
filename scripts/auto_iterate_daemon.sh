#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ROUND_SCRIPT="${ROUND_SCRIPT:-$ROOT/scripts/auto_iterate_round.sh}"
STATE_DIR="${STATE_DIR:-$ROOT/run/auto-iterate}"
LOG_FILE="${LOG_FILE:-$STATE_DIR/daemon.log}"
LOCK_FILE="${LOCK_FILE:-$ROOT/.auto-iterate.lock}"
PAUSE_FILE="${PAUSE_FILE:-$ROOT/.auto-iterate.pause}"
STOP_FILE="${STOP_FILE:-$ROOT/.auto-iterate.stop}"
MAX_CONSEC_FAIL="${MAX_CONSEC_FAIL:-2}"
SLEEP_SECONDS="${SLEEP_SECONDS:-30}"
PUSH_RETRIES="${PUSH_RETRIES:-6}"
AUTO_PR_COMMENT="${AUTO_PR_COMMENT:-1}"
PR_NUMBER="${PR_NUMBER:-17}"

# launchd default PATH is minimal; include common Homebrew locations.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

mkdir -p "$STATE_DIR"

if [[ -f "$LOCK_FILE" ]]; then
  echo "[auto-iterate] lock exists: $LOCK_FILE" | tee -a "$LOG_FILE"
  exit 11
fi
trap 'rm -f "$LOCK_FILE"' EXIT
printf "%s\n" "$$" > "$LOCK_FILE"

consec_fail=0
round=0

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"
}

comment_latest_commit_to_pr() {
  [[ "$AUTO_PR_COMMENT" == "1" ]] || return 0

  if ! command -v gh >/dev/null 2>&1; then
    log "pr-comment-skip: gh not found in PATH"
    return 0
  fi

  local branch repo latest_commit title body
  branch="$(git branch --show-current)"
  repo="$(git config --get remote.origin.url | sed -E 's#.*github.com[:/]([^/]+/[^/.]+)(\.git)?#\1#')"
  latest_commit="$(git rev-parse --short HEAD)"
  title="$(git log -1 --pretty=%s)"

  printf -v body \
    'Round update (local auto-iterate daemon)\n\n- Commit: `%s`\n- Branch: `%s`\n- Change: %s\n- Validation: task-local verification passed before commit\n- Risk: low (automation/script/gate scope)\n' \
    "$latest_commit" "$branch" "$title"

  if gh pr comment "$PR_NUMBER" --repo "$repo" --body "$body" >/dev/null 2>&1; then
    log "pr-comment-ok: pr=#$PR_NUMBER commit=$latest_commit"
  else
    log "pr-comment-warn: failed to comment on pr=#$PR_NUMBER (non-fatal)"
  fi
}

push_with_retry_if_needed() {
  local ahead
  ahead="$(git rev-list --count @{u}..HEAD 2>/dev/null || echo 0)"
  if [[ "$ahead" == "0" ]]; then
    log "push-skip: branch not ahead"
    return 0
  fi

  log "push-needed: ahead=$ahead"
  local i rc
  rc=1
  for ((i=1; i<=PUSH_RETRIES; i++)); do
    if git push; then
      log "push-ok (attempt $i/$PUSH_RETRIES)"
      return 0
    fi
    rc=$?
    local backoff=$((i * 15))
    log "push-fail rc=$rc (attempt $i/$PUSH_RETRIES), sleep ${backoff}s"
    sleep "$backoff"
  done
  return "$rc"
}

log "daemon-start: round_script=$ROUND_SCRIPT max_consec_fail=$MAX_CONSEC_FAIL"

while true; do
  if [[ -f "$STOP_FILE" ]]; then
    log "stop-file detected: $STOP_FILE"
    break
  fi

  if [[ -f "$PAUSE_FILE" ]]; then
    log "pause-file detected, sleeping ${SLEEP_SECONDS}s"
    sleep "$SLEEP_SECONDS"
    continue
  fi

  round=$((round + 1))
  log "round-start: #$round"

  set +e
  "$ROUND_SCRIPT"
  rc=$?
  set -e

  case "$rc" in
    0)
      consec_fail=0
      if ! push_with_retry_if_needed; then
        consec_fail=$((consec_fail + 1))
        log "round-fail: push retry exhausted (consec_fail=$consec_fail/$MAX_CONSEC_FAIL)"
      else
        comment_latest_commit_to_pr
        log "round-ok: #$round"
      fi
      ;;
    20)
      consec_fail=0
      log "round-noop: no new commit"
      ;;
    *)
      consec_fail=$((consec_fail + 1))
      log "round-fail: rc=$rc (consec_fail=$consec_fail/$MAX_CONSEC_FAIL)"
      ;;
  esac

  if (( consec_fail >= MAX_CONSEC_FAIL )); then
    log "circuit-break: consecutive failures reached threshold"
    break
  fi

  sleep "$SLEEP_SECONDS"
done

log "daemon-exit"