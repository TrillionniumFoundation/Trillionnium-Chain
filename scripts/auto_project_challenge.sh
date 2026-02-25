#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

LOG_DIR="$ROOT/run/auto-iterate"
LOG_FILE="$LOG_DIR/project-challenge.log"
MAX_APPEND="${MAX_APPEND:-30}"
PUSH_RETRIES="${PUSH_RETRIES:-6}"

mkdir -p "$LOG_DIR"
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }

log "project-challenge start"

before="$(git rev-parse HEAD)"
MAX_APPEND="$MAX_APPEND" ./scripts/auto_task_pack.sh || true
after="$(git rev-parse HEAD)"

if [[ "$before" == "$after" ]]; then
  log "no new refill commit"
  exit 20
fi

log "new refill commit: $(git rev-parse --short HEAD)"

for ((i=1;i<=PUSH_RETRIES;i++)); do
  if git push; then
    log "push ok ($i/$PUSH_RETRIES)"
    exit 0
  fi
  rc=$?
  sleep $((i*10))
  log "push retry rc=$rc ($i/$PUSH_RETRIES)"
done

log "push failed after retries"
exit 1