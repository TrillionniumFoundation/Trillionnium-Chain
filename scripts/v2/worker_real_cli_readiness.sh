#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TX_CLI="${TRNM_TX_CLI:-trnm-cli}"
REQUIRE_REAL_TX_CLI="${REQUIRE_REAL_TX_CLI:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/data/worker-cli-readiness}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/worker-real-cli-readiness-$TS.md"

status="NOT_READY"
reason=""
cmd_exists="no"
supports_tx="no"
commit_ok="no"
query_ok="no"
query_hash_match="no"
query_status=""
commit_tx_hash=""

normalize_receipt_text() {
  python3 -c '
import sys
text = sys.stdin.read()
for src, dst in {
    "\ufeff": "",
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
    "\u2060": "",
    "\u2061": "",
    "\u2062": "",
    "\u2063": "",
    "\u2064": "",
    "\u2066": "",
    "\u2067": "",
    "\u2068": "",
    "\u2069": "",
    "\u200e": "",
    "\u200f": "",
    "\u202a": "",
    "\u202b": "",
    "\u202c": "",
    "\u202d": "",
    "\u202e": "",
    "：": ":",
    "＝": "=",
    "`": "\"",
    "“": "\"",
    "”": "\"",
    "‘": "\u0027",
    "’": "\u0027",
    "«": "\"",
    "»": "\"",
    "‹": "\"",
    "›": "\"",
    "〈": "\"",
    "〉": "\"",
    "《": "\"",
    "》": "\"",
    "「": "\"",
    "」": "\"",
    "『": "\"",
    "』": "\"",
}.items():
    text = text.replace(src, dst)
sys.stdout.write(text)
'
}

extract_tx_hash() {
  local raw="$1"
  local normalized
  normalized="$(printf "%s" "$raw" | normalize_receipt_text)"
  printf "%s" "$normalized" | python3 -c '
import json
import re
import sys

text = sys.stdin.read()
keys = {"tx_hash", "txHash", "transaction_hash", "transactionHash"}

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def exact_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys:
                yield item
            if isinstance(item, (dict, list)):
                yield from exact_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from exact_values(item)

try:
    parsed = json.loads(text, object_pairs_hook=strict_object)
except Exception:
    parsed = None

if parsed is not None:
    candidates = list(exact_values(parsed))
elif text.lstrip().startswith(("{", "[")):
    candidates = []
else:
    pattern = re.compile(
        r"""(?i)(?<![A-Za-z0-9_-])[\"]?(?:tx|transaction)(?:[\s_-]*hash)[\"]?\s*[:=]\s*[\"]?((?:0[xX])?[0-9A-Fa-f]{16,128})[\"]?"""
    )
    candidates = [match.group(1) for match in pattern.finditer(text)]

normalized = []
for candidate in candidates:
    if not isinstance(candidate, str):
        normalized = []
        break
    cleaned = candidate.strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[0-9A-Fa-f]{16,128}", cleaned):
        normalized = []
        break
    normalized.append(cleaned.lower())

if normalized and len(set(normalized)) == 1:
    sys.stdout.write(normalized[0])
'
}

extract_query_status() {
  local raw="$1"
  local normalized
  normalized="$(printf "%s" "$raw" | normalize_receipt_text)"
  printf "%s" "$normalized" | python3 -c '
import json
import re
import sys

text = sys.stdin.read()
keys = {
    "status", "state", "tx_status", "txStatus", "tx_state", "txState",
    "transaction_status", "transactionStatus", "transaction_state",
    "transactionState",
}
hash_keys = {"tx_hash", "txHash", "transaction_hash", "transactionHash"}
committed = {
    "committed", "confirmed", "success", "succeeded", "ok", "included",
    "finalized", "finalised", "complete", "completed", "done",
}
pending = {
    "pending", "submitted", "accepted", "queued", "broadcast",
    "broadcasted", "broadcasting", "processing", "executing", "in_progress",
    "inflight", "in_flight",
}
failed = {
    "fail", "failed", "error", "rejected", "reverted", "aborted", "dropped",
    "timeout", "timed_out", "expired",
}

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def normalize(value):
    if isinstance(value, bool):
        return "committed" if value else "fail"
    if isinstance(value, int) and not isinstance(value, bool):
        return "committed" if value == 0 else "fail"
    if not isinstance(value, str):
        return "unknown"
    cleaned = value.strip().lower()
    canonical = re.sub(r"[^a-z0-9]+", "_", cleaned).strip("_")
    if canonical in committed:
        return "committed"
    if canonical in pending:
        return "pending"
    if canonical in failed:
        return "fail"
    if canonical == "true":
        return "committed"
    if canonical == "false":
        return "fail"
    return "unknown"

def scoped_values(value):
    if isinstance(value, dict):
        # Bare RPC envelope status is not transaction lifecycle evidence.
        # Bind every accepted status/state field to an exact hash in the same
        # canonical transaction object.
        if any(key in hash_keys for key in value):
            for key, item in value.items():
                if key in keys:
                    yield item
        for item in value.values():
            if isinstance(item, (dict, list)):
                yield from scoped_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from scoped_values(item)

try:
    parsed = json.loads(text, object_pairs_hook=strict_object)
except Exception:
    parsed = None

if parsed is not None:
    values = list(scoped_values(parsed))
elif text.lstrip().startswith(("{", "[")):
    values = []
else:
    pattern = re.compile(
        r"""(?i)(?<![A-Za-z0-9_-])[\"]?(?:(?:tx|transaction)[\s_-]?)?(?:status|state)[\"]?\s*[:=]\s*[\"]?([^\s\",}\]]+)"""
    )
    values = [match.group(1) for match in pattern.finditer(text)]

statuses = [normalize(value) for value in values]
if statuses and all(status == "committed" for status in statuses):
    sys.stdout.write("committed")
elif "fail" in statuses:
    sys.stdout.write("fail")
elif "pending" in statuses:
    sys.stdout.write("pending")
else:
    # Missing, unknown, or conflicting lifecycle evidence is never READY.
    sys.stdout.write("unknown")
'
}

if command -v "$TX_CLI" >/dev/null 2>&1; then
  cmd_exists="yes"
  if "$TX_CLI" tx --help >/dev/null 2>&1; then
    supports_tx="yes"

    # Minimal tx lifecycle proof: submit commit-result, then query by tx_hash.
    task_id="${TRNM_REALCLI_PROBE_TASK_ID:-9999991}"
    worker="${TRNM_REALCLI_PROBE_WORKER:-worker_readiness}"
    commit_hash="${TRNM_REALCLI_PROBE_COMMIT_HASH:-$(printf 'a%.0s' {1..64})}"
    nonce="${TRNM_REALCLI_PROBE_NONCE:-1}"

    set +e
    commit_out=$("$TX_CLI" tx commit-result "$task_id" "$worker" "$commit_hash" "$nonce" 2>&1)
    commit_rc=$?
    set -e

    if [[ $commit_rc -eq 0 ]]; then
      commit_tx_hash="$(extract_tx_hash "$commit_out")"
      if [[ "$commit_tx_hash" =~ ^[0-9A-Fa-f]{16,128}$ ]]; then
        commit_ok="yes"

        query_retries="${TRNM_REALCLI_QUERY_RETRIES:-3}"
        query_retry_sleep="${TRNM_REALCLI_QUERY_RETRY_SLEEP_SEC:-1}"
        commit_tx_hash_lc="$(printf "%s" "$commit_tx_hash" | tr '[:upper:]' '[:lower:]')"

        for ((attempt=1; attempt<=query_retries; attempt++)); do
          query_hash_match="no"
          query_status=""
          query_seen_hash=""
          query_seen_hash_lc=""
          set +e
          query_out=$("$TX_CLI" tx query "$commit_tx_hash" 2>&1)
          query_rc=$?
          set -e

          if [[ $query_rc -eq 0 ]]; then
            query_ok="yes"
            query_seen_hash="$(extract_tx_hash "$query_out")"
            query_status="$(extract_query_status "$query_out")"
            query_seen_hash_lc="$(printf "%s" "$query_seen_hash" | tr '[:upper:]' '[:lower:]')"
            query_status_lc="$(printf "%s" "$query_status" | tr '[:upper:]' '[:lower:]')"

            if [[ -n "$query_seen_hash" && "$query_seen_hash_lc" == "$commit_tx_hash_lc" ]]; then
              query_hash_match="yes"
            fi
            # READY requires a matching hash and an explicit positive terminal
            # lifecycle state from this same query response.
            if [[ "$query_hash_match" == "yes" && "$query_status_lc" == "committed" ]]; then
              status="READY"
              reason="tx lifecycle verified (commit + query visible)"
              break
            fi
            reason="tx query output missing matching hash or positive terminal status"
          else
            reason="tx query failed for submitted tx_hash=$commit_tx_hash"
          fi

          if (( attempt < query_retries )); then
            sleep "$query_retry_sleep"
          fi
        done
      else
        reason="commit-result output missing valid tx_hash"
      fi
    else
      reason="commit-result failed during readiness probe"
    fi
  else
    reason="tx subcommand missing: '$TX_CLI tx --help' failed"
  fi
else
  reason="tx cli not found in PATH: $TX_CLI"
fi

cat > "$REPORT" <<EOF
# Worker Real CLI Readiness

- ts: \
  $(date '+%F %T %Z')
- tx_cli: \
  \
  \
  $TX_CLI
- status: **$status**
- reason: $reason

## Checks
- command exists: $cmd_exists
- supports \`tx\` subcommand: $supports_tx
- probe commit-result success: $commit_ok
- probe commit tx_hash: ${commit_tx_hash:-N/A}
- probe query success: $query_ok
- probe query hash match: $query_hash_match
- probe query status: ${query_status:-N/A}
- require real tx cli: $REQUIRE_REAL_TX_CLI

## Next Action
- If status is NOT_READY: provide a tx-capable CLI implementation that supports and verifies lifecycle:
  - \`tx commit-result <task_id> <worker> <commit_hash> <nonce>\`
  - \`tx query <tx_hash>\`
  - Query result MUST include matching tx hash + non-empty status.
- Then run:
  - \`TRNM_TX_CLI=<your-cli> ./scripts/v2/run_worker_receipt_gates_real_cli.sh\`
EOF

echo "$REPORT"

if [[ "$REQUIRE_REAL_TX_CLI" == "1" && "$status" != "READY" ]]; then
  echo "[FAIL] real tx cli required but not ready: $reason" >&2
  exit 18
fi
