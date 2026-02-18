#!/usr/bin/env bash
set -euo pipefail

command -v jq >/dev/null 2>&1 || {
	echo "[ERR] jq not found" >&2
	exit 1
}

ok='{"status":"ok","job_id":"1","task_id":"2","tx_complete":"ABC","worker":"w","result_hash":"r","duration_s":3}'
failed='{"status":"failed","reason":"x","job_id":"1","last_tx":"ABC","task_id":"2"}'

echo "$ok" | jq -e '
  (.status == "ok") and
  (.job_id|type=="string") and
  (.task_id|type=="string") and
  (.tx_complete|type=="string") and
  (.worker|type=="string") and
  (.result_hash|type=="string") and
  (.duration_s|type=="number")
' >/dev/null

echo "$failed" | jq -e '
  (.status == "failed") and
  (.reason|type=="string") and
  (.job_id|type=="string") and
  (.last_tx|type=="string") and
  (.task_id|type=="string")
' >/dev/null

echo "OK: compute lifecycle summary contract test passed"
