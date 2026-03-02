#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TMP_DIR="run/query-audit-smoke"
mkdir -p "$TMP_DIR"
INGRESS="$TMP_DIR/requests.jsonl"
EXPORT="$TMP_DIR/audit-export.jsonl"
QUERY_OUT="$TMP_DIR/query-out.json"
QUERY_FP_OUT="$TMP_DIR/query-fp-out.json"

cat > "$INGRESS" <<'JSONL'
{"request_id":"r-qa-1","task_id":7002,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hello","idempotency_key":"ik1","status":"reveal_submitted","created_at_unix_ms":1700000000000,"assigned_worker":"worker-a","model_output":"done","result_hash":"0xabc","verifier_status":"ok","provenance_schema_version":"llm.v2","llm_provenance":{"provider":"openai","model":"gpt-4o-mini","adapter":"trnm-openai","agent_protocol":"mcp","compliance_profile":"enterprise-default"}}
{"request_id":"r-qa-2","task_id":7003,"channel":"telegram","user_id":"u2","session_id":"s2","text":"skip me","idempotency_key":"ik2","status":"accepted","created_at_unix_ms":1700000001000}
{"request_id":"r-qa-3","task_id":7002,"channel":"telegram","user_id":"u3","session_id":"s3","text":"world","idempotency_key":"ik3","status":"rejected","created_at_unix_ms":1700000002000,"assigned_worker":"worker-b","model_output":"bad"}
JSONL

cargo run -q -p trnm-worker-agent -- \
  export-audit \
  --ingress-file "$INGRESS" \
  --output-file "$EXPORT" >/dev/null

cargo run -q -p trnm-worker-agent -- \
  query-audit \
  --output-file "$EXPORT" \
  --task-id 7002 > "$QUERY_OUT"

FINGERPRINT="$(python3 - <<'PY' "$EXPORT"
import json
import sys

export_path = sys.argv[1]
with open(export_path, "r", encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)
        fp = row.get("provenance_fingerprint")
        if fp:
            print(fp)
            break
PY
)"

if [[ -z "$FINGERPRINT" ]]; then
  echo "missing provenance_fingerprint in export: $EXPORT"
  exit 7
fi

cargo run -q -p trnm-worker-agent -- \
  query-audit \
  --output-file "$EXPORT" \
  --provenance-fingerprint "$FINGERPRINT" > "$QUERY_FP_OUT"

python3 - <<'PY' "$QUERY_OUT" "$QUERY_FP_OUT" "$EXPORT" "$EXPORT.index.json"
import json
import os
import sys

query_path, fp_query_path, export_path, index_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

if not os.path.exists(export_path):
    print(f"missing export file: {export_path}")
    sys.exit(2)
if not os.path.exists(index_path):
    print(f"missing index file: {index_path}")
    sys.exit(3)

with open(query_path, "r", encoding="utf-8") as f:
    q = json.load(f)

hit_indexes = q.get("hit_indexes", [])
records = q.get("records", [])
if len(hit_indexes) != 2:
    print("expected 2 hit indexes, got", len(hit_indexes))
    print(q)
    sys.exit(4)
if len(records) != 2:
    print("expected 2 records, got", len(records))
    print(q)
    sys.exit(5)
if any(r.get("task_id") != 7002 for r in records):
    print("unexpected task_id in records")
    print(q)
    sys.exit(6)

required_fields = ("task_id", "proof_type", "settlement_status", "timestamp_unix_ms")
for idx, rec in enumerate(records):
    missing = [k for k in required_fields if k not in rec]
    if missing:
        print(f"record[{idx}] missing required fields: {missing}")
        print(q)
        sys.exit(12)
    if rec.get("settlement_status") != rec.get("status"):
        print(f"record[{idx}] settlement_status/status mismatch")
        print(q)
        sys.exit(13)

with open(fp_query_path, "r", encoding="utf-8") as f:
    qfp = json.load(f)

fp = qfp.get("provenance_fingerprint", "")
fp_hits = qfp.get("hit_indexes", [])
fp_records = qfp.get("records", [])
if not fp:
    print("missing provenance_fingerprint in fingerprint query result")
    print(qfp)
    sys.exit(8)
if len(fp_hits) != 1:
    print("expected 1 fingerprint hit index, got", len(fp_hits))
    print(qfp)
    sys.exit(9)
if len(fp_records) != 1:
    print("expected 1 fingerprint record, got", len(fp_records))
    print(qfp)
    sys.exit(10)
if fp_records[0].get("provenance_fingerprint") != fp:
    print("fingerprint query result does not echo matched fingerprint")
    print(qfp)
    sys.exit(11)

print("query-audit smoke ok")
PY

echo "[OK] query-audit smoke passed: $QUERY_OUT, $QUERY_FP_OUT"
