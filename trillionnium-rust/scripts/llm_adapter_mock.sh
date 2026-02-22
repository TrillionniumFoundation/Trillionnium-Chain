#!/usr/bin/env bash
set -euo pipefail

prompt="${1:-}"

python3 - <<'PY' "$prompt"
import json,sys,time
p = sys.argv[1] if len(sys.argv) > 1 else ""
out = {
  "output_text": f"[mock-llm] {p}",
  "provider_request_id": f"mock-{int(time.time()*1000)}"
}
print(json.dumps(out, ensure_ascii=False))
PY
