#!/usr/bin/env bash
set -euo pipefail
prompt="${1:-}"
python3 - <<'PY' "$prompt"
import json,sys,time
p=sys.argv[1] if len(sys.argv)>1 else ""
print(json.dumps({"output_text": p, "provider_request_id": f"echo-{int(time.time()*1000)}"}, ensure_ascii=False))
PY
