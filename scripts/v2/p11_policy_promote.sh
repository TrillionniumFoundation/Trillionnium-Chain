#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POLICY_FILE="$ROOT/config/alert-policy/current.json"
FROM=""
TO=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  scripts/v2/p11_policy_promote.sh --from staging --to prod [--dry-run] [--policy <path>]

Options:
  --from <name>   source profile (must be staging)
  --to <name>     target profile (must be prod)
  --dry-run       do not overwrite current policy
  --policy <path> policy json path (default: config/alert-policy/current.json)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      FROM="${2:-}"; shift 2 ;;
    --to)
      TO="${2:-}"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    --policy)
      POLICY_FILE="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[P11][FAIL] unknown arg: $1" >&2
      usage
      exit 2 ;;
  esac
done

if [[ "$FROM" != "staging" || "$TO" != "prod" ]]; then
  echo "[P11][FAIL] only explicit promotion --from staging --to prod is allowed" >&2
  exit 2
fi

if [[ ! "$POLICY_FILE" = /* ]]; then
  POLICY_FILE="$ROOT/$POLICY_FILE"
fi

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "[P11][FAIL] policy file not found: $POLICY_FILE" >&2
  exit 2
fi

RUN_DIR="$ROOT/run/pr11"
SNAPSHOT_DIR="$RUN_DIR/policy-snapshots"
PROFILE_DIR="$ROOT/config/alert-policy/profiles"
mkdir -p "$RUN_DIR" "$SNAPSHOT_DIR" "$PROFILE_DIR"

TS_UTC="$(date -u +%Y%m%d-%H%M%S)"
BEFORE_SNAPSHOT="$SNAPSHOT_DIR/${TS_UTC}-before.json"
AFTER_SNAPSHOT="$SNAPSHOT_DIR/${TS_UTC}-after.json"
TMP_PROMOTED="$SNAPSHOT_DIR/${TS_UTC}-promoted.tmp.json"

# 1) Lint before promote (required)
python3 "$ROOT/scripts/v2/alert_policy_lint.py" --policy "$POLICY_FILE"

# 2) Build promoted policy candidate
python3 - "$POLICY_FILE" "$FROM" "$TO" "$TMP_PROMOTED" <<'PY'
from __future__ import annotations
import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

policy_path = Path(sys.argv[1])
from_profile = sys.argv[2]
to_profile = sys.argv[3]
out_path = Path(sys.argv[4])

doc = json.loads(policy_path.read_text(encoding="utf-8"))
profiles = doc.get("profiles") or {}
if from_profile not in profiles:
    raise SystemExit(f"source profile not found: {from_profile}")

src = copy.deepcopy(profiles[from_profile])
profiles[to_profile] = src

old_version = str(doc.get("version", "0.0.0.0"))
m = re.match(r"^(.*?)(\d+)$", old_version)
if m:
    new_version = f"{m.group(1)}{int(m.group(2)) + 1}"
else:
    new_version = old_version + ".1"

doc["version"] = new_version
doc["effective_from_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

OLD_VERSION="$(python3 - "$POLICY_FILE" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
print(json.loads(p.read_text(encoding='utf-8')).get('version', 'unknown'))
PY
)"
NEW_VERSION="$(python3 - "$TMP_PROMOTED" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
print(json.loads(p.read_text(encoding='utf-8')).get('version', 'unknown'))
PY
)"

# 3) Lint promoted candidate
python3 "$ROOT/scripts/v2/alert_policy_lint.py" --policy "$TMP_PROMOTED"

# 4) Snapshot + apply
cp "$POLICY_FILE" "$BEFORE_SNAPSHOT"
cp "$TMP_PROMOTED" "$AFTER_SNAPSHOT"
python3 - "$TMP_PROMOTED" "$PROFILE_DIR/staging.json" "$PROFILE_DIR/prod.json" <<'PY'
from __future__ import annotations
import json
import sys
from pathlib import Path
src = Path(sys.argv[1])
staging_out = Path(sys.argv[2])
prod_out = Path(sys.argv[3])
doc = json.loads(src.read_text(encoding='utf-8'))
profiles = doc.get("profiles") or {}
base = {
  "schema_version": doc.get("schema_version", "1.0"),
  "policy_id": doc.get("policy_id", "trnm-alert-policy"),
  "version": doc.get("version", "unknown"),
}
staging_payload = {**base, "profile": "staging", "profile_config": profiles.get("staging", {})}
prod_payload = {**base, "profile": "prod", "profile_config": profiles.get("prod", {})}
staging_out.write_text(json.dumps(staging_payload, ensure_ascii=False, indent=2) + "\n", encoding='utf-8')
prod_out.write_text(json.dumps(prod_payload, ensure_ascii=False, indent=2) + "\n", encoding='utf-8')
PY

if [[ "$DRY_RUN" -eq 0 ]]; then
  cp "$TMP_PROMOTED" "$POLICY_FILE"
fi

# 5) Immutable-style append-only audit log
python3 - "$RUN_DIR/policy-promotions.log" "$TS_UTC" "$FROM" "$TO" "$DRY_RUN" "$OLD_VERSION" "$NEW_VERSION" "$POLICY_FILE" "$BEFORE_SNAPSHOT" "$AFTER_SNAPSHOT" <<'PY'
from __future__ import annotations
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

log_path = Path(sys.argv[1])
ts = sys.argv[2]
entry = {
  "ts_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "run_id": ts,
  "from": sys.argv[3],
  "to": sys.argv[4],
  "dry_run": sys.argv[5] == "1",
  "old_version": sys.argv[6],
  "new_version": sys.argv[7],
  "policy_file": sys.argv[8],
  "before_snapshot": sys.argv[9],
  "after_snapshot": sys.argv[10],
}
line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
entry["sha256"] = hashlib.sha256(line.encode("utf-8")).hexdigest()
log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("a", encoding="utf-8") as f:
    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
print(log_path)
PY

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[P11][DRY-RUN] validated + generated promoted candidate"
else
  echo "[P11][OK] promoted $FROM -> $TO, version $OLD_VERSION -> $NEW_VERSION"
fi

echo "[P11] policy=$POLICY_FILE"
echo "[P11] snapshots: before=$BEFORE_SNAPSHOT after=$AFTER_SNAPSHOT"
echo "[P11] audit log: $RUN_DIR/policy-promotions.log"
