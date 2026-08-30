#!/usr/bin/env bash
set -euo pipefail

readonly WORLD_HEAD="2b3a71c34fcbe9b8dac51826d70e65c4553cbba7"
readonly STAGE_DIR="transport/world-direct-source-${WORLD_HEAD}"
readonly WORLD_DIR="world"

cd "${GITHUB_WORKSPACE}"
test -d "${STAGE_DIR}"

cp "${WORLD_DIR}/trillionnium/crates/trnm-game-server/tests/settlement_game_server_boundary.rs" \
  "${STAGE_DIR}/settlement_game_server_boundary.rs"
cp "${WORLD_DIR}/scripts/check-trnm-settlement-transaction-boundary.sh" \
  "${STAGE_DIR}/check-trnm-settlement-transaction-boundary.sh"

STAGE_DIR="${STAGE_DIR}" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

stage = Path(os.environ["STAGE_DIR"])
manifest_path = stage / "manifest.json"
record = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in (
    "lib.rs",
    "cex.rs",
    "Cargo.toml",
    "deleted-files.txt",
    "settlement_game_server_boundary.rs",
    "check-trnm-settlement-transaction-boundary.sh",
):
    data = stage.joinpath(name).read_bytes()
    record["files"][name] = {
        "bytes": len(data),
        "git_blob_sha1": hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY

find "${STAGE_DIR}" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum > "${STAGE_DIR}/SHA256SUMS"
cat "${STAGE_DIR}/manifest.json"

git add "${STAGE_DIR}"
if git diff --cached --quiet; then
  echo "extended transport payload already current"
  exit 0
fi
git commit -m "chore(transport): bind direct-source boundary files [skip ci]"
git push origin HEAD:refs/heads/tmp/world-source-materializer-20260830
