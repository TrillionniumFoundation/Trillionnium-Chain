#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

sha256sum --check --strict config/legacy-harness-freeze.sha256

python3 - <<'PY'
from pathlib import Path
import tomllib

manifest_path = Path("trillionnium/crates/trnm-node/Cargo.toml")
with manifest_path.open("rb") as handle:
    manifest = tomllib.load(handle)

package = manifest["package"]
assert package.get("publish") is False, "trnm-node must remain publish=false"
assert "default-run" not in package, "trnm-node must not expose a default legacy binary"

features = manifest.get("features", {})
assert features.get("default") == [], "trnm-node default features must remain empty"
assert features.get("legacy-harness") == [], "legacy-harness feature must remain explicit"

expected_bins = {
    "trnm-sim",
    "trnm-chain-node",
    "trnm-chain-validator",
    "trnm-chain-cli",
}
bins = manifest.get("bin", [])
assert {entry["name"] for entry in bins} == expected_bins, "legacy binary set changed"
for entry in bins:
    assert entry.get("required-features") == [
        "legacy-harness"
    ], f"{entry['name']} must require legacy-harness"

print("legacy_harness_manifest_freeze=ok")
PY

printf '%s\n' 'legacy_harness_entrypoint_manifest_freeze=ok'
