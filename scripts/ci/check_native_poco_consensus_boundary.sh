#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
from pathlib import Path
import tomllib

workspace_path = Path("trillionnium/Cargo.toml")
node_manifest_path = Path("trillionnium/crates/trnm-node/Cargo.toml")

with workspace_path.open("rb") as handle:
    workspace = tomllib.load(handle)
members = set(workspace["workspace"]["members"])
required = {
    "crates/trnm-node",
    "crates/trnm-pouw",
    "crates/trnm-state",
    "crates/trnm-executor",
    "crates/trnm-mempool",
    "crates/trnm-finality-types",
    "crates/trnm-finality-verifier",
}
assert required <= members, "native PoCO workspace members are incomplete"

with node_manifest_path.open("rb") as handle:
    manifest = tomllib.load(handle)

package = manifest["package"]
metadata = package["metadata"]["trnm"]
features = manifest["features"]
bins = manifest["bin"]

assert package.get("publish") is False
assert package.get("default-run") == "trnm-chain-node"
assert features.get("default") == ["native-consensus"]
assert features.get("native-consensus") == []
assert features.get("legacy-harness") == ["native-consensus"]
assert metadata.get("lane") == "native-poco-consensus"
assert metadata.get("protocol_features_frozen") is False
assert metadata.get("production_candidate") is True
assert metadata.get("release_ready") is False

expected_bins = {
    "trnm-sim",
    "trnm-chain-node",
    "trnm-chain-validator",
    "trnm-chain-cli",
}
assert {entry["name"] for entry in bins} == expected_bins
for entry in bins:
    assert entry.get("required-features") == ["native-consensus"]

print("native_poco_consensus_boundary=ok")
PY
