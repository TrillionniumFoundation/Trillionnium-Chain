#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
python3 "$root/scripts/ci/check_native_consensus_only.py"
python3 - "$root" <<'PY'
import json
import pathlib
import sys
import tomllib
root = pathlib.Path(sys.argv[1])
truth = json.loads((root / "config/consensus-mainline.json").read_text())
boundary = json.loads((root / "PROJECT_BOUNDARY.json").read_text())
with (root / "trillionnium/Cargo.toml").open("rb") as handle:
    cargo = tomllib.load(handle)
assert truth["consensus_mainline"] == "native-poco-bft"
assert truth["protocol_target"] == "poco-bft-v0"
assert truth["production_candidate"] is False
assert truth["production_consensus_activation"] is False
assert boundary["consensus"]["dependency_policy"] == "native-only"
assert boundary["consensus"]["external_consensus_engines_allowed"] is False
metadata = cargo["workspace"]["metadata"]["trnm"]
assert metadata["consensus_mainline"] == "native-poco-bft"
assert metadata["consensus_dependency_policy"] == "native-only"
assert metadata["external_consensus_dependency_count"] == 0
assert set(cargo["workspace"].get("exclude", [])) == {"fuzz"}
print('{"schema":"trnm-native-mainline-gate-v1","result":"PASS"}')
PY
