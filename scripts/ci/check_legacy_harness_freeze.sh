#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# M17 technical contract: freeze all four legacy entrypoint bytes and their
# explicit Cargo feature/path mappings; never regenerate checksums in this gate.
# The original 2fb758bd2 freeze matched d9905b8bc's parent. The reviewed adoption
# d9905b8bc6ef19988c964839c5c93c4e52f6558b changed only four CLI descriptions and
# three startup banners to identify development-only/non-production behavior.
# The updated checksum baseline retains those disclosures; it authorizes no
# runtime/protocol change. Future baseline changes require source-diff review.
# This bounded freeze is not a whole-crate audit or production acceptance.

python3 - <<'PY'
from pathlib import Path
import re
import tomllib


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SystemExit(f"legacy harness freeze failed: {reason}")


manifest_path = Path("trillionnium/crates/trnm-node/Cargo.toml")
with manifest_path.open("rb") as handle:
    manifest = tomllib.load(handle)

package = manifest["package"]
require(package.get("publish") is False, "trnm-node must remain publish=false")
require(package.get("autobins") is False, "trnm-node must not discover unfrozen binaries")
require("default-run" not in package, "trnm-node must not expose a default legacy binary")

metadata = package.get("metadata", {}).get("trnm", {})
for key, value in {
    "lane": "legacy-harness",
    "development_only": True,
    "protocol_features_frozen": True,
    "production_candidate": False,
}.items():
    require(type(metadata.get(key)) is type(value) and metadata[key] == value,
            f"trnm-node metadata {key} changed")

features = manifest.get("features", {})
require(features.get("default") == [], "trnm-node default features must remain empty")
require(features.get("legacy-harness") == [], "legacy-harness feature must remain explicit")

expected_bins = {
    "trnm-sim": "src/main.rs",
    "trnm-chain-node": "src/bin/trnm-chain-node.rs",
    "trnm-chain-validator": "src/bin/trnm-chain-validator.rs",
    "trnm-chain-cli": "src/bin/trnm-chain-cli.rs",
}
bins = manifest.get("bin", [])
require(len(bins) == len(expected_bins) and {entry["name"] for entry in bins} == set(expected_bins),
        "legacy binary set changed")
for entry in bins:
    require(entry.get("path") == expected_bins[entry["name"]],
            f"{entry['name']} must use its frozen entrypoint")
    require(entry.get("required-features") == ["legacy-harness"],
            f"{entry['name']} must require legacy-harness")

freeze_path = Path("config/legacy-harness-freeze.sha256")
rows = freeze_path.read_text(encoding="ascii").splitlines()
expected_paths = {str(manifest_path.parent / path) for path in expected_bins.values()}
require(len(rows) == len(expected_paths), "checksum inventory must contain exactly four entries")
frozen_paths = set()
for row in rows:
    match = re.fullmatch(r"[0-9a-f]{64}  (\S+)", row)
    require(match is not None, "malformed checksum entry")
    frozen_paths.add(match[1])
require(frozen_paths == expected_paths, "checksum inventory must cover every frozen entrypoint once")

print("legacy_harness_manifest_freeze=ok")
PY

sha256sum --check --strict config/legacy-harness-freeze.sha256
python3 scripts/ci/test_legacy_node_cargo_boundary.py

printf '%s\n' 'legacy_harness_entrypoint_manifest_freeze=ok'
