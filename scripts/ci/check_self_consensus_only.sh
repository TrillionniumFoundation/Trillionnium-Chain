#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib

root = pathlib.Path.cwd()
workspace_path = root / "trillionnium" / "Cargo.toml"
node_manifest_path = root / "trillionnium" / "crates" / "trnm-node" / "Cargo.toml"
boundary_path = root / "PROJECT_BOUNDARY.json"

for required in (workspace_path, node_manifest_path, boundary_path):
    if not required.is_file():
        raise SystemExit(f"missing required native-consensus file: {required}")

with workspace_path.open("rb") as handle:
    workspace = tomllib.load(handle)
with node_manifest_path.open("rb") as handle:
    node = tomllib.load(handle)

members = set(workspace.get("workspace", {}).get("members", []))
required_members = {
    "crates/trnm-node",
    "crates/trnm-runtime",
    "crates/trnm-state",
}
missing = sorted(required_members - members)
if missing:
    raise SystemExit(f"native workspace members missing: {missing}")

prohibited_packages = {
    "crates/trnm-" + "consensus-app",
}
unexpected = sorted(members & prohibited_packages)
if unexpected:
    raise SystemExit(f"external consensus package present: {unexpected}")

features = node.get("features", {})
if "self-consensus" not in features:
    raise SystemExit("trnm-node self-consensus feature missing")
if "self-consensus" not in features.get("default", []):
    raise SystemExit("trnm-node must default to self-consensus")

metadata = node.get("package", {}).get("metadata", {}).get("trnm", {})
if metadata.get("lane") != "self-developed-consensus":
    raise SystemExit("trnm-node lane must be self-developed-consensus")
if metadata.get("production_candidate") is not True:
    raise SystemExit("trnm-node must be the production candidate")
if metadata.get("consensus_authority") != "native-only":
    raise SystemExit("consensus authority must be native-only")

expected_bins = {
    "trnm-sim",
    "trnm-chain-node",
    "trnm-chain-validator",
    "trnm-chain-cli",
}
bins = node.get("bin", [])
if {entry.get("name") for entry in bins} != expected_bins:
    raise SystemExit("native consensus binary set changed unexpectedly")
for entry in bins:
    if entry.get("required-features") != ["self-consensus"]:
        raise SystemExit(f"{entry.get('name')} must require self-consensus")

fragments = [
    "co" + "met",
    "co" + "met" + "bft",
    "tender" + "mint",
    "ab" + "ci",
    "trnm-" + "consensus-app",
    "trnm_" + "consensus_app",
    "trnm-" + "co" + "met" + "bft-app",
    "trnm_" + "co" + "met" + "bft",
]
fragments = [item.casefold() for item in fragments]

listed = subprocess.run(
    ["git", "ls-files", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout.split(b"\0")
violations: list[str] = []
for raw in listed:
    if not raw:
        continue
    rel = raw.decode("utf-8", errors="surrogateescape")
    folded_path = rel.casefold()
    if any(term in folded_path for term in fragments):
        violations.append(f"path:{rel}")
        continue
    path = root / rel
    try:
        data = path.read_bytes()
    except OSError as exc:
        violations.append(f"read:{rel}:{exc}")
        continue
    if b"\0" in data:
        continue
    text = data.decode("utf-8", errors="ignore").casefold()
    for term in fragments:
        if term in text:
            violations.append(f"content:{rel}:{term}")
            break

if violations:
    print("native-consensus-only policy violations:", file=sys.stderr)
    for item in violations:
        print(f"  {item}", file=sys.stderr)
    raise SystemExit(2)

print("native_consensus_manifest=ok")
print("external_consensus_residue=none")
PY
