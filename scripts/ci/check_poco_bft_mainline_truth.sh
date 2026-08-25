#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MODE="${1:---pre-cutover}"

case "$MODE" in
  --pre-cutover|--post-cutover) ;;
  *)
    echo "usage: $0 [--pre-cutover|--post-cutover]" >&2
    exit 2
    ;;
esac

fail() {
  printf 'PoCO-BFT mainline truth gate failed: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: ${1#$ROOT/}"
}

CONFIG="$ROOT/config/consensus-mainline.json"
CARGO_MANIFEST="$ROOT/trillionnium/Cargo.toml"
NODE_MANIFEST="$ROOT/trillionnium/crates/trnm-poco-node/Cargo.toml"
TX_BUILDER_MANIFEST="$ROOT/trillionnium/crates/trnm-application-tx-builder-v0/Cargo.toml"
MAINLINE_DOC="$ROOT/docs/architecture/TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md"
EXECUTION_BOARD="$ROOT/docs/development/TRNM_POCO_BFT_EXECUTION_BOARD_2026-08-25.md"
DUAL_TRACK_DOC="$ROOT/docs/architecture/TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md"

for required in "$CONFIG" "$CARGO_MANIFEST" "$NODE_MANIFEST" "$TX_BUILDER_MANIFEST" "$MAINLINE_DOC" \
  "$EXECUTION_BOARD" "$DUAL_TRACK_DOC"; do
  require_file "$required"
done

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT

if ! CARGO_NET_OFFLINE=true cargo metadata \
  --manifest-path "$CARGO_MANIFEST" --locked --offline --no-deps \
  --format-version 1 >"$metadata_file"; then
  fail "cargo metadata --locked --offline failed"
fi

python3 - "$CONFIG" "$CARGO_MANIFEST" "$NODE_MANIFEST" "$TX_BUILDER_MANIFEST" "$metadata_file" \
  "$MAINLINE_DOC" "$EXECUTION_BOARD" "$DUAL_TRACK_DOC" "$MODE" <<'PY'
import json
import pathlib
import sys
import tomllib

config_path, cargo_path, node_path, tx_builder_path, metadata_path, decision_path, board_path, dual_path, mode = map(pathlib.Path, sys.argv[1:])

def fail(message: str) -> None:
    raise SystemExit(message)

config = json.loads(config_path.read_text(encoding="utf-8"))
pre_cutover = mode.name == "--pre-cutover"
if config.get("schema") != "trnm-consensus-mainline-truth-v1":
    fail("unexpected consensus-mainline schema")
if config.get("consensus_mainline") != "native-poco-bft":
    fail("native PoCO-BFT is not the declared sole mainline")
if pre_cutover:
    if config.get("production_candidate") is not False or config.get("production_consensus_activation") is not False:
        fail("production truth must remain false before C0")
else:
    if config.get("production_candidate") is not True or config.get("production_consensus_activation") is not True:
        fail("post-cutover truth requires reviewed production candidate and activation")

comet = config.get("cometbft", {})
expected_comet = ({
    "role": "migration-residue-only",
    "production_dependency": False,
    "active_workspace_member": False,
    "new_features_allowed": False,
    "cleanup_eligible": False,
} if pre_cutover else {
    "role": "removed",
    "production_dependency": False,
    "active_workspace_member": False,
    "new_features_allowed": False,
    "historical_replay_allowed": False,
    "cleanup_eligible": True,
})
for key, expected in expected_comet.items():
    if comet.get(key) != expected:
        fail(f"cometbft.{key}={comet.get(key)!r}, expected {expected!r}")

cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
workspace_meta = cargo.get("workspace", {}).get("metadata", {}).get("trnm", {})
workspace_expectations = ({
    "consensus_mainline": "native-poco-bft",
    "native_poco_mainline_decision": "adopted",
    "zero_comet_production_dependency_target": True,
    "zero_comet_production_dependency_achieved": True,
    "legacy_comet_migration_residue_present": True,
    "cometbft_role": "migration-residue-only",
    "cometbft_cleanup_eligible": False,
} if pre_cutover else {
    "consensus_mainline": "native-poco-bft",
    "native_poco_mainline_decision": "adopted",
    "zero_comet_production_dependency_target": True,
    "zero_comet_production_dependency_achieved": True,
    "legacy_comet_migration_residue_present": False,
    "cometbft_role": "removed",
    "cometbft_cleanup_eligible": True,
})
for key, expected in workspace_expectations.items():
    if workspace_meta.get(key) != expected:
        fail(f"workspace metadata {key}={workspace_meta.get(key)!r}, expected {expected!r}")

node = tomllib.loads(node_path.read_text(encoding="utf-8"))
node_meta = node.get("package", {}).get("metadata", {}).get("trnm", {})
node_expectations = ({
    "consensus_mainline": "native-poco-bft",
    "zero_comet_production_dependency_achieved": True,
    "legacy_comet_migration_residue_present": True,
    "cometbft_role": "migration-residue-only",
    "cometbft_cleanup_eligible": False,
    "production_candidate": False,
    "production_consensus_activation": False,
} if pre_cutover else {
    "consensus_mainline": "native-poco-bft",
    "zero_comet_production_dependency_achieved": True,
    "legacy_comet_migration_residue_present": False,
    "cometbft_role": "removed",
    "cometbft_cleanup_eligible": True,
    "production_candidate": True,
    "production_consensus_activation": True,
})
for key, expected in node_expectations.items():
    if node_meta.get(key) != expected:
        fail(f"node metadata {key}={node_meta.get(key)!r}, expected {expected!r}")

tx_builder = tomllib.loads(tx_builder_path.read_text(encoding="utf-8"))
tx_builder_meta = tx_builder.get("package", {}).get("metadata", {}).get("trnm", {})
tx_builder_expectations = ({
    "development_only": True,
    "production_candidate": False,
    "signing_runtime": False,
    "signing_or_broadcast": False,
    "broadcast": False,
    "pending_nonce_authority": False,
    "external_signer_only": True,
    "mempool_view_adapter": True,
} if pre_cutover else {
    "development_only": False,
    "production_candidate": True,
    "signing_runtime": True,
    "signing_or_broadcast": True,
    "broadcast": True,
    "pending_nonce_authority": True,
})
for key, expected in tx_builder_expectations.items():
    if tx_builder_meta.get(key) != expected:
        fail(f"tx-builder metadata {key}={tx_builder_meta.get(key)!r}, expected {expected!r}")

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
packages = {package["name"] for package in metadata.get("packages", [])}
for forbidden in ("trnm-consensus-app", "trnm-node"):
    if forbidden in packages:
        fail(f"legacy package is in the active workspace graph: {forbidden}")
if "trnm-application-tx-builder-v0" not in packages:
    fail("canonical tx-builder candidate is missing from the active workspace graph")

decision = decision_path.read_text(encoding="utf-8")
board = board_path.read_text(encoding="utf-8")
dual = dual_path.read_text(encoding="utf-8")
for marker, text, label in (
    ("sole future production consensus route", decision, "mainline decision"),
    ("migration residue and historical replay input only", decision, "mainline decision"),
    ("C1 — Comet tombstone and removal", decision, "mainline decision"),
    ("MIG-001", board, "execution board"),
    ("MIG-014/016", board, "execution board"),
    ("SUPERSEDED on 2026-08-25", dual, "dual-track decision"),
):
    if " ".join(marker.split()) not in " ".join(text.split()):
        fail(f"missing {label} marker: {marker}")

if not pre_cutover:
    residue = [
        pathlib.Path("trillionnium/crates/trnm-consensus-app"),
        pathlib.Path("trillionnium/crates/trnm-node"),
        pathlib.Path(".github/workflows/trnm-cometbft-spike.yml"),
    ]
    present = [str(path) for path in residue if (config_path.parent.parent / path).exists()]
    if present:
        fail("post-cutover Comet residue remains: " + ", ".join(present))
PY

if rg -n -i 'cometbft|tendermint|abci' "$ROOT/trillionnium/Cargo.lock" >/dev/null 2>&1; then
  fail "active PoCO Cargo.lock contains Comet/Tendermint/ABCI dependency text"
fi

if rg -n 'cometbft_role = "development-differential-oracle"' \
  "$CARGO_MANIFEST" "$NODE_MANIFEST" >/dev/null 2>&1; then
  fail "old differential-oracle metadata remains in active manifests"
fi

if [[ "$MODE" == "--pre-cutover" ]]; then
  printf 'poco_bft_mainline_truth=passed mode=%s mainline=native-poco-bft production_dependency=false cleanup_eligible=false activation=false\n' "$MODE"
else
  printf 'poco_bft_mainline_truth=passed mode=%s mainline=native-poco-bft production_dependency=false cleanup_eligible=true activation=true\n' "$MODE"
fi
