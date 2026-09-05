#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

source=trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs
cargo_manifest=trillionnium/crates/trnm-poco-node/Cargo.toml
workflow=.github/workflows/trnm-replay-to-core-coordinator-v1.yml
truth=config/consensus-mainline.json
plan=docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
modules=docs/development/module-registry-v1.toml
train=docs/development/release-train-v1.toml

for required in "$source" "$cargo_manifest" "$workflow" "$truth" "$plan" "$modules" "$train"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'G1-R2B contract truth gate failed: missing regular file: %s\n' "$required" >&2
    exit 2
  }
done

bash scripts/ci/check_canonical_development_plan.sh

python3 - "$source" "$cargo_manifest" "$workflow" "$truth" "$plan" "$modules" "$train" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

source_path, cargo_path, workflow_path, truth_path, plan_path, modules_path, train_path = map(pathlib.Path, sys.argv[1:])

def fail(message: str) -> None:
    raise SystemExit(f"G1-R2B contract truth gate failed: {message}")

def no_duplicate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON member in machine truth: {key}")
        value[key] = item
    return value

source = source_path.read_text(encoding="utf-8")
cargo = cargo_path.read_text(encoding="utf-8")
workflow = workflow_path.read_text(encoding="utf-8")
truth = json.loads(truth_path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_object)
plan = plan_path.read_text(encoding="utf-8")
modules = tomllib.loads(modules_path.read_text(encoding="utf-8"))
train = tomllib.loads(train_path.read_text(encoding="utf-8"))

for literal in (
    "REPLAY_TO_CORE_REAL_CORE_INGRESS_CANDIDATE_V1: bool = true",
    "REPLAY_TO_CORE_FAULT_CUT_MATRIX_CANDIDATE_V1: bool = true",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = false",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = false",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = false",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = false",
):
    if literal not in source:
        fail(f"coordinator source is missing negative truth marker: {literal}")

for forbidden in (
    "pub fn new_after_durable_core",
    "pub(crate) fn new_after_durable_core",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = true",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = true",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = true",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = true",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = true",
):
    if forbidden in source:
        fail(f"coordinator source contains forbidden authority claim: {forbidden}")

if re.search(r'name\s*=\s*"trnm-poco-replay-to-core-(?:adapter|r2b)', cargo):
    fail("a separate R2B production binary target is not authorized")

for literal in (
    "scripts/ci/check_replay_to_core_r2b_contract_v1.sh",
    "bash ./scripts/ci/check_replay_to_core_r2b_contract_v1.sh",
    "scripts/ci/check_canonical_development_plan.sh",
):
    if literal not in workflow:
        fail(f"workflow is missing canonical R2B hook: {literal}")

if truth.get("stage") != "G1-native-host-incomplete":
    fail(f"machine truth stage changed unexpectedly: {truth.get('stage')!r}")
for key in ("production_candidate", "production_consensus_activation"):
    if truth.get(key) is not False:
        fail(f"machine truth {key} must remain false")

plan_lower = plan.lower()
for marker in (
    "node commit ledger",
    "whole-node",
    "replay",
    "production_candidate = false",
    "no machine flag is promoted",
):
    if marker not in plan_lower:
        fail(f"canonical plan missing R2B boundary: {marker}")

module_rows = modules.get("module", modules.get("modules", []))
ids = {row.get("id") for row in module_rows if isinstance(row, dict)} if isinstance(module_rows, list) else set()
if not {"M02", "M03", "M08", "M15"} <= ids:
    fail("module registry is missing R2B producer/consumer ownership")

train_text = repr(train).lower()
for marker in ("cross-store", "node", "recovery"):
    if marker not in train_text:
        fail(f"release train is missing R2B blocker class: {marker}")

print("G1-R2B contract truth gate: PASS; source and machine truth replace retired package narratives")
PY

git diff --check
