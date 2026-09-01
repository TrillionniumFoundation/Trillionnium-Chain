#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PLAN_REL="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
PLAN="$ROOT/$PLAN_REL"
EVIDENCE_ALIAS_REL="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md"
MANIFEST_REL="docs/development/plan-manifest-v1.toml"
MANIFEST="$ROOT/$MANIFEST_REL"
SNAPSHOT_REL="docs/development/CURRENT_SNAPSHOT_V1.json"
MODULES_REL="docs/development/module-registry-v1.toml"
TRAIN_REL="docs/development/release-train-v1.toml"

fail() { printf 'canonical development plan gate failed: %s\n' "$*" >&2; exit 1; }

for path in "$PLAN_REL" "$EVIDENCE_ALIAS_REL" "$MANIFEST_REL" "$SNAPSHOT_REL" "$MODULES_REL" "$TRAIN_REL"; do
  [[ -e "$path" ]] || fail "missing canonical development input: $path"
done
[[ -s "$PLAN" ]] || fail "canonical plan is empty"
[[ -L "$EVIDENCE_ALIAS_REL" ]] || fail "evidence compatibility path must be a symbolic link, not independent prose"
[[ "$(readlink "$EVIDENCE_ALIAS_REL")" == "TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md" ]] \
  || fail "evidence compatibility path does not resolve to the canonical plan"
[[ ! -e docs/archive ]] || fail "docs/archive is prohibited; Git history is the archive"
[[ ! -e docs/development/agents ]] || fail "legacy per-agent development documents are prohibited"
[[ ! -e docs/development/packages ]] || fail "legacy package development documents are prohibited"

mapfile -t regular_markdown < <(find docs/development -type f -name '*.md' -printf '%p\n' | sort)
[[ "${#regular_markdown[@]}" -eq 1 && "${regular_markdown[0]}" == "$PLAN_REL" ]] \
  || fail "docs/development must contain one regular Markdown file: ${regular_markdown[*]-none}"

mapfile -t development_entries < <(find docs/development -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
expected_entries=(
  CURRENT_SNAPSHOT_V1.json
  TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
  TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md
  module-registry-v1.toml
  plan-manifest-v1.toml
  release-train-v1.toml
)
[[ "${development_entries[*]}" == "${expected_entries[*]}" ]] \
  || fail "unexpected docs/development entries: ${development_entries[*]}"

if [[ "${TRNM_PLAN_EDITING:-0}" != "1" ]]; then
  for path in "$PLAN_REL" "$EVIDENCE_ALIAS_REL" "$MANIFEST_REL" "$SNAPSHOT_REL" "$MODULES_REL" "$TRAIN_REL"; do
    git ls-files --error-unmatch -- "$path" >/dev/null || fail "untracked canonical input: $path"
    git cat-file -e "HEAD:$path" >/dev/null 2>&1 || fail "canonical input absent from HEAD: $path"
  done
  git diff --quiet -- "$PLAN_REL" "$EVIDENCE_ALIAS_REL" "$MANIFEST_REL" "$SNAPSHOT_REL" "$MODULES_REL" "$TRAIN_REL" \
    || fail "canonical development inputs are dirty"
  git diff --cached --quiet -- "$PLAN_REL" "$EVIDENCE_ALIAS_REL" "$MANIFEST_REL" "$SNAPSHOT_REL" "$MODULES_REL" "$TRAIN_REL" \
    || fail "canonical development inputs are staged against another source"
fi

# The active development tree is replaced atomically above. Historical audit and
# immutable evidence records may quote retired paths for provenance, but they do
# not become active development entry points.

python3 - "$ROOT" "$PLAN_REL" "$MANIFEST_REL" "$SNAPSHOT_REL" "$MODULES_REL" "$TRAIN_REL" <<'PY'
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tomllib

root = Path(sys.argv[1])
plan_rel, manifest_rel, snapshot_rel, modules_rel, train_rel = sys.argv[2:]
plan = root / plan_rel
manifest = tomllib.loads((root / manifest_rel).read_text())
snapshot = json.loads((root / snapshot_rel).read_text())
modules = tomllib.loads((root / modules_rel).read_text())
train = tomllib.loads((root / train_rel).read_text())
config = json.loads((root / "config/consensus-mainline.json").read_text())
protocol = tomllib.loads((root / "docs/protocol/poco-ai-native-v1/spec-manifest.toml").read_text())

expected_commit = "3c46293e78a125dec9504e51c355a20216341338"
expected_tree = "875a1e6366df7cd9da80de145e25584ae309cee8"
expected_ref = "refs/heads/integration/native-poco-a04-a19-a23-qualified-v1-20260901"
expected_plan_id = "trnm-chain-development-plan-v2"

assert config["authoritative_docs"]["development_plan"] == plan_rel
assert config["authoritative_docs"]["execution_board"] == plan_rel
assert config["authoritative_docs"]["development_plan_manifest"] == manifest_rel
assert config["authoritative_docs"]["development_evidence_contract"] == "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md"
assert protocol["delivery_plan_path"] == plan_rel
assert plan_rel in protocol["required_files"]

assert manifest["manifest_version"] == 1
assert manifest["plan_id"] == expected_plan_id
assert manifest["plan_path"] == plan_rel
assert manifest["canonical_ref"] == "refs/heads/main"
assert manifest["candidate_ref"] == "refs/heads/docs/chain-development-plan-v2-20260901"
assert manifest["assessed_ref"] == expected_ref
assert manifest["assessed_commit"] == expected_commit
assert manifest["assessed_tree"] == expected_tree

actual_tree = subprocess.run(
    ["git", "rev-parse", f"{expected_commit}^{{tree}}"],
    cwd=root, check=True, capture_output=True, text=True,
).stdout.strip()
assert actual_tree == expected_tree
assert subprocess.run(
    ["git", "merge-base", "--is-ancestor", expected_commit, "HEAD"],
    cwd=root, check=False,
).returncode == 0

plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
assert manifest["plan_sha256"] == plan_sha
assert manifest["evidence_contract_sha256"] == plan_sha
for path_key, digest_key in (
    ("machine_truth_path", "machine_truth_sha256"),
    ("protocol_manifest_path", "protocol_manifest_sha256"),
    ("toolchain_lock", "toolchain_lock_sha256"),
):
    path = root / manifest[path_key]
    assert path.is_file(), path
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest[digest_key]

assert snapshot["schema"] == "trnm-current-snapshot-v1"
assert snapshot["as_of"] == "2026-09-01"
assert snapshot["default_branch_head_observed"] == "b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9"
assert snapshot["latest_candidate"]["pull_request"] == 58
assert snapshot["latest_candidate"]["ref"] == expected_ref
assert snapshot["latest_candidate"]["commit"] == expected_commit
assert snapshot["latest_candidate"]["tree"] == expected_tree
assert snapshot["machine_truth"]["production_candidate"] is False
assert snapshot["machine_truth"]["production_consensus_activation"] is False

rows = modules["modules"]
ids = [row["id"] for row in rows]
assert ids == [f"M{i:02d}" for i in range(18)], ids
assert modules["module_count"] == 18
assert len(ids) == len(set(ids))
assert sum(row["staff_target"] for row in rows) == 48
assert modules["policy"]["control_plane_consensus_authority"] is False
assert modules["policy"]["production_may_depend_on_candidate_or_lab"] is False

assert train["source"]["selected_successor_pull_request"] == 58
assert train["source"]["head_commit"] == expected_commit
assert train["source"]["head_tree"] == expected_tree
assert train["production_candidate"] is False
assert train["production_consensus_activation"] is False
assert train["documentation"]["sole_plan_path"] == plan_rel
assert train["documentation"]["active_archive_directory_allowed"] is False
blocker_ids = {row["id"] for row in train["blockers"]}
assert {"A19-NS-001", "A19-SCHEMA-001", "A19-RETURN-001", "INT-STACK-001"} <= blocker_ids

text = " ".join(plan.read_text().split())
for marker in (
    "one active engineering plan",
    "candidate-non-normative",
    "production_candidate = false",
    "production_consensus_activation = false",
    "No machine flag is promoted",
    "MIG-001",
    "MIG-014/016",
    "G5",
    "Node Commit Ledger",
    "PinnedSqliteNamespace",
    "M00-M17",
):
    assert marker in text, marker
for forbidden in (
    "/home/alex/",
    "feature/chain-g1-r4c-full-gap-closure-20260829",
    "docs/chain-poco-bft-mainline-20260825",
):
    assert forbidden not in text, forbidden

print(
    "canonical_development_plan=passed "
    f"plan_id={expected_plan_id} plan_sha256={plan_sha} "
    "regular_markdown=1 modules=18 staff_target=48 archive=absent "
    f"assessed_commit={expected_commit} assessed_tree={expected_tree}"
)
PY

git diff --check
