#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PLAN_REL="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
MANIFEST_REL="docs/development/plan-manifest-v1.toml"
MODULES_REL="docs/development/module-registry-v1.toml"
COVERAGE_REL="config/module-coverage-v1.toml"
TECHREF_REL="docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"
TRAIN_REL="docs/development/release-train-v1.toml"
SNAPSHOT_REL="docs/development/CURRENT_SNAPSHOT_V1.json"
POLICY_REL="config/documentation-truth-v1.json"
REPOSITORY_POLICY_REL="config/repository-policy-v1.json"
REFERENCE_GATE="scripts/ci/check_documentation_reference_closure_v1.py"
MODULE_GATE="scripts/ci/check_module_coverage_v1.py"

fail() {
  printf 'canonical development plan gate failed: %s\n' "$*" >&2
  exit 2
}

canonical_inputs=(
  "$PLAN_REL"
  "$MANIFEST_REL"
  "$MODULES_REL"
  "$COVERAGE_REL"
  "$TECHREF_REL"
  "$TRAIN_REL"
  "$SNAPSHOT_REL"
  "$POLICY_REL"
  "$REPOSITORY_POLICY_REL"
  "$REFERENCE_GATE"
  "$MODULE_GATE"
  "scripts/ci/check_canonical_development_plan.sh"
)

for path in "${canonical_inputs[@]}"; do
  [[ -s "$path" ]] || fail "missing canonical input: $path"
done

if [[ "${TRNM_PLAN_EDITING:-0}" != "1" ]]; then
  for path in "${canonical_inputs[@]}"; do
    git ls-files --error-unmatch -- "$path" >/dev/null \
      || fail "canonical input is untracked: $path"
    git cat-file -e "HEAD:$path" >/dev/null 2>&1 \
      || fail "canonical input is absent from HEAD: $path"
  done
  git diff --quiet -- "${canonical_inputs[@]}" \
    || fail "canonical development inputs are dirty"
  git diff --cached --quiet -- "${canonical_inputs[@]}" \
    || fail "canonical development inputs are staged against another source"
fi

python3 - \
  "$ROOT" \
  "$PLAN_REL" \
  "$MANIFEST_REL" \
  "$MODULES_REL" \
  "$COVERAGE_REL" \
  "$TECHREF_REL" \
  "$TRAIN_REL" \
  "$SNAPSHOT_REL" \
  "$POLICY_REL" \
  "$REPOSITORY_POLICY_REL" \
  "$REFERENCE_GATE" \
  "$MODULE_GATE" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from typing import Any

(
    root_arg,
    plan_rel,
    manifest_rel,
    modules_rel,
    coverage_rel,
    techref_rel,
    train_rel,
    snapshot_rel,
    policy_rel,
    repository_policy_rel,
    reference_gate_rel,
    module_gate_rel,
) = sys.argv[1:]
root = Path(root_arg)


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(relative: str) -> dict[str, Any]:
    value = json.loads(
        (root / relative).read_text(encoding="utf-8"),
        object_pairs_hook=strict_object,
    )
    require(isinstance(value, dict), f"{relative}: object required")
    return value


def load_toml(relative: str) -> dict[str, Any]:
    with (root / relative).open("rb") as handle:
        value = tomllib.load(handle)
    require(isinstance(value, dict), f"{relative}: table required")
    return value


def values(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for candidate_key, candidate_value in value.items():
            if candidate_key == key:
                found.append(candidate_value)
            found.extend(values(candidate_value, key))
    elif isinstance(value, list):
        for candidate_value in value:
            found.extend(values(candidate_value, key))
    return found


def unique_sha(value: Any, key: str) -> str:
    found = sorted(
        {
            item
            for item in values(value, key)
            if isinstance(item, str) and re.fullmatch(r"[0-9a-f]{40}", item)
        }
    )
    require(len(found) == 1, f"{key} must be unique: {found}")
    return found[0]


def head_blob(relative: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, f"{relative}: invalid HEAD blob")
    return value


plan = (root / plan_rel).read_text(encoding="utf-8")
lower = plan.lower()
manifest = load_toml(manifest_rel)
modules = load_toml(modules_rel)
train = load_toml(train_rel)
snapshot = load_json(snapshot_rel)
policy = load_json(policy_rel)
truth = load_json("config/consensus-mainline.json")
repository_policy = load_json(repository_policy_rel)
boundary = load_json("PROJECT_BOUNDARY.json")

require(policy.get("schema") == "trnm-documentation-truth-v1", "documentation policy schema drift")
require(
    policy.get("canonical_plan") == plan_rel and manifest.get("plan_path") == plan_rel,
    "canonical plan path drift",
)
require(
    modules.get("coverage_manifest") == coverage_rel,
    "module coverage manifest binding missing",
)
require(
    modules.get("technical_reference") == techref_rel,
    "module technical reference binding missing",
)
plan_id = manifest.get("plan_id")
require(plan_id == "trnm-chain-development-plan-v2", f"plan id drift: {plan_id!r}")
require("plan id: `trnm-chain-development-plan-v2`" in lower, "plan body id drift")

actual_plan_sha = hashlib.sha256((root / plan_rel).read_bytes()).hexdigest()
declared_plan_sha = manifest.get("plan_sha256")
require(
    declared_plan_sha == actual_plan_sha
    or (
        os.environ.get("TRNM_PLAN_EDITING") == "1"
        and declared_plan_sha == "PENDING_FINAL_PLAN_HASH"
    ),
    f"plan SHA mismatch: {declared_plan_sha} != {actual_plan_sha}",
)

evidence_rel = manifest.get("evidence_contract_path")
require(isinstance(evidence_rel, str) and evidence_rel, "evidence contract path missing")
actual_evidence_sha = hashlib.sha256((root / evidence_rel).read_bytes()).hexdigest()
require(
    manifest.get("evidence_contract_sha256") == actual_evidence_sha,
    "evidence contract SHA mismatch",
)

commit = unique_sha(manifest, "assessed_commit")
tree = unique_sha(manifest, "assessed_tree")
actual_tree = subprocess.run(
    ["git", "rev-parse", f"{commit}^{{tree}}"],
    cwd=root,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
require(actual_tree == tree, "assessed tree mismatch")
require(
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=root,
    ).returncode
    == 0,
    "assessed source is not ancestor of HEAD",
)

manifest_text = repr(manifest).lower()
require(
    "runtime-git-commit-and-tree" in manifest_text
    or "derived-at-verification-time" in manifest_text
    or manifest.get("document_candidate_binding") in {"runtime", "runtime-git-commit-and-tree"},
    "runtime document binding missing",
)

expected_pins = {
    "module_registry_git_blob": modules_rel,
    "module_coverage_git_blob": coverage_rel,
    "module_technical_reference_git_blob": techref_rel,
    "current_snapshot_git_blob": snapshot_rel,
    "documentation_truth_git_blob": policy_rel,
    "repository_policy_git_blob": repository_policy_rel,
    "documentation_reference_gate_git_blob": reference_gate_rel,
    "module_coverage_gate_git_blob": module_gate_rel,
    "canonical_plan_gate_git_blob": "scripts/ci/check_canonical_development_plan.sh",
}
for field, relative in expected_pins.items():
    declared = manifest.get(field)
    actual = head_blob(relative)
    require(declared == actual, f"{field} mismatch: {declared} != {actual}")

require(
    manifest.get("documentation_gate_revision") == policy.get("gate_revision") == 4,
    "documentation gate revision mismatch",
)

module_rows = modules.get("module", modules.get("modules"))
require(isinstance(module_rows, list), "module rows missing")
module_ids = [row.get("id") for row in module_rows if isinstance(row, dict)]
require(module_ids == [f"M{index:02d}" for index in range(18)], f"module IDs drift: {module_ids}")

staff = 0
for row in module_rows:
    count = next(
        (
            row.get(key)
            for key in ("staff", "staff_target", "target_staff", "recommended_staff")
            if isinstance(row.get(key), int)
        ),
        None,
    )
    require(isinstance(count, int) and count > 0, f"staff missing for {row.get('id')}")
    staff += count
require(staff == 48, f"staff target drift: {staff}")

for marker in (
    "one active engineering plan",
    "node commit ledger",
    "pinnedsqlitenamespace",
    "global control plane",
    "production_candidate = false",
    "no machine flag is promoted",
    "g5",
):
    require(marker in lower, f"plan missing {marker}")
require(
    re.search(r"\b(?:18|eighteen)\s+long-lived\s+modules\b", lower) is not None,
    "plan missing 18 long-lived modules",
)
for forbidden in (
    "production_candidate = true",
    "production_consensus_activation = true",
    "release_ready = true",
    "public_testnet_ready = true",
):
    require(forbidden not in lower, f"plan contains {forbidden}")

for document in (snapshot, truth, repository_policy, boundary, train):
    for key in (
        "production_candidate",
        "production_consensus_activation",
        "release_ready",
        "public_testnet_ready",
    ):
        require(
            all(item is False for item in values(document, key) if isinstance(item, bool)),
            f"{key} promoted",
        )

require(
    snapshot.get("machine_truth", {}).get("stage") == "G1-native-host-incomplete",
    "snapshot stage drift",
)
require(
    truth.get("stage") == "G1-native-host-incomplete"
    and truth.get("consensus_mainline") == "native-poco-bft"
    and truth.get("protocol_target") == "poco-bft-v0",
    "machine truth drift",
)

train_lower = repr(train).lower()
for marker in ("selected", "successor", "sqlite", "schema", "review", "production_candidate"):
    require(marker in train_lower, f"release train missing {marker}")

print(
    "canonical_development_plan=passed "
    f"plan_id={plan_id} "
    f"plan_sha256={actual_plan_sha} "
    "regular_markdown=1 "
    f"modules={len(module_rows)} "
    f"staff_target={staff} "
    "archive=absent "
    f"assessed_commit={commit} "
    f"assessed_tree={tree} "
    "document_binding=runtime-git-commit-and-tree "
    "duplicate_json_keys=rejected "
    f"documentation_gate_revision={policy.get('gate_revision')} "
    f"pinned_inputs={len(expected_pins)}"
)
PY

args=(--self-test --binding-mode "${TRNM_DOC_BINDING_MODE:-local}")
if [[ -n "${TRNM_DOC_BINDING_OUTPUT:-}" ]]; then
  args+=(--binding-output "$TRNM_DOC_BINDING_OUTPUT")
fi

python3 "$REFERENCE_GATE" "${args[@]}"
python3 "$MODULE_GATE"
git diff --check
