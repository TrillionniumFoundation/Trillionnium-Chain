#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PLAN_REL="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
PLAN="$ROOT/$PLAN_REL"
MANIFEST_REL="docs/development/plan-manifest-v1.toml"
MANIFEST="$ROOT/$MANIFEST_REL"
fail() { printf 'canonical development plan gate failed: %s\n' "$*" >&2; exit 1; }

[[ -s "$PLAN" ]] || fail "missing canonical plan: $PLAN"
[[ -s "$MANIFEST" ]] || fail "missing canonical plan manifest: $MANIFEST"

# Iterative editing may opt into a provisional check explicitly. CI and release
# checks must use the default strict mode: the sole plan and its manifest are
# tracked, committed inputs, not working-tree-only prose.
if [[ "${TRNM_PLAN_EDITING:-0}" != "1" ]]; then
  git ls-files --error-unmatch -- "$PLAN_REL" >/dev/null \
    || fail "canonical plan is untracked; commit the plan before promotion"
  git ls-files --error-unmatch -- "$MANIFEST_REL" >/dev/null \
    || fail "canonical plan manifest is untracked; commit the manifest before promotion"
  git cat-file -e "HEAD:$PLAN_REL" >/dev/null 2>&1 \
    || fail "canonical plan is absent from HEAD; clean-clone authority is not established"
  git cat-file -e "HEAD:$MANIFEST_REL" >/dev/null 2>&1 \
    || fail "canonical plan manifest is absent from HEAD; clean-clone authority is not established"
  git diff --quiet -- "$PLAN_REL" "$MANIFEST_REL" "docs/protocol/poco-ai-native-v1/status.toml" \
    || fail "plan, manifest, or v1 status is dirty after the assessed commit"
  git diff --cached --quiet -- "$PLAN_REL" "$MANIFEST_REL" "docs/protocol/poco-ai-native-v1/status.toml" \
    || fail "plan, manifest, or v1 status is staged against a different assessed commit"
fi

mapfile -t live_plans < <(find docs/development -maxdepth 1 -type f -iname '*plan*.md' -printf '%f\n' | sort)
[[ "${#live_plans[@]}" -eq 1 && "${live_plans[0]}" == "TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md" ]] \
  || fail "docs/development must contain exactly one *plan*.md: ${live_plans[*]-none}"
mapfile -t nested_plans < <(find trillionnium/docs/development -maxdepth 1 -type f -iname '*plan*.md' -printf '%p\n' | sort)
[[ "${#nested_plans[@]}" -eq 0 ]] \
  || fail "trillionnium/docs/development must not contain a competing Chain plan: ${nested_plans[*]}"

# Historical audit/archive text may name retired paths for provenance. Active
# navigation, configuration, CI, and source paths may not revive them.
if rg -n -i --hidden \
  -g '!**/.git/**' -g '!**/target/**' -g '!docs/audits/**' -g '!docs/archive/**' \
  -g '!scripts/ci/check_canonical_development_plan.sh' \
  '(TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13|TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04|TRNM_POCO_BFT_EXECUTION_BOARD_2026-08-25|TRNM_POCO_P2_STORE_WRITER_MATRIX_2026-08-26|TRNM_4_WEEK_SPRINT_PLAN_2026-03-19|TRNM_90_DAY_EXECUTION_PLAN_2026-03-19|SPLIT_ROADMAP_2026-03-19)' .; then
  fail "retired plan basename is referenced outside audit/archive"
fi

# Legacy workflow files are still present until the signed C0/C1 cutover. The
# plan must describe that residue accurately instead of claiming every trigger
# is inert or Comet-free. This guard prevents a future plan edit from silently
# reopening that contradiction.
if rg -l -i --hidden -g '*.yml' -g '*.yaml' \
  '(cometbft|tendermint|abci|26657|trnm-consensus-app|trnm-node|legacy[-_ ]harness)' \
  .github/workflows >/dev/null; then
  if rg -q -i 'every automatically triggered workflow is free|six historical workflows are manual inert' "$PLAN"; then
    fail "plan overclaims workflow cleanup while legacy workflow residue remains"
  fi
  rg -q -i 'legacy (workflows|migration/development workflows).*cleanup remains open|cleanup remains open until.*C0/C1' "$PLAN" \
    || fail "plan must state that legacy workflow cleanup remains open until C0/C1"
fi

python3 - "$ROOT" "$PLAN" "$PLAN_REL" "$MANIFEST" "$MANIFEST_REL" <<'PY'
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tomllib

root = Path(sys.argv[1])
plan = Path(sys.argv[2])
plan_rel = sys.argv[3]
manifest_path = Path(sys.argv[4])
manifest_rel = sys.argv[5]
config = json.loads((root / "config/consensus-mainline.json").read_text())
docs = config.get("authoritative_docs", {})
if docs.get("development_plan") != plan_rel:
    raise SystemExit("config authoritative_docs.development_plan is not canonical")
if docs.get("execution_board") != plan_rel:
    raise SystemExit("config authoritative_docs.execution_board is not canonical")
if docs.get("development_plan_manifest") != "docs/development/plan-manifest-v1.toml":
    raise SystemExit("config authoritative_docs.development_plan_manifest is not canonical")
if docs.get("development_evidence_contract") != "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md":
    raise SystemExit("config authoritative_docs.development_evidence_contract is not canonical")
protocol_manifest = tomllib.loads((root / "docs/protocol/poco-ai-native-v1/spec-manifest.toml").read_text())
if protocol_manifest.get("delivery_plan_path") != plan_rel:
    raise SystemExit("v1 manifest delivery_plan_path is not canonical")
if plan_rel not in protocol_manifest.get("required_files", []):
    raise SystemExit("canonical plan is absent from v1 required_files")
status = tomllib.loads((root / "docs/protocol/poco-ai-native-v1/status.toml").read_text())
if not status.get("design_only") or status.get("implementation_status") != "not-implemented":
    raise SystemExit("v1 status changed unexpectedly; review the canonical-plan gate")
manifest = tomllib.loads(manifest_path.read_text())
if manifest.get("plan_path") != plan_rel:
    raise SystemExit("plan manifest plan_path is not canonical")
if manifest.get("manifest_version") != 1:
    raise SystemExit("unsupported plan manifest version")
if manifest.get("plan_id") != "trnm-ai-native-blockchain-development-plan-v1":
    raise SystemExit("plan manifest plan_id is not canonical")
if manifest.get("canonical_ref") != "refs/heads/docs/chain-poco-bft-mainline-20260825":
    raise SystemExit("plan manifest canonical_ref is not canonical")

assessed_commit = manifest.get("assessed_commit")
assessed_tree = manifest.get("assessed_tree")
if not isinstance(assessed_commit, str) or re.fullmatch(r"[0-9a-f]{40}", assessed_commit) is None:
    raise SystemExit("plan manifest assessed_commit is not a full lowercase Git object ID")
if not isinstance(assessed_tree, str) or re.fullmatch(r"[0-9a-f]{40}", assessed_tree) is None:
    raise SystemExit("plan manifest assessed_tree is not a full lowercase Git object ID")
try:
    actual_tree = subprocess.run(
        ["git", "rev-parse", f"{assessed_commit}^{{tree}}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
except subprocess.CalledProcessError as error:
    raise SystemExit("plan manifest assessed_commit is unavailable in this clone") from error
if actual_tree != assessed_tree:
    raise SystemExit(
        f"plan manifest assessed_tree mismatch: declared={assessed_tree} actual={actual_tree}"
    )
ancestor = subprocess.run(
    ["git", "merge-base", "--is-ancestor", assessed_commit, "HEAD"],
    cwd=root,
    check=False,
    capture_output=True,
)
if ancestor.returncode != 0:
    raise SystemExit("plan manifest assessed_commit is not an ancestor of HEAD")

for path_key, digest_key in (
    ("machine_truth_path", "machine_truth_sha256"),
    ("protocol_manifest_path", "protocol_manifest_sha256"),
    ("evidence_contract_path", "evidence_contract_sha256"),
    ("toolchain_lock", "toolchain_lock_sha256"),
):
    relative = manifest.get(path_key)
    declared = manifest.get(digest_key)
    if not isinstance(relative, str) or not relative:
        raise SystemExit(f"plan manifest {path_key} is missing")
    bound = (root / relative).resolve()
    if root.resolve() not in bound.parents or not bound.is_file():
        raise SystemExit(f"plan manifest {path_key} is outside the repository or missing")
    actual = hashlib.sha256(bound.read_bytes()).hexdigest()
    if declared != actual:
        raise SystemExit(
            f"plan manifest {digest_key} mismatch: declared={declared} actual={actual}"
        )

plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
declared_sha = manifest.get("plan_sha256")
if declared_sha != plan_sha:
    if not (declared_sha == "PENDING_FINAL_PLAN_HASH" and __import__("os").environ.get("TRNM_PLAN_EDITING") == "1"):
        raise SystemExit(f"plan manifest SHA mismatch: declared={declared_sha} actual={plan_sha}")
text = " ".join(plan.read_text().split())
for marker in (
    "one active engineering plan",
    "production_candidate = false",
    "MIG-001",
    "MIG-014/016",
    "candidate-non-normative",
    "no machine flag is promoted",
    "G5",
):
    if marker not in text:
        raise SystemExit(f"canonical plan missing truth marker: {marker}")
for forbidden in (
    "every automatically triggered workflow is free",
    "six historical workflows are manual inert",
    "dependency closure is complete",
):
    if forbidden in text:
        raise SystemExit(f"canonical plan contains an unsafe completion phrase: {forbidden}")
print(
    "canonical_development_plan=passed "
    f"live_plan_count=1 stale_active_paths=0 plan_sha256={plan_sha} "
    f"assessed_commit={assessed_commit} assessed_tree={assessed_tree} bound_inputs=4"
)
PY
