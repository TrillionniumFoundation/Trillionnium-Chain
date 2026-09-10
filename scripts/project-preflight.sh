#!/usr/bin/env bash
set -euo pipefail

mode="${1:---dev}"
case "$mode" in
  --dev|--audit|--staged|--push) ;;
  *)
    echo "ERROR: unsupported preflight mode: $mode" >&2
    exit 10
    ;;
esac

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a Git repository" >&2
  exit 10
}
root="$(cd "$root" && pwd -P)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

policy="$root/PROJECT_BOUNDARY.json"
project_id_file="$root/PROJECT_ID"
case "$mode" in
  --staged)
    git -C "$root" show :PROJECT_BOUNDARY.json >"$tmpdir/PROJECT_BOUNDARY.json" 2>/dev/null || {
      echo "ERROR: PROJECT_BOUNDARY.json must exist in the index" >&2
      exit 10
    }
    git -C "$root" show :PROJECT_ID >"$tmpdir/PROJECT_ID" 2>/dev/null || {
      echo "ERROR: PROJECT_ID must exist in the index" >&2
      exit 10
    }
    policy="$tmpdir/PROJECT_BOUNDARY.json"
    project_id_file="$tmpdir/PROJECT_ID"
    ;;
  --push)
    git -C "$root" show HEAD:PROJECT_BOUNDARY.json >"$tmpdir/PROJECT_BOUNDARY.json" 2>/dev/null || {
      echo "ERROR: PROJECT_BOUNDARY.json must exist in HEAD" >&2
      exit 10
    }
    git -C "$root" show HEAD:PROJECT_ID >"$tmpdir/PROJECT_ID" 2>/dev/null || {
      echo "ERROR: PROJECT_ID must exist in HEAD" >&2
      exit 10
    }
    policy="$tmpdir/PROJECT_BOUNDARY.json"
    project_id_file="$tmpdir/PROJECT_ID"
    ;;
esac

[[ -f "$policy" && -f "$project_id_file" ]] || {
  echo "ERROR: missing project boundary files" >&2
  exit 10
}

project_id="$(tr -d '\r\n' <"$project_id_file")"
branch="$(git -C "$root" branch --show-current 2>/dev/null || true)"
origin="$(git -C "$root" remote get-url origin 2>/dev/null || true)"

printf 'project_id=%s\n' "$project_id"
printf 'physical_root=%s\n' "$root"
printf 'branch=%s\n' "$branch"
printf 'origin=%s\n' "${origin:-(none)}"

python3 - "$policy" "$root" "$project_id" "$branch" "$mode" "$origin" <<'PY'
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlparse

policy_path = Path(sys.argv[1])
root = Path(sys.argv[2])
project_id = sys.argv[3]
branch = sys.argv[4]
mode = sys.argv[5]
origin = sys.argv[6]
errors: list[str] = []

try:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"ERROR: invalid PROJECT_BOUNDARY.json: {exc}", file=sys.stderr)
    raise SystemExit(10)

if project_id != "trillionnium-chain" or policy.get("project_id") != project_id:
    errors.append("project identity mismatch")
if policy.get("lane") != "chain-consensus":
    errors.append("lane must be chain-consensus")
if policy.get("lifecycle") != "active" or policy.get("development") is not True:
    errors.append("repository must be active development")

consensus = policy.get("consensus", {})
if consensus.get("family") != "native-poco":
    errors.append("consensus family must be native-poco")
if consensus.get("third_party_engines") != "forbidden":
    errors.append("third-party consensus engines must be forbidden")
if consensus.get("release_ready") is not False:
    errors.append("release_ready must remain false until release gates close")

workspace_rel = policy.get("cargo", {}).get("workspace_manifest")
workspace_path = root / str(workspace_rel or "")
if not workspace_path.is_file():
    errors.append("workspace manifest is missing")
    workspace = {}
else:
    try:
        workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"workspace manifest is invalid: {exc}")
        workspace = {}

members = set(workspace.get("workspace", {}).get("members", []))
required_members = {
    "crates/trnm-node",
    "crates/trnm-pouw",
    "crates/trnm-state",
    "crates/trnm-executor",
    "crates/trnm-mempool",
    "crates/trnm-finality-types",
    "crates/trnm-finality-verifier",
}
missing = sorted(required_members - members)
if missing:
    errors.append("missing native PoCO workspace members: " + ", ".join(missing))

node_manifest_path = root / "trillionnium/crates/trnm-node/Cargo.toml"
if not node_manifest_path.is_file():
    errors.append("native node manifest is missing")
else:
    try:
        node = tomllib.loads(node_manifest_path.read_text(encoding="utf-8"))
        package = node.get("package", {})
        features = node.get("features", {})
        metadata = package.get("metadata", {}).get("trnm", {})
        bins = {entry.get("name"): entry for entry in node.get("bin", [])}
        if package.get("default-run") != "trnm-chain-node":
            errors.append("native node must be the default run target")
        if features.get("default") != ["native-consensus"]:
            errors.append("native-consensus must be the default feature")
        if features.get("native-consensus") != []:
            errors.append("native-consensus feature must be defined")
        if metadata.get("lane") != "native-poco-consensus":
            errors.append("native node lane metadata mismatch")
        if metadata.get("protocol_features_frozen") is not False:
            errors.append("native protocol must not be marked frozen")
        if metadata.get("production_candidate") is not True:
            errors.append("native node must be the production candidate")
        if metadata.get("release_ready") is not False:
            errors.append("native node must not claim release readiness")
        expected_bins = {
            "trnm-sim",
            "trnm-chain-node",
            "trnm-chain-validator",
            "trnm-chain-cli",
        }
        if set(bins) != expected_bins:
            errors.append("native binary set mismatch")
        for name, entry in bins.items():
            if entry.get("required-features") != ["native-consensus"]:
                errors.append(f"{name} is not bound to native-consensus")
    except Exception as exc:
        errors.append(f"native node manifest is invalid: {exc}")

protected = set(policy.get("branch", {}).get("protected", []))
branch_regex = policy.get("branch", {}).get("development_regex", "")
if mode != "--audit":
    if not branch:
        errors.append("detached HEAD is not allowed for development")
    elif branch in protected:
        errors.append(f"development on protected branch {branch!r} is disabled")
    elif not branch_regex or re.fullmatch(branch_regex, branch) is None:
        errors.append(f"branch {branch!r} does not match development policy")

canonical_slug = policy.get("remote", {}).get("canonical_slug", "")
if origin and canonical_slug:
    normalized = origin.removesuffix(".git")
    normalized = re.sub(r"^git@github\.com:", "https://github.com/", normalized)
    normalized = re.sub(r"^ssh://git@github\.com/", "https://github.com/", normalized)
    if normalized != f"https://github.com/{canonical_slug}":
        errors.append("origin does not match canonical repository")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(10)

print("lane=chain-consensus")
print("consensus_family=native-poco")
print("preflight=ok")
PY
