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
cd "$root"

policy_source="PROJECT_BOUNDARY.json"
project_id_source="PROJECT_ID"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

case "$mode" in
  --staged)
    git show :PROJECT_BOUNDARY.json >"$tmpdir/PROJECT_BOUNDARY.json" 2>/dev/null || { echo "ERROR: PROJECT_BOUNDARY.json must exist in the index" >&2; exit 10; }
    git show :PROJECT_ID >"$tmpdir/PROJECT_ID" 2>/dev/null || { echo "ERROR: PROJECT_ID must exist in the index" >&2; exit 10; }
    policy_source="$tmpdir/PROJECT_BOUNDARY.json"
    project_id_source="$tmpdir/PROJECT_ID"
    ;;
  --push)
    git show HEAD:PROJECT_BOUNDARY.json >"$tmpdir/PROJECT_BOUNDARY.json" 2>/dev/null || { echo "ERROR: PROJECT_BOUNDARY.json must exist in HEAD" >&2; exit 10; }
    git show HEAD:PROJECT_ID >"$tmpdir/PROJECT_ID" 2>/dev/null || { echo "ERROR: PROJECT_ID must exist in HEAD" >&2; exit 10; }
    policy_source="$tmpdir/PROJECT_BOUNDARY.json"
    project_id_source="$tmpdir/PROJECT_ID"
    ;;
esac

python3 - "$policy_source" "$project_id_source" <<'PY'
import json
import pathlib
import sys
policy_path = pathlib.Path(sys.argv[1])
id_path = pathlib.Path(sys.argv[2])
with policy_path.open(encoding="utf-8") as handle:
    data = json.load(handle)
project_id = id_path.read_text(encoding="utf-8").strip()
issues = []
if project_id != "trillionnium-chain": issues.append("PROJECT_ID must be trillionnium-chain")
if data.get("project_id") != project_id: issues.append("PROJECT_ID and PROJECT_BOUNDARY.json disagree")
if data.get("lane") != "chain-consensus": issues.append("lane must be chain-consensus")
if data.get("remote", {}).get("canonical_slug") != "TrillionniumFoundation/Trillionnium-Chain": issues.append("canonical repository slug mismatch")
consensus = data.get("consensus", {})
if consensus.get("policy") != "self-developed-only": issues.append("consensus policy must be self-developed-only")
if consensus.get("canonical_package") != "trnm-node": issues.append("canonical consensus package must be trnm-node")
if consensus.get("external_engines") != "forbid": issues.append("external consensus engines must be forbidden")
required = set(data.get("cargo", {}).get("required_packages", []))
for package in ("trnm-node", "trnm-runtime", "trnm-state"):
    if package not in required: issues.append(f"required package missing: {package}")
if issues:
    for issue in issues: print(f"ERROR: {issue}", file=sys.stderr)
    raise SystemExit(10)
PY

branch="$(git branch --show-current 2>/dev/null || true)"
if [[ "$mode" != "--audit" ]]; then
  if [[ -z "$branch" ]]; then echo "ERROR: detached HEAD is not allowed for development" >&2; exit 10; fi
  if [[ "$branch" == "main" || "$branch" == "master" ]]; then echo "ERROR: development on protected branch '$branch' is disabled" >&2; exit 10; fi
  if [[ ! "$branch" =~ ^(feature|fix|chore|docs|test)/chain-[a-z0-9][a-z0-9._-]*$ ]]; then echo "ERROR: branch '$branch' does not match repository lane policy" >&2; exit 10; fi
fi

origin="$(git remote get-url origin 2>/dev/null || true)"
if [[ -z "$origin" ]]; then echo "ERROR: origin is required" >&2; exit 10; fi
case "$origin" in
  git@github.com:TrillionniumFoundation/Trillionnium-Chain.git|ssh://git@github.com/TrillionniumFoundation/Trillionnium-Chain.git|https://github.com/TrillionniumFoundation/Trillionnium-Chain.git|https://github.com/TrillionniumFoundation/Trillionnium-Chain) ;;
  *) echo "ERROR: origin does not match canonical repository" >&2; exit 10 ;;
esac

bash scripts/ci/check_self_consensus_only.sh

if command -v cargo >/dev/null 2>&1; then
  cargo metadata --manifest-path trillionnium/Cargo.toml --locked --no-deps --format-version 1 >/dev/null
else
  echo "WARN: cargo unavailable; manifest metadata execution skipped" >&2
fi

printf 'project_id=trillionnium-chain\n'
printf 'lane=chain-consensus\n'
printf 'branch=%s\n' "${branch:-(detached)}"
printf 'consensus_policy=self-developed-only\n'
printf 'preflight=ok\n'
