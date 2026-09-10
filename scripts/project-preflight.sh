#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/project-preflight.sh [--dev|--main]" >&2
}

mode="${1:---dev}"
case "$mode" in
  --dev|--main) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

root="$(git rev-parse --show-toplevel)"
cd "$root"

fail() {
  echo "[project-preflight][FAIL] $*" >&2
  exit 1
}

[[ -f PROJECT_BOUNDARY.json ]] || fail "PROJECT_BOUNDARY.json is missing"
[[ -f PROJECT_ID ]] || fail "PROJECT_ID is missing"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

project_id="$(tr -d '[:space:]' < PROJECT_ID)"
[[ "$project_id" == "trillionnium-chain" ]] || fail "unexpected PROJECT_ID: $project_id"
[[ "$(jq -r '.project_id' PROJECT_BOUNDARY.json)" == "$project_id" ]] || fail "project boundary ID mismatch"
[[ "$(jq -r '.consensus_policy' PROJECT_BOUNDARY.json)" == "native-poco-only" ]] || fail "native PoCO policy is not active"

manifest="$(jq -r '.cargo.workspace_manifest' PROJECT_BOUNDARY.json)"
[[ -f "$manifest" ]] || fail "workspace manifest is missing: $manifest"

while IFS= read -r package; do
  rg -q "name = \"${package}\"" trillionnium/crates/*/Cargo.toml || fail "required package is missing: $package"
done < <(jq -r '.cargo.required_packages[]' PROJECT_BOUNDARY.json)

while IFS= read -r package; do
  if rg -q "name = \"${package}\"" trillionnium/crates/*/Cargo.toml; then
    fail "forbidden package is present: $package"
  fi
done < <(jq -r '.cargo.forbidden_packages[]' PROJECT_BOUNDARY.json)

cargo metadata --manifest-path "$manifest" --no-deps --format-version 1 >/dev/null

if [[ "$(jq -r '.cargo.external_path_dependencies' PROJECT_BOUNDARY.json)" == "forbid" ]]; then
  while IFS= read -r cargo_file; do
    cargo_dir="$(cd "$(dirname "$cargo_file")" && pwd -P)"
    while IFS= read -r rel; do
      dep_path="$(cd "$cargo_dir" && realpath -m "$rel")"
      case "$dep_path" in
        "$root"|"$root"/*) ;;
        *) fail "external path dependency in $cargo_file: $rel" ;;
      esac
    done < <(sed -nE 's/.*path[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$cargo_file")
  done < <(find "$root" -name Cargo.toml -not -path '*/target/*' -print)
fi

branch="$(git branch --show-current)"
[[ -n "$branch" ]] || fail "detached HEAD is not allowed"
if [[ "$mode" == "--dev" ]]; then
  [[ "$branch" =~ $(jq -r '.branch.development_regex' PROJECT_BOUNDARY.json) ]] || fail "development branch violates policy: $branch"
else
  jq -e --arg branch "$branch" '.branch.protected | index($branch) != null' PROJECT_BOUNDARY.json >/dev/null || fail "main mode requires a protected branch"
fi

canonical_slug="$(jq -r '.remote.canonical_slug' PROJECT_BOUNDARY.json)"
remote_url="$(git remote get-url origin 2>/dev/null || true)"
[[ "$remote_url" == *"$canonical_slug"* ]] || fail "origin does not match canonical remote"

if [[ "$mode" == "--dev" ]]; then
  [[ "$(git status --porcelain | wc -l | tr -d ' ')" == "0" ]] || fail "development worktree must be clean"
fi

echo "[project-preflight][PASS] project=$project_id branch=$branch mode=$mode"
