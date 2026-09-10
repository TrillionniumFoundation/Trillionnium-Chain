#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

self='scripts/ci/check_native_poco_boundary.sh'

forbidden_terms=(
  $'\x43\x6f\x6d\x65\x74\x42\x46\x54'
  $'\x54\x65\x6e\x64\x65\x72\x6d\x69\x6e\x74'
  $'\x41\x42\x43\x49'
  $'\x74\x72\x6e\x6d\x2d\x63\x6f\x6e\x73\x65\x6e\x73\x75\x73\x2d\x61\x70\x70'
  $'\x74\x72\x6e\x6d\x5f\x63\x6f\x6d\x65\x74\x62\x66\x74'
)

failed=0
for term in "${forbidden_terms[@]}"; do
  matches="$(git grep -n -I -i -- "$term" -- . ":!$self" || true)"
  if [[ -n "$matches" ]]; then
    printf '[native-poco-boundary][FAIL] forbidden consensus integration residue detected\n%s\n' "$matches" >&2
    failed=1
  fi
done

if (( failed != 0 )); then
  exit 1
fi

required_packages=(
  trnm-node
  trnm-pouw
  trnm-state
  trnm-finality-types
  trnm-finality-verifier
)

for package in "${required_packages[@]}"; do
  if ! grep -Rqs --include Cargo.toml "name = \"$package\"" trillionnium/crates; then
    echo "[native-poco-boundary][FAIL] missing native package: $package" >&2
    exit 1
  fi
done

echo '[native-poco-boundary][PASS] native PoCO repository boundary is clean'
