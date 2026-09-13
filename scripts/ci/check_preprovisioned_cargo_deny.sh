#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: check_preprovisioned_cargo_deny.sh" >&2
  exit 2
fi

expected_tool="${HOME:?HOME is required}/.cargo/bin/cargo-deny"
tool=$(command -v cargo-deny)
[[ "$tool" == "$expected_tool" && -f "$tool" && ! -L "$tool" ]] || {
  echo "cargo-deny must resolve to the hardened runner binary: $expected_tool" >&2
  exit 2
}
[[ "$(stat -c '%u' "$tool")" == "0" ]] \
  && (( (8#$(stat -c '%a' "$tool") & 0222) == 0 )) || {
  echo "cargo-deny must be root-owned and read-only" >&2
  exit 2
}
[[ "$("$tool" --version)" == "cargo-deny 0.20.2" ]] || {
  echo "unexpected cargo-deny version" >&2
  exit 2
}
printf '%s  %s\n' \
  b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a \
  "$tool" | sha256sum --check --strict

advisory_db="$HOME/.cargo/advisory-dbs/advisory-db-3157b0e258782691"
[[ -d "$advisory_db" && ! -L "$advisory_db" ]] || {
  echo "missing hardened RustSec advisory database" >&2
  exit 2
}
bad=$(find "$advisory_db" \( -type d -o -type f \) \
  \( ! -user root -o -perm /0222 \) -print -quit)
[[ -z "$bad" ]] || {
  echo "RustSec advisory database contains writable or non-root authority: $bad" >&2
  exit 2
}
[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$advisory_db" \
  -C "$advisory_db" rev-parse HEAD)" == \
  "1237bbe09d2701e14e6593a630fbaf28928df712" ]] || {
  echo "RustSec advisory database commit differs from the frozen policy" >&2
  exit 2
}
[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$advisory_db" \
  -C "$advisory_db" rev-parse 'HEAD^{tree}')" == \
  "ab125d2529cff71167188bf27b5deceaa4a86994" ]] || {
  echo "RustSec advisory database tree differs from the frozen policy" >&2
  exit 2
}
[[ -z "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$advisory_db" \
  -C "$advisory_db" status --porcelain --untracked-files=all)" ]] || {
  echo "RustSec advisory database is dirty" >&2
  exit 2
}

printf '%s\n' \
  "preprovisioned_cargo_deny=passed version=0.20.2 advisory_commit=1237bbe09d2701e14e6593a630fbaf28928df712"
