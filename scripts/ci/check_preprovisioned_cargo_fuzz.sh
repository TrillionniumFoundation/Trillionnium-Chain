#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: check_preprovisioned_cargo_fuzz.sh" >&2
  exit 2
fi

expected_tool="${HOME:?HOME is required}/.cargo/bin/cargo-fuzz"
tool=$(command -v cargo-fuzz)
[[ "$tool" == "$expected_tool" && -f "$tool" && ! -L "$tool" ]] || {
  echo "cargo-fuzz must resolve to the hardened runner binary: $expected_tool" >&2
  exit 2
}
[[ "$(stat -c '%u' "$tool")" == "0" ]] \
  && (( (8#$(stat -c '%a' "$tool") & 0222) == 0 )) || {
  echo "cargo-fuzz must be root-owned and read-only" >&2
  exit 2
}
[[ "$("$tool" --version)" == "cargo-fuzz 0.13.2" ]] || {
  echo "unexpected cargo-fuzz version" >&2
  exit 2
}
printf '%s  %s\n' \
  e915260ced1c90e460153583597cb05efb8f72df489491682f5762710cd0b2ef \
  "$tool" | sha256sum --check --strict

printf '%s\n' "preprovisioned_cargo_fuzz=passed version=0.13.2"
