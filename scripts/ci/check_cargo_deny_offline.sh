#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
  echo "usage: check_cargo_deny_offline.sh MANIFEST_PATH..." >&2
  exit 2
fi
[[ "${CARGO_NET_OFFLINE:-}" == "true" ]] || {
  echo "CARGO_NET_OFFLINE=true is required" >&2
  exit 2
}
[[ "${CARGO_CACHE_AUTO_CLEAN_FREQUENCY:-}" == "never" ]] || {
  echo "CARGO_CACHE_AUTO_CLEAN_FREQUENCY=never is required" >&2
  exit 2
}
[[ -z "${CARGO_HOME:-}" ]] || {
  echo "CARGO_HOME must not override the hardened runner cache" >&2
  exit 2
}

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
advisory_db="${HOME:?HOME is required}/.cargo/advisory-dbs/advisory-db-3157b0e258782691"
cargo_proxy="$HOME/.cargo/bin/cargo"
[[ "$(command -v cargo)" == "$cargo_proxy" ]] || {
  echo "Cargo must resolve from the hardened runner binary authority" >&2
  exit 2
}
declare -A seen=()
for manifest in "$@"; do
  case "$manifest" in
    trillionnium/Cargo.toml|contracts/Cargo.toml|trillionnium/fuzz/Cargo.toml) ;;
    *)
      echo "unapproved cargo-deny manifest: $manifest" >&2
      exit 2
      ;;
  esac
  [[ -z "${seen[$manifest]:-}" ]] || {
    echo "duplicate cargo-deny manifest: $manifest" >&2
    exit 2
  }
  seen[$manifest]=1
  [[ -f "$root/$manifest" && ! -L "$root/$manifest" ]] || {
    echo "missing non-symlink cargo-deny manifest: $manifest" >&2
    exit 2
  }
  GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0="$advisory_db" \
    "$cargo_proxy" deny --frozen --manifest-path "$manifest" check
done

printf 'cargo_deny_offline=passed manifests=%d\n' "$#"
