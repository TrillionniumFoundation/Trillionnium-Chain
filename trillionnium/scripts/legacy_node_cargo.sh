#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
TRILLIONNIUM_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
MANIFEST="$TRILLIONNIUM_ROOT/crates/trnm-node/Cargo.toml"
LOCKFILE="$TRILLIONNIUM_ROOT/crates/trnm-node/Cargo.lock"

fail() {
  printf 'legacy-node-cargo: %s\n' "$*" >&2
  exit 2
}

[[ $# -ge 1 ]] || fail "usage: $0 <run|build|test|check|clippy> [cargo arguments...]"
[[ -f "$MANIFEST" ]] || fail "standalone manifest missing: $MANIFEST"
[[ -f "$LOCKFILE" ]] || fail "standalone lockfile missing: $LOCKFILE"

subcommand="$1"
shift
case "$subcommand" in
  run|build|test|check|clippy) ;;
  *) fail "unsupported cargo subcommand: $subcommand" ;;
esac

for arg in "$@"; do
  case "$arg" in
    -p|--package|-p=*|--package=*|-p?*)
      fail "do not select packages through the active workspace; the helper owns the standalone trnm-node manifest boundary"
      ;;
  esac
done

# trnm-node is intentionally excluded from the active native workspace. Keep
# every legacy/migration rehearsal on its standalone manifest and lock while
# sharing the repository target directory expected by existing launch scripts.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TRILLIONNIUM_ROOT/target}"
exec cargo "$subcommand" --manifest-path "$MANIFEST" --locked "$@"
