#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
FUZZ_ROOT="$ROOT/trillionnium/fuzz"
FUZZ_TOOLCHAIN="${TRNM_FUZZ_TOOLCHAIN:-nightly-2026-07-27}"
SECONDS_PER_TARGET="${TRNM_FUZZ_SMOKE_SECONDS:-15}"
MAX_LEN="${TRNM_FUZZ_MAX_LEN:-2162688}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trnm-canonical-fuzz-smoke.XXXXXX")"

cleanup() {
  rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT

if [[ ! "$SECONDS_PER_TARGET" =~ ^[0-9]+$ ]] \
  || ((SECONDS_PER_TARGET < 1 || SECONDS_PER_TARGET > 60)); then
  printf '%s\n' \
    "TRNM_FUZZ_SMOKE_SECONDS must be an integer from 1 through 60" >&2
  exit 2
fi
if [[ ! "$MAX_LEN" =~ ^[0-9]+$ ]] || ((MAX_LEN < 1 || MAX_LEN > 2162688)); then
  printf '%s\n' "TRNM_FUZZ_MAX_LEN must be between 1 and 2162688" >&2
  exit 2
fi
if ! cargo +"$FUZZ_TOOLCHAIN" fuzz --help >/dev/null 2>&1; then
  printf '%s\n' \
    "cargo-fuzz 0.13.2 is required; see trillionnium/fuzz/README.md" >&2
  exit 2
fi
FUZZ_VERSION="$(cargo +"$FUZZ_TOOLCHAIN" fuzz --version)"
if [[ "$FUZZ_VERSION" != "cargo-fuzz 0.13.2" ]]; then
  printf 'expected cargo-fuzz 0.13.2, found %s\n' "$FUZZ_VERSION" >&2
  exit 2
fi

cd "$FUZZ_ROOT"
for target in canonical_tx_json signed_envelope_json poco_cev0_exact; do
  mkdir -p "$WORK_ROOT/$target"
  cp -a "$FUZZ_ROOT/corpus/$target/." "$WORK_ROOT/$target/"
  printf 'bounded_fuzz_smoke target=%s seconds=%s max_len=%s\n' \
    "$target" "$SECONDS_PER_TARGET" "$MAX_LEN"
  cargo +"$FUZZ_TOOLCHAIN" fuzz run "$target" "$WORK_ROOT/$target" -- \
    "-max_total_time=$SECONDS_PER_TARGET" \
    -timeout=10 \
    -rss_limit_mb=2048 \
    "-max_len=$MAX_LEN"
done

printf '%s\n' \
  "bounded_fuzz_smoke=passed scope=integration-only long_campaign=false"
