#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${TRNM_LEGACY_HARNESS_ACKNOWLEDGED:-0}" != "1" ]]; then
  echo "refusing to build frozen legacy harness package; set TRNM_LEGACY_HARNESS_ACKNOWLEDGED=1 for reproducibility audit only" >&2
  exit 2
fi

args=(build)
: "${TRNM_RELEASE_SIGNING_KEY:?TRNM_RELEASE_SIGNING_KEY must name an owner-only Ed25519 PEM private key}"
args+=(--signing-key "$TRNM_RELEASE_SIGNING_KEY")

if [[ -n "${TRNM_DEVNET_RELEASE_OUT_DIR:-}" ]]; then
  args+=(--output-dir "$TRNM_DEVNET_RELEASE_OUT_DIR")
fi
if [[ -n "${TRNM_DEVNET_TARGET_DIR:-}" ]]; then
  args+=(--target-dir "$TRNM_DEVNET_TARGET_DIR")
fi
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  args+=(--source-date-epoch "$SOURCE_DATE_EPOCH")
fi
if [[ "${TRNM_DEVNET_ALLOW_DIRTY:-0}" == "1" ]]; then
  args+=(--allow-dirty)
fi

exec python3 "$script_dir/trnm_chain_devnet_v1.py" "${args[@]}"
