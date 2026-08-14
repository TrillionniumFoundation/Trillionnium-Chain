#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
component_lock=${1:-}
[[ -n "$component_lock" && $# -eq 1 ]] || {
  echo "usage: $0 /absolute/path/to/integration/components.lock.json" >&2
  exit 64
}
[[ "$component_lock" == /* ]] || {
  echo "ERROR: component lock must be an absolute path" >&2
  exit 64
}

for command_name in awk basename cargo cmp dirname env find git id install mktemp python3 rustc sha256sum stat sync tar; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: Paper Raid Chain SBOM gate requires %s\n' "$command_name" >&2
    exit 1
  }
done

cd "$root"
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
  echo "ERROR: immutable Paper Raid Chain SBOM gate requires a clean committed worktree" >&2
  exit 1
}
[[ -f "$component_lock" && ! -L "$component_lock" ]] || {
  echo "ERROR: Integration component lock must be a regular non-symlink file" >&2
  exit 1
}
integration_root=$(dirname -- "$component_lock")
producer_contract=$integration_root/scripts/paper-raid-chain-release-producer-v1.json
[[ -f "$producer_contract" && ! -L "$producer_contract" ]] || {
  echo "ERROR: Integration release producer contract must be a regular non-symlink file" >&2
  exit 1
}
physical_integration_root=$(cd "$integration_root" && pwd -P)
[[ "$physical_integration_root" == "$integration_root" ]] || {
  echo "ERROR: Integration component lock must use its physical repository path" >&2
  exit 1
}
publisher=$integration_root/scripts/publish-paper-raid-chain-release-evidence.py
[[ -f "$publisher" && ! -L "$publisher" ]] || {
  echo "ERROR: Integration release evidence publisher must be a regular non-symlink file" >&2
  exit 1
}

revision=$(git rev-parse HEAD)
source_tree=$(git rev-parse 'HEAD^{tree}')
source_epoch=$(git show -s --format=%ct "$revision")
[[ "$revision" =~ ^[0-9a-f]{40}$ && "$source_tree" =~ ^[0-9a-f]{40}$ && "$source_epoch" =~ ^[0-9]+$ ]] || {
  echo "ERROR: source revision metadata is not canonical" >&2
  exit 1
}

umask 077
scratch=$(mktemp -d /tmp/trnm-chain-paper-raid-sbom.XXXXXXXX)
scratch_identity=$(stat -c '%d:%i' -- "$scratch")
cleanup() {
  local original_status=$?
  trap - EXIT
  set +e
  if [[ -n ${scratch:-} ]]; then
    case "$scratch" in
      /tmp/trnm-chain-paper-raid-sbom.*)
        if [[ -d "$scratch" && ! -L "$scratch" \
          && $(stat -c '%d:%i' -- "$scratch" 2>/dev/null) == "${scratch_identity:-}" ]]; then
          find "$scratch" -depth -delete
        else
          echo "ERROR: refusing to clean replaced build scratch path" >&2
        fi
        ;;
      *) echo "ERROR: refusing to clean unexpected build scratch path" >&2 ;;
    esac
  fi
  exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

gate_user_home=${HOME:?HOME must identify the invoking user toolchain home}
gate_cargo_home=${CARGO_HOME:-$gate_user_home/.cargo}
gate_rustup_home=${RUSTUP_HOME:-$gate_user_home/.rustup}
cargo_environment=(
  env -i
  "PATH=$PATH"
  "HOME=$gate_user_home"
  "CARGO_HOME=$gate_cargo_home"
  "RUSTUP_HOME=$gate_rustup_home"
  "CARGO_INCREMENTAL=0"
  "CARGO_NET_OFFLINE=true"
  "SOURCE_DATE_EPOCH=$source_epoch"
  "LANG=C"
  "LC_ALL=C"
  "TZ=UTC"
)

mkdir -m 0700 \
  "$scratch/source" \
  "$scratch/target-a" \
  "$scratch/target-b" \
  "$scratch/artifacts-a" \
  "$scratch/artifacts-b" \
  "$scratch/metadata-target"
git archive --format=tar "$revision" | tar -xf - -C "$scratch/source"
archive_symlink=$(find "$scratch/source" -type l -print -quit)
[[ -z "$archive_symlink" ]] || {
  printf 'ERROR: archived source symlink is forbidden: %s\n' "$archive_symlink" >&2
  exit 1
}

# Copy the external lock from a single O_NOFOLLOW descriptor. The final digest
# check below also detects a caller changing the external file during the run.
python3 - "$component_lock" "$scratch/components.lock.json" <<'PY'
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit("component lock is not a regular file")
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
finally:
    os.close(descriptor)
out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
try:
    os.write(out, b"".join(chunks))
    os.fsync(out)
finally:
    os.close(out)
PY
python3 - "$producer_contract" "$scratch/producer-contract.json" <<'PY'
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit("producer contract is not one regular link")
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
finally:
    os.close(descriptor)
out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
try:
    os.write(out, b"".join(chunks))
    os.fsync(out)
finally:
    os.close(out)
PY
component_lock_snapshot_sha256=$(sha256sum "$scratch/components.lock.json" | awk '{print $1}')
[[ $(sha256sum "$component_lock" | awk '{print $1}') == "$component_lock_snapshot_sha256" ]] || {
  echo "ERROR: Integration component lock changed while it was snapshotted" >&2
  exit 1
}
producer_contract_snapshot_sha256=$(sha256sum "$scratch/producer-contract.json" | awk '{print $1}')
[[ $(sha256sum "$producer_contract" | awk '{print $1}') == "$producer_contract_snapshot_sha256" ]] || {
  echo "ERROR: Integration release producer contract changed while it was snapshotted" >&2
  exit 1
}

archive_root=$scratch/source
workspace=$archive_root/trillionnium
metadata=$scratch/cargo-metadata.raw.json
metadata_evidence=$scratch/cargo-metadata.evidence.json
cargo_version_evidence=$scratch/cargo-version-verbose.txt
rustc_version_evidence=$scratch/rustc-version-verbose.txt
"${cargo_environment[@]}" cargo --version --verbose >"$cargo_version_evidence"
"${cargo_environment[@]}" rustc -vV >"$rustc_version_evidence"
(
  cd "$workspace"
  "${cargo_environment[@]}" CARGO_TARGET_DIR="$scratch/metadata-target" \
    cargo metadata --frozen --format-version 1
) >"$metadata"

build_candidate() {
  local target_dir=$1
  (
    cd "$workspace"
    "${cargo_environment[@]}" CARGO_TARGET_DIR="$target_dir" \
      cargo build --frozen --release -p trnm-consensus-app --bin trnm-cometbft-app
    "${cargo_environment[@]}" CARGO_TARGET_DIR="$target_dir" \
      cargo build --frozen --release -p trnm-finality-verifier --bin trnm-research-receipt-v2
  )
}

build_candidate "$scratch/target-a"
build_candidate "$scratch/target-b"

for binary in trnm-cometbft-app trnm-research-receipt-v2; do
  install -m 0500 \
    "$scratch/target-a/release/$binary" "$scratch/artifacts-a/$binary"
  install -m 0500 \
    "$scratch/target-b/release/$binary" "$scratch/artifacts-b/$binary"
  sync -f "$scratch/artifacts-a/$binary"
  sync -f "$scratch/artifacts-b/$binary"
  [[ $(stat -c '%h' "$scratch/artifacts-a/$binary") == 1 \
    && $(stat -c '%h' "$scratch/artifacts-b/$binary") == 1 ]] || {
    printf 'ERROR: staged release artifact is not one regular link: %s\n' "$binary" >&2
    exit 1
  }
  cmp --silent "$scratch/target-a/release/$binary" "$scratch/artifacts-a/$binary"
  cmp --silent "$scratch/target-b/release/$binary" "$scratch/artifacts-b/$binary"
  cmp --silent "$scratch/artifacts-a/$binary" "$scratch/artifacts-b/$binary" || {
    printf 'ERROR: isolated release builds differ byte-for-byte: %s\n' "$binary" >&2
    exit 1
  }
done

generator=$archive_root/scripts/generate-paper-raid-chain-sbom.py
verifier=$archive_root/scripts/verify-paper-raid-chain-sbom.py
library=$archive_root/scripts/paper_raid_chain_sbom_lib.py
gate=$archive_root/scripts/check-paper-raid-chain-sbom.sh
sbom=$scratch/trillionnium-chain-paper-raid.cdx.json
provenance=$scratch/trillionnium-chain-paper-raid.provenance.json
common_arguments=(
  --metadata "$metadata"
  --source "$archive_root"
  --revision "$revision"
  --tree "$source_tree"
  --component-lock "$scratch/components.lock.json"
  --producer-contract "$scratch/producer-contract.json"
  --cargo-version-evidence "$cargo_version_evidence"
  --rustc-version-evidence "$rustc_version_evidence"
  --binary-a "trnm-cometbft-app=$scratch/artifacts-a/trnm-cometbft-app"
  --binary-a "trnm-research-receipt-v2=$scratch/artifacts-a/trnm-research-receipt-v2"
  --binary-b "trnm-cometbft-app=$scratch/artifacts-b/trnm-cometbft-app"
  --binary-b "trnm-research-receipt-v2=$scratch/artifacts-b/trnm-research-receipt-v2"
  --tool "gate=$gate"
  --tool "generator=$generator"
  --tool "library=$library"
  --tool "verifier=$verifier"
)

python3 "$generator" "${common_arguments[@]}" \
  --metadata-evidence-output "$metadata_evidence" \
  --output "$sbom" --provenance-output "$provenance"
python3 "$verifier" "${common_arguments[@]}" \
  --metadata-evidence "$metadata_evidence" \
  --sbom "$sbom" --provenance "$provenance" >/dev/null

[[ $(git rev-parse HEAD) == "$revision" \
  && $(git rev-parse 'HEAD^{tree}') == "$source_tree" \
  && -z $(git status --porcelain=v1 --untracked-files=all) ]] || {
  echo "ERROR: Chain repository changed while the immutable gate was running" >&2
  exit 1
}
[[ $(sha256sum "$component_lock" | awk '{print $1}') == "$component_lock_snapshot_sha256" ]] || {
  echo "ERROR: Integration component lock changed while the immutable gate was running" >&2
  exit 1
}
[[ $(sha256sum "$producer_contract" | awk '{print $1}') == "$producer_contract_snapshot_sha256" ]] || {
  echo "ERROR: Integration release producer contract changed while the immutable gate was running" >&2
  exit 1
}

sbom_sha256=$(sha256sum "$sbom" | awk '{print $1}')
python3 "$publisher" \
  --component-lock "$component_lock" \
  --chain-source "$root" \
  --sbom "$sbom" \
  --provenance "$provenance" \
  --cargo-metadata "$metadata_evidence" \
  --cargo-version-evidence "$cargo_version_evidence" \
  --rustc-version-evidence "$rustc_version_evidence" \
  --binary-a "consensus_app=$scratch/artifacts-a/trnm-cometbft-app" \
  --binary-a "receipt_v4=$scratch/artifacts-a/trnm-research-receipt-v2" \
  --binary-b "consensus_app=$scratch/artifacts-b/trnm-cometbft-app" \
  --binary-b "receipt_v4=$scratch/artifacts-b/trnm-research-receipt-v2"

# A successful gate must also remove the build scratch before printing PASS.
[[ -d "$scratch" && ! -L "$scratch" \
  && $(stat -c '%d:%i' -- "$scratch") == "$scratch_identity" ]]
find "$scratch" -depth -delete
[[ ! -e "$scratch" && ! -L "$scratch" ]]
scratch=
printf 'Paper Raid Chain release SBOM/provenance gate: PASS revision=%s tree=%s sbom_sha256=%s\n' \
  "$revision" "$source_tree" "$sbom_sha256"
