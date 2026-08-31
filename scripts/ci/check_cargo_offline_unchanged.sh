#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || $1 != "--state" ]]; then
  echo "usage: check_cargo_offline_unchanged.sh --state DIR" >&2
  exit 2
fi
state_dir=$2
runner_temp=${RUNNER_TEMP:?RUNNER_TEMP must name the job-scoped temporary directory}
runner_temp=$(cd "$runner_temp" && pwd -P)
case "$state_dir" in
  "$runner_temp"/*) ;;
  *)
    echo "offline state must stay below RUNNER_TEMP: $state_dir" >&2
    exit 2
    ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" ]] || {
  echo "missing offline-ready state: $state_dir" >&2
  exit 2
}
for file in metadata pairs.tsv locks.tsv manifests.sha256; do
  [[ -f "$state_dir/$file" && ! -L "$state_dir/$file" ]] || {
    echo "invalid offline-ready state file: $state_dir/$file" >&2
    exit 2
  }
done

metadata_value() {
  local key=$1
  sed -n "s/^${key}=//p" "$state_dir/metadata" | tail -n 1
}

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
[[ "$(metadata_value repo_root)" == "$root" ]] || {
  echo "offline-ready state belongs to a different checkout" >&2
  exit 2
}
cd "$root"

status=0
fail() {
  printf '%s\n' "$*" >&2
  status=1
}

[[ "${CARGO_NET_OFFLINE:-}" == "true" ]] || fail "CARGO_NET_OFFLINE changed during the job"
[[ "${CARGO_CACHE_AUTO_CLEAN_FREQUENCY:-}" == "never" ]] \
  || fail "CARGO_CACHE_AUTO_CLEAN_FREQUENCY changed during the job"
cargo_home=$(metadata_value cargo_home)
stamp=$(metadata_value stamp)
expected_stamp_hash=$(metadata_value stamp_sha256)
[[ -d "$cargo_home" && ! -L "$cargo_home" ]] || fail "CARGO_HOME changed or became a symlink"
[[ "${CARGO_HOME:-${HOME:?}/.cargo}" == "$cargo_home" ]] || fail "CARGO_HOME changed during the job"
if [[ ! -f "$stamp" || -L "$stamp" ]]; then
  fail "offline cache stamp disappeared or became a symlink"
else
  [[ "$(stat -c '%u' "$stamp")" == "0" ]] || fail "offline cache stamp is no longer root-owned"
  stamp_mode=$(stat -c '%a' "$stamp")
  (( (8#$stamp_mode & 0222) == 0 )) || fail "offline cache stamp became writable"
  [[ "$(sha256sum -- "$stamp" | awk '{print $1}')" == "$expected_stamp_hash" ]] \
    || fail "offline cache stamp changed during the job"
fi

locks=()
original_modes=()
while IFS=$'\t' read -r expected_hash original_mode expected_inode lock; do
  locks+=("$lock")
  original_modes+=("$original_mode")
  if [[ ! -f "$lock" || -L "$lock" ]]; then
    fail "Cargo lock disappeared or became a symlink: $lock"
    continue
  fi
  [[ "$(sha256sum -- "$lock" | awk '{print $1}')" == "$expected_hash" ]] \
    || fail "Cargo lock content changed during the job: $lock"
  [[ "$(stat -c '%d:%i' "$lock")" == "$expected_inode" ]] \
    || fail "Cargo lock inode changed during the job: $lock"
  current_mode=$(stat -c '%a' "$lock")
  (( (8#$current_mode & 0222) == 0 )) || fail "Cargo lock became writable during the job: $lock"
done <"$state_dir/locks.tsv"

if ! sha256sum --check --status "$state_dir/manifests.sha256"; then
  fail "tracked Cargo.toml content changed during the job"
fi

mapfile -d '' -t current_manifests < <(
  git ls-files -z -- 'Cargo.toml' ':(glob)**/Cargo.toml' | LC_ALL=C sort -z
)
if [[ ${#current_manifests[@]} -ne $(wc -l <"$state_dir/manifests.sha256") ]]; then
  fail "tracked Cargo.toml set changed during the job"
fi

manifest_paths=()
while read -r _hash manifest; do
  manifest_paths+=("$manifest")
done <"$state_dir/manifests.sha256"
if ! git diff --quiet -- "${manifest_paths[@]}" "${locks[@]}" \
  || ! git diff --cached --quiet -- "${manifest_paths[@]}" "${locks[@]}"; then
  fail "tracked Cargo inputs are dirty after the job"
fi

for i in "${!locks[@]}"; do
  [[ -e "${locks[$i]}" && ! -L "${locks[$i]}" ]] || continue
  chmod "${original_modes[$i]}" -- "${locks[$i]}" || status=1
done

((status == 0)) || exit 1
printf 'cargo_offline_unchanged=passed roots=%d manifests=%d\n' \
  "${#locks[@]}" "${#manifest_paths[@]}"
