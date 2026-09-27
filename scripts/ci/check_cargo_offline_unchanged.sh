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

authority_home=$(metadata_value authority_home)
cargo_home=$(metadata_value cargo_home)
expected_cargo_home_identity=$(metadata_value cargo_home_identity)
cargo_bin=$(metadata_value cargo_bin)
expected_cargo_bin_identity=$(metadata_value cargo_bin_identity)
expected_cargo_bin_sha256=$(metadata_value cargo_bin_sha256)
rustc_bin=$(metadata_value rustc_bin)
expected_rustc_bin_identity=$(metadata_value rustc_bin_identity)
expected_rustc_bin_sha256=$(metadata_value rustc_bin_sha256)
toolchain_bin=$(metadata_value toolchain_bin)
stamp=$(metadata_value stamp)
expected_stamp_hash=$(metadata_value stamp_sha256)
expected_authority_home=$(cd "${HOME:?HOME is required}" && pwd -P)/.cargo
[[ "$authority_home" == "$expected_authority_home" ]] \
  || fail "Cargo authority changed during the job"
[[ "${TRNM_CARGO_AUTHORITY_HOME:-$expected_authority_home}" == "$authority_home" ]] \
  || fail "Cargo authority environment changed during the job"
[[ -d "$cargo_home" && ! -L "$cargo_home" ]] \
  || fail "job-scoped CARGO_HOME changed or became a symlink"
case "$cargo_home" in
  "$runner_temp"/trnm-cargo-home-*) ;;
  *) fail "job-scoped CARGO_HOME escaped RUNNER_TEMP" ;;
esac
[[ "${CARGO_HOME:-}" == "$cargo_home" ]] || fail "CARGO_HOME changed during the job"
[[ "${TRNM_CARGO_BIN:-}" == "$cargo_bin" ]] || fail "TRNM_CARGO_BIN changed during the job"
[[ "${TRNM_RUSTC_BIN:-}" == "$rustc_bin" ]] || fail "TRNM_RUSTC_BIN changed during the job"
[[ "${TRNM_TOOLCHAIN_BIN:-}" == "$toolchain_bin" ]] || fail "TRNM_TOOLCHAIN_BIN changed during the job"
[[ "$(command -v cargo)" == "$cargo_bin" ]] || fail "Cargo no longer resolves from the pinned toolchain"
for tool_record in   "$cargo_bin:$expected_cargo_bin_identity:$expected_cargo_bin_sha256"   "$rustc_bin:$expected_rustc_bin_identity:$expected_rustc_bin_sha256"; do
  tool=${tool_record%%:*}
  rest=${tool_record#*:}
  expected_identity=${rest%:*}
  expected_hash=${tool_record##*:}
  if [[ ! -f "$tool" || -L "$tool" ]]; then
    fail "pinned tool disappeared or became a symlink: $tool"
    continue
  fi
  [[ "$(stat -c '%d:%i:%u:%a' "$tool")" == "$expected_identity" ]] \
    || fail "pinned tool identity changed: $tool"
  [[ "$(sha256sum -- "$tool" | awk '{print $1}')" == "$expected_hash" ]] \
    || fail "pinned tool bytes changed: $tool"
done
if [[ -d "$cargo_home" && ! -L "$cargo_home" ]]; then
  [[ "$(stat -c '%d:%i:%u:%a' "$cargo_home")" == "$expected_cargo_home_identity" ]] \
    || fail "job-scoped CARGO_HOME identity or mode changed"
  for registry_input in cache index; do
    link="$cargo_home/registry/$registry_input"
    [[ -L "$link" && "$(readlink -- "$link")" == "$authority_home/registry/$registry_input" ]] \
      || fail "job-scoped Cargo registry authority link changed: $registry_input"
  done
  for credential in credentials credentials.toml; do
    [[ ! -e "$cargo_home/$credential" && ! -L "$cargo_home/$credential" ]] \
      || fail "job-scoped CARGO_HOME acquired a credentials file: $credential"
  done
fi

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

if ((status == 0)); then
  case "$cargo_home" in
    "$runner_temp"/trnm-cargo-home-*) rm -rf -- "$cargo_home" ;;
    *) fail "refusing to remove non-job Cargo home" ;;
  esac
fi

((status == 0)) || exit 1
printf 'cargo_offline_unchanged=passed roots=%d manifests=%d job_cargo_home=removed\n' \
  "${#locks[@]}" "${#manifest_paths[@]}"
