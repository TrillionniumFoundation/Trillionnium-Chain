#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: check_preprovisioned_rust_toolchain.sh --toolchain TOOLCHAIN [--component clippy|rustfmt]" >&2
  exit 2
}

toolchain=""
components=()
while (($#)); do
  case "$1" in
    --toolchain)
      (($# >= 2)) || usage
      [[ -z "$toolchain" ]] || {
        echo "duplicate --toolchain option" >&2
        exit 2
      }
      toolchain=$2
      shift 2
      ;;
    --component)
      (($# >= 2)) || usage
      components+=("$2")
      shift 2
      ;;
    *) usage ;;
  esac
done
[[ -n "$toolchain" ]] || usage

[[ -z "${RUSTUP_TOOLCHAIN:-}" ]] || {
  echo "RUSTUP_TOOLCHAIN must not override the repository toolchain" >&2
  exit 2
}
expected_rustup_home="${HOME:?HOME is required}/.rustup"
[[ "${RUSTUP_HOME:-$expected_rustup_home}" == "$expected_rustup_home" ]] || {
  echo "RUSTUP_HOME must remain at the hardened runner path" >&2
  exit 2
}

assert_trusted_ancestors() {
  local current=$1 label=$2 uid mode
  while :; do
    uid=$(stat -c '%u' "$current")
    mode=$(stat -c '%a' "$current")
    if [[ "$uid" != "0" ]] || (( (8#$mode & 0022) != 0 )); then
      printf '%s ancestor is not root-owned and non-group/other-writable: %s uid=%s mode=%s\n' \
        "$label" "$current" "$uid" "$mode" >&2
      exit 2
    fi
    [[ "$current" == "/" ]] && break
    current=$(dirname "$current")
    [[ -n "$current" ]] || current=/
  done
}

assert_root_readonly_tree() {
  local tree=$1 label=$2 bad
  [[ -d "$tree" && ! -L "$tree" ]] || {
    echo "$label must be a real directory: $tree" >&2
    exit 2
  }
  bad=$(find "$tree" \( -type d -o -type f \) \
    \( ! -user root -o -perm /0222 \) -print -quit)
  [[ -z "$bad" ]] || {
    echo "$label contains a non-root-owned or writable authority entry: $bad" >&2
    exit 2
  }
  bad=$(find "$tree" ! -type d ! -type f ! -type l -print -quit)
  [[ -z "$bad" ]] || {
    echo "$label contains an unsupported filesystem entry: $bad" >&2
    exit 2
  }
  bad=$(find "$tree" -type l ! -user root -print -quit)
  [[ -z "$bad" ]] || {
    echo "$label contains a non-root-owned symlink: $bad" >&2
    exit 2
  }
}

rustup_home=$(cd "$expected_rustup_home" && pwd -P)
cargo_bin_home=$(cd "$HOME/.cargo/bin" && pwd -P)
[[ "$rustup_home" == "$(cd "$HOME" && pwd -P)/.rustup" ]] || {
  echo "RUSTUP_HOME resolved outside the hardened runner path" >&2
  exit 2
}
assert_trusted_ancestors "$rustup_home" RUSTUP_HOME
assert_trusted_ancestors "$cargo_bin_home" Cargo-bin
assert_root_readonly_tree "$rustup_home" "Rust toolchain authority"
assert_root_readonly_tree "$cargo_bin_home" "Cargo binary authority"

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
toolchain_file="$root/rust-toolchain.toml"
[[ -f "$toolchain_file" && ! -L "$toolchain_file" ]] || {
  echo "missing non-symlink repository rust-toolchain.toml" >&2
  exit 2
}
git -C "$root" diff --quiet -- rust-toolchain.toml \
  && git -C "$root" diff --cached --quiet -- rust-toolchain.toml || {
    echo "repository rust-toolchain.toml must be clean" >&2
    exit 2
  }
[[ "$(sha256sum "$toolchain_file" | awk '{print $1}')" \
  == "24ef3b9d3edbd850aa386cb0a98e10450b0030991a4537cb359f54d49dbbb33a" ]] || {
  echo "repository rust-toolchain.toml differs from the frozen 1.95.0 policy" >&2
  exit 2
}

case "$toolchain" in
  1.95.0)
    expected_commit=59807616e1fa2540724bfbac14d7976d7e4a3860
    ;;
  nightly-2026-07-27)
    expected_commit=dc3f85158a955a87a6e4363af1fbe9cf2d063cce
    ;;
  *)
    echo "unapproved preprovisioned Rust toolchain: $toolchain" >&2
    exit 2
    ;;
esac

rustup_proxy="$cargo_bin_home/rustup"
cargo_proxy="$cargo_bin_home/cargo"
rustc_proxy="$cargo_bin_home/rustc"
[[ "$(command -v rustup)" == "$rustup_proxy" \
  && "$(command -v cargo)" == "$cargo_proxy" \
  && "$(command -v rustc)" == "$rustc_proxy" ]] || {
  echo "Rust proxies must resolve from the hardened Cargo binary authority" >&2
  exit 2
}
[[ "$(readlink -f "$cargo_proxy")" == "$rustup_proxy" \
  && "$(readlink -f "$rustc_proxy")" == "$rustup_proxy" ]] || {
  echo "Cargo and rustc proxies must resolve to the hardened rustup binary" >&2
  exit 2
}
rustc_bin=$("$rustup_proxy" which --toolchain "$toolchain" rustc 2>/dev/null) || {
  echo "missing preprovisioned rustc toolchain: $toolchain" >&2
  exit 2
}
cargo_bin=$("$rustup_proxy" which --toolchain "$toolchain" cargo 2>/dev/null) || {
  echo "missing preprovisioned Cargo toolchain: $toolchain" >&2
  exit 2
}
rustc_verbose=$("$rustc_bin" -vV)
actual_commit=$(sed -n 's/^commit-hash: //p' <<<"$rustc_verbose")
actual_host=$(sed -n 's/^host: //p' <<<"$rustc_verbose")
[[ "$actual_commit" == "$expected_commit" ]] || {
  printf 'rustc commit mismatch: toolchain=%s expected=%s actual=%s\n' \
    "$toolchain" "$expected_commit" "${actual_commit:-<missing>}" >&2
  exit 2
}
[[ "$actual_host" == "x86_64-unknown-linux-gnu" ]] || {
  printf 'rustc host mismatch: expected=x86_64-unknown-linux-gnu actual=%s\n' \
    "${actual_host:-<missing>}" >&2
  exit 2
}
"$cargo_bin" --version >/dev/null

plain_rustc=$("$rustc_proxy" -vV)
plain_commit=$(sed -n 's/^commit-hash: //p' <<<"$plain_rustc")
[[ "$plain_commit" == "59807616e1fa2540724bfbac14d7976d7e4a3860" ]] || {
  echo "plain rustc does not resolve to the repository-pinned 1.95.0 toolchain" >&2
  exit 2
}
"$cargo_proxy" --version >/dev/null

declare -A seen=()
for component in "${components[@]}"; do
  [[ -z "${seen[$component]:-}" ]] || {
    echo "duplicate Rust component request: $component" >&2
    exit 2
  }
  seen[$component]=1
  case "$component" in
    clippy)
      "$rustup_proxy" which --toolchain "$toolchain" cargo-clippy >/dev/null 2>&1 || {
        echo "missing preprovisioned clippy component: $toolchain" >&2
        exit 2
      }
      ;;
    rustfmt)
      "$rustup_proxy" which --toolchain "$toolchain" rustfmt >/dev/null 2>&1 || {
        echo "missing preprovisioned rustfmt component: $toolchain" >&2
        exit 2
      }
      ;;
    *)
      echo "unsupported Rust component verification: $component" >&2
      exit 2
      ;;
  esac
done

printf 'preprovisioned_rust_toolchain=passed toolchain=%s commit=%s host=%s components=%d\n' \
  "$toolchain" "$actual_commit" "$actual_host" "${#components[@]}"
