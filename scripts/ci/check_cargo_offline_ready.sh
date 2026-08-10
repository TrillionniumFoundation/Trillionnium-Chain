#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: check_cargo_offline_ready.sh --toolchain TOOLCHAIN --state DIR \
  [--target TARGET] MANIFEST:LOCK [MANIFEST:LOCK ...]
EOF
  exit 2
}

toolchain=""
state_dir=""
target="x86_64-unknown-linux-gnu"
target_seen=0
pairs=()
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
    --state)
      (($# >= 2)) || usage
      [[ -z "$state_dir" ]] || {
        echo "duplicate --state option" >&2
        exit 2
      }
      state_dir=$2
      shift 2
      ;;
    --target)
      (($# >= 2)) || usage
      ((target_seen == 0)) || {
        echo "duplicate --target option" >&2
        exit 2
      }
      target=$2
      target_seen=1
      shift 2
      ;;
    --help|-h)
      usage
      ;;
    --*)
      printf 'unsupported offline-ready option: %s\n' "$1" >&2
      usage
      ;;
    *)
      pairs+=("$1")
      shift
      ;;
  esac
done

[[ -n "$toolchain" && -n "$state_dir" && ${#pairs[@]} -gt 0 ]] || usage
[[ "${CARGO_NET_OFFLINE:-}" == "true" ]] || {
  echo "CARGO_NET_OFFLINE must be exactly true" >&2
  exit 2
}
[[ "${CARGO_CACHE_AUTO_CLEAN_FREQUENCY:-}" == "never" ]] || {
  echo "CARGO_CACHE_AUTO_CLEAN_FREQUENCY must be exactly never" >&2
  exit 2
}
[[ "$toolchain" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "unsafe Rust toolchain identifier: $toolchain" >&2
  exit 2
}
[[ "$target" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "unsafe Rust target identifier: $target" >&2
  exit 2
}

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
cd "$root"

runner_temp=${RUNNER_TEMP:?RUNNER_TEMP must name the job-scoped temporary directory}
runner_temp=$(cd "$runner_temp" && pwd -P)
case "$state_dir" in
  "$runner_temp"/*) ;;
  *)
    echo "offline state must stay below RUNNER_TEMP: $state_dir" >&2
    exit 2
    ;;
esac
[[ ! -e "$state_dir" && ! -L "$state_dir" ]] || {
  echo "offline state already exists: $state_dir" >&2
  exit 2
}

cargo_home=${CARGO_HOME:-${HOME:?HOME is required when CARGO_HOME is unset}/.cargo}
[[ -d "$cargo_home" && ! -L "$cargo_home" ]] || {
  echo "CARGO_HOME must be a real directory, not a symlink: $cargo_home" >&2
  exit 2
}
cargo_home=$(cd "$cargo_home" && pwd -P)
expected_cargo_home=$(cd "${HOME:?HOME is required}" && pwd -P)/.cargo
[[ "$cargo_home" == "$expected_cargo_home" ]] || {
  echo "CARGO_HOME must remain at the hardened runner path: $expected_cargo_home" >&2
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
}

assert_trusted_ancestors "$cargo_home" CARGO_HOME
assert_root_readonly_tree "$cargo_home/registry" "Cargo registry cache"
stamp="$cargo_home/trnm-chain-offline-cache-v2.sha256"
[[ -f "$stamp" && ! -L "$stamp" && -r "$stamp" ]] || {
  echo "missing readable non-symlink offline cache stamp: $stamp" >&2
  exit 2
}
[[ "$(stat -c '%u' "$stamp")" == "0" ]] || {
  echo "offline cache stamp must be owned by root: $stamp" >&2
  exit 2
}
stamp_mode=$(stat -c '%a' "$stamp")
(( (8#$stamp_mode & 0222) == 0 )) || {
  echo "offline cache stamp must be read-only: $stamp mode=$stamp_mode" >&2
  exit 2
}

declare -A stamped_paths=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9_./-]+)$ ]] || {
    echo "malformed offline cache stamp line" >&2
    exit 2
  }
  stamp_hash=${BASH_REMATCH[1]}
  stamp_path=${BASH_REMATCH[2]}
  [[ "$stamp_path" != /* && "$stamp_path" != ".." && "$stamp_path" != ../* \
    && "$stamp_path" != */../* && "$stamp_path" != */.. ]] || {
    echo "unsafe lock path in offline cache stamp: $stamp_path" >&2
    exit 2
  }
  [[ -z "${stamped_paths[$stamp_path]:-}" ]] || {
    echo "duplicate lock path in offline cache stamp: $stamp_path" >&2
    exit 2
  }
  stamped_paths[$stamp_path]=$stamp_hash
done <"$stamp"
((${#stamped_paths[@]} > 0)) || {
  echo "offline cache stamp is empty: $stamp" >&2
  exit 2
}

rustup_proxy="$HOME/.cargo/bin/rustup"
[[ "$(command -v rustup)" == "$rustup_proxy" ]] || {
  echo "rustup must resolve from the hardened Cargo binary authority" >&2
  exit 2
}
cargo_bin=$("$rustup_proxy" which --toolchain "$toolchain" cargo 2>/dev/null) || {
  echo "runner is missing pinned Cargo toolchain: $toolchain" >&2
  exit 2
}
rustc_bin=$("$rustup_proxy" which --toolchain "$toolchain" rustc 2>/dev/null) || {
  echo "runner is missing pinned rustc toolchain: $toolchain" >&2
  exit 2
}
host_target=$("$rustc_bin" -vV | sed -n 's/^host: //p')
[[ "$host_target" == "$target" ]] || {
  printf 'pinned toolchain host mismatch: expected=%s actual=%s\n' \
    "$target" "${host_target:-<missing>}" >&2
  exit 2
}

declare -A seen_manifests=()
declare -A seen_locks=()
manifests=()
locks=()
lock_modes=()
lock_inodes=()
for pair in "${pairs[@]}"; do
  [[ "$pair" == *:* && "$pair" != *:*:* ]] || {
    echo "manifest/lock input must use MANIFEST:LOCK: $pair" >&2
    exit 2
  }
  manifest=${pair%%:*}
  lock=${pair#*:}
  for path in "$manifest" "$lock"; do
    [[ "$path" =~ ^[A-Za-z0-9_./-]+$ && "$path" != /* && "$path" != ".." \
      && "$path" != ../* && "$path" != */../* && "$path" != */.. ]] || {
      echo "unsafe repository-relative Cargo input: $path" >&2
      exit 2
    }
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "Cargo input must be a regular non-symlink file: $path" >&2
      exit 2
    }
    git ls-files --error-unmatch -- "$path" >/dev/null 2>&1 || {
      echo "Cargo input must be tracked: $path" >&2
      exit 2
    }
    git diff --quiet -- "$path" && git diff --cached --quiet -- "$path" || {
      echo "Cargo input must be clean before offline execution: $path" >&2
      exit 2
    }
  done
  [[ "$lock" == "$(dirname "$manifest")/Cargo.lock" ]] || {
    echo "lock must be adjacent to its manifest: $pair" >&2
    exit 2
  }
  [[ -z "${seen_manifests[$manifest]:-}" && -z "${seen_locks[$lock]:-}" ]] || {
    echo "duplicate Cargo manifest or lock input: $pair" >&2
    exit 2
  }
  seen_manifests[$manifest]=1
  seen_locks[$lock]=1
  actual_hash=$(sha256sum -- "$lock" | awk '{print $1}')
  expected_hash=${stamped_paths[$lock]:-}
  [[ -n "$expected_hash" && "$actual_hash" == "$expected_hash" ]] || {
    printf 'offline cache stamp mismatch: lock=%s expected=%s actual=%s\n' \
      "$lock" "${expected_hash:-<missing>}" "$actual_hash" >&2
    exit 2
  }
  manifests+=("$manifest")
  locks+=("$lock")
  lock_modes+=("$(stat -c '%a' "$lock")")
  lock_inodes+=("$(stat -c '%d:%i' "$lock")")
done

mapfile -d '' -t tracked_manifests < <(
  git ls-files -z -- 'Cargo.toml' ':(glob)**/Cargo.toml' | LC_ALL=C sort -z
)
((${#tracked_manifests[@]} > 0)) || {
  echo "repository contains no tracked Cargo.toml inputs" >&2
  exit 2
}
for manifest in "${tracked_manifests[@]}"; do
  [[ "$manifest" =~ ^[A-Za-z0-9_./-]+$ && -f "$manifest" && ! -L "$manifest" ]] || {
    echo "unsafe tracked Cargo manifest: $manifest" >&2
    exit 2
  }
  git diff --quiet -- "$manifest" && git diff --cached --quiet -- "$manifest" || {
    echo "tracked Cargo manifest must be clean before offline execution: $manifest" >&2
    exit 2
  }
done

tmp_state=$(mktemp -d "$runner_temp/trnm-cargo-offline-ready.XXXXXX")
restore_on_error=0
cleanup() {
  rc=$?
  if ((rc != 0 && restore_on_error)); then
    for i in "${!locks[@]}"; do
      chmod "${lock_modes[$i]}" -- "${locks[$i]}" || true
    done
  fi
  [[ "$tmp_state" == "$runner_temp"/* ]] && rm -rf -- "$tmp_state"
  exit "$rc"
}
trap cleanup EXIT

{
  printf 'repo_root=%s\n' "$root"
  printf 'toolchain=%s\n' "$toolchain"
  printf 'target=%s\n' "$target"
  printf 'cargo_home=%s\n' "$cargo_home"
  printf 'stamp=%s\n' "$stamp"
  printf 'stamp_sha256=%s\n' "$(sha256sum -- "$stamp" | awk '{print $1}')"
} >"$tmp_state/metadata"

: >"$tmp_state/pairs.tsv"
: >"$tmp_state/locks.tsv"
for i in "${!manifests[@]}"; do
  printf '%s\t%s\n' "${manifests[$i]}" "${locks[$i]}" >>"$tmp_state/pairs.tsv"
  printf '%s\t%s\t%s\t%s\n' \
    "$(sha256sum -- "${locks[$i]}" | awk '{print $1}')" \
    "${lock_modes[$i]}" "${lock_inodes[$i]}" "${locks[$i]}" \
    >>"$tmp_state/locks.tsv"
done

: >"$tmp_state/manifests.sha256"
for manifest in "${tracked_manifests[@]}"; do
  sha256sum -- "$manifest" >>"$tmp_state/manifests.sha256"
done

for manifest in "${manifests[@]}"; do
  # Omit --target deliberately: cargo-deny resolves the complete locked graph,
  # including target-specific packages outside the Linux host target. The
  # provisioned cache must therefore prove all-target coverage for every root.
  env CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true \
    "$cargo_bin" fetch \
      --manifest-path "$manifest" \
      --locked \
      --offline
done

(cd "$root" && sha256sum --check --status "$tmp_state/manifests.sha256") || {
  echo "Cargo manifest changed during offline cache verification" >&2
  exit 2
}
while IFS=$'\t' read -r expected_hash _mode _inode lock; do
  [[ "$(sha256sum -- "$lock" | awk '{print $1}')" == "$expected_hash" ]] || {
    echo "Cargo lock changed during offline cache verification: $lock" >&2
    exit 2
  }
done <"$tmp_state/locks.tsv"

restore_on_error=1
chmod a-w -- "${locks[@]}"
mv -- "$tmp_state" "$state_dir"
tmp_state="$runner_temp/.trnm-cargo-offline-ready-moved"
restore_on_error=0
trap - EXIT

printf 'cargo_offline_ready=passed toolchain=%s host_target=%s fetch_scope=all-targets roots=%d manifests=%d\n' \
  "$toolchain" "$target" "${#manifests[@]}" "${#tracked_manifests[@]}"
