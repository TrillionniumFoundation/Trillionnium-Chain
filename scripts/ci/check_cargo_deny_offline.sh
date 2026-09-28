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
[[ -n "${CARGO_HOME:-}" ]] || {
  echo "job-scoped CARGO_HOME is required" >&2
  exit 2
}

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
authority_home="${TRNM_CARGO_AUTHORITY_HOME:?Cargo authority home is required}"
[[ -d "$authority_home" && ! -L "$authority_home" ]] || {
  echo "Cargo authority home must be a real directory: $authority_home" >&2
  exit 2
}
authority_home=$(cd "$authority_home" && pwd -P)
job_home=$(cd "$CARGO_HOME" && pwd -P)
[[ "$job_home" != "$authority_home" ]] || {
  echo "cargo-deny must not run against the shared Cargo authority home" >&2
  exit 2
}

advisory_name=advisory-db-3157b0e258782691
authority_db="$authority_home/advisory-dbs/$advisory_name"
[[ -d "$authority_db" && ! -L "$authority_db" ]] || {
  echo "missing non-symlink advisory database authority: $authority_db" >&2
  exit 2
}
authority_commit=$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$authority_db" \
  -C "$authority_db" rev-parse HEAD)
authority_tree=$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$authority_db" \
  -C "$authority_db" rev-parse 'HEAD^{tree}')
[[ -z "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$authority_db" \
  -C "$authority_db" status --porcelain --untracked-files=all)" ]] || {
  echo "advisory database authority is dirty" >&2
  exit 2
}

job_db_parent="$job_home/advisory-dbs"
job_db="$job_db_parent/$advisory_name"
install -d -m 0700 "$job_db_parent"
if [[ ! -e "$job_db" && ! -L "$job_db" ]]; then
  temporary_db="$job_db_parent/.${advisory_name}.tmp-$$"
  cleanup_advisory_copy() { rm -rf -- "$temporary_db"; }
  trap cleanup_advisory_copy EXIT
  cp -a --reflink=auto --no-preserve=ownership "$authority_db" "$temporary_db"
  # The authority stays root-owned and read-only. Only the disposable,
  # job-scoped mirror is made owner-private and writable so the mandatory
  # post-job cleanup can remove every nested Git/advisory directory.
  chmod -R u+rwX,go-rwx "$temporary_db"
  [[ -z "$(find "$temporary_db" -type l -print -quit)" ]] || {
    echo "job advisory database copy contains a symlink" >&2
    exit 2
  }
  mv "$temporary_db" "$job_db"
  trap - EXIT
fi
[[ -d "$job_db" && ! -L "$job_db" ]] || {
  echo "job advisory database must be a real directory" >&2
  exit 2
}
[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" rev-parse HEAD)" == "$authority_commit" ]] || {
  echo "job advisory database commit differs from authority" >&2
  exit 2
}
[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" rev-parse 'HEAD^{tree}')" == "$authority_tree" ]] || {
  echo "job advisory database tree differs from authority" >&2
  exit 2
}
[[ -z "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" status --porcelain --untracked-files=all)" ]] || {
  echo "job advisory database copy is dirty" >&2
  exit 2
}

cargo_bin="${TRNM_CARGO_BIN:?pinned Cargo binary is required}"
[[ "$(command -v cargo)" == "$cargo_bin" ]] || {
  echo "Cargo must resolve from the pinned job toolchain" >&2
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
    GIT_CONFIG_VALUE_0="$job_db" \
    "$cargo_bin" deny --frozen --manifest-path "$manifest" check
done

[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" rev-parse HEAD)" == "$authority_commit" ]] || {
  echo "cargo-deny changed the job advisory database commit" >&2
  exit 2
}
[[ "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" rev-parse 'HEAD^{tree}')" == "$authority_tree" ]] || {
  echo "cargo-deny changed the job advisory database tree" >&2
  exit 2
}
[[ -z "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$job_db" \
  -C "$job_db" status --porcelain --untracked-files=all)" ]] || {
  echo "cargo-deny changed the job advisory database worktree" >&2
  exit 2
}

printf 'cargo_deny_offline=passed manifests=%d advisory_commit=%s\n' \
  "$#" "$authority_commit"
