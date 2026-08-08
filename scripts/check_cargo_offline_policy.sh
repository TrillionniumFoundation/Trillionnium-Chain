#!/usr/bin/env bash
set -euo pipefail

source_mode=${1:---worktree}
case "$source_mode" in
  --worktree|--staged|--head) ;;
  *)
    echo "unsupported Cargo offline policy source: $source_mode" >&2
    exit 2
    ;;
esac

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

declare -A class=()
declare -A toolchain=()
declare -A roots=()

register() {
  local key=$1 policy_class=$2 rust_toolchain=$3 cargo_roots=${4:-}
  [[ -z "${class[$key]:-}" ]] || {
    echo "duplicate Cargo offline policy entry: $key" >&2
    exit 2
  }
  class[$key]=$policy_class
  toolchain[$key]=$rust_toolchain
  roots[$key]=$cargo_roots
}

register agent-user-phasea-gate.yml:phasea-gate required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register p1-rust-sidecar.yml:p1-with-rust-sidecar required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register rust-l1-nightly-health.yml:rust-l1-health required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register rust-l1-testnet-preflight.yml:preflight required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-canonical-input-fuzz-smoke.yml:bounded-smoke cargo-fuzz nightly-2026-07-27 \
  trillionnium/fuzz/Cargo.toml:trillionnium/fuzz/Cargo.lock
register trnm-cometbft-spike.yml:dependency-policy cargo-deny 1.95.0 \
  'trillionnium/Cargo.toml:trillionnium/Cargo.lock contracts/Cargo.toml:contracts/Cargo.lock trillionnium/fuzz/Cargo.toml:trillionnium/fuzz/Cargo.lock'
register trnm-cometbft-spike.yml:cometbft-four-validator required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-cometbft-spike.yml:cometbft-partition-matrix required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-gate-quick-check.yml:shell-static-checks required 1.95.0 \
  'trillionnium/Cargo.toml:trillionnium/Cargo.lock contracts/Cargo.toml:contracts/Cargo.lock'
register trnm-live-devnet-package.yml:legacy-harness-reproducibility required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-merge-gates.yml:rust-l1-merge-gates required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-poco-bft-v0.yml:vectors-schema-proto required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-poco-bft-v0.yml:rust required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-poco-bft-v0.yml:formal not-applicable none
register trnm-poco-bft-v0.yml:release-artifacts required 1.95.0 \
  trillionnium/Cargo.toml:trillionnium/Cargo.lock
register trnm-poco-bft-v0.yml:dependency-policy cargo-deny 1.95.0 \
  'trillionnium/Cargo.toml:trillionnium/Cargo.lock trillionnium/fuzz/Cargo.toml:trillionnium/fuzz/Cargo.lock'
register trnm-poco-bft-v0.yml:fuzz-smoke cargo-fuzz nightly-2026-07-27 \
  trillionnium/fuzz/Cargo.toml:trillionnium/fuzz/Cargo.lock
register web4-frontend-ci.yml:gates not-applicable none

read_path() {
  local path=$1
  case "$source_mode" in
    --worktree) cat "$root/$path" ;;
    --staged) git -C "$root" show ":$path" ;;
    --head) git -C "$root" show "HEAD:$path" ;;
  esac
}

list_workflows() {
  case "$source_mode" in
    --worktree)
      find "$root/.github/workflows" -maxdepth 1 -type f \
        \( -name '*.yml' -o -name '*.yaml' \) -printf '%f\n' | LC_ALL=C sort
      ;;
    --staged)
      git -C "$root" ls-files --cached -- '.github/workflows/*.yml' \
        '.github/workflows/*.yaml' | sed 's#^.github/workflows/##' | LC_ALL=C sort
      ;;
    --head)
      git -C "$root" ls-tree -r --name-only HEAD -- .github/workflows/ \
        | sed 's#^.github/workflows/##' | awk '/\.ya?ml$/' | LC_ALL=C sort
      ;;
  esac
}

list_script_paths() {
  case "$source_mode" in
    --worktree)
      git -C "$root" ls-files -co --exclude-standard -- \
        'scripts/*.sh' 'scripts/**/*.sh' 'trillionnium/scripts/*.sh' \
        'trillionnium/scripts/**/*.sh' | LC_ALL=C sort -u
      ;;
    --staged)
      git -C "$root" ls-files --cached -- \
        'scripts/*.sh' 'scripts/**/*.sh' 'trillionnium/scripts/*.sh' \
        'trillionnium/scripts/**/*.sh' | LC_ALL=C sort -u
      ;;
    --head)
      git -C "$root" ls-tree -r --name-only HEAD -- scripts/ trillionnium/scripts/ \
        | awk '/\.sh$/' | LC_ALL=C sort -u
      ;;
  esac
}

extract_jobs() {
  awk '
    /^jobs:[[:space:]]*(#.*)?$/ { in_jobs=1; next }
    in_jobs && /^[^ ]/ && $0 !~ /^#/ { in_jobs=0 }
    in_jobs && /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*(#.*)?$/ {
      line=$0
      sub(/^  /, "", line)
      sub(/:.*/, "", line)
      print line
    }
  '
}

extract_job_block() {
  local workflow_file=$1 wanted=$2
  awk -v wanted="$wanted" '
    /^jobs:[[:space:]]*(#.*)?$/ { in_jobs=1; next }
    in_jobs && /^[^ ]/ && $0 !~ /^#/ { in_jobs=0 }
    in_jobs && /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*(#.*)?$/ {
      line=$0
      sub(/^  /, "", line)
      sub(/:.*/, "", line)
      if (capture && line != wanted) exit
      capture=(line == wanted)
    }
    capture { print }
  ' "$workflow_file"
}

extract_named_step() {
  local block=$1 name=$2
  awk -v name="$name" '
    $0 == "      - name: " name { capture=1 }
    capture && seen && /^      - / { exit }
    capture { print; seen=1 }
  ' "$block"
}

invalid_guard_step_lines() {
  awk '
    /^$/ { next }
    /^      - name: Verify runner-provisioned Rust toolchain$/ { next }
    /^      - name: Verify Cargo offline cache readiness$/ { next }
    /^      - name: Verify Cargo offline inputs remained unchanged$/ { next }
    /^        if: always\(\)$/ { next }
    /^        working-directory: trillionnium-chain$/ { next }
    /^        run: \|$/ { next }
    /^          set -euo pipefail$/ { next }
    /^          \.\/scripts\/ci\/check_preprovisioned_rust_toolchain\.sh[[:space:]]*\\?$/ { next }
    /^          \.\/scripts\/ci\/check_cargo_offline_ready\.sh[[:space:]]*\\?$/ { next }
    /^          \.\/scripts\/ci\/check_cargo_offline_unchanged\.sh[[:space:]]*\\?$/ { next }
    /^            --toolchain [A-Za-z0-9._-]+[[:space:]]*\\?$/ { next }
    /^            --component (clippy|rustfmt)[[:space:]]*\\?$/ { next }
    /^            --state ".+"[[:space:]]*\\?$/ { next }
    /^            [A-Za-z0-9_./-]+Cargo\.toml:[A-Za-z0-9_./-]+Cargo\.lock[[:space:]]*\\?$/ { next }
    { print NR ":" $0 }
  ' "$1"
}

error_count=0
home_override_re="(^|[[:space:]\"'])HOME([\"']?[[:space:]]*:|=)"
error() {
  printf 'ERROR: %s\n' "$*" >&2
  error_count=$((error_count + 1))
}

validate_simple_helper_step() {
  local key=$1 block=$2 name=$3 helper=$4 step expected normalized
  step="$tmp/${key//[:\/]/--}.${helper##*/}.step"
  expected="$step.expected"
  normalized="$step.normalized"
  extract_named_step "$block" "$name" >"$step"
  [[ $(grep -Fxc "      - name: $name" "$block" || true) -eq 1 ]] \
    || error "$key must contain exactly one $name step"
  [[ $(grep -Fxc "          $helper" "$block" || true) -eq 1 ]] \
    || error "$key must invoke $helper exactly once"
  [[ -s "$step" ]] || {
    error "$key is missing the canonical $name step"
    return
  }
  sed -e '/^        working-directory: trillionnium-chain$/d' -e '/^$/d' \
    "$step" >"$normalized"
  printf '%s\n' \
    "      - name: $name" \
    '        run: |' \
    '          set -euo pipefail' \
    "          $helper" >"$expected"
  diff -u "$expected" "$normalized" >/dev/null \
    || error "$key $name step differs from its frozen fail-closed form"
}

validate_cargo_deny_run_step() {
  local key=$1 block=$2 step expected normalized pair manifest index=0
  local -a manifests=()
  step="$tmp/${key//[:\/]/--}.cargo-deny-run.step"
  expected="$step.expected"
  normalized="$step.normalized"
  extract_named_step "$block" "Run frozen cargo-deny policy checks" >"$step"
  [[ $(grep -Fxc '      - name: Run frozen cargo-deny policy checks' "$block" || true) -eq 1 ]] \
    || error "$key must contain exactly one frozen cargo-deny execution step"
  [[ $(grep -Fxc '          ./scripts/ci/check_cargo_deny_offline.sh \' "$block" || true) -eq 1 ]] \
    || error "$key must invoke the frozen cargo-deny helper exactly once"
  [[ -s "$step" ]] || {
    error "$key is missing the canonical frozen cargo-deny execution step"
    return
  }
  for pair in ${roots[$key]}; do
    manifests+=("${pair%%:*}")
  done
  sed -e '/^        working-directory: trillionnium-chain$/d' -e '/^$/d' \
    "$step" >"$normalized"
  {
    printf '%s\n' \
      '      - name: Run frozen cargo-deny policy checks' \
      '        run: |' \
      '          set -euo pipefail' \
      '          ./scripts/ci/check_cargo_deny_offline.sh \'
    for manifest in "${manifests[@]}"; do
      index=$((index + 1))
      if ((index < ${#manifests[@]})); then
        printf '            %s \\\n' "$manifest"
      else
        printf '            %s\n' "$manifest"
      fi
    done
  } >"$expected"
  diff -u "$expected" "$normalized" >/dev/null \
    || error "$key frozen cargo-deny execution step differs from the exact manifest policy"
}

validate_fuzz_smoke_step() {
  local key=$1 block=$2 step expected normalized
  step="$tmp/${key//[:\/]/--}.fuzz-smoke.step"
  expected="$step.expected"
  normalized="$step.normalized"
  extract_named_step "$block" "Run bounded three-target smoke" >"$step"
  [[ $(grep -Fxc '      - name: Run bounded three-target smoke' "$block" || true) -eq 1 ]] \
    || error "$key must contain exactly one bounded fuzz smoke step"
  [[ $(grep -Fxc '        run: ./scripts/ci/check_canonical_fuzz_smoke.sh' "$block" || true) -eq 1 ]] \
    || error "$key must invoke the bounded fuzz helper exactly once"
  [[ -s "$step" ]] || {
    error "$key is missing the canonical bounded fuzz smoke step"
    return
  }
  sed -e '/^        working-directory: trillionnium-chain$/d' -e '/^$/d' \
    "$step" >"$normalized"
  printf '%s\n' \
    '      - name: Run bounded three-target smoke' \
    '        env:' \
    '          TRNM_FUZZ_SMOKE_SECONDS: "15"' \
    '        run: ./scripts/ci/check_canonical_fuzz_smoke.sh' >"$expected"
  diff -u "$expected" "$normalized" >/dev/null \
    || error "$key bounded fuzz smoke step differs from its frozen fail-closed form"
}

toolchain_policy_file="$tmp/rust-toolchain.toml"
if ! read_path rust-toolchain.toml >"$toolchain_policy_file" 2>/dev/null; then
  error "cannot read rust-toolchain.toml from ${source_mode#--}"
elif [[ "$(sha256sum "$toolchain_policy_file" | awk '{print $1}')" \
  != "24ef3b9d3edbd850aa386cb0a98e10450b0030991a4537cb359f54d49dbbb33a" ]]; then
  error "rust-toolchain.toml differs from the frozen 1.95.0 policy"
fi

declare -A helper_hash=(
  [scripts/ci/check_preprovisioned_rust_toolchain.sh]=702ba1e134eee42e57e46da595ca9931f6298375112029c36807882c2d6c940a
  [scripts/ci/check_cargo_offline_ready.sh]=273f7b7a933f6e092c859b9464da746b6f37853bebaa303267bcce3e4de40882
  [scripts/ci/check_cargo_offline_unchanged.sh]=e76c1c06108553664b82fcc75789e4bde40541b99ebf8f5e86c09e7e6f59182f
  [scripts/ci/check_preprovisioned_cargo_deny.sh]=a1eb25bea55e2ec5ef41a5be596ef3447d77d8453e25ffd526d950933ec0ba5c
  [scripts/ci/check_cargo_deny_offline.sh]=84cb9a42c13117a3eba5a0630f2d9ce85fb5733d47513a2c75a3b96baf89ac09
  [scripts/ci/check_preprovisioned_cargo_fuzz.sh]=b2b1fa060440e2111f24f011bfc71c97baa1a558757b0ba8e960736c6c249040
  [scripts/ci/check_canonical_fuzz_smoke.sh]=c1e4ce4ed6b4220171bc237e702a57497475b44762966f792cbe1384e6e1baa5
)
for helper in "${!helper_hash[@]}"; do
  helper_file="$tmp/${helper//\//--}"
  if ! read_path "$helper" >"$helper_file" 2>/dev/null; then
    error "cannot read frozen CI helper from ${source_mode#--}: $helper"
  elif [[ "$(sha256sum "$helper_file" | awk '{print $1}')" != "${helper_hash[$helper]}" ]]; then
    error "$helper differs from its frozen reviewed content"
  fi
done

mapfile -t workflows < <(list_workflows)
expected_workflows="$tmp/expected-workflows"
printf '%s\n' "${!class[@]}" | cut -d: -f1 | LC_ALL=C sort -u >"$expected_workflows"
actual_workflows="$tmp/actual-workflows"
printf '%s\n' "${workflows[@]}" | LC_ALL=C sort -u >"$actual_workflows"
if ! diff -u "$expected_workflows" "$actual_workflows" >&2; then
  error "workflow file set differs from the frozen 11-workflow Cargo policy"
fi

actual="$tmp/actual-jobs"
: >"$actual"
for workflow in "${workflows[@]}"; do
  read_path ".github/workflows/$workflow" >"$tmp/$workflow" || {
    error "cannot read workflow from ${source_mode#--}: $workflow"
    continue
  }
  if grep -Eq '^  CARGO_NET_OFFLINE:' "$tmp/$workflow"; then
    error "$workflow sets CARGO_NET_OFFLINE at workflow scope; classification must stay job-local"
  fi
  if grep -Eq 'CARGO_HOME|CARGO_REGISTRIES_|RUSTUP_(HOME|TOOLCHAIN)|TRNM_FUZZ_TOOLCHAIN' "$tmp/$workflow"; then
    error "$workflow contains a workflow/job/step override of a provisioned Cargo or Rust authority"
  fi
  if grep -Eq '(^|[^A-Za-z0-9_])(PATH|BASH_ENV|ENV|GITHUB_PATH)([^A-Za-z0-9_]|$)' "$tmp/$workflow"; then
    error "$workflow can redirect command or shell authority through PATH/BASH_ENV/ENV"
  fi
  if grep -Eq "^[[:space:]]+[\"']?shell[\"']?[[:space:]]*:" "$tmp/$workflow"; then
    error "$workflow selects a custom shell instead of the frozen runner shell"
  fi
  if grep -Eq "$home_override_re" "$tmp/$workflow"; then
    error "$workflow overrides HOME and can redirect the provisioned Cargo/Rust authority"
  fi
  expected_offline_jobs=0
  for frozen_key in "${!class[@]}"; do
    if [[ "${frozen_key%%:*}" == "$workflow" \
      && "${class[$frozen_key]}" != "not-applicable" ]]; then
      expected_offline_jobs=$((expected_offline_jobs + 1))
    fi
  done
  [[ $(grep -Fc 'CARGO_NET_OFFLINE' "$tmp/$workflow" || true) -eq $expected_offline_jobs ]] \
    || error "$workflow CARGO_NET_OFFLINE token count differs from its frozen Cargo job count"
  [[ $(grep -Fc 'CARGO_CACHE_AUTO_CLEAN_FREQUENCY' "$tmp/$workflow" || true) -eq $expected_offline_jobs ]] \
    || error "$workflow Cargo auto-clean token count differs from its frozen Cargo job count"
  invalid_job_keys=$(awk '
    /^jobs:[[:space:]]*(#.*)?$/ { in_jobs=1; next }
    in_jobs && /^[^ ]/ && $0 !~ /^#/ { in_jobs=0 }
    in_jobs && /^  [^ ]/ \
      && $0 !~ /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*(#.*)?$/ \
      && $0 !~ /^  #[[:space:]]*/ {
        print NR ":" $0
      }
  ' "$tmp/$workflow")
  if [[ -n "$invalid_job_keys" ]]; then
    error "$workflow contains a non-canonical or flow-style job key: $invalid_job_keys"
  fi
  while IFS= read -r job; do
    [[ -n "$job" ]] && printf '%s:%s\n' "$workflow" "$job" >>"$actual"
  done < <(extract_jobs <"$tmp/$workflow")
done
LC_ALL=C sort -u -o "$actual" "$actual"

expected="$tmp/expected-jobs"
printf '%s\n' "${!class[@]}" | LC_ALL=C sort >"$expected"
if ! diff -u "$expected" "$actual" >&2; then
  error "workflow/job set differs from the frozen 11-workflow/18-job Cargo policy"
fi

for key in "${!class[@]}"; do
  workflow=${key%%:*}
  job=${key#*:}
  workflow_file="$tmp/$workflow"
  [[ -f "$workflow_file" ]] || continue
  block="$tmp/${workflow%.yml}--$job.block"
  extract_job_block "$workflow_file" "$job" >"$block"
  [[ -s "$block" ]] || {
    error "$key is missing its direct job block"
    continue
  }
  steps_start=$(grep -n '^    steps:[[:space:]]*$' "$block" | cut -d: -f1 | head -n1)
  if [[ -n "$steps_start" ]] \
    && head -n "$((steps_start - 1))" "$block" | grep -Fq '${{ runner.temp }}'; then
    error "$key uses runner.temp before runner allocation; move it to step scope"
  fi

  policy_class=${class[$key]}
  expected_marker="TRNM_CARGO_OFFLINE_POLICY: \"$policy_class\""
  [[ $(grep -Ec -- "^      ${expected_marker}$" "$block" || true) -eq 1 ]] \
    || error "$key must contain exactly one $expected_marker"

  if [[ "$policy_class" == "not-applicable" ]]; then
    ! grep -Fq 'CARGO_NET_OFFLINE' "$block" \
      || error "$key is no-Cargo but sets CARGO_NET_OFFLINE"
    ! grep -Fq 'check_cargo_offline_ready.sh' "$block" \
      || error "$key is no-Cargo but invokes the Cargo offline-ready guard"
    ! grep -Eq '(^|[^A-Za-z0-9_])(cargo([[:space:]]|\+|-deny|-fuzz)|rustup([[:space:]]|$)|Cargo\.(toml|lock))' "$block" \
      || error "$key is no-Cargo but contains a Rust/Cargo execution surface"
    case "$key" in
      trnm-poco-bft-v0.yml:formal)
        [[ $(grep -Fc './scripts/ci/check_poco_bft_v0_formal.sh' "$block" || true) -eq 1 ]] \
          || error "$key must invoke exactly the frozen formal-only shell entrypoint"
        if grep -Eo '(\./)?scripts/[A-Za-z0-9_./-]+\.sh' "$block" \
          | grep -Fvx './scripts/ci/check_poco_bft_v0_formal.sh' >/dev/null; then
          error "$key invokes a shell entrypoint outside the frozen formal-only boundary"
        fi
        ;;
      web4-frontend-ci.yml:gates)
        ! grep -Eq '(\./)?scripts/[A-Za-z0-9_./-]+\.sh' "$block" \
          || error "$key invokes a repository shell entrypoint from the Node-only boundary"
        ;;
    esac
    continue
  fi

  [[ $(grep -Ec '^      CARGO_NET_OFFLINE: "true"$' "$block" || true) -eq 1 ]] \
    || error "$key must set job-local CARGO_NET_OFFLINE exactly once"
  [[ $(grep -Fc 'CARGO_NET_OFFLINE' "$block" || true) -eq 1 ]] \
    || error "$key must not override CARGO_NET_OFFLINE after the canonical job env"
  [[ $(grep -Ec '^      TRNM_CARGO_OFFLINE_POLICY:' "$block" || true) -eq 1 ]] \
    || error "$key must have exactly one Cargo offline classification"
  [[ $(grep -Ec '^      CARGO_CACHE_AUTO_CLEAN_FREQUENCY: "never"$' "$block" || true) -eq 1 ]] \
    || error "$key must disable Cargo cache auto-clean exactly once"
  [[ $(grep -Fc 'CARGO_CACHE_AUTO_CLEAN_FREQUENCY' "$block" || true) -eq 1 ]] \
    || error "$key must not override Cargo cache auto-clean after the canonical job env"
  ! grep -Eq 'CARGO_NET_OFFLINE[=:][^[:alnum:]]*(false|0)([^[:alnum:]_]|$)|unset[[:space:]]+CARGO_NET_OFFLINE|env[[:space:]]+-u[[:space:]]+CARGO_NET_OFFLINE' "$block" \
    || error "$key contains a CARGO_NET_OFFLINE bypass"
  ! grep -Eq 'RUSTUP_(HOME|TOOLCHAIN)|TRNM_FUZZ_TOOLCHAIN' "$block" \
    || error "$key overrides the preprovisioned Rust toolchain selection"
  ! grep -Eq 'cargo[[:space:]]+\+|rustup[[:space:]]+run([[:space:]]|$)' "$block" \
    || error "$key bypasses the verified Rust toolchain for a direct Cargo invocation"
  ! grep -Eq '(^|[[:space:]])(\./)?scripts/ci/install_cargo_(deny|fuzz)\.sh([[:space:]]|$)' "$block" \
    || error "$key invokes a network-capable Cargo tool installer"
  ! grep -Fq 'CARGO_HOME' "$block" \
    || error "$key overrides the provisioned Cargo home"
  ! grep -Fq 'CARGO_REGISTRIES_' "$block" \
    || error "$key overrides a provisioned Cargo registry"
  ! grep -Eq 'net\.offline[[:space:]]*=[[:space:]]*false' "$block" \
    || error "$key overrides the provisioned Cargo cache or offline mode"
  ! grep -Eq 'cargo([[:space:]]+\+[A-Za-z0-9._-]+)?[[:space:]]+(fetch|install|update|generate-lockfile|search|login|publish|yank)([[:space:]]|$)' "$block" \
    || error "$key contains a direct online-capable Cargo mutation command"
  ! grep -Eq 'dtolnay/rust-toolchain|rustup[[:space:]]+(toolchain[[:space:]]+)?(install|update)' "$block" \
    || error "$key contains a network-capable Rust toolchain setup"

  toolchain_step="$tmp/${workflow%.yml}--$job.toolchain.step"
  ready_step="$tmp/${workflow%.yml}--$job.ready.step"
  unchanged_step="$tmp/${workflow%.yml}--$job.unchanged.step"
  awk '
    /^      - name: Verify runner-provisioned Rust toolchain$/ { capture=1 }
    capture && seen && /^      - / { exit }
    capture { print; seen=1 }
  ' "$block" >"$toolchain_step"
  awk '
    /^      - name: Verify Cargo offline cache readiness$/ { capture=1 }
    capture && seen && /^      - / { exit }
    capture { print; seen=1 }
  ' "$block" >"$ready_step"
  awk '
    /^      - name: Verify Cargo offline inputs remained unchanged$/ { capture=1 }
    capture && seen && /^      - / { exit }
    capture { print; seen=1 }
  ' "$block" >"$unchanged_step"

  ready_step_header_count=$(grep -Ec '^      - name: Verify Cargo offline cache readiness$' "$block" || true)
  [[ $ready_step_header_count -eq 1 ]] \
    || error "$key must contain exactly one offline-ready step header"
  ready_step_start=$(grep -n '^      - name: Verify Cargo offline cache readiness$' "$block" \
    | cut -d: -f1 | head -n1)
  if [[ -n "$ready_step_start" ]]; then
    pre_ready_runs=$(head -n "$((ready_step_start - 1))" "$block" \
      | grep -Ec '^        run:' || true)
    [[ $pre_ready_runs -eq 1 ]] \
      || error "$key may run only its exact Rust toolchain verifier before offline-ready"
  fi

  toolchain_check_count=$(grep -Ec '^          \./scripts/ci/check_preprovisioned_rust_toolchain\.sh([[:space:]]|$)' "$toolchain_step" || true)
  [[ $toolchain_check_count -eq 1 ]] \
    || error "$key must verify its preprovisioned Rust toolchain exactly once"

  ready_count=$(grep -Ec '^          \./scripts/ci/check_cargo_offline_ready\.sh([[:space:]]|$)' "$ready_step" || true)
  unchanged_count=$(grep -Ec '^          \./scripts/ci/check_cargo_offline_unchanged\.sh([[:space:]]|$)' "$unchanged_step" || true)
  [[ $ready_count -eq 1 ]] || error "$key must invoke offline-ready exactly once"
  [[ $unchanged_count -eq 1 ]] || error "$key must invoke offline-unchanged exactly once"
  grep -Eq -- "^            --toolchain ${toolchain[$key]}([[:space:]]*\\\\)?$" "$toolchain_step" \
    || error "$key does not bind the expected toolchain ${toolchain[$key]}"
  grep -Eq -- "^            --toolchain ${toolchain[$key]}([[:space:]]*\\\\)?$" "$ready_step" \
    || error "$key offline-ready guard does not bind the expected toolchain ${toolchain[$key]}"
  [[ $(grep -Ec '^            --toolchain [A-Za-z0-9._-]+([[:space:]]*\\)?$' "$toolchain_step" || true) -eq 1 ]] \
    || error "$key toolchain verifier must contain exactly one --toolchain option"
  [[ $(grep -Ec '^            --toolchain [A-Za-z0-9._-]+([[:space:]]*\\)?$' "$ready_step" || true) -eq 1 ]] \
    || error "$key offline-ready guard must contain exactly one --toolchain option"
  grep -Eq -- '^            --state "\$RUNNER_TEMP/trnm-cargo-offline-\$\{GITHUB_JOB\}"([[:space:]]*\\)?$' "$ready_step" \
    || error "$key does not use the canonical job-scoped offline state"
  grep -Eq -- '^            --state "\$RUNNER_TEMP/trnm-cargo-offline-\$\{GITHUB_JOB\}"([[:space:]]*\\)?$' "$unchanged_step" \
    || error "$key unchanged guard does not use the canonical job-scoped state"
  [[ $(grep -Ec '^            --state .+([[:space:]]*\\)?$' "$ready_step" || true) -eq 1 ]] \
    || error "$key offline-ready guard must contain exactly one --state option"
  [[ $(grep -Ec '^            --state .+([[:space:]]*\\)?$' "$unchanged_step" || true) -eq 1 ]] \
    || error "$key offline-unchanged guard must contain exactly one --state option"
  expected_roots="$tmp/${workflow%.yml}--$job.expected-roots"
  actual_roots="$tmp/${workflow%.yml}--$job.actual-roots"
  : >"$expected_roots"
  for pair in ${roots[$key]}; do
    printf '%s\n' "$pair" >>"$expected_roots"
  done
  LC_ALL=C sort -u -o "$expected_roots" "$expected_roots"
  grep -E '^            [A-Za-z0-9_./-]*Cargo\.toml:[A-Za-z0-9_./-]*Cargo\.lock([[:space:]]*\\)?$' "$ready_step" \
    | grep -Eo '[A-Za-z0-9_./-]*Cargo\.toml:[A-Za-z0-9_./-]*Cargo\.lock' \
    | LC_ALL=C sort -u >"$actual_roots" || true
  if ! diff -u "$expected_roots" "$actual_roots" >&2; then
    error "$key Cargo manifest/lock root set differs from the frozen policy"
  fi

  ready_line=$(grep -nE '^          \./scripts/ci/check_cargo_offline_ready\.sh([[:space:]]|$)' "$block" | cut -d: -f1 | head -n1)
  toolchain_line=$(grep -nE '^          \./scripts/ci/check_preprovisioned_rust_toolchain\.sh([[:space:]]|$)' "$block" | cut -d: -f1 | head -n1)
  unchanged_line=$(grep -nE '^          \./scripts/ci/check_cargo_offline_unchanged\.sh([[:space:]]|$)' "$block" | cut -d: -f1 | head -n1)
  if [[ -n "$toolchain_line" && -n "$ready_line" ]]; then
    ((toolchain_line < ready_line)) || error "$key verifies Cargo cache before its Rust toolchain"
  fi
  if [[ -n "$ready_line" && -n "$unchanged_line" ]]; then
    ((ready_line < unchanged_line)) || error "$key runs unchanged before ready"
    if tail -n "+$((unchanged_line + 1))" "$block" | grep -Eq '^      - ';
    then
      error "$key must keep offline-unchanged as its final explicit step"
    fi
  fi
  if [[ $(grep -Ec '^        if: always\(\)$' "$unchanged_step" || true) -ne 1 ]]; then
    error "$key offline-unchanged step must be explicitly if: always()"
  fi

  for step_file in "$toolchain_step" "$ready_step" "$unchanged_step"; do
    [[ -s "$step_file" ]] || continue
    invalid_lines=$(invalid_guard_step_lines "$step_file")
    [[ -z "$invalid_lines" ]] \
      || error "$key guard step contains a non-canonical command/control line: $invalid_lines"
    ! grep -Eq 'continue-on-error:|\|\||&&|^[[:space:]]*(if|then|elif|else|fi|while|until|case|esac|trap)([[:space:]]|$)|^[[:space:]]*set[[:space:]]+\+' "$step_file" \
      || error "$key weakens an offline guard step"
    [[ $(grep -Ec '^          set -euo pipefail$' "$step_file" || true) -eq 1 ]] \
      || error "$key offline guard step must use strict shell mode"
  done

  case "$policy_class" in
    cargo-deny)
      validate_simple_helper_step "$key" "$block" \
        "Verify runner-provisioned cargo-deny" \
        "./scripts/ci/check_preprovisioned_cargo_deny.sh"
      validate_cargo_deny_run_step "$key" "$block"
      ! grep -Fq 'install_cargo_deny.sh' "$block" \
        || error "$key installs cargo-deny inside the offline CI job"
      ;;
    cargo-fuzz)
      validate_simple_helper_step "$key" "$block" \
        "Verify runner-provisioned cargo-fuzz" \
        "./scripts/ci/check_preprovisioned_cargo_fuzz.sh"
      validate_fuzz_smoke_step "$key" "$block"
      ! grep -Fq 'install_cargo_fuzz.sh' "$block" \
        || error "$key installs cargo-fuzz inside the offline CI job"
      ;;
  esac
done

while IFS= read -r path; do
  case "$path" in
    scripts/ci/install_cargo_fuzz.sh|scripts/ci/check_cargo_offline_ready.sh|\
    scripts/ci/check_cargo_offline_unchanged.sh|\
    scripts/check_cargo_offline_policy.sh|scripts/check_cargo_offline_policy_test.sh)
      continue
      ;;
  esac
  content="$tmp/script-content"
  if ! read_path "$path" >"$content" 2>/dev/null; then
    error "cannot read script from ${source_mode#--}: $path"
    continue
  fi
  if grep -Eq 'cargo([[:space:]]+\+[^[:space:]]+)?[[:space:]]+(fetch|install|update|generate-lockfile|search|login|publish|yank)([[:space:]]|$)' "$content"; then
    error "$path contains an online-capable Cargo command outside the provisioning allowlist"
  fi
  if grep -Eq 'CARGO_NET_OFFLINE[=:][^[:alnum:]]*(false|0)([^[:alnum:]_]|$)|unset[[:space:]]+CARGO_NET_OFFLINE|env[[:space:]]+-u[[:space:]]+CARGO_NET_OFFLINE|net\.offline[[:space:]]*=[^[:alnum:]]*false([^[:alnum:]_]|$)' "$content"; then
    error "$path contains a Cargo offline bypass"
  fi
  if grep -Eq 'RUSTUP_(HOME|TOOLCHAIN)|TRNM_FUZZ_TOOLCHAIN' "$content"; then
    case "$path" in
      scripts/ci/check_preprovisioned_rust_toolchain.sh)
        if grep -Eq '(^|[^A-Za-z0-9_])(export[[:space:]]+)?(RUSTUP_HOME|RUSTUP_TOOLCHAIN|TRNM_FUZZ_TOOLCHAIN)[[:space:]]*=' "$content"; then
          error "$path assigns a Rust toolchain authority variable instead of only rejecting it"
        fi
        ;;
      *) error "$path overrides the preprovisioned Rust toolchain selection" ;;
    esac
  fi
  if grep -Eq 'CARGO_HOME|CARGO_REGISTRIES_' "$content"; then
    case "$path" in
      scripts/ci/check_cargo_deny_offline.sh)
        if grep -Eq '(^|[^A-Za-z0-9_])(export[[:space:]]+)?(CARGO_HOME|CARGO_REGISTRIES_[A-Za-z0-9_]+)[[:space:]]*=' "$content"; then
          error "$path assigns Cargo authority instead of only rejecting an override"
        fi
        ;;
      *) error "$path overrides the provisioned Cargo home or registry" ;;
    esac
  fi
  if grep -Eq "$home_override_re" "$content"; then
    case "$path" in
      scripts/v2/worker_poco_cli_cutover_gate.sh|\
      scripts/v2/consensus_fault_matrix_canonical_metrics_prefix_test.sh)
        if grep -Eq '(^|[^A-Za-z0-9_])(cargo([[:space:]]|\+|-deny|-fuzz)|rustup([[:space:]]|$))' "$content"; then
          error "$path combines its narrowly allowed application HOME sandbox with Cargo/Rust"
        fi
        ;;
      *) error "$path overrides HOME and can redirect Cargo/Rust authority" ;;
    esac
  fi
  if grep -Eq 'cargo[[:space:]]+\+|rustup[[:space:]]+run([[:space:]]|$)' "$content"; then
    if [[ "$path" != scripts/ci/check_canonical_fuzz_smoke.sh ]]; then
      error "$path bypasses the repository-pinned Rust toolchain"
    else
      cargo_plus_count=$(grep -Ec 'cargo[[:space:]]+\+' "$content" || true)
      exact_fuzz_count=$(grep -Fc 'cargo +"$FUZZ_TOOLCHAIN"' "$content" || true)
      if [[ $(grep -Fc 'FUZZ_TOOLCHAIN="nightly-2026-07-27"' "$content" || true) -ne 1 \
        || $cargo_plus_count -ne 3 || $exact_fuzz_count -ne 3 \
        || $(grep -Ec 'rustup[[:space:]]+run([[:space:]]|$)' "$content" || true) -ne 0 ]]; then
        error "$path must use only the exact dated nightly toolchain at its three frozen Cargo call sites"
      fi
    fi
  fi
  if [[ "$path" == scripts/ci/check_poco_bft_v0_formal.sh ]] \
    && grep -Eq '(^|[^A-Za-z0-9_])(cargo([[:space:]]|\+|-deny|-fuzz)|rustup([[:space:]]|$)|Cargo\.(toml|lock))' "$content"; then
    error "$path crosses the frozen no-Cargo formal boundary"
  fi
  if grep -Eq 'dtolnay/rust-toolchain|rustup[[:space:]]+(toolchain[[:space:]]+)?(install|update)' "$content"; then
    error "$path contains a network-capable Rust toolchain setup"
  fi
done < <(list_script_paths)

((error_count == 0)) || exit 1
printf 'cargo_offline_policy=passed workflows=%d jobs=%d cargo_jobs=16 no_cargo_jobs=2 source=%s\n' \
  "${#workflows[@]}" "${#class[@]}" "${source_mode#--}"
