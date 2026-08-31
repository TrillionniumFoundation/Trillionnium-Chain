#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
checker="$root/scripts/check_cargo_offline_policy.sh"
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
repo="$fixture/repo"
mkdir -p "$repo/.github/workflows" "$repo/scripts/ci"
cp "$root"/.github/workflows/*.yml "$repo/.github/workflows/"
cp "$root/rust-toolchain.toml" "$repo/rust-toolchain.toml"
install -m 0755 "$root/scripts/check_ci_runner_policy.sh" \
  "$repo/scripts/check_ci_runner_policy.sh"
install -m 0755 \
  "$root/scripts/check_privileged_cargo_offline_policy.sh" \
  "$repo/scripts/check_privileged_cargo_offline_policy.sh"
cp "$root/scripts/ci/check_preprovisioned_rust_toolchain.sh" \
  "$root/scripts/ci/check_cargo_offline_ready.sh" \
  "$root/scripts/ci/check_cargo_offline_unchanged.sh" \
  "$root/scripts/ci/check_preprovisioned_cargo_deny.sh" \
  "$root/scripts/ci/check_cargo_deny_offline.sh" \
  "$root/scripts/ci/check_preprovisioned_cargo_fuzz.sh" \
  "$root/scripts/ci/check_canonical_fuzz_smoke.sh" \
  "$root/scripts/ci/check_poco_bft_v0_formal.sh" "$repo/scripts/ci/"
git init -q "$repo"
git -C "$repo" config user.name cargo-offline-policy-test
git -C "$repo" config user.email cargo-offline-policy-test@example.invalid

run_policy() {
  (cd "$repo" && bash "$checker" "$1")
}

expect_pass() {
  local name=$1 mode=$2 output
  if ! output=$(run_policy "$mode" 2>&1); then
    printf 'FAIL: %s unexpectedly failed\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  [[ "$output" == *'jobs=22 cargo_jobs=20 no_cargo_jobs=2'* ]] || {
    printf 'FAIL: %s returned unexpected summary\n%s\n' "$name" "$output" >&2
    exit 1
  }
  printf 'PASS: %s\n' "$name"
}

expect_fail() {
  local name=$1 mode=${2:---worktree} output
  if output=$(run_policy "$mode" 2>&1); then
    printf 'FAIL: %s unexpectedly passed\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  printf 'PASS: %s rejected\n' "$name"
}

restore_fixture() {
  git -C "$repo" restore --source=HEAD --staged --worktree .
  git -C "$repo" clean -qfd
}

git -C "$repo" add .github/workflows scripts rust-toolchain.toml
git -C "$repo" commit -qm 'cargo offline policy baseline'
expect_pass worktree-positive --worktree
expect_pass staged-positive --staged
expect_pass head-positive --head

sed -i 's/channel = "1.95.0"/channel = "nightly"/' "$repo/rust-toolchain.toml"
expect_fail root-toolchain-policy-drift
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '0,/^      CARGO_NET_OFFLINE: "true"$/d' "$workflow"
expect_fail missing-job-offline-env
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '0,/^      CARGO_CACHE_AUTO_CLEAN_FREQUENCY: "never"$/d' "$workflow"
expect_fail missing-cache-auto-clean-disable
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '0,/^      TRNM_CARGO_OFFLINE_POLICY: "required"$/s//      # TRNM_CARGO_OFFLINE_POLICY: "required"/' "$workflow"
expect_fail comment-cannot-satisfy-classification
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i 's#\./scripts/ci/check_cargo_offline_ready.sh#\./scripts/ci/missing_ready.sh#' "$workflow"
expect_fail missing-ready-call
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i 's@          \./scripts/ci/check_cargo_offline_ready.sh@          # ./scripts/ci/check_cargo_offline_ready.sh@' "$workflow"
expect_fail commented-ready-call
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i 's#\./scripts/ci/check_preprovisioned_rust_toolchain.sh#rustup toolchain install 1.95.0#' "$workflow"
expect_fail rustup-install-cannot-replace-preprovisioned-check
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i '/Verify runner-provisioned Rust toolchain/a\        uses: dtolnay/rust-toolchain@deadbeef' "$workflow"
expect_fail dtolnay-toolchain-setup-forbidden
restore_fixture

workflow="$repo/.github/workflows/rust-l1-nightly-health.yml"
sed -i '/check_cargo_offline_ready.sh/a\          || true' "$workflow"
expect_fail ready-cannot-be-softened
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/            --toolchain 1.95.0$/a\          || :' "$workflow"
expect_fail toolchain-check-cannot-be-softened
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/          set -euo pipefail$/a\          exit 0' "$workflow"
expect_fail guard-step-cannot-exit-before-check
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/      - name: Verify Cargo offline cache readiness/i\      - name: Cargo before readiness\n        run: cargo test --locked' "$workflow"
expect_fail cargo-cannot-run-before-readiness
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      PATH: /tmp/attacker-bin' "$workflow"
expect_fail path-authority-override
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      BASH_ENV: /tmp/attacker-env' "$workflow"
expect_fail bash-env-authority-override
restore_fixture

workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      NPM_CONFIG_CACHE: ${{ runner.temp }}/npm-cache' "$workflow"
expect_fail runner-temp-cannot-be-used-at-job-scope
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Verify Cargo offline cache readiness/a\        shell: /tmp/attacker-shell {0}' "$workflow"
expect_fail custom-shell-authority-override
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Verify Cargo offline cache readiness/,/--state/{s/--toolchain 1.95.0/--toolchain nightly/}' "$workflow"
expect_fail ready-toolchain-must-match-verifier
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/            --toolchain 1.95.0$/a\            --toolchain nightly-2026-07-27' "$workflow"
expect_fail duplicate-toolchain-last-wins-rejected
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i '/check_cargo_offline_unchanged.sh/a\      - name: late Cargo step\n        run: cargo test --locked' "$workflow"
expect_fail unchanged-must-be-last-step
restore_fixture

workflow="$repo/.github/workflows/rust-l1-testnet-preflight.yml"
sed -i '/check_cargo_offline_unchanged.sh/a\      - run: cargo test --locked' "$workflow"
expect_fail anonymous-step-cannot-follow-unchanged
restore_fixture

workflow="$repo/.github/workflows/p1-rust-sidecar.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      CARGO_HOME: /tmp/attacker-cache' "$workflow"
expect_fail alternate-cargo-home
restore_fixture

workflow="$repo/.github/workflows/p1-rust-sidecar.yml"
sed -i '/Verify Cargo offline cache readiness/a\        env:\n          "CARGO_HOME": /tmp/attacker-cache' "$workflow"
expect_fail quoted-cargo-home
restore_fixture

workflow="$repo/.github/workflows/trnm-poco-bft-v0.yml"
sed -i '/^env:$/a\  "RUSTUP_TOOLCHAIN": nightly' "$workflow"
expect_fail workflow-scope-quoted-toolchain-override
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Verify Cargo offline cache readiness/a\        env:\n          "HOME": /tmp/alternate-home' "$workflow"
expect_fail quoted-home-override
restore_fixture

workflow="$repo/.github/workflows/trnm-merge-gates.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      CARGO_NET_OFFLINE: false' "$workflow"
expect_fail step-or-job-offline-false
restore_fixture

workflow="$repo/.github/workflows/trnm-merge-gates.yml"
sed -i '/^      CARGO_NET_OFFLINE: "true"$/a\      CARGO_NET_OFFLINE: "false"' "$workflow"
expect_fail quoted-offline-false
restore_fixture

workflow="$repo/.github/workflows/trnm-merge-gates.yml"
sed -i '/Verify Cargo offline cache readiness/a\        env:\n          RUSTUP_TOOLCHAIN: nightly' "$workflow"
expect_fail rustup-toolchain-override
restore_fixture

workflow="$repo/.github/workflows/trnm-canonical-input-fuzz-smoke.yml"
sed -i '/Run bounded three-target smoke/a\        env:\n          TRNM_FUZZ_TOOLCHAIN: nightly' "$workflow"
expect_fail fuzz-toolchain-override
restore_fixture

printf '%s\n' 'cargo +nightly fuzz --help' >> \
  "$repo/scripts/ci/check_canonical_fuzz_smoke.sh"
expect_fail canonical-fuzz-cannot-add-direct-toolchain
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Run Agent↔User Phase A gate/a\        run: cargo +nightly test --locked' "$workflow"
expect_fail direct-cargo-toolchain-override
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Run Agent↔User Phase A gate/a\        run: rustup run nightly cargo test --locked' "$workflow"
expect_fail rustup-run-toolchain-override
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '/Run Agent↔User Phase A gate/a\        run: ./scripts/ci/install_cargo_fuzz.sh "$RUNNER_TEMP/tools"' "$workflow"
expect_fail ordinary-job-cannot-install-cargo-tools
restore_fixture

workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"
sed -i '/Verify runner-provisioned cargo-deny/a\        run: ./scripts/ci/install_cargo_deny.sh "$RUNNER_TEMP/tools"' "$workflow"
expect_fail deny-installer-reintroduction
restore_fixture

sed -i '0,/ deny --frozen/s/ --frozen//' \
  "$repo/scripts/ci/check_cargo_deny_offline.sh"
expect_fail cargo-deny-must-stay-frozen
restore_fixture

sed -i 's/1237bbe09d2701e14e6593a630fbaf28928df712/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$repo/scripts/ci/check_preprovisioned_cargo_deny.sh"
expect_fail cargo-deny-advisory-db-commit-drift
restore_fixture

sed -i 's/e915260ced1c90e460153583597cb05efb8f72df489491682f5762710cd0b2ef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$repo/scripts/ci/check_preprovisioned_cargo_fuzz.sh"
expect_fail cargo-fuzz-hash-drift
restore_fixture

workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"
sed -i '/Verify runner-provisioned cargo-deny/a\        continue-on-error: true' "$workflow"
expect_fail cargo-deny-verifier-cannot-swallow-failure
restore_fixture

workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"
sed -i '0,/^          \.\/scripts\/ci\/check_preprovisioned_cargo_deny\.sh$/{s|^          |          # |}' "$workflow"
expect_fail commented-cargo-deny-verifier-cannot-satisfy-policy
restore_fixture

workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"
sed -i '/Run frozen cargo-deny policy checks/a\        continue-on-error: true' "$workflow"
expect_fail cargo-deny-run-cannot-swallow-failure
restore_fixture

workflow="$repo/.github/workflows/trnm-canonical-input-fuzz-smoke.yml"
sed -i '/Verify runner-provisioned cargo-fuzz/a\        continue-on-error: true' "$workflow"
expect_fail cargo-fuzz-verifier-cannot-swallow-failure
restore_fixture

workflow="$repo/.github/workflows/trnm-canonical-input-fuzz-smoke.yml"
sed -i '/Run bounded three-target smoke/a\        continue-on-error: true' "$workflow"
expect_fail cargo-fuzz-smoke-cannot-swallow-failure
restore_fixture

workflow="$repo/.github/workflows/trnm-poco-bft-v0.yml"
sed -i '/TRNM_CARGO_OFFLINE_POLICY: "not-applicable"/a\      CARGO_NET_OFFLINE: "true"' "$workflow"
expect_fail no-cargo-job-cannot-claim-offline
restore_fixture

workflow="$repo/.github/workflows/trnm-poco-bft-v0.yml"
sed -i '/Run bounded formal gate/a\        run: cargo test --locked' "$workflow"
expect_fail no-cargo-job-cannot-run-cargo
restore_fixture

mkdir -p "$repo/scripts"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'cargo update' >"$repo/scripts/online-bypass.sh"
chmod +x "$repo/scripts/online-bypass.sh"
expect_fail nested-cargo-update
restore_fixture

mkdir -p "$repo/scripts"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'export HOME=/tmp/alternate-home' \
  'cargo test --locked' >"$repo/scripts/home-bypass.sh"
chmod +x "$repo/scripts/home-bypass.sh"
expect_fail nested-home-override
restore_fixture

workflow="$repo/.github/workflows/rust-l1-nightly-health.yml"
sed -i '/check_cargo_offline_ready.sh/a\          --config net.offline=false' "$workflow"
expect_fail cargo-config-online-bypass
restore_fixture

workflow="$repo/.github/workflows/rust-l1-nightly-health.yml"
sed -i '/check_cargo_offline_ready.sh/a\          env -u CARGO_NET_OFFLINE cargo test --locked' "$workflow"
expect_fail env-unset-offline-bypass
restore_fixture

workflow="$repo/.github/workflows/rust-l1-nightly-health.yml"
sed -i '/trillionnium\/Cargo.toml:trillionnium\/Cargo.lock/d' "$workflow"
expect_fail missing-manifest-lock-root
restore_fixture

workflow="$repo/.github/workflows/trnm-gate-quick-check.yml"
sed -i '0,/contracts\/Cargo.toml:contracts\/Cargo.lock/s/^            /            # /' "$workflow"
expect_fail commented-manifest-root-cannot-satisfy-ready
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '0,/trillionnium\/Cargo.toml:trillionnium\/Cargo.lock$/s//& contracts\/Cargo.toml:contracts\/Cargo.lock/' "$workflow"
expect_fail extra-manifest-lock-root
restore_fixture

printf '\n  unclassified-job:\n    runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]\n    steps:\n      - run: true\n' \
  >>"$repo/.github/workflows/web4-frontend-ci.yml"
expect_fail new-job-must-be-classified
restore_fixture

printf '\n  bypass: { runs-on: ubuntu-latest, steps: [{run: cargo update}] }\n' \
  >>"$repo/.github/workflows/web4-frontend-ci.yml"
expect_fail flow-style-job-key-rejected
restore_fixture

printf "\n  'bypass':\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo update\n" \
  >>"$repo/.github/workflows/web4-frontend-ci.yml"
expect_fail quoted-job-key-rejected
restore_fixture

workflow="$repo/.github/workflows/web4-frontend-ci.yml"
awk '
  { print }
  /^  gates:/ && !inserted {
    print "# YAML comments do not end the jobs mapping"
    print "  bypass: { runs-on: ubuntu-latest, steps: [{run: cargo update}] }"
    inserted=1
  }
' "$workflow" >"$workflow.tmp"
mv "$workflow.tmp" "$workflow"
expect_fail top-level-comment-cannot-hide-job
restore_fixture

printf '%s\n' 'name: unclassified' 'on: workflow_dispatch' > \
  "$repo/.github/workflows/unclassified.yaml"
expect_fail new-workflow-file-must-be-classified
restore_fixture

workflow="$repo/.github/workflows/agent-user-phasea-gate.yml"
sed -i '0,/^      CARGO_NET_OFFLINE: "true"$/d' "$workflow"
git -C "$repo" add "$workflow"
expect_fail staged-policy-rejects-drift --staged
git -C "$repo" commit -qm 'negative staged fixture'
expect_fail head-policy-rejects-drift --head

printf 'check_cargo_offline_policy tests passed\n'
