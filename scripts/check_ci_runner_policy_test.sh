#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
checker="$root/scripts/check_ci_runner_policy.sh"
expected='runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]'
standard_guard_lines=(
  '    if: >-'
  "      github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&"
  "      (github.event_name == 'schedule' ||"
  "        (github.actor == 'ProfAlexQI' &&"
  "         github.triggering_actor == 'ProfAlexQI' &&"
  "         (github.event_name != 'pull_request' ||"
  '          github.event.pull_request.head.repo.full_name == github.repository)))'
)
p1_guard_lines=(
  '    if: >-'
  "      github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&"
  "      github.actor == 'ProfAlexQI' &&"
  "      github.triggering_actor == 'ProfAlexQI' &&"
  "      (github.event_name != 'pull_request' ||"
  '       github.event.pull_request.head.repo.full_name == github.repository) &&'
  "      (github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main')"
)

fixture_root=$(mktemp -d)
trap 'rm -rf -- "$fixture_root"' EXIT

repo="$fixture_root/repo"
workflow_dir="$repo/.github/workflows"
policy_workflow="$workflow_dir/policy.yml"
companion_workflow="$workflow_dir/companion.yaml"
p1_workflow="$workflow_dir/p1-rust-sidecar.yml"
poco_workflow="$workflow_dir/trnm-poco-bft-v0.yml"
mkdir -p "$workflow_dir"
git init -q "$repo"
git -C "$repo" config user.name ci-runner-policy-test
git -C "$repo" config user.email ci-runner-policy-test@example.invalid

write_policy_workflow() {
  printf '%s\n' "$@" >"$policy_workflow"
}

write_companion_workflow() {
  printf '%s\n' \
    'name: companion' \
    'on: [push]' \
    'jobs:' \
    '  companion:' \
    "${standard_guard_lines[@]}" \
    "    $expected" \
    '    steps:' \
    '      - run: true' >"$companion_workflow"
}

write_p1_workflow() {
  printf '%s\n' \
    'name: p1-rust-sidecar' \
    'on: [workflow_dispatch]' \
    'jobs:' \
    '  p1-with-rust-sidecar:' \
    "${p1_guard_lines[@]}" \
    "    $expected" \
    '    steps:' \
    '      - run: true' >"$p1_workflow"
}

write_poco_workflow() {
  printf '%s\n' \
    'name: trnm-poco-bft-v0' \
    'on: [schedule]' \
    'jobs:' \
    '  scheduled-main-only:' \
    '    if: >-' \
    "      github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&" \
    "      (github.event_name == 'schedule' && github.ref == 'refs/heads/main' ||" \
    "       (github.actor == 'ProfAlexQI' &&" \
    "        github.triggering_actor == 'ProfAlexQI' &&" \
    "        (github.event_name != 'pull_request' ||" \
    '         github.event.pull_request.head.repo.full_name == github.repository)))' \
    "    $expected" \
    '    steps:' \
    '      - run: true' >"$poco_workflow"
}

run_policy() {
  (
    cd "$repo"
    bash "$checker" "$1"
  )
}

expect_pass() {
  local name=$1
  local source_mode=$2
  local expected_jobs="${3:-3}"
  local output
  if ! output=$(run_policy "$source_mode" 2>&1); then
    printf 'FAIL: %s unexpectedly failed\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  if [[ "$output" != *"jobs=${expected_jobs} "* ]]; then
    printf 'FAIL: %s returned an unexpected job count\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  printf 'PASS: %s\n' "$name"
}

expect_fail() {
  local name=$1
  local source_mode=$2
  local output
  if output=$(run_policy "$source_mode" 2>&1); then
    printf 'FAIL: %s unexpectedly passed\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  printf 'PASS: %s rejected\n' "$name"
}

write_companion_workflow
write_p1_workflow
write_poco_workflow
write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  direct-runner:' \
  "${standard_guard_lines[@]}" \
  "    $expected" \
  '    steps:' \
  '      - run: |' \
  '          # Nested scalar content must not be interpreted as a job runner.' \
  '          runs-on: ubuntu-latest'

expect_pass worktree-positive --worktree 4
git -C "$repo" add .github/workflows
expect_pass staged-positive --staged 4
git -C "$repo" commit -qm 'baseline runner policy fixture'
expect_pass head-positive --head 4

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  missing-guard:' \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail missing-job-trust-guard --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  comment-guard:' \
  '    # if: >-' \
  "    # github.repository == 'TrillionniumFoundation/Trillionnium-Chain'" \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail comment-cannot-satisfy-trust-guard --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  nested-guard:' \
  "    $expected" \
  '    steps:' \
  '      - name: nested guard is not a job guard' \
  '        if: >-' \
  "          github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&" \
  "          github.actor == 'ProfAlexQI' &&" \
  "          github.triggering_actor == 'ProfAlexQI'" \
  '        run: true'
expect_fail nested-guard-cannot-satisfy-job --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  schedule-only:' \
  '    if: >-' \
  "      github.event_name == 'schedule'" \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail schedule-alone-cannot-bypass-trust --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  forged-repository:' \
  '    if: >-' \
  "      github.repository == 'TrillionniumFoundation/Trillionnium' &&" \
  "      github.actor == 'ProfAlexQI' &&" \
  "      github.triggering_actor == 'ProfAlexQI' &&" \
  '      github.event.pull_request.head.repo.full_name == github.repository' \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail forged-repository-guard --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  forged-dead-branch:' \
  '    if: >-' \
  "      github.event_name == 'schedule' || true ||" \
  "      (github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&" \
  "       github.actor == 'ProfAlexQI' &&" \
  "       github.triggering_actor == 'ProfAlexQI' &&" \
  '       github.event.pull_request.head.repo.full_name == github.repository)' \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail dead-branch-tokens-cannot-forge-trust --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  inline-guard:' \
  "    if: github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && github.actor == 'ProfAlexQI'" \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail trust-guard-must-be-folded --worktree

printf '%s\n' \
  'name: p1-rust-sidecar' \
  'on: [workflow_dispatch]' \
  'jobs:' \
  '  p1-with-rust-sidecar:' \
  "${standard_guard_lines[@]}" \
  "    $expected" \
  '    steps:' \
  '      - run: true' >"$p1_workflow"
expect_fail p1-cannot-use-schedule-exception-guard --worktree
write_p1_workflow

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  unauthorized:' \
  "${standard_guard_lines[@]}" \
  '    runs-on: ubuntu-latest' \
  '    steps:' \
  '      - run: true'
expect_fail unauthorized-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  missing-runner:' \
  "${standard_guard_lines[@]}" \
  "    # $expected" \
  '    steps:' \
  '      - run: true'
expect_fail comment-cannot-satisfy-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  nested-runner-only:' \
  "${standard_guard_lines[@]}" \
  '    steps:' \
  '      - run: |' \
  "          $expected"
expect_fail nested-runner-cannot-satisfy-job --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  reusable:' \
  "${standard_guard_lines[@]}" \
  '    uses: owner/repository/.github/workflows/reusable.yml@0123456789abcdef'
expect_fail reusable-job-without-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  reusable-with-runner:' \
  "${standard_guard_lines[@]}" \
  "    $expected" \
  '    uses: owner/repository/.github/workflows/reusable.yml@0123456789abcdef'
expect_fail reusable-job-with-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  duplicate-runner:' \
  "${standard_guard_lines[@]}" \
  "    $expected" \
  "    $expected" \
  '    steps:' \
  '      - run: true'
expect_fail duplicate-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  valid:' \
  "${standard_guard_lines[@]}" \
  "    $expected" \
  '    steps:' \
  '      - run: true' \
  '  missing:' \
  '    steps:' \
  '      - run: true'
expect_fail one-valid-job-cannot-hide-missing-runner --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  inline: { uses: owner/repository/.github/workflows/reusable.yml@0123456789abcdef }'
expect_fail inline-job-cannot-bypass-parser --worktree

write_policy_workflow \
  'name: policy' \
  'on: [push]' \
  'jobs:' \
  '  staged-reusable:' \
  "${standard_guard_lines[@]}" \
  '    uses: owner/repository/.github/workflows/reusable.yml@0123456789abcdef'
git -C "$repo" add "$policy_workflow"
expect_fail staged-reusable-job --staged
git -C "$repo" commit -qm 'negative reusable workflow fixture'
expect_fail head-reusable-job --head

printf 'check_ci_runner_policy tests passed\n'
