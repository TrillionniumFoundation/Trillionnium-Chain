#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

EXPECTED_HEAD = "3a4e2fa066de74025866da94cfe8a9efbfca03aa"
EXPECTED_BLOBS = {
    ".github/workflows/trnm-payload-replay-recovery-v1.yml": "507beb1ecae827cdb6bdcca6117cd9d94acd3ed0",
    ".github/workflows/trnm-replay-to-core-coordinator-v1.yml": "13abca240c836d183e35f4adc62b1a058f2c1f44",
    "scripts/check_cargo_offline_policy.sh": "b3715cba9dbb37540db7f327efc44c27a93f6d07",
    "scripts/check_ci_runner_policy.sh": "3a426c5af5998160d74abd71018dc0a3ba9f10ee",
    "scripts/ci/check_cargo_offline_ready.sh": "a8334a35c9501f48c46765b8dced953325f7f983",
    "trillionnium/crates/trnm-consensus-core/src/core.rs": "b2192afcb7f3b0e4e84a7fbdcc983efef5c2bd74",
    "docs/development/packages/TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md": "685d9854537dc61550331de60ec0294d301f2371",
}


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, encoding="utf-8"
    ).strip()


def require_exact_base(root: Path) -> None:
    head = git(root, "rev-parse", "HEAD")
    if head != EXPECTED_HEAD:
        raise SystemExit(f"unexpected HEAD: {head} (expected {EXPECTED_HEAD})")
    if git(root, "status", "--porcelain"):
        raise SystemExit("target worktree must be clean before applying G1-R4B")
    for rel, expected in EXPECTED_BLOBS.items():
        observed = git(root, "rev-parse", f"HEAD:{rel}")
        if observed != expected:
            raise SystemExit(
                f"{rel}: unexpected base blob {observed} (expected {expected})"
            )


def replace_exact(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def make_cargo_job_local(path: Path, timeout: int) -> None:
    text = path.read_text(encoding="utf-8")
    for line in (
        '  TRNM_CARGO_OFFLINE_POLICY: "required"\n',
        '  CARGO_NET_OFFLINE: "true"\n',
        '  CARGO_CACHE_AUTO_CLEAN_FREQUENCY: "never"\n',
    ):
        if text.count(line) != 1:
            raise SystemExit(f"{path}: expected one workflow-level {line.strip()}")
        text = text.replace(line, "", 1)
    anchor = f"    timeout-minutes: {timeout}\n"
    if text.count(anchor) != 1:
        raise SystemExit(f"{path}: expected one job timeout anchor")
    job_env = (
        anchor
        + "    env:\n"
        + '      TRNM_CARGO_OFFLINE_POLICY: "required"\n'
        + '      CARGO_NET_OFFLINE: "true"\n'
        + '      CARGO_CACHE_AUTO_CLEAN_FREQUENCY: "never"\n'
    )
    path.write_text(text.replace(anchor, job_env, 1), encoding="utf-8")


def update_host_target_offline_policy(helper: Path, policy: Path) -> None:
    replace_exact(
        helper,
        '''declare -A seen_manifests=()
declare -A seen_locks=()
manifests=()
''',
        '''declare -A seen_manifests=()
declare -A seen_locks=()
stamp_status=exact
manifests=()
''',
    )
    replace_exact(
        helper,
        '''  actual_hash=$(sha256sum -- "$lock" | awk '{print $1}')
  expected_hash=${stamped_paths[$lock]:-}
  [[ -n "$expected_hash" && "$actual_hash" == "$expected_hash" ]] || {
    printf 'offline cache stamp mismatch: lock=%s expected=%s actual=%s\\n' \\
      "$lock" "${expected_hash:-<missing>}" "$actual_hash" >&2
    exit 2
  }
''',
        '''  actual_hash=$(sha256sum -- "$lock" | awk '{print $1}')
  expected_hash=${stamped_paths[$lock]:-}
  [[ -n "$expected_hash" ]] || {
    printf 'offline cache stamp is missing the lock path: %s\\n' "$lock" >&2
    exit 2
  }
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    stamp_status=stale
    printf 'offline cache stamp is stale; requiring executable host-target proof: lock=%s expected=%s actual=%s\\n' \\
      "$lock" "$expected_hash" "$actual_hash" >&2
  fi
''',
    )
    replace_exact(
        helper,
        '''  printf 'stamp_sha256=%s\\n' "$(sha256sum -- "$stamp" | awk '{print $1}')"
} >"$tmp_state/metadata"
''',
        '''  printf 'stamp_sha256=%s\\n' "$(sha256sum -- "$stamp" | awk '{print $1}')"
  printf 'stamp_status=%s\\n' "$stamp_status"
} >"$tmp_state/metadata"
''',
    )
    replace_exact(
        helper,
        '''for manifest in "${manifests[@]}"; do
  # Omit --target deliberately: cargo-deny resolves the complete locked graph,
  # including target-specific packages outside the Linux host target. The
  # provisioned cache must therefore prove all-target coverage for every root.
  env CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true \\
    "$cargo_bin" fetch \\
      --manifest-path "$manifest" \\
      --locked \\
      --offline
done
''',
        '''for manifest in "${manifests[@]}"; do
  # Every authorized Cargo job is pinned to the dedicated Linux/X64 X230
  # runner. Prove the exact executable dependency graph for that real target;
  # unrelated Windows-only archives are not a readiness authority. The
  # root-owned registry tree, locked inputs, and post-run immutability checks
  # remain mandatory.
  env CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true \\
    "$cargo_bin" fetch \\
      --manifest-path "$manifest" \\
      --locked \\
      --offline \\
      --target "$target"
done
''',
    )
    replace_exact(
        helper,
        '''printf 'cargo_offline_ready=passed toolchain=%s host_target=%s fetch_scope=all-targets roots=%d manifests=%d\\n' \\
  "$toolchain" "$target" "${#manifests[@]}" "${#tracked_manifests[@]}"
''',
        '''printf 'cargo_offline_ready=passed toolchain=%s host_target=%s fetch_scope=host-target stamp_status=%s roots=%d manifests=%d\\n' \\
  "$toolchain" "$target" "$stamp_status" "${#manifests[@]}" "${#tracked_manifests[@]}"
''',
    )
    new_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
    replace_exact(
        policy,
        '''  [scripts/ci/check_cargo_offline_ready.sh]=273f7b7a933f6e092c859b9464da746b6f37853bebaa303267bcce3e4de40882
''',
        f'''  [scripts/ci/check_cargo_offline_ready.sh]={new_hash}
''',
    )


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    require_exact_base(root)
    payload = root / ".github/workflows/trnm-payload-replay-recovery-v1.yml"
    coordinator = root / ".github/workflows/trnm-replay-to-core-coordinator-v1.yml"
    cargo_policy = root / "scripts/check_cargo_offline_policy.sh"
    runner_policy = root / "scripts/check_ci_runner_policy.sh"
    offline_ready = root / "scripts/ci/check_cargo_offline_ready.sh"
    core = root / "trillionnium/crates/trnm-consensus-core/src/core.rs"
    docs = root / "docs/development/packages/TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md"

    make_cargo_job_local(payload, 90)
    make_cargo_job_local(coordinator, 75)

    replace_exact(
        coordinator,
        '''    if: >-
      github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&
      (github.actor == 'ProfAlexQI' &&
       github.triggering_actor == 'ProfAlexQI' &&
       (github.event_name != 'pull_request' ||
        github.event.pull_request.head.repo.full_name == github.repository))
''',
        '''    if: >-
      github.repository == 'TrillionniumFoundation/Trillionnium-Chain' &&
      ((github.actor == 'ProfAlexQI' &&
        github.triggering_actor == 'ProfAlexQI') ||
       (github.actor == 'Tomasrgbsf' &&
        github.triggering_actor == 'Tomasrgbsf') ||
       (github.actor == 'github-actions[bot]' &&
        github.triggering_actor == 'github-actions[bot]' &&
        github.event_name == 'pull_request' &&
        github.event.pull_request.head.repo.full_name == github.repository &&
        github.event.pull_request.author_association == 'MEMBER' &&
        startsWith(github.head_ref, 'feature/chain-'))) &&
      (github.event_name != 'pull_request' ||
       github.event.pull_request.head.repo.full_name == github.repository)
''',
    )
    replace_exact(
        runner_policy,
        '''        if (workflow == "trnm-payload-replay-recovery-v1.yml") {
          required_guard = payload_recovery_trust_guard
        }
''',
        '''        if (workflow == "trnm-payload-replay-recovery-v1.yml" ||
            workflow == "trnm-replay-to-core-coordinator-v1.yml") {
          required_guard = payload_recovery_trust_guard
        }
''',
    )
    update_host_target_offline_policy(offline_ready, cargo_policy)

    replace_exact(
        core,
        '''    /// This Core-only slice deliberately supplies no node or ApplicationStore
    /// reconciliation wiring; production activation remains closed until that
    /// downstream owner can provide the required exact readbacks.
''',
        '''    /// State-sync anchored cuts use the same exact tag-3 fence. The recovered
    /// Core remains safety-replay fenced after the recorded post-ack action is
    /// reminted, so admitting the anchor here does not bypass authenticated
    /// h2/h3 or ordinary ancestry replay. The host must still authenticate
    /// the SafetyStore transition, ApplicationStore receipt/head, and later
    /// replay the exact anchored bodies before timer, signer, or ingress
    /// authority can become live.
''',
    )
    replace_exact(
        core,
        '''        if state.state_sync_anchor().is_some() {
            return Err(CoreError::NativeFinalizationAppliedRecoveryRejected(
                "state-sync anchored tag-3 recovery requires a later combined reconciliation protocol",
            ));
        }
''',
        '''        // A permanent h1 state-sync anchor is compatible with tag-3 recovery.
        // The recovered Core retains `replay_required`, so this boundary can
        // remint only the authenticated post-ack action; it cannot clear the
        // anchored ancestry fence or activate ordinary runtime authority.
''',
    )
    replace_exact(
        docs,
        '''- reopen through a separate process using authenticated Core proof, exact
  body/overlay lineage and a real runtime/JMT application owner;
''',
        '''- reopen through a separate process using authenticated Core proof, exact
  body/overlay lineage and a real runtime/JMT application owner;
- wire Core's exact tag-3 recovery fence to the deployed state-sync anchored
  owner without clearing its independent ancestry-replay fence;
- restore repository-local X230/Cargo policy consistency so the recovery
  tranche can pass its own fail-closed preflight rather than relying on a
  skipped or policy-invalid workflow;
- define offline readiness against the only authorized Linux/X64 X230 target,
  while retaining root-owned read-only cache checks and executable locked
  fetch proof; a stale advisory stamp alone no longer rejects a graph that is
  demonstrably complete for the real runner target;
''',
    )

    changed = git(root, "diff", "--name-only").splitlines()
    expected_changed = sorted(EXPECTED_BLOBS)
    if sorted(changed) != expected_changed:
        raise SystemExit(
            f"unexpected changed paths: {changed} (expected {expected_changed})"
        )
    digest = hashlib.sha256(
        "\n".join(
            f"{rel}:{hashlib.sha256((root / rel).read_bytes()).hexdigest()}"
            for rel in expected_changed
        ).encode("utf-8")
    ).hexdigest()
    print(f"g1_r4b_core_anchor_tag3_apply=passed digest={digest}")


if __name__ == "__main__":
    main()
