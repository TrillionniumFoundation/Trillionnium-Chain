#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

EXPECTED_HEAD = "3a4e2fa066de74025866da94cfe8a9efbfca03aa"
EXPECTED_BLOBS = {
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


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    require_exact_base(root)
    core = root / "trillionnium/crates/trnm-consensus-core/src/core.rs"
    docs = root / "docs/development/packages/TRNM_G1_R4_FINALIZATION_RECOVERY_TARGET_V1.md"

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
