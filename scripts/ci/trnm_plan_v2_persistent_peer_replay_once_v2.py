#!/usr/bin/env python3
"""Publish the validated persistent peer replay slice without mutating workflows.

The qualification job runs on the repository-owned trusted x230 runner.  This
wrapper reuses the exact source patch and validation logic, reverts the runtime
workflow edit because the Actions token has no workflow-write authority, and
commits only the Rust source, lockfile and manifest changes.  A connector-owned
follow-up commit permanently wires the runtime matrix and retires this one-shot.
"""

from __future__ import annotations

import pathlib

import trnm_plan_v2_persistent_peer_replay_once as base

RUNTIME_WORKFLOW = pathlib.Path(
    ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml"
)
ORIGINAL_PATCH_SOURCES = base.patch_sources


def patch_sources_without_workflow_mutation() -> None:
    ORIGINAL_PATCH_SOURCES()
    base.run("git", "checkout", "--", str(RUNTIME_WORKFLOW))
    if base.run(
        "git", "status", "--short", "--", str(RUNTIME_WORKFLOW), capture=True
    ):
        raise RuntimeError("runtime workflow remained modified after explicit revert")


def commit_source_only() -> None:
    status = base.run("git", "status", "--short", capture=True)
    changed = sorted(
        line.split(maxsplit=1)[1]
        for line in status.splitlines()
        if line.strip()
    )
    expected = sorted(
        [
            "docs/development/plan-manifest-v1.toml",
            "trillionnium/Cargo.lock",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/candidate_peer_replay.rs",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
            "trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs",
        ]
    )
    if changed != expected:
        raise RuntimeError(f"unexpected source-only changed files: {changed!r} != {expected!r}")

    base.run("git", "config", "user.name", "trillionnium-plan-v2-bot")
    base.run(
        "git",
        "config",
        "user.email",
        "trillionnium-plan-v2-bot@users.noreply.github.com",
    )
    base.run("git", "add", "-A")
    base.run(
        "git",
        "commit",
        "-m",
        "feat(plan-v2): qualify persistent peer replay Core acknowledgement",
    )


def main() -> int:
    base.patch_sources = patch_sources_without_workflow_mutation
    base.commit_final_source = commit_source_only
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
