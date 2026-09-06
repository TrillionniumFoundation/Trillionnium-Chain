#!/usr/bin/env python3
"""One-shot exact-source qualification for the Plan v2 persistent peer replay slice."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = pathlib.Path(
    ".github/workflows/trnm-plan-v2-persistent-peer-replay-once.yml"
)
SELF = pathlib.Path("scripts/ci/trnm_plan_v2_persistent_peer_replay_once.py")


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )
    return result.stdout.strip() if capture else ""


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_sources() -> None:
    replace_once(
        "trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs",
        """pub struct VerifiedPeerFrameV0 {
    prior: PeerReplayStateV0,
    frame: AuthenticatedPeerFrameV0,
}

pub struct CandidateP2pAdmissionV0 {""",
        """pub struct VerifiedPeerFrameV0 {
    prior: PeerReplayStateV0,
    frame: AuthenticatedPeerFrameV0,
}

impl VerifiedPeerFrameV0 {
    #[must_use]
    pub const fn prior(&self) -> PeerReplayStateV0 {
        self.prior
    }

    #[must_use]
    pub const fn frame(&self) -> AuthenticatedPeerFrameV0 {
        self.frame
    }
}

pub struct CandidateP2pAdmissionV0 {""",
    )
    replace_once(
        "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
        """mod candidate_authority;
pub use candidate_authority::{CandidateAuthorityErrorV0, CandidateAuthorityJournalV0};

use fs2::FileExt;""",
        """mod candidate_authority;
pub use candidate_authority::{CandidateAuthorityErrorV0, CandidateAuthorityJournalV0};

#[cfg(feature = "candidate-peer-replay")]
mod candidate_peer_replay;
#[cfg(feature = "candidate-peer-replay")]
pub use candidate_peer_replay::*;

use fs2::FileExt;""",
    )
    replace_once(
        "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
        """const POINTER_MAGIC_V0: &[u8; 8] = b"TRNMSP00";
const POINTER_BYTES_V0: usize = 120;

#[derive(Debug)]""",
        """const POINTER_MAGIC_V0: &[u8; 8] = b"TRNMSP00";
const POINTER_BYTES_V0: usize = 120;

#[must_use]
pub fn file_authority_record_digest_v0(
    identity_digest: NodeDigestV0,
    binding: OperationBindingV0,
    stage: AuthorityStageV0,
    sequence: u64,
    facts_digest: NodeDigestV0,
    previous_record_digest: NodeDigestV0,
) -> NodeDigestV0 {
    NodeDigestV0::hash(
        b"trnm.file-authority-record.v0",
        &[
            &identity_digest.0,
            &binding.operation_id.0,
            &binding.height.to_be_bytes(),
            &binding.view.to_be_bytes(),
            &binding.block_id.0,
            &binding.parent_id.0,
            &binding.proposal_digest.0,
            &[stage as u8],
            &sequence.to_be_bytes(),
            &facts_digest.0,
            &previous_record_digest.0,
        ],
    )
}

#[derive(Debug)]""",
    )
    replace_once(
        "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
        """    fn canonical_digest(
        identity_digest: NodeDigestV0,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        sequence: u64,
        facts_digest: NodeDigestV0,
        previous_record_digest: NodeDigestV0,
    ) -> NodeDigestV0 {
        NodeDigestV0::hash(
            b"trnm.file-authority-record.v0",
            &[
                &identity_digest.0,
                &binding.operation_id.0,
                &binding.height.to_be_bytes(),
                &binding.view.to_be_bytes(),
                &binding.block_id.0,
                &binding.parent_id.0,
                &binding.proposal_digest.0,
                &[stage as u8],
                &sequence.to_be_bytes(),
                &facts_digest.0,
                &previous_record_digest.0,
            ],
        )
    }""",
        """    fn canonical_digest(
        identity_digest: NodeDigestV0,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        sequence: u64,
        facts_digest: NodeDigestV0,
        previous_record_digest: NodeDigestV0,
    ) -> NodeDigestV0 {
        file_authority_record_digest_v0(
            identity_digest,
            binding,
            stage,
            sequence,
            facts_digest,
            previous_record_digest,
        )
    }""",
    )
    replace_once(
        "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
        "use trnm_durable_file_adapters_v0::FileAuthorityCoordinatorV0;\n",
        "use trnm_durable_file_adapters_v0::{\n    file_authority_record_digest_v0, FileAuthorityCoordinatorV0,\n};\n",
    )
    replace_once(
        "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
        """        Some(Digest32V0::hash(
            b"trnm.node.authority-record.v0",
            &[
                &identity.digest().0,
                &current.binding.operation_id.0,
                &[next_stage as u8],
                &expected_sequence.to_be_bytes(),
                &facts_digest.0,
                &current.record_digest.0,
            ],
        ))""",
        """        Some(file_authority_record_digest_v0(
            identity.digest(),
            current.binding,
            next_stage,
            expected_sequence,
            facts_digest,
            current.record_digest,
        ))""",
    )
    replace_once(
        ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml",
        "      - name: Run candidate pacemaker and authenticated P2P authority bridge\n",
        "      - name: Run candidate pacemaker, authenticated P2P and persistent replay authority bridge\n",
    )
    replace_once(
        ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml",
        """          cargo test --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-io \\
            --features candidate-pacemaker,candidate-authenticated-p2p \\
            --all-targets --locked --offline
          cargo test --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-host \\
""",
        """          cargo test --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-io \\
            --features candidate-pacemaker,candidate-authenticated-p2p \\
            --all-targets --locked --offline
          cargo test --manifest-path trillionnium/Cargo.toml \\
            -p trnm-durable-file-adapters-v0 \\
            --features candidate-peer-replay \\
            --all-targets --locked --offline
          cargo test --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-host \\
""",
    )
    replace_once(
        ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml",
        """          cargo clippy --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-io \\
            --features candidate-pacemaker,candidate-authenticated-p2p \\
            --all-targets --locked --offline -- -D warnings
          cargo clippy --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-host \\
""",
        """          cargo clippy --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-io \\
            --features candidate-pacemaker,candidate-authenticated-p2p \\
            --all-targets --locked --offline -- -D warnings
          cargo clippy --manifest-path trillionnium/Cargo.toml \\
            -p trnm-durable-file-adapters-v0 \\
            --features candidate-peer-replay \\
            --all-targets --locked --offline -- -D warnings
          cargo clippy --manifest-path trillionnium/Cargo.toml \\
            -p trnm-poco-node-host \\
""",
    )
    replace_once(
        ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml",
        """              "candidate_authenticated_p2p": True,
              "candidate_p2p_authority_bridge": True,
""",
        """              "candidate_authenticated_p2p": True,
              "candidate_persistent_peer_replay": True,
              "candidate_atomic_core_prepared_ack": True,
              "candidate_p2p_authority_bridge": True,
""",
    )


def update_lock_and_pin() -> None:
    run(
        "cargo",
        "check",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "-p",
        "trnm-durable-file-adapters-v0",
        "--features",
        "candidate-peer-replay",
    )
    lock_blob = run("git", "hash-object", "trillionnium/Cargo.lock", capture=True)
    manifest_path = ROOT / "docs/development/plan-manifest-v1.toml"
    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    matches = [
        index
        for index, line in enumerate(lines)
        if line.startswith('workspace_lock_git_blob = "')
    ]
    if len(matches) != 1:
        raise RuntimeError(f"unexpected workspace lock pin count: {len(matches)}")
    lines[matches[0]] = f'workspace_lock_git_blob = "{lock_blob}"'
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    run("cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all")
    run(
        "cargo",
        "fmt",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "--all",
        "--",
        "--check",
    )
    run("git", "diff", "--check")


def commit_final_source() -> None:
    run("git", "rm", str(WORKFLOW), str(SELF))
    status = run("git", "status", "--short", capture=True)
    changed = sorted(
        line.split(maxsplit=1)[1]
        for line in status.splitlines()
        if line.strip()
    )
    expected = sorted(
        [
            ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml",
            str(WORKFLOW),
            "docs/development/plan-manifest-v1.toml",
            str(SELF),
            "trillionnium/Cargo.lock",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/candidate_peer_replay.rs",
            "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
            "trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs",
        ]
    )
    if changed != expected:
        raise RuntimeError(f"unexpected changed files: {changed!r} != {expected!r}")
    run("git", "config", "user.name", "trillionnium-plan-v2-bot")
    run(
        "git",
        "config",
        "user.email",
        "trillionnium-plan-v2-bot@users.noreply.github.com",
    )
    run("git", "add", "-A")
    run(
        "git",
        "commit",
        "-m",
        "feat(plan-v2): qualify persistent peer replay Core acknowledgement",
    )


def validate_exact_source() -> None:
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("worktree is not clean after final commit")
    run(sys.executable, "scripts/ci/check_plan_manifest_pins_v1.py")
    run(sys.executable, "scripts/ci/check_blocker_execution_v1.py")
    run(sys.executable, "scripts/ci/check_module_coverage_v1.py")
    run(sys.executable, "scripts/ci/check_repository_truth_v1.py")
    run("bash", "scripts/ci/check_poco_bft_mainline_truth.sh", "--pre-cutover")
    run(
        "cargo",
        "fmt",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "--all",
        "--",
        "--check",
    )
    run(
        "cargo",
        "check",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "--workspace",
        "--all-targets",
        "--locked",
    )
    run(
        "cargo",
        "test",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "-p",
        "trnm-poco-node-io",
        "--features",
        "candidate-pacemaker,candidate-authenticated-p2p",
        "--all-targets",
        "--locked",
    )
    run(
        "cargo",
        "test",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "-p",
        "trnm-durable-file-adapters-v0",
        "--features",
        "candidate-peer-replay",
        "--all-targets",
        "--locked",
    )
    run(
        "cargo",
        "test",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "-p",
        "trnm-poco-node-host",
        "--features",
        "candidate-networked-authority",
        "--all-targets",
        "--locked",
    )
    for package, features in (
        (
            "trnm-poco-node-io",
            "candidate-pacemaker,candidate-authenticated-p2p",
        ),
        ("trnm-durable-file-adapters-v0", "candidate-peer-replay"),
        ("trnm-poco-node-host", "candidate-networked-authority"),
    ):
        run(
            "cargo",
            "clippy",
            "--manifest-path",
            "trillionnium/Cargo.toml",
            "-p",
            package,
            "--features",
            features,
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        )
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("validation changed the exact source")


def main() -> int:
    expected_parent = os.environ["EXPECTED_PARENT_SHA"]
    target_branch = os.environ["TARGET_BRANCH"]
    if run("git", "rev-parse", "HEAD^", capture=True) != expected_parent:
        raise RuntimeError("one-shot parent changed")
    if os.environ.get("GITHUB_REF_NAME") != target_branch:
        raise RuntimeError("one-shot branch changed")
    patch_sources()
    update_lock_and_pin()
    commit_final_source()
    validate_exact_source()
    run("git", "push", "origin", f"HEAD:{target_branch}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"persistent peer replay qualification failed: {error}", file=sys.stderr)
        raise SystemExit(2)
