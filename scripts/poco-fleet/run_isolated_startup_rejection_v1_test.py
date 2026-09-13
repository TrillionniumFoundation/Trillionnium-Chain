#!/usr/bin/env python3
"""Focused contract tests for the isolated startup-rejection runner."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import stat
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "run_isolated_startup_rejection_v1",
    HERE / "run_isolated_startup_rejection_v1.py",
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def private_dir(path: pathlib.Path, mode: int = 0o700) -> None:
    path.mkdir(mode=mode)
    path.chmod(mode)


def private_file(path: pathlib.Path, payload: bytes, mode: int = 0o600) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def fixture(root: pathlib.Path) -> pathlib.Path:
    primary = root / "runtime-authority-v1"
    private_dir(primary)
    safety = primary / "target-safety"
    application = primary / "target-application"
    signer = primary / "target-signer"
    for directory in (safety, application, signer):
        private_dir(directory)
    private_file(safety / "safety.sqlite3", b"SQLite format 3\x00" + b"S" * 256)
    private_file(application / "application.sqlite3", b"SQLite format 3\x00" + b"A" * 320)
    private_file(signer / "signer.sqlite3", b"SQLite format 3\x00" + b"J" * 384)
    return primary


def tree_projection(root: pathlib.Path) -> dict[str, tuple[int, int, str, int, int]]:
    result: dict[str, tuple[int, int, str, int, int]] = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            result[relative] = (
                1,
                stat.S_IMODE(metadata.st_mode),
                "",
                metadata.st_dev,
                metadata.st_ino,
            )
        else:
            result[relative] = (
                metadata.st_size,
                stat.S_IMODE(metadata.st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
                metadata.st_dev,
                metadata.st_ino,
            )
    return result


def assert_exact_shape_and_changes(
    primary: pathlib.Path,
    isolated: pathlib.Path,
    expected_changed: int,
) -> None:
    left = tree_projection(primary)
    right = tree_projection(isolated)
    assert set(left) == set(right)
    changed = 0
    for relative in left:
        left_size, left_mode, left_digest, left_dev, left_inode = left[relative]
        right_size, right_mode, right_digest, right_dev, right_inode = right[relative]
        assert (left_size, left_mode) == (right_size, right_mode)
        assert (left_dev, left_inode) != (right_dev, right_inode)
        if left_digest != right_digest:
            changed += 1
    assert changed == expected_changed


def result_fixture(evidence: pathlib.Path, fault_kind: str) -> dict[str, object]:
    artifact = runner.sha256_file(evidence, runner.MAX_EVIDENCE_BYTES)
    changed = 1 if fault_kind == "rollback_attempt" else 2
    return {
        "schema_version": 1,
        "status": "isolated-startup-rejection-authenticated-and-persisted",
        "run_id": "poco-g3-7-20260814T000000Z-deadbeef",
        "validator_id": "01" * 32,
        "target_config_sha256": "02" * 32,
        "fleet_start_certificate_sha256": "03" * 32,
        "fault_kind": fault_kind,
        "changed_file_count": changed,
        "attempt_nonce": "04" * 32,
        "node_error_class": "deployed_ordinary_reopen_v0",
        "node_error_stage": "safety.open_existing",
        "primary_cut_sha256": "05" * 32,
        "isolated_snapshot_sha256": "06" * 32,
        "isolated_snapshot_inventory_sha256": "07" * 32,
        "runtime_journal_sha256": "08" * 32,
        "runtime_journal_bytes": 100,
        "process_instance": 1,
        "primary_unchanged": True,
        "runtime_journal_unchanged": True,
        "network_started": False,
        "evidence_sha256": "09" * 32,
        "artifact_sha256": artifact,
        "artifact_path": str(evidence),
        "fault_campaign_observed": False,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def reject(callable_value) -> None:
    try:
        callable_value()
    except SystemExit:
        return
    raise AssertionError("negative case unexpectedly succeeded")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_value:
        temporary = pathlib.Path(temporary_value)
        temporary.chmod(0o700)
        primary = fixture(temporary)

        rollback = temporary / "rollback"
        copied, mutated = runner.prepare_isolated_mutation(
            primary, rollback, "rollback_attempt"
        )
        assert len(copied) == 3
        assert mutated == (runner.SAFETY_MUTATION_RELATIVE,)
        assert_exact_shape_and_changes(primary, rollback, 1)

        stale = temporary / "stale"
        copied, mutated = runner.prepare_isolated_mutation(
            primary, stale, "stale_snapshot"
        )
        assert len(copied) == 3
        assert len(mutated) == 2
        assert mutated[0] == runner.SAFETY_MUTATION_RELATIVE
        assert_exact_shape_and_changes(primary, stale, 2)

        hardlink = primary / "target-signer" / "hardlink.sqlite3"
        hardlink.hardlink_to(primary / "target-signer" / "signer.sqlite3")
        reject(
            lambda: runner.prepare_isolated_mutation(
                primary, temporary / "hardlink-copy", "rollback_attempt"
            )
        )
        hardlink.unlink()

        escape = primary / "target-signer" / "escape"
        escape.symlink_to(primary / "target-safety" / "safety.sqlite3")
        reject(
            lambda: runner.prepare_isolated_mutation(
                primary, temporary / "symlink-copy", "rollback_attempt"
            )
        )
        escape.unlink()

        evidence = temporary / "evidence.bin"
        private_file(evidence, b"canonical-evidence")
        positive = result_fixture(evidence, "rollback_attempt")
        assert (
            runner.validate_result(
                positive,
                fault_kind="rollback_attempt",
                attempt_nonce="04" * 32,
                evidence_path=evidence,
            )
            == positive
        )
        observed = dict(positive)
        observed["fault_campaign_observed"] = True
        reject(
            lambda: runner.validate_result(
                observed,
                fault_kind="rollback_attempt",
                attempt_nonce="04" * 32,
                evidence_path=evidence,
            )
        )
        extra = dict(positive)
        extra["unexpected"] = False
        reject(
            lambda: runner.validate_result(
                extra,
                fault_kind="rollback_attempt",
                attempt_nonce="04" * 32,
                evidence_path=evidence,
            )
        )
        boolean_count = dict(positive)
        boolean_count["changed_file_count"] = True
        reject(
            lambda: runner.validate_result(
                boolean_count,
                fault_kind="rollback_attempt",
                attempt_nonce="04" * 32,
                evidence_path=evidence,
            )
        )

    print("isolated startup rejection runner: positives=3 negatives=5")


if __name__ == "__main__":
    main()
