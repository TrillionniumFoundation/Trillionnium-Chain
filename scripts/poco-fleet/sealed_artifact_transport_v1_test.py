#!/usr/bin/env python3
"""Focused closed-boundary tests for sealed artifact transport v1."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
from collections.abc import Callable


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "sealed_artifact_transport_v1", HERE / "sealed_artifact_transport_v1.py"
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load sealed artifact transport module")
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)


def expect_failure(action: Callable[[], object], contains: str) -> None:
    try:
        action()
    except (transport.SealedArtifactTransportError, OSError) as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("sealed artifact negative control unexpectedly succeeded")


def private_file(path: pathlib.Path, content: bytes) -> pathlib.Path:
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def private_directory(path: pathlib.Path) -> pathlib.Path:
    path.mkdir()
    path.chmod(0o700)
    return path


class CaptureInput(io.BytesIO):
    def close(self) -> None:
        self.flush()


class FakeProcess:
    def __init__(self, stdout: bytes, *, stdin: bool = False, return_code: int = 0):
        self.stdout = io.BytesIO(stdout)
        self.stdin = CaptureInput() if stdin else None
        self.return_code = return_code
        self.killed = False

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        return self.return_code

    def kill(self) -> None:
        self.killed = True


def export_frame(payload: bytes, *, second: str | None = None) -> bytes:
    digest = hashlib.sha256(payload).hexdigest()
    return (
        f"TRNM_SEALED_ARTIFACT_EXPORT_V1 {len(payload)}\n".encode("ascii")
        + payload
        + f"TRNM_SEALED_ARTIFACT_EXPORT_END_V1 {len(payload)} {digest} {second or digest}\n".encode(
            "ascii"
        )
    )


def receipt(payload: bytes, *, digest: str | None = None) -> bytes:
    expected = digest or hashlib.sha256(payload).hexdigest()
    return (
        "TRNM_SEALED_ARTIFACT_RECEIPT_V1 "
        f"{len(payload)} {expected} {expected} 10 20 30 40 {os.geteuid()} 1 384\n"
    ).encode("ascii")


def test_local_good_path_and_revalidation() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-local-") as raw:
        root = pathlib.Path(raw)
        source_root = private_directory(root / "source")
        target_root = private_directory(root / "target")
        payload = b"sealed-context\x00with-binary\n" * 41
        source = private_file(source_root / "context.json", payload)
        target = target_root / "copied.json"
        facts = transport.copy_sealed_stage_artifact_v1(
            management="unused",
            remote=False,
            source=source,
            target=target,
            maximum_bytes=4096,
        )
        assert facts.path == str(target)
        assert facts.sha256 == hashlib.sha256(payload).hexdigest()
        assert facts.bytes == len(payload)
        assert facts.mode == 0o600 and facts.nlink == 1
        assert target.read_bytes() == payload
        assert transport.revalidate_local_sealed_artifact_v1(target, facts) == facts
        assert facts.as_dict()["sha256"] == facts.sha256


def test_local_source_and_target_negative_controls() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-negative-") as raw:
        root = pathlib.Path(raw)
        source_root = private_directory(root / "source")
        target_root = private_directory(root / "target")

        real = private_file(source_root / "real", b"sealed")
        link = source_root / "link"
        link.symlink_to(real)
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, link, target_root / "from-link", 1024
            ),
            "regular file",
        )

        hard = source_root / "hard"
        os.link(real, hard)
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, real, target_root / "from-hard", 1024
            ),
            "link count",
        )
        hard.unlink()

        real.chmod(0o640)
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, real, target_root / "from-mode", 1024
            ),
            "mode",
        )
        real.chmod(0o600)

        fifo = source_root / "fifo"
        os.mkfifo(fifo, 0o600)
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, fifo, target_root / "from-fifo", 1024
            ),
            "regular file",
        )

        existing = private_file(target_root / "existing", b"preserve")
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, real, existing, 1024
            ),
            "File exists",
        )
        assert existing.read_bytes() == b"preserve"

        target_link = target_root / "target-link"
        target_link.symlink_to(existing)
        expect_failure(
            lambda: transport.copy_sealed_stage_artifact_v1(
                "unused", False, real, target_link, 1024
            ),
            "File exists",
        )
        assert existing.read_bytes() == b"preserve"


def test_source_mutation_seam_fails_and_cleans_target() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-mutation-") as raw:
        root = pathlib.Path(raw)
        source_root = private_directory(root / "source")
        target_root = private_directory(root / "target")
        source = private_file(source_root / "archive", b"first-version")
        target = target_root / "copied"

        def mutate(path: str) -> None:
            private_file(pathlib.Path(path), b"other-version")

        previous = transport._TEST_AFTER_FIRST_SOURCE_PASS_V1
        transport._TEST_AFTER_FIRST_SOURCE_PASS_V1 = mutate
        try:
            expect_failure(
                lambda: transport.copy_sealed_stage_artifact_v1(
                    "unused", False, source, target, 1024
                ),
                "changed",
            )
        finally:
            transport._TEST_AFTER_FIRST_SOURCE_PASS_V1 = previous
        assert not target.exists()


def test_fixed_remote_export_frames() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-export-") as raw:
        root = pathlib.Path(raw)
        target_root = private_directory(root / "target")
        payload = b"remote-sealed-payload" * 17
        calls: list[list[str]] = []

        def factory(arguments: list[str], **_kwargs: object) -> FakeProcess:
            calls.append(arguments)
            return FakeProcess(export_frame(payload))

        previous = transport._SSH_PROCESS_FACTORY_V1
        transport._SSH_PROCESS_FACTORY_V1 = factory
        try:
            facts = transport.copy_sealed_stage_artifact_v1(
                management="validator-route",
                remote=True,
                source="/absolute/remote/archive.entries",
                target=target_root / "archive.entries",
                maximum_bytes=4096,
            )
        finally:
            transport._SSH_PROCESS_FACTORY_V1 = previous
        assert facts.sha256 == hashlib.sha256(payload).hexdigest()
        assert pathlib.Path(facts.path).read_bytes() == payload
        assert calls and calls[0][0] == "ssh" and calls[0][5] == "validator-route"

        for label, frame, contains in (
            ("truncated", export_frame(payload)[:-12], "trailer"),
            (
                "hash-mismatch",
                export_frame(payload, second="f" * 64),
                "digest or size",
            ),
        ):
            target = target_root / label
            previous = transport._SSH_PROCESS_FACTORY_V1
            transport._SSH_PROCESS_FACTORY_V1 = (
                lambda _arguments, _frame=frame, **_kwargs: FakeProcess(_frame)
            )
            try:
                expect_failure(
                    lambda: transport.copy_sealed_stage_artifact_v1(
                        "validator-route",
                        True,
                        "/absolute/remote/archive.entries",
                        target,
                        4096,
                    ),
                    contains,
                )
            finally:
                transport._SSH_PROCESS_FACTORY_V1 = previous
            assert not target.exists()

        failed_after_frame = target_root / "failed-after-frame"
        previous = transport._SSH_PROCESS_FACTORY_V1
        transport._SSH_PROCESS_FACTORY_V1 = (
            lambda _arguments, **_kwargs: FakeProcess(
                export_frame(payload), return_code=73
            )
        )
        try:
            expect_failure(
                lambda: transport.copy_sealed_stage_artifact_v1(
                    "validator-route",
                    True,
                    "/absolute/remote/archive.entries",
                    failed_after_frame,
                    4096,
                ),
                "exporter failed",
            )
        finally:
            transport._SSH_PROCESS_FACTORY_V1 = previous
        assert not failed_after_frame.exists()


def test_export_helper_good_path_without_network() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-helper-export-") as raw:
        root = pathlib.Path(raw)
        source_root = private_directory(root / "source")
        payload = b"helper-export" * 101
        source = private_file(source_root / "artifact", payload)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                transport._REMOTE_EXPORT_HELPER_V1,
                str(source),
                "65536",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == export_frame(payload)


def test_observer_receiver_and_stage_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-observer-") as raw:
        root = pathlib.Path(raw)
        reports = private_directory(root / "reports")
        payload = b"observer-stage" * 53
        digest = hashlib.sha256(payload).hexdigest()
        frame = (
            f"TRNM_SEALED_ARTIFACT_STAGE_V1 {len(payload)} {digest}\n".encode("ascii")
            + payload
            + f"TRNM_SEALED_ARTIFACT_STAGE_END_V1 {len(payload)} {digest}\n".encode(
                "ascii"
            )
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                transport._REMOTE_RECEIVER_HELPER_V1,
                str(reports),
                "artifact.bin",
                "65536",
                str(len(payload)),
                digest,
            ],
            input=frame,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        received = reports / "artifact.bin"
        assert received.read_bytes() == payload
        assert received.stat().st_mode & 0o777 == 0o600
        assert result.stdout.startswith(b"TRNM_SEALED_ARTIFACT_RECEIPT_V1 ")

        existing = private_file(reports / "existing.bin", b"preserve")
        existing_result = subprocess.run(
            [
                sys.executable,
                "-c",
                transport._REMOTE_RECEIVER_HELPER_V1,
                str(reports),
                "existing.bin",
                "65536",
                str(len(payload)),
                digest,
            ],
            input=frame,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert existing_result.returncode != 0
        assert existing.read_bytes() == b"preserve"

        local_root = private_directory(root / "local")
        source = private_file(local_root / "artifact.bin", payload)
        fake = FakeProcess(receipt(payload), stdin=True)
        calls: list[list[str]] = []

        def factory(arguments: list[str], **_kwargs: object) -> FakeProcess:
            calls.append(arguments)
            return fake

        previous = transport._SSH_PROCESS_FACTORY_V1
        transport._SSH_PROCESS_FACTORY_V1 = factory
        try:
            facts = transport.stage_sealed_artifact_on_observer_v1(
                management="mac-route",
                source=source,
                remote_reports_root="/absolute/observer/reports",
                remote_name="artifact.bin",
                maximum_bytes=65536,
            )
        finally:
            transport._SSH_PROCESS_FACTORY_V1 = previous
        assert facts.path == "/absolute/observer/reports/artifact.bin"
        assert facts.sha256 == digest and facts.bytes == len(payload)
        sent = fake.stdin.getvalue()
        assert sent.startswith(b"TRNM_SEALED_ARTIFACT_STAGE_V1 ")
        assert payload in sent
        assert calls and calls[0][0] == "ssh" and calls[0][5] == "mac-route"


def test_observer_bad_receipt_and_source_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="sealed-artifact-observer-negative-") as raw:
        root = pathlib.Path(raw)
        source_root = private_directory(root / "source")
        payload = b"source-for-observer"
        source = private_file(source_root / "source.bin", payload)
        wrong = "0" * 64

        previous_factory = transport._SSH_PROCESS_FACTORY_V1
        transport._SSH_PROCESS_FACTORY_V1 = (
            lambda _arguments, **_kwargs: FakeProcess(
                receipt(payload, digest=wrong), stdin=True
            )
        )
        try:
            expect_failure(
                lambda: transport.stage_sealed_artifact_on_observer_v1(
                    "mac-route",
                    source,
                    "/absolute/reports",
                    "source.bin",
                    1024,
                ),
                "differs from its source",
            )
        finally:
            transport._SSH_PROCESS_FACTORY_V1 = previous_factory

        def mutate(path: str) -> None:
            private_file(pathlib.Path(path), b"mutated-for-observer")

        previous_hook = transport._TEST_AFTER_FIRST_SOURCE_PASS_V1
        previous_factory = transport._SSH_PROCESS_FACTORY_V1
        transport._TEST_AFTER_FIRST_SOURCE_PASS_V1 = mutate
        transport._SSH_PROCESS_FACTORY_V1 = (
            lambda _arguments, **_kwargs: FakeProcess(receipt(payload), stdin=True)
        )
        try:
            expect_failure(
                lambda: transport.stage_sealed_artifact_on_observer_v1(
                    "mac-route",
                    source,
                    "/absolute/reports",
                    "mutated.bin",
                    1024,
                ),
                "changed",
            )
        finally:
            transport._TEST_AFTER_FIRST_SOURCE_PASS_V1 = previous_hook
            transport._SSH_PROCESS_FACTORY_V1 = previous_factory


def test_static_closed_transport_boundary() -> None:
    source = (HERE / "sealed_artifact_transport_v1.py").read_text(encoding="utf-8")
    forbidden = "s" + "cp"
    assert forbidden not in source
    assert "O_EXCL" in source and "O_NOFOLLOW" in source
    assert "MAX_SEALED_ARTIFACT_BYTES_V1 = 512 * 1024 * 1024" in source
    assert "_SSH_PROCESS_FACTORY_V1" in source


def main() -> None:
    test_local_good_path_and_revalidation()
    test_local_source_and_target_negative_controls()
    test_source_mutation_seam_fails_and_cleans_target()
    test_fixed_remote_export_frames()
    test_export_helper_good_path_without_network()
    test_observer_receiver_and_stage_contract()
    test_observer_bad_receipt_and_source_mutation()
    test_static_closed_transport_boundary()
    print(
        "sealed_artifact_transport_v1_test=passed positives=5 negatives=13 "
        "nofollow=true o_excl=true double_hash=true fixed_frames=true "
        "observer_receipt=true source_mutation_fail_closed=true "
        "runtime_evidence_observed=false g3_complete=false"
    )


if __name__ == "__main__":
    main()
