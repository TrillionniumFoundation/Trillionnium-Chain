#!/usr/bin/env python3
"""Black-box Unix-socket checks for the remote-signer P0 slice.

The request payloads are produced by the Rust fixture encoder, so this test
exercises the real schema-1 wire decoder instead of duplicating CEV0 encoding
in Python. The Python side owns the process lifecycle, framing, and
replay/rollback assertions.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


FRAME_OK = 0
FRAME_REJECT = 1
REJECT_INVALID_FRAME = 1
REJECT_WRONG_PURPOSE = 3
REJECT_DUPLICATE_NONCE = 4
REJECT_DUPLICATE_REQUEST = 5
REJECT_ROLLBACK = 7


def read_exact(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise AssertionError("signer socket closed before complete frame")
        chunks.extend(chunk)
    return bytes(chunks)


def request_bytes(binary: Path, kind: str, view: int, nonce: str, root: Path) -> bytes:
    completed = subprocess.run(
        [
            str(binary),
            "fixture-request",
            "--kind",
            kind,
            "--view",
            str(view),
            "--nonce",
            nonce,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return bytes.fromhex(completed.stdout.strip())


def send_frame(socket_path: Path, payload: bytes) -> tuple[str, bytes | int]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3.0)
        stream.connect(str(socket_path))
        stream.sendall(struct.pack(">I", len(payload)))
        if payload:
            stream.sendall(payload)
        frame_length = struct.unpack(">I", read_exact(stream, 4))[0]
        frame = read_exact(stream, frame_length)
    if not frame:
        raise AssertionError("empty signer response frame")
    if frame[0] == FRAME_OK:
        return "ok", frame[1:]
    if frame[0] == FRAME_REJECT and len(frame) == 2:
        return "reject", frame[1]
    raise AssertionError(f"malformed signer response frame: {frame.hex()}")


def send_truncated_frame(socket_path: Path) -> tuple[str, bytes | int]:
    """Send a declared payload that ends at EOF and require a framed reject."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3.0)
        stream.connect(str(socket_path))
        stream.sendall(struct.pack(">I", 8) + b"short")
        stream.shutdown(socket.SHUT_WR)
        frame_length = struct.unpack(">I", read_exact(stream, 4))[0]
        frame = read_exact(stream, frame_length)
    if frame == bytes((FRAME_REJECT, REJECT_INVALID_FRAME)):
        return "reject", REJECT_INVALID_FRAME
    raise AssertionError(f"unexpected truncated-frame response: {frame.hex()}")


def wait_for_socket(proc: subprocess.Popen[bytes], socket_path: Path) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if socket_path.exists():
            # On restart the previous process may leave a stale socket inode
            # behind.  Existence alone is not readiness; require one
            # successful connect so the first assertion cannot race bind(2).
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.1)
                    probe.connect(str(socket_path))
                return
            except (ConnectionRefusedError, FileNotFoundError):
                pass
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise AssertionError(f"signer exited during startup: {stderr}")
        time.sleep(0.01)
    raise AssertionError("timed out waiting for signer Unix socket")


def stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def run(binary: Path, root: Path) -> None:
    truth = subprocess.run(
        [str(binary), "truth"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "runtime_activation=false" in truth
    assert "production_signature_producer=false" in truth
    assert "consensus_runtime_integration=false" in truth

    with tempfile.TemporaryDirectory(prefix="trnm-remote-signer-p0-") as directory:
        state = Path(directory)
        socket_path = state / "signer.sock"
        watermark_path = state / "watermark.sqlite3"
        command = [
            str(binary),
            "serve-fixture",
            "--socket",
            str(socket_path),
            "--watermark",
            str(watermark_path),
            "--purpose",
            "vote",
        ]

        proc = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_for_socket(proc, socket_path)

            first = request_bytes(binary, "vote", 10, "first", root)
            status, response = send_frame(socket_path, first)
            assert status == "ok"
            assert isinstance(response, bytes) and response.startswith(b"TRNMRS01")

            status, code = send_frame(socket_path, first)
            assert status == "reject" and code == REJECT_DUPLICATE_REQUEST

            same_nonce_different_round = request_bytes(binary, "vote", 11, "first", root)
            status, code = send_frame(socket_path, same_nonce_different_round)
            assert status == "reject" and code == REJECT_DUPLICATE_NONCE

            wrong_purpose = request_bytes(binary, "timeout", 12, "timeout", root)
            status, code = send_frame(socket_path, wrong_purpose)
            assert status == "reject" and code == REJECT_WRONG_PURPOSE

            rollback = request_bytes(binary, "vote", 9, "rollback", root)
            status, code = send_frame(socket_path, rollback)
            assert status == "reject" and code == REJECT_ROLLBACK

            next_round = request_bytes(binary, "vote", 11, "next", root)
            status, response = send_frame(socket_path, next_round)
            assert status == "ok" and isinstance(response, bytes)
        finally:
            stop(proc)

        # The process may have died without unlinking its socket. A fresh
        # process must safely remove only that stale socket and preserve the
        # durable watermark database.
        proc = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_for_socket(proc, socket_path)
            stale = request_bytes(binary, "vote", 10, "after-restart", root)
            status, code = send_frame(socket_path, stale)
            assert status == "reject" and code == REJECT_ROLLBACK

            malformed = b""
            status, code = send_frame(socket_path, malformed)
            assert status == "reject" and code == REJECT_INVALID_FRAME

            status, code = send_truncated_frame(socket_path)
            assert status == "reject" and code == REJECT_INVALID_FRAME
        finally:
            stop(proc)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = args.binary or root / "target" / "debug" / "trnm-remote-signer-p0"
    if not binary.exists():
        subprocess.run(
            ["cargo", "build", "-p", "trnm-consensus-remote-signer-service", "--bin", "trnm-remote-signer-p0"],
            cwd=root,
            check=True,
        )
    run(binary, root)
    print("remote signer P0 Python checks: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
