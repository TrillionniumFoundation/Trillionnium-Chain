"""Real TCP deadline regressions; no successful crypto result is substituted.

The deliberately incomplete attack responses cannot reach signature acceptance.
Positive ML-DSA and whole-fetch tests remain in test_pq_cell_swarm.py and require
an actual ML-DSA-capable OpenSSL provider.
"""
from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from pq_envelope import Reject, SIGNED_BYTES, _run, public_key_id
from pq_cell_custody import catalog_from_chunks, catalog_id
from pq_cell_swarm import Peer, _fetch_one, fetch_to_immutable_file, content_id
from pq_operation_budget import OperationBudget


@contextmanager
def incomplete_tcp_reply(*, slow_prefix=False):
    """A real malicious TCP peer which stays under the old idle timeout."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    stop = threading.Event()
    connected = threading.Event()

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                conn.recv(4096)
                connected.set()
                prefix = struct.pack(">I", 13 + SIGNED_BYTES)
                started = time.monotonic()
                if slow_prefix:
                    for octet in prefix:
                        conn.sendall(bytes([octet]))
                        if stop.wait(0.35):
                            return
                else:
                    conn.sendall(prefix)
                # Never finish a valid frame. The unpatched implementation waits
                # until this connection closes, despite the 0.3-second deadline.
                while time.monotonic() - started < 1.4:
                    conn.sendall(b"x")
                    if stop.wait(0.04):
                        return
        except (OSError, TimeoutError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, name="pcs1-attack-peer", daemon=True)
    thread.start()
    try:
        yield port, connected
    finally:
        stop.set()
        listener.close()
        thread.join(3)
        if thread.is_alive():
            raise AssertionError("attack peer thread did not terminate")


class PQCellTransportDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog_from_chunks(bytes([1]) * 32, bytes([2]) * 48,
                                           1, (b"a",), 1)

    def run_attack(self, slow_prefix):
        with incomplete_tcp_reply(slow_prefix=slow_prefix) as (port, connected):
            # The public-key field is never used: the hostile response is always
            # incomplete. There is no stub returning verified=True anywhere.
            peer = Peer("127.0.0.1", port, b"not-used-by-incomplete-transport", bytes([3]) * 32)
            started = time.monotonic()
            with self.assertRaises((Reject, TimeoutError)):
                _fetch_one(0, self.catalog, (peer,), bytes([4]) * 32,
                           1, started + 0.3)
            elapsed = time.monotonic() - started
            self.assertTrue(connected.is_set(), "test must exercise real TCP")
            self.assertLess(elapsed, 0.9,
                            "peer progress must not reset the absolute deadline")

    def test_slow_frame_prefix_cannot_reset_absolute_deadline(self):
        self.run_attack(True)

    def test_slow_frame_body_cannot_reset_absolute_deadline(self):
        self.run_attack(False)

    def test_shared_cancel_interrupts_actual_socket_before_original_deadline(self):
        with incomplete_tcp_reply() as (port, connected):
            peer = Peer("127.0.0.1", port, b"unused-incomplete", bytes([3]) * 32)
            budget = OperationBudget(time.monotonic() + 10)
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pcs1-cancel-test") as pool:
                future = pool.submit(_fetch_one, 0, self.catalog, (peer,),
                                     bytes([4]) * 32, 1, budget.deadline, budget)
                self.assertTrue(connected.wait(2))
                started = time.monotonic()
                budget.cancel()
                with self.assertRaises((Reject, TimeoutError)):
                    future.result(timeout=1)
                self.assertLess(time.monotonic() - started, 0.6)


class PQCryptoChildBudgetTests(unittest.TestCase):
    """Tests the real subprocess owner, not a successful signature substitute."""

    def child_args(self, pid_path):
        return [sys.executable, "-c",
                "import os, pathlib, sys, time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)",
                str(pid_path)]

    def assert_reaped(self, path):
        self.assertTrue(path.exists(), "child must really have started")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(path.read_text()), 0)

    def test_original_deadline_kills_and_reaps_child(self):
        with tempfile.TemporaryDirectory(prefix="pcs1-child-") as root:
            path = Path(root) / "pid"
            started = time.monotonic()
            with self.assertRaises(Reject):
                _run(self.child_args(path), budget=OperationBudget(started + 0.3))
            self.assertLess(time.monotonic() - started, 1)
            self.assert_reaped(path)

    def test_peer_failure_cancel_kills_and_reaps_crypto_child(self):
        with tempfile.TemporaryDirectory(prefix="pcs1-child-") as root:
            path = Path(root) / "pid"
            budget = OperationBudget(time.monotonic() + 10)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_run, self.child_args(path), budget=budget)
                until = time.monotonic() + 2
                while not path.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertTrue(path.exists())
                started = time.monotonic()
                budget.cancel()
                with self.assertRaises(Reject):
                    future.result(timeout=1)
                self.assertLess(time.monotonic() - started, 0.6)
            self.assert_reaped(path)


class PQWholeFetchDeadlineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pcs1-deadline-key-")
        cls.addClassCleanup(cls.temp.cleanup)
        secret = Path(cls.temp.name) / "ephemeral-secret.pem"
        public = Path(cls.temp.name) / "public.pem"
        for cmd in (["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(secret)],
                    ["openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(public)]):
            subprocess.run(cmd, check=True, capture_output=True, timeout=15)
        cls.public = public.read_bytes()
        cls.key_id = public_key_id(cls.public)

    def test_two_actual_stalled_workers_exit_and_no_object_is_published(self):
        c = catalog_from_chunks(bytes([1]) * 32, bytes([2]) * 48, 1, (b"a", b"b"), 1)
        prior = set(threading.enumerate())
        with tempfile.TemporaryDirectory(prefix="pcs1-deadline-out-") as root:
            destination = Path(root) / "weights.bin"
            with incomplete_tcp_reply() as (port_a, ready_a), incomplete_tcp_reply() as (port_b, ready_b):
                peers = tuple(Peer("127.0.0.1", port, self.public, self.key_id)
                              for port in (port_a, port_b))
                started = time.monotonic()
                with self.assertRaises(Reject):
                    fetch_to_immutable_file(
                        catalog_bytes=c.encode(), expected_catalog_digest=catalog_id(c),
                        expected_release=c.release_manifest, expected_content_id=content_id(b"ab"),
                        requester_id=bytes([4]) * 32, peers=peers, destination=destination,
                        max_parallel=2, max_attempts_per_chunk=2, max_wall_seconds=1)
                self.assertLess(time.monotonic() - started, 1.3)
                self.assertTrue(ready_a.is_set() and ready_b.is_set())
                self.assertFalse(destination.exists())
                self.assertEqual(list(Path(root).glob(".pcs1-incomplete-*")), [])
                self.assertEqual([thread for thread in threading.enumerate()
                                  if thread not in prior and thread.name.startswith("pcs1-fetch")], [])


if __name__ == "__main__":
    unittest.main()
