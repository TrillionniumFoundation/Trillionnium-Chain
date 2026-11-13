"""Real process/resource controls. Fixture programs do NOT prove any W1 statement.

The separate saved-receipt campaign must use the built Rust verifier. Here a
hash-pinned test executable interprets an explicit resource fixture after its
minimal framing; it exercises kernel limits, kill/reap, accounting and types.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import w1_v2_supervisor as supervisor
from w1_v2_supervisor import INPUT_RESERVATION, Limits, VerifierOwner


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="w1-supervisor-controls-")
        self.root = Path(self.directory.name)
        self.header, self.artifacts = self.root / "header", self.root / "artifacts"
        self.header.write_bytes(b"h" * 318)
        self.artifacts.write_bytes(b"a" * 64)
        self.executable = self.root / "resource-fixture-verifier"
        # Explicitly not a W1 verifier: only process-resource tests use this.
        # No production flag can disable the supervisor's wire preflight.
        self.executable.write_text(f"#!{Path(sys.executable).resolve()}\n"
            "import pathlib,sys\n"
            "body=pathlib.Path(sys.argv[1]).read_bytes()[16:]\n"
            "exec(compile(body, 'resource_control_fixture_not_W1', 'exec'))\n")
        self.executable.chmod(0o700)
        self.executable_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.owners = []

    def tearDown(self):
        for owner in self.owners:
            owner.close()
        self.directory.cleanup()

    def owner(self, **limits):
        owner = VerifierOwner(self.executable, self.executable_sha, replace(Limits(), **limits))
        self.owners.append(owner)
        return owner

    def fixture(self, body, name="fixture.py"):
        path = self.root / name
        path.write_bytes((1).to_bytes(4, "little") + (1).to_bytes(8, "little")
                         + bytes(4) + body.encode())
        return path

    def refusal(self, code=22, marker="W1_V2_CRYPTO_REJECT", name="fixture.py"):
        return self.fixture(f"import sys\nsys.stderr.write('Error: {marker}\\n')\nsys.exit({code})\n", name)

    def verify(self, owner, path, **kwargs):
        return owner.verify(path, self.header, self.artifacts,
                            deadline=time.monotonic() + 5, **kwargs)

    def assert_settled(self, owner, row):
        self.assertTrue(row["worker_reaped"])
        self.assertGreater(row["worker_cpu_ns"], 0)
        self.assertEqual(owner.stats()["active_workers"], 0)
        self.assertEqual(owner.stats()["reserved_unverified_bytes"], 0)
        self.assertEqual(owner.stats()["reserved_cpu_ns"], 0)
        self.assertFalse(owner.stats()["blocked_on_unknown_worker"])

    def test_exact_invalid_bytes_reuse_one_owner_across_caller_classes(self):
        owner, path = self.owner(), self.refusal()
        first = self.verify(owner, path, caller_class="public")
        self.assertEqual(first["status"], "Invalid")
        self.assert_settled(owner, first)
        second = self.verify(owner, path, caller_class="recovery")
        self.assertEqual(second["status"], "Invalid")
        self.assertTrue(second["cache_hit"])
        self.assertFalse(second["worker_started"])
        self.assertEqual(owner.stats()["workers_started"], 1)
        self.assertEqual(first["proof_context_sha256"], second["proof_context_sha256"])

    def test_distinct_proof_header_or_expected_artifacts_never_hit_bad_proof_cache(self):
        owner = self.owner()
        path = self.refusal()
        first = self.verify(owner, path)
        second_path = self.root / "different.py"
        second_path.write_bytes(path.read_bytes() + b"# different exact proof bytes\n")
        second = self.verify(owner, second_path)
        self.header.write_bytes(b"i" + b"h" * 317)
        third = self.verify(owner, path)
        self.artifacts.write_bytes(b"b" * 64)
        fourth = self.verify(owner, path)
        self.assertEqual(len({row["proof_context_sha256"] for row in (first, second, third, fourth)}), 4)
        self.assertTrue(all(row["status"] == "Invalid" and not row["cache_hit"]
                            for row in (first, second, third, fourth)))
        self.assertEqual(owner.stats()["workers_started"], 4)

    def test_expired_deadline_does_not_spawn_or_poison_cache(self):
        owner, path = self.owner(), self.refusal()
        row = owner.verify(path, self.header, self.artifacts, deadline=time.monotonic() - 1)
        self.assertEqual(row["status"], "Deadline")
        self.assertEqual(owner.stats()["workers_started"], 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)
        self.assertEqual(self.verify(owner, path)["status"], "Invalid")

    def test_busy_cpu_and_byte_reservations_refuse_without_a_worker(self):
        for limits in ({"campaign_cpu_ns": 1}, {"unverified_bytes": INPUT_RESERVATION - 1}):
            with self.subTest(limits=limits):
                owner = self.owner(**limits)
                row = self.verify(owner, self.refusal())
                self.assertEqual(row["status"], "Busy")
                self.assertEqual(owner.stats()["workers_started"], 0)
                self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_concurrent_new_caller_label_cannot_mint_worker_or_cpu_quota(self):
        owner = self.owner(workers=1)
        marker = self.root / "entered"
        path = self.fixture(f"import os,time\nopen({str(marker)!r}, 'w').write(str(os.getpid()))\ntime.sleep(0.6)\n")
        results = []
        thread = threading.Thread(target=lambda: results.append(self.verify(owner, path)))
        thread.start()
        limit = time.monotonic() + 2
        while not marker.exists() and thread.is_alive() and time.monotonic() < limit:
            time.sleep(0.005)
        try:
            self.assertTrue(marker.exists(), "first real worker did not enter")
            for label in ("history", "recovery", "relay"):
                row = self.verify(owner, path, caller_class=label)
                self.assertEqual(row["status"], "Busy")
                self.assertFalse(row["worker_started"])
        finally:
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assert_settled(owner, results[0])
        self.assertEqual(owner.stats()["workers_started"], 1)

    def test_actual_wall_timeout_kills_and_reaps_then_allows_a_later_request(self):
        owner = self.owner(wall_seconds=0.2)
        marker = self.root / "pid"
        path = self.fixture(f"import os,time\nopen({str(marker)!r}, 'w').write(str(os.getpid()))\ntime.sleep(10)\n")
        row = self.verify(owner, path)
        self.assertEqual(row["status"], "Deadline")
        self.assertEqual(row["returncode"], -signal.SIGKILL)
        self.assert_settled(owner, row)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)
        later = self.verify(owner, self.refusal(name="later.py"))
        self.assertEqual(later["status"], "Invalid")

    def test_actual_cpu_limit_signals_and_charges_cpu(self):
        owner = self.owner(wall_seconds=5)
        row = self.verify(owner, self.fixture("while True:\n    pass\n"))
        self.assertEqual((row["status"], row["returncode"]), ("Deadline", -signal.SIGXCPU))
        self.assert_settled(owner, row)
        self.assertGreater(row["worker_cpu_ns"], 500_000_000)
        self.assertLess(owner.stats()["available_cpu_ns"], owner.limits.campaign_cpu_ns - 500_000_000)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_actual_address_space_failure_is_operational_not_invalid(self):
        owner = self.owner(worker_address_space_bytes=64 * 1024 * 1024)
        row = self.verify(owner, self.fixture("x = bytearray(512 * 1024 * 1024)\n"))
        self.assertEqual(row["status"], "OperationalFailure")
        self.assertIn("MemoryError", row["stderr"])
        self.assert_settled(owner, row)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_stream_flood_is_bounded_killed_and_not_cached(self):
        owner = self.owner()
        row = self.verify(owner, self.fixture("import os\nwhile True:\n    os.write(1, b'x'*65536)\n"))
        self.assertEqual(row["status"], "OperationalFailure")
        self.assertEqual(len(row["stdout"]), 65536)
        self.assert_settled(owner, row)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_untyped_error_and_success_report_spoof_cannot_become_invalid_or_verified(self):
        owner = self.owner()
        for path in (self.refusal(code=1, name="untyped.py"),
                     self.fixture("print('{\"claimed\": true}')\n", "claimed.py"),
                     self.fixture("import os\nos.abort()\n", "abort.py")):
            with self.subTest(path=path):
                row = self.verify(owner, path)
                self.assertEqual(row["status"], "OperationalFailure")
                self.assert_settled(owner, row)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_fifo_and_symlink_refuse_without_blocking_open_or_spawning(self):
        owner = self.owner(wall_seconds=0.2)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        regular = self.refusal()
        link = self.root / "link"
        link.symlink_to(regular)
        for path in (fifo, link):
            with self.subTest(path=path):
                row = self.verify(owner, path)
                self.assertEqual(row["status"], "OperationalFailure")
                self.assertFalse(row["worker_started"])
                self.assertLess(row["wall_seconds"], 0.2)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_batch_attempts_each_pay_same_owner_and_deadline(self):
        owner = self.owner(cache_entries=0)
        path = self.refusal()
        rows = owner.verify_batch([(path, self.header, self.artifacts)] * 3,
                                  deadline=time.monotonic() + 5)
        self.assertTrue(all(row["status"] == "Invalid" for row in rows))
        self.assertEqual(owner.stats()["workers_started"], 3)
        self.assertEqual(owner.stats()["settled_worker_cpu_ns"], sum(row["worker_cpu_ns"] for row in rows))
        self.assertEqual(owner.stats()["available_cpu_ns"], owner.limits.campaign_cpu_ns
                         - owner.stats()["settled_worker_cpu_ns"] - owner.stats()["settled_owner_thread_cpu_ns"])

    def test_malformed_later_batch_shape_refuses_before_any_worker(self):
        owner, path = self.owner(), self.refusal()
        valid = (path, self.header, self.artifacts)
        for malformed in ((path, self.header), None, "abc", (path, self.header, self.artifacts, path)):
            with self.subTest(malformed=malformed), \
                    self.assertRaisesRegex(ValueError, "every batch request"):
                owner.verify_batch([valid, malformed], deadline=time.monotonic() + 5)
        self.assertEqual(owner.stats()["workers_started"], 0)
        self.assertEqual(owner.stats()["active_workers"], 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_invalid_resource_limits_and_wrong_executable_hash_refuse(self):
        for kwargs in ({"workers": True}, {"wall_seconds": float("nan")},
                       {"hard_cpu_seconds": 1}, {"cache_entries": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Limits(**kwargs)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            VerifierOwner(self.executable, "0" * 64)

    def assert_preworker_refusal_settled(self, owner, row):
        self.assertFalse(row["worker_started"])
        self.assertEqual(row["worker_settlement"], "not_started")
        self.assertEqual(row["worker_cpu_ns"], 0)
        self.assertIsNone(row["proof_context_sha256"])
        self.assertEqual(owner.stats()["workers_started"], 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)
        self.assertEqual(owner.stats()["active_workers"], 0)
        self.assertEqual(owner.stats()["reserved_unverified_bytes"], 0)
        self.assertEqual(owner.stats()["reserved_cpu_ns"], 0)
        self.assertGreater(owner.stats()["settled_owner_thread_cpu_ns"], 0)
        self.assertEqual(owner.stats()["available_cpu_ns"], owner.limits.campaign_cpu_ns
                         - owner.stats()["settled_owner_thread_cpu_ns"])

    def test_local_context_lengths_are_operational_without_worker_or_bad_proof_cache(self):
        owner, path = self.owner(), self.refusal()
        for local, expected in ((self.header, 318), (self.artifacts, 64)):
            original = local.read_bytes()
            for size in (0, expected - 1, expected + 1):
                with self.subTest(local=local.name, size=size):
                    local.write_bytes(b"x" * size)
                    try:
                        row = self.verify(owner, path)
                        self.assertEqual(row["status"], "OperationalFailure")
                        self.assert_preworker_refusal_settled(owner, row)
                    finally:
                        local.write_bytes(original)

    def test_stable_oversized_receipt_remains_invalid_before_worker(self):
        owner = self.owner()
        path = self.root / "oversized-receipt"
        with path.open("wb") as stream:
            stream.truncate(supervisor.MAX_RECEIPT + 1)
        row = self.verify(owner, path)
        self.assertEqual(row["status"], "Invalid")
        self.assert_preworker_refusal_settled(owner, row)

    def test_receipt_growth_crossing_snapshot_bound_is_operational(self):
        owner, path = self.owner(), self.fixture("")
        original_read, original_stat = supervisor.os.read, path.stat()
        changed = [False]

        def grow_receipt(fd, size):
            current = os.fstat(fd)
            if not changed[0] and (current.st_dev, current.st_ino) == (
                    original_stat.st_dev, original_stat.st_ino):
                # Change the actual source between its first fstat and read.
                # The small test bound avoids allocating a full-size receipt.
                with path.open("ab") as stream:
                    stream.write(bytes(65 - current.st_size))
                changed[0] = True
            return original_read(fd, size)

        with mock.patch.object(supervisor, "MAX_RECEIPT", 64), \
                mock.patch.object(supervisor.os, "read", side_effect=grow_receipt), \
                mock.patch.object(supervisor, "run_bounded", wraps=supervisor.run_bounded) as process:
            row = self.verify(owner, path)
        self.assertTrue(changed[0])
        process.assert_not_called()
        self.assertEqual(row["status"], "OperationalFailure")
        self.assert_preworker_refusal_settled(owner, row)

    def test_wire_tag_and_impossible_seal_length_refuse_before_worker(self):
        owner = self.owner()
        for i, contents in enumerate((b"", b"\0" * 12,
                (1).to_bytes(4, "little") + bytes(8),
                (1).to_bytes(4, "little") + ((1 << 64) - 1).to_bytes(8, "little"),
                (1).to_bytes(4, "little") + (2).to_bytes(8, "little") + bytes(4))):
            with self.subTest(case=i):
                path = self.root / f"wire-{i}"
                path.write_bytes(contents)
                row = self.verify(owner, path)
                self.assertEqual(row["status"], "Invalid")
                self.assertTrue(row["wire_precheck_rejected"])
                self.assertFalse(row["worker_started"])
        self.assertEqual(owner.stats()["workers_started"], 0)

    def test_unknown_wait4_keeps_reservation_and_cli_persists_before_close_refusal(self):
        owner, path = self.owner(), self.refusal()
        out = self.root / "unknown-result"
        # Fault injection covers unavailable settlement, not a real child exit.
        # No actual worker is launched by this injected exception; the other
        # controls above exercise real timeout/SIGXCPU/SIGKILL/wait4 behavior.
        with mock.patch.object(supervisor, "VerifierOwner", return_value=owner), \
                mock.patch.object(supervisor, "run_bounded", side_effect=OSError("injected lost wait4")):
            status = supervisor.main(["--verifier", str(self.executable),
                "--verifier-sha256", self.executable_sha, "--receipt", str(path),
                "--header", str(self.header), "--expected-artifacts", str(self.artifacts),
                "--out", str(out)])
        row = json.loads((out / "result.json").read_text())
        self.assertEqual(status, 2)
        self.assertEqual(row["status"], "OperationalFailure")
        self.assertEqual(row["worker_settlement"], "unknown")
        self.assertIsNone(row["worker_started"])
        self.assertIsNone(row["worker_cpu_ns"])
        self.assertFalse(row["worker_reaped"])
        self.assertEqual(row["owner_close"]["state"], "failed")
        self.assertTrue(owner.stats()["blocked_on_unknown_worker"])
        self.assertEqual(owner.stats()["active_workers"], 1)
        self.assertEqual(owner.stats()["reserved_unverified_bytes"], INPUT_RESERVATION)
        self.assertEqual(owner.stats()["reserved_cpu_ns"], owner.limits.hard_cpu_seconds * 1_000_000_000)
        self.assertTrue(Path(row["retained_snapshot_directory"]).is_dir())
        self.assertEqual(self.verify(owner, path)["status"], "OperationalFailure")
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)
        # This cleanup is specific to the no-spawn fault fixture. Production
        # has no reset/refund API for an unobserved worker.
        self.owners.remove(owner)
        os.close(owner._fd)
        shutil = __import__("shutil")
        shutil.rmtree(row["retained_snapshot_directory"])

    def test_pause_before_shared_owner_never_restarts_original_deadline(self):
        owner = self.owner(wall_seconds=0.2)
        marker = self.root / "must-not-start"
        path = self.fixture(f"open({str(marker)!r},'w').write('entered')\n")
        original = supervisor.run_bounded

        def delayed(*args, **kwargs):
            time.sleep(0.25)  # Deliberate scheduling-pause injection, same limits.
            return original(*args, **kwargs)

        with mock.patch.object(supervisor, "run_bounded", side_effect=delayed):
            row = self.verify(owner, path)
        self.assertEqual(row["status"], "Deadline")
        self.assertFalse(row["worker_started"])
        self.assertEqual(row["worker_settlement"], "not_started")
        self.assertEqual(row["worker_cpu_ns"], 0)
        self.assertFalse(marker.exists())
        self.assertEqual(owner.stats()["active_workers"], 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)

    def test_pause_between_last_check_and_remaining_calculation_is_deadline(self):
        owner = self.owner(wall_seconds=0.2)
        path = self.refusal()
        armed = [False]
        original_precheck, original_deadline = supervisor.wire_precheck, supervisor.check_deadline

        def precheck(*args):
            value = original_precheck(*args)
            armed[0] = True
            return value

        def last_check(deadline):
            original_deadline(deadline)
            if armed[0]:
                armed[0] = False
                time.sleep(0.25)  # Expires just AFTER a successful last check.

        with mock.patch.object(supervisor, "wire_precheck", side_effect=precheck), \
                mock.patch.object(supervisor, "check_deadline", side_effect=last_check), \
                mock.patch.object(supervisor, "run_bounded", wraps=supervisor.run_bounded) as process:
            row = self.verify(owner, path)
        process.assert_not_called()
        self.assertEqual(row["status"], "Deadline")
        self.assertFalse(row["worker_started"])
        self.assertFalse(owner.stats()["blocked_on_unknown_worker"])
        self.assertEqual(owner.stats()["active_workers"], 0)
        self.assertEqual(owner.stats()["negative_cache_entries"], 0)


if __name__ == "__main__":
    unittest.main()
