"""Finite synthetic wire/process controls. No real proof cost is measured."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import measure_w1_receipt_loopback_v1 as transport

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class FileAndProcessBounds(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_header_caps_refuse_before_body_allocation(self):
        self.assertEqual(transport.parse_header(transport.header(transport.INPUT_BYTES, transport.RECEIPT_CAP)),
                         (transport.INPUT_BYTES, transport.RECEIPT_CAP))
        for raw in (b"", bytes(15), transport.header(transport.INPUT_BYTES, 1, b"PWAI0001"),
                    transport.header(transport.INPUT_BYTES - 1, 1),
                    transport.header(transport.INPUT_BYTES, 0),
                    transport.header(transport.INPUT_BYTES, transport.RECEIPT_CAP + 1),
                    transport.header(transport.INPUT_BYTES, 2**32 - 1)):
            with self.subTest(raw_length=len(raw)), self.assertRaises(transport.Refusal):
                transport.parse_header(raw)

    def test_symlink_fifo_empty_and_oversized_files_are_refused(self):
        regular = self.root / "regular"
        regular.write_bytes(b"abcd")
        link = self.root / "symlink"
        link.symlink_to(regular)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        empty = self.root / "empty"
        empty.touch()
        oversized = self.root / "oversized"
        with oversized.open("wb") as output:
            output.truncate(transport.RECEIPT_CAP + 1)
        for path in (link, fifo, empty, oversized):
            with self.subTest(path=path.name), self.assertRaises((OSError, transport.Refusal)):
                transport.regular(path, transport.RECEIPT_CAP)

    def test_growth_after_open_is_refused_before_fingerprint_read(self):
        path = self.root / "growing"
        path.write_bytes(b"a")
        descriptor = transport.regular(path, 4)
        try:
            path.write_bytes(b"abcde")
            with self.assertRaisesRegex(transport.Refusal, "fingerprint-input-cap"):
                transport.fingerprint(descriptor, time.monotonic() + 1, 4)
        finally:
            os.close(descriptor)

    def test_duplicate_nonfinite_and_nonobject_metadata_are_refused(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', '[]', 'null'):
            path = self.root / "metadata.json"
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(transport.Refusal):
                transport.read_json(path, time.monotonic() + 1)

    def fixture(self):
        paths = {"host": Path("/usr/bin/false"), "program": self.root / "program",
                 "input": self.root / "input", "receipt": self.root / "receipt"}
        for name in ("program", "input", "receipt"):
            paths[name].write_bytes(bytes(transport.INPUT_BYTES) if name == "input" else b"synthetic-only")
        descriptors = {name: transport.regular(path, transport.ASSET_CAPS[name]) for name, path in paths.items()}
        self.addCleanup(lambda: [os.close(value) for value in descriptors.values()])
        expected = {name: transport.fingerprint(value, time.monotonic() + 2, transport.ASSET_CAPS[name])
                    for name, value in descriptors.items()}
        expected.update(image_id="not-a-proof", statement_id="not-a-proof")
        return descriptors, expected

    def test_actual_held_elf_nonzero_exit_is_retained_as_failure(self):
        descriptors, expected = self.fixture()
        out = self.root / "verify"
        with self.assertRaisesRegex(transport.Refusal, "actual-verifier-did-not-pass"):
            transport.verify_once(*[descriptors[name] for name in ("host", "program", "input", "receipt")],
                                  out, expected, time.monotonic() + 5)
        result = json.loads((out / "result.json").read_text())
        self.assertEqual(result["direct_wait4"]["returncode"], 1)
        self.assertIs(result["passed"], False)
        self.assertFalse(result["timed_out"])

    def test_actual_short_timeout_kills_and_reaps_only_owned_child(self):
        descriptors, expected = self.fixture()
        original = subprocess.Popen
        children = []

        def sleeper(command, **options):
            self.assertIn("_verify", command)
            self.assertIs(options["start_new_session"], False)
            child = original([sys.executable, "-c", "import time;time.sleep(60)"], **options)
            children.append(child)
            return child

        out = self.root / "timeout"
        with patch.object(transport, "VERIFY_SECONDS", 0.1), \
             patch.object(transport.subprocess, "Popen", side_effect=sleeper), \
             self.assertRaisesRegex(transport.Refusal, "actual-verifier-did-not-pass"):
            transport.verify_once(*[descriptors[name] for name in ("host", "program", "input", "receipt")],
                                  out, expected, time.monotonic() + 5)
        result = json.loads((out / "result.json").read_text())
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["direct_wait4"]["returncode"], -signal.SIGKILL)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)

    def test_nondefault_sigchld_refuses_before_output_or_spawn(self):
        before = signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            with patch.object(transport.subprocess, "Popen") as spawn, \
                 self.assertRaisesRegex(transport.Refusal, "sigchld-disposition"):
                transport.verify_once(-1, -1, -1, -1, self.root / "no-output", {}, time.monotonic() + 1)
            spawn.assert_not_called()
            self.assertFalse((self.root / "no-output").exists())
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGCHLD, before)

    def test_missing_actual_artifact_cannot_create_a_qualified_cost(self):
        artifact = self.root / "empty-artifact"
        artifact.mkdir()
        out = self.root / "campaign"
        command = [sys.executable, "-B", str(HERE / "measure_w1_receipt_loopback_v1.py"),
                   "--repository-root", str(ROOT), "--artifact", str(artifact),
                   "--host", "/usr/bin/false", "--expected-proof-source", "a" * 40,
                   "--expected-host-sha256", "b" * 64, "--out", str(out)]
        completed = subprocess.run(command, env=dict(os.environ, RAYON_NUM_THREADS="2"),
                                   capture_output=True, timeout=10)
        self.assertNotEqual(completed.returncode, 0)
        record = json.loads((out / "campaign-owner.json").read_text())
        self.assertIs(record["passed"], False)
        self.assertIsNone(record["qualified_cost"])
        self.assertTrue(record["finite_cleanup_observed"])
        campaign = json.loads((out / "campaign/result.json").read_text())
        self.assertFalse(campaign["real_receipt_verified_before_network"])
        self.assertEqual(campaign["cases"], [])

    def test_actual_sigterm_owner_cancels_and_reaps_its_worker_group(self):
        report = os.environ.get("TRNM_LOOPBACK_TEST_REPORT")
        control_output = Path(report).with_suffix(".cancel-owner") if report else self.root / "cancel-owner"
        code = ("import sys,json,signal;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                "sys.path.insert(0,sys.argv[2]);import measure_w1_receipt_loopback_v1 as t;"
                "import proof_observer_v1 as o;"
                "child=[str(Path(sys.executable).resolve()),'-c','import os,signal,time;os.kill(os.getppid(),signal.SIGTERM);time.sleep(0.5)'];"
                "r,s=t.owned_campaign(o,child,sys.argv[3]);"
                "print(json.dumps({'signal':s,'returncode':r['returncode'],"
                "'cleanup':r['finite_cleanup_observed'],'child':None if r['direct_wait4'] is None else r['direct_wait4']['returncode'],"
                "'failure':r.get('failure')}))")
        result = subprocess.run([sys.executable, "-B", "-c", code, str(HERE), str(ROOT / transport.BACKEND),
                                 str(control_output)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        actual = json.loads(result.stdout)
        self.assertEqual(actual["signal"], signal.SIGTERM)
        self.assertNotEqual(actual["returncode"], 0)
        self.assertTrue(actual["cleanup"])
        self.assertEqual(actual["child"], -signal.SIGKILL)

    def test_sampling_oserror_catch_cannot_consume_cancellation(self):
        calls = []
        original = lambda deadline: calls.append(deadline)
        observer = SimpleNamespace(deadline_check=original)

        def run(_command, _out, _timeout):
            work = time.monotonic() + 2400
            cleanup = time.monotonic() + 5
            observer.deadline_check(work)
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            try:
                observer.deadline_check(work)
            except OSError:
                pass  # Exact integration hazard: proc sampling catches this.
            with self.assertRaises(InterruptedError):
                observer.deadline_check(work)
            observer.deadline_check(cleanup)
            return {"returncode": 125}

        observer.run_observed = run
        result, interrupted = transport.owned_campaign(observer, [], self.root)
        self.assertEqual(interrupted, signal.SIGTERM)
        self.assertEqual(result["returncode"], 125)
        self.assertEqual(len(calls), 2)  # Initial work check and normal cleanup.
        self.assertIs(observer.deadline_check, original)


class ActualLoopbackWireControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "input").write_bytes(bytes(transport.INPUT_BYTES))
        (self.root / "receipt").write_bytes(b"synthetic wire control, never a proof\n" * 19)
        self.descriptors = {name: transport.regular(self.root / name, transport.ASSET_CAPS[name])
                            for name in ("input", "receipt")}
        self.addCleanup(lambda: [os.close(value) for value in self.descriptors.values()])
        self.expected = {name: transport.fingerprint(value, time.monotonic() + 2, transport.ASSET_CAPS[name])
                         for name, value in self.descriptors.items()}

    def test_eight_real_loopback_cases_keep_wire_scope_and_exact_counters(self):
        rows = []
        for case in transport.CASES:
            with self.subTest(case=case):
                result = transport.transfer(case, self.descriptors["input"], self.descriptors["receipt"],
                                            self.expected, self.root / case, time.monotonic() + 3)
                self.assertTrue(result["passed"], result)
                self.assertFalse(result["cryptographic_verification_performed_here"])
                self.assertFalse(result["wan_measurement"])
                count = result["counters"]["sent_bytes"]
                self.assertEqual(count, result["counters"]["received_bytes"])
                if case.startswith("positive"):
                    self.assertEqual(count, 16 + transport.INPUT_BYTES + self.expected["receipt"]["bytes"])
                    self.assertEqual((self.root / case / "receipt.bin").read_bytes(),
                                     (self.root / "receipt").read_bytes())
                elif case in ("wrong-magic", "wrong-input-length", "over-receipt-cap"):
                    self.assertEqual(count, 16)
                    self.assertFalse((self.root / case / "receipt.bin").exists())
                rows.append(result)
        destination = os.environ.get("TRNM_LOOPBACK_TEST_REPORT")
        if destination:
            transport.durable_json(Path(destination), {
                "schema": "pon-w1-synthetic-loopback-controls-v1", "real_receipt": False,
                "proof_generated": False, "qualified_proof_cost": None,
                "source_sha256": hashlib.sha256((HERE / "measure_w1_receipt_loopback_v1.py").read_bytes()).hexdigest(),
                "cases": rows})

    def test_digest_mismatch_is_refused_after_complete_transport(self):
        wrong = {name: dict(value) for name, value in self.expected.items()}
        wrong["receipt"]["sha256"] = "0" * 64
        result = transport.transfer("positive-0", self.descriptors["input"], self.descriptors["receipt"],
                                    wrong, self.root / "digest", time.monotonic() + 3)
        self.assertFalse(result["passed"])
        self.assertEqual(result["receiver"]["refusal"], "received-asset-digest")

    def test_socket_deadline_is_an_operational_failure(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(TimeoutError):
                transport.receive_exact(left, 1, time.monotonic() + 0.05, {"received_bytes": 0})
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
