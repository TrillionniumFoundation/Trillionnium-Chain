#!/usr/bin/env python3
"""Real subprocess/log controls, not native Cell throughput or model evidence."""

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "run_llm_cell_native_handoff.py"
SPEC = importlib.util.spec_from_file_location("provider_evidence_handoff", SCRIPT)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)

LISTEN = {"schema": "trnm.cell.listen.v1", "address": "127.0.0.1:12345"}
SERVE = {"schema": "trnm.cell.serve.bounded.v1", "connections": 3,
         "overloaded": 1, "completed": 2, "peak_active_workers": 2,
         "sent_response_bytes": 17}


def start(output, program):
    command = [sys.executable, "-u", "-c", program]
    with (output / "server-stdout.log").open("xb", buffering=0) as stdout, \
            (output / "server-stderr.log").open("xb", buffering=0) as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    return child, command


class ProviderEvidenceTests(unittest.TestCase):
    def read_reports(self, output):
        return json.loads((output / "server-serve-report.json").read_text())

    def test_natural_exit_keeps_exact_listener_final_report_and_binary_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            raw = json.dumps(LISTEN) + "\n" + json.dumps(SERVE) + "\n"
            child, command = start(output,
                f"import os; os.write(1, {raw.encode()!r}); os.write(2, b'error\\xff\\n')")
            try:
                self.assertEqual(handoff.wait_for_provider_listener(child,
                    output / "server-stdout.log"), LISTEN["address"])
                self.assertEqual(child.wait(timeout=5), 0)
            finally:
                terminal = handoff.retain_provider_terminal(child, output, command)
            self.assertEqual((output / "server-stdout.log").read_bytes(), raw.encode())
            self.assertEqual((output / "server-stderr.log").read_bytes(), b"error\xff\n")
            self.assertEqual(terminal["returncode"], 0)
            self.assertTrue(terminal["reaped"])
            self.assertEqual(terminal["cleanup_actions"], [])
            report = self.read_reports(output)
            self.assertEqual(report["reports"], [{"stdout_line": 2, "report": SERVE}])
            self.assertFalse(report["network_failure_cause_inferred"])

    def test_transfer_failure_cleanup_preserves_report_written_on_terminate(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            program = ("import signal,time,sys,json\n"
                "def stop(*args):\n"
                f" print({json.dumps(SERVE)!r}, flush=True)\n"
                " print('real termination diagnostic', file=sys.stderr, flush=True)\n"
                " raise SystemExit(23)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                f"print({json.dumps(LISTEN)!r}, flush=True)\n"
                "while True: time.sleep(1)\n")
            child, command = start(output, program)
            try:
                handoff.wait_for_provider_listener(child, output / "server-stdout.log")
                with self.assertRaisesRegex(RuntimeError, "original transfer refusal"):
                    raise RuntimeError("original transfer refusal")
            finally:
                terminal = handoff.retain_provider_terminal(child, output, command)
            self.assertEqual(terminal["returncode"], 23)
            self.assertEqual(terminal["cleanup_actions"], ["terminate"])
            self.assertEqual(self.read_reports(output)["reports"][0]["report"], SERVE)
            self.assertEqual((output / "server-stderr.log").read_text(),
                             "real termination diagnostic\n")

    def test_ignored_terminate_uses_kill_and_never_invents_a_serve_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            child, command = start(output,
                "import signal,time,os\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"print({json.dumps(LISTEN)!r}, flush=True)\n"
                "os.write(2,b'before kill\\n')\n"
                "while True: time.sleep(1)\n")
            try:
                handoff.wait_for_provider_listener(child, output / "server-stdout.log")
            finally:
                terminal = handoff.retain_provider_terminal(child, output, command,
                                                             cleanup_timeout=0.05)
            self.assertEqual(terminal["returncode"], -signal.SIGKILL)
            self.assertEqual(terminal["cleanup_actions"], ["terminate", "kill"])
            self.assertTrue(terminal["reaped"])
            self.assertEqual(self.read_reports(output)["observation"], "not_emitted")
            self.assertEqual(self.read_reports(output)["reports"], [])
            self.assertEqual((output / "server-stderr.log").read_bytes(), b"before kill\n")

    def test_partial_announcement_timeout_preserves_raw_bytes_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            child, command = start(output,
                "import os,time; os.write(1,b'{\"schema\":'); time.sleep(10)")
            try:
                # Establish partial output before testing its missing newline;
                # process startup scheduling is a separate announcement case.
                deadline = time.monotonic() + 5
                while not (output / "server-stdout.log").stat().st_size:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                with self.assertRaises(TimeoutError):
                    handoff.wait_for_provider_listener(child, output / "server-stdout.log", 0.1)
            finally:
                terminal = handoff.retain_provider_terminal(child, output, command)
            self.assertTrue(terminal["reaped"])
            self.assertEqual((output / "server-stdout.log").read_bytes(), b'{"schema":')
            self.assertEqual(self.read_reports(output)["malformed_stdout_lines"], [1])

    def test_early_nonzero_exit_preserves_unparseable_output_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            child, command = start(output,
                "import os,sys; os.write(1,b'partial\\xff'); os.write(2,b'open failed\\n'); sys.exit(7)")
            try:
                with self.assertRaisesRegex(RuntimeError, "complete listener"):
                    handoff.wait_for_provider_listener(child, output / "server-stdout.log")
            finally:
                terminal = handoff.retain_provider_terminal(child, output, command)
            self.assertEqual(terminal["returncode"], 7)
            self.assertEqual((output / "server-stdout.log").read_bytes(), b"partial\xff")
            self.assertEqual((output / "server-stderr.log").read_bytes(), b"open failed\n")
            self.assertEqual(self.read_reports(output)["observation"], "not_emitted")

    def test_before_spawn_failure_creates_explicit_not_started_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            terminal = handoff.retain_provider_terminal(None, output, ["/not/a/provider"])
            self.assertFalse(terminal["started"])
            self.assertIsNone(terminal["returncode"])
            self.assertTrue(terminal["reaped"])
            self.assertEqual(terminal["server-stdout.log"]["bytes"], 0)
            self.assertEqual(terminal["server-stderr.log"]["bytes"], 0)
            self.assertEqual(self.read_reports(output)["observation"], "not_emitted")


if __name__ == "__main__":
    unittest.main()
