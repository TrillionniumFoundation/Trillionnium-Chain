#!/usr/bin/env python3
"""Deadline regression controls. Mocked orchestration is not transfer evidence."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "run_llm_cell_native_handoff.py"
SPEC = importlib.util.spec_from_file_location("cell_handoff", SCRIPT)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


def controlled_release(command, flags, payloads):
    """Mock CLI framing only; real TCR1 validation is tested by the native CLI."""
    if command[1] == "prepare-release":
        members = flags["--manifests"].split(",")
        data = json.dumps(sorted(members)).encode()
        Path(flags["--output"]).write_bytes(data)
        release = handoff.hashlib.sha256(data).hexdigest()
        schema = "trnm.cell.release.prepare.v1"
    else:
        data = Path(flags["--release-file"]).read_bytes()
        members = json.loads(data)
        Path(flags["--output"]).write_bytes(data)
        release = flags["--release"]
        schema = "trnm.cell.release.fetch.v1"
    observation = {"schema": schema, "release": release, "cells": len(members),
        "payload_bytes": sum(len(payloads[member]) for member in members),
        "chunks": len(members)}
    if command[1] == "fetch-release":
        observation.update({"cached_chunks": 0, "downloaded_chunks": len(members),
            "received_response_bytes": observation["payload_bytes"],
            "connection_attempts": 2 * len(members)})
    return observation


class CellHandoffDeadlineTests(unittest.TestCase):
    def test_remaining_window_is_floored_and_request_never_exceeds_it(self):
        for now, expected in ((100.0, (35.0, 35000, 2000)),
                              (133.5, (1.5, 1500, 1500)),
                              (134.75, (0.25, 250, 250)),
                              (134.999, None)):
            with self.subTest(now=now), mock.patch.object(handoff.time, "monotonic", return_value=now):
                if expected is None:
                    with self.assertRaises(TimeoutError):
                        handoff.remaining_fetch_budget(135.0)
                else:
                    self.assertEqual(handoff.remaining_fetch_budget(135.0), expected)
        with mock.patch.object(handoff.time, "monotonic", return_value=133.5001):
            remaining, overall_ms, request_ms = handoff.remaining_fetch_budget(135.0)
        self.assertEqual((overall_ms, request_ms), (1499, 1499))
        self.assertLessEqual(overall_ms / 1000, remaining)

    def test_expired_or_below_minimum_request_window_cannot_start_fetch(self):
        for now in (135.0, 135.001, 136.0, 134.995):
            with self.subTest(now=now), mock.patch.object(handoff.time, "monotonic", return_value=now):
                with self.assertRaises(TimeoutError):
                    handoff.remaining_fetch_budget(135.0)

    def test_all_eleven_real_readbacks_after_parent_deadline_still_fail(self):
        # Real create-only files/SHA readbacks, synthetic subprocess/clock. This
        # tests rejection after cleanup slack, never claims native model use.
        with tempfile.TemporaryDirectory(prefix="cell-deadline-control-") as temp:
            root = Path(temp)
            chain, materials, parent_root = root / "chain", root / "materials", root / "parent"
            for path in (chain / "config/pon", chain / "scripts", materials, parent_root):
                path.mkdir(parents=True)
            (chain / "scripts/llm_neural_read_worker.py").write_text("# controlled fixture\n")
            pins = {}
            for index in range(7):
                name = f"public-{index}.bin"
                path = materials / name
                path.write_bytes(bytes([index + 1]) * (index + 1))
                pins[name] = {"size": path.stat().st_size, "sha256": handoff.sha(path)}
            family = {"id": "controlled-deadline-fixture", "reference": {"model": "controlled", "revision": "fixed"}, "material_pins": {"files": pins}}
            (chain / "config/pon/model-family-smollm2-135m-v1.json").write_text(json.dumps(family))
            (materials / "material-manifest.json").write_text(json.dumps({"model": "controlled", "revision": "fixed", "files": pins}))
            (parent_root / "target-contract.json").write_text(json.dumps({"backbone": {"index_root": "11" * 32}, "tokenizer": {"files_root": "22" * 32}}))
            (parent_root / "wrapped-adapter.json").write_text("{}")
            (parent_root / "artifact.safetensors").write_bytes(b"controlled-not-a-model")
            parent = {"directory": str(parent_root), "generation": 3, "file_sha256": handoff.sha(parent_root / "artifact.safetensors"), "contract": "33" * 32}
            parent_file = parent_root / "parent.json"
            parent_file.write_text(json.dumps(parent))
            cell_bin = root / "cell-bin"
            cell_bin.write_bytes(b"controlled-not-an-executable")
            output = root / "run"
            arguments = {"chain": chain, "hepta": root / "hepta", "source-parent": parent_file,
                "source-materials": materials, "output": output, "python": root / "python",
                "cell-bin": cell_bin, "just": root / "just", "hepta-target": root / "hepta-target"}
            argv = [str(SCRIPT)]
            for key, value in arguments.items():
                argv.extend(("--" + key, str(value)))
            clock, payloads, fetched_names = [100.0], {}, []
            readbacks = []
            actual_sha = handoff.sha

            def controlled_sha(path):
                path = Path(path)
                value = actual_sha(path)
                if output in path.parents and path.parent.name in ("consumer-parent", "consumer-materials"):
                    readbacks.append(path.name)
                    if path.name == "artifact.safetensors":
                        clock[0] = 135.25
                return value

            def controlled_run(command, **kwargs):
                flags = dict(zip(command[2::2], command[3::2]))
                if command[1] == "pack":
                    data = Path(flags["--input"]).read_bytes()
                    digest = actual_sha(Path(flags["--input"]))
                    payloads[digest] = data
                    observation = {"manifest": digest, "payload_sha256": digest, "bytes": len(data), "chunks": 1}
                elif command[1] in ("prepare-release", "fetch-release"):
                    observation = controlled_release(command, flags, payloads)
                elif command[1] == "fetch":
                    self.assertEqual(flags["--peers"], "")
                    self.assertEqual(flags["--max-response-bytes"], "0")
                    self.assertNotIn("--seconds", flags)
                    overall_ms, request_ms = int(flags["--overall-ms"]), int(flags["--request-ms"])
                    self.assertGreaterEqual(request_ms, 10)
                    self.assertLessEqual(request_ms, min(2000, overall_ms))
                    self.assertLessEqual(overall_ms / 1000, 135.0 - clock[0])
                    self.assertLessEqual(kwargs["timeout"], 135.0 - clock[0] + 2)
                    destination = Path(flags["--output"])
                    destination.write_bytes(payloads[flags["--manifest"]])
                    fetched_names.append(destination.name)
                    clock[0] += 0.5
                    observation = {"downloaded_chunks": 0, "cached_chunks": 1,
                        "received_response_bytes": 0, "connection_attempts": 0}
                else:
                    self.fail("late transfer must not start native consumer use")
                return subprocess.CompletedProcess(command, 0, json.dumps(observation), "")

            producer = mock.Mock()
            producer.stdout = io.StringIO('{"address":"127.0.0.1:12345"}\n')
            producer.poll.return_value = None
            producer.wait.return_value = 0
            producer.communicate.side_effect = AssertionError("late transfer must not enter success/provider-drain path")
            selector = mock.MagicMock()
            selector.__enter__.return_value.select.return_value = [(object(), object())]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(handoff.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(handoff, "sha", side_effect=controlled_sha), \
                    mock.patch.object(handoff.subprocess, "run", side_effect=controlled_run), \
                    mock.patch.object(handoff.subprocess, "Popen", return_value=producer), \
                    mock.patch.object(handoff.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch("sys.stdout", new=io.StringIO()):
                with self.assertRaisesRegex(TimeoutError, "after consumer readback"):
                    handoff.main()
            report = json.loads((output / "handoff.json").read_text())
            self.assertEqual(len(fetched_names), 11)
            self.assertEqual(len(readbacks), 22)
            self.assertTrue(report["transfer"]["all_members_verified"])
            self.assertFalse(report["transfer"]["within_original_deadline"])
            self.assertEqual(report["transfer"]["limit_seconds"], 35)
            self.assertEqual(report["transfer"]["elapsed_seconds"], 35.25)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(report["producer_cleanup_after_failure"])
            self.assertFalse((output / "native-config.json").exists())
            for flag in ("independent_operators", "independent_evaluation", "product_qualification", "production_activation"):
                self.assertIs(report[flag], False)


class CellHandoffConsumerTests(unittest.TestCase):
    def test_unshipped_consumer_never_runs_or_admits_an_unknown_report(self):
        # Only orchestration is mocked. Actual create-only files and SHA
        # readbacks do not establish a real transfer, model or I10 receipt.
        reports = (None, '{"status":"failed"}', '{"status":"indeterminate"}',
                   '{"status":"passed"}', '{"schema":"unknown","parent_sha256":"wrong"}',
                   '[]', '{')
        for raw_report in reports:
            with self.subTest(report=raw_report), tempfile.TemporaryDirectory(
                    prefix="cell-consumer-control-") as temp:
                self.completed_transfer_refuses_consumer(Path(temp), raw_report)

    def completed_transfer_refuses_consumer(self, root, raw_report):
        chain, materials, parent_root = root / "chain", root / "materials", root / "parent"
        for path in (chain / "config/pon", chain / "scripts", materials, parent_root):
            path.mkdir(parents=True)
        (chain / "scripts/llm_neural_read_worker.py").write_text("# controlled fixture\n")
        pins = {}
        for index in range(7):
            path = materials / f"public-{index}.bin"
            path.write_bytes(bytes([index + 1]))
            pins[path.name] = {"size": 1, "sha256": handoff.sha(path)}
        family = {"id": "controlled-consumer-fixture", "reference": {"model": "controlled", "revision": "fixed"}, "material_pins": {"files": pins}}
        (chain / "config/pon/model-family-smollm2-135m-v1.json").write_text(json.dumps(family))
        (materials / "material-manifest.json").write_text(json.dumps({"model": "controlled", "revision": "fixed", "files": pins}))
        (parent_root / "target-contract.json").write_text(json.dumps({"backbone": {"index_root": "11" * 32}, "tokenizer": {"files_root": "22" * 32}}))
        (parent_root / "wrapped-adapter.json").write_text("{}")
        (parent_root / "artifact.safetensors").write_bytes(b"controlled-not-a-model")
        parent_file = parent_root / "parent.json"
        parent_file.write_text(json.dumps({"directory": str(parent_root), "generation": 3,
            "file_sha256": handoff.sha(parent_root / "artifact.safetensors"), "contract": "33" * 32}))
        cell_bin = root / "cell-bin"
        cell_bin.write_bytes(b"controlled-not-an-executable")
        output = root / "run"
        arguments = {"chain": chain, "hepta": root / "hepta", "source-parent": parent_file,
            "source-materials": materials, "output": output, "python": root / "python",
            "cell-bin": cell_bin, "just": root / "just", "hepta-target": root / "hepta-target"}
        argv = [str(SCRIPT)]
        for key, value in arguments.items():
            argv.extend(("--" + key, str(value)))
        payloads, native_calls, fetched_names = {}, [], []

        def controlled_run(command, **kwargs):
            if command[1] == "test":
                native_calls.append(command)
                return subprocess.CompletedProcess(command, 0)
            flags = dict(zip(command[2::2], command[3::2]))
            if command[1] == "pack":
                source = Path(flags["--input"])
                digest = handoff.sha(source)
                payloads[digest] = source.read_bytes()
                observation = {"manifest": digest, "payload_sha256": digest,
                    "bytes": len(payloads[digest]), "chunks": 1}
            elif command[1] in ("prepare-release", "fetch-release"):
                observation = controlled_release(command, flags, payloads)
            elif command[1] == "fetch":
                self.assertEqual(flags["--peers"], "")
                self.assertEqual(flags["--max-response-bytes"], "0")
                destination = Path(flags["--output"])
                with destination.open("xb") as stream:
                    stream.write(payloads[flags["--manifest"]])
                fetched_names.append(destination.name)
                observation = {"downloaded_chunks": 0, "cached_chunks": 1,
                        "received_response_bytes": 0, "connection_attempts": 0}
            else:
                self.fail("unexpected controlled subprocess")
            return subprocess.CompletedProcess(command, 0, json.dumps(observation), "")

        def producer_drained(**kwargs):
            # Even a newly appearing arbitrary report in this run's directory
            # cannot establish an absent consumer/report contract.
            if raw_report is not None:
                report_directory = output / "original-hepta-consumer"
                report_directory.mkdir(mode=0o700)
                (report_directory / "native-owner-bridge-result.json").write_text(raw_report)
            return "", None

        producer = mock.Mock()
        producer.stdout = io.StringIO('{"address":"127.0.0.1:12345"}\n')
        producer.returncode = 0
        producer.poll.return_value = 0
        producer.communicate.side_effect = producer_drained
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.return_value = [(object(), object())]
        refusal = None
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(handoff.time, "monotonic", return_value=100.0), \
                mock.patch.object(handoff.subprocess, "run", side_effect=controlled_run), \
                mock.patch.object(handoff.subprocess, "Popen", return_value=producer), \
                mock.patch.object(handoff.selectors, "DefaultSelector", return_value=selector), \
                mock.patch("sys.stdout", new=io.StringIO()):
            try:
                handoff.main()
            except Exception as error:
                refusal = error
        report = json.loads((output / "handoff.json").read_text())
        self.assertEqual(report["status"], "failed", "unknown JSON must not establish native success")
        self.assertIsInstance(refusal, RuntimeError)
        self.assertRegex(str(refusal), "UNAVAILABLE.*UNVERIFIED")
        self.assertEqual(len(fetched_names), 11)
        self.assertTrue(report["transfer"]["all_members_verified"])
        self.assertTrue(report["transfer"]["within_original_deadline"])
        self.assertEqual(report["producer_exit_code_before_consumer_load"], 0)
        self.assertEqual(report["native_consumer_status"], "UNAVAILABLE")
        self.assertEqual(report["native_receipt_status"], "UNVERIFIED")
        for flag in ("independent_operators", "independent_evaluation", "product_qualification", "production_activation"):
            self.assertIs(report[flag], False)
        self.assertEqual(native_calls, [])
        self.assertNotIn("native_result", report)
        self.assertFalse((output / "native-config.json").exists())
        # Reusing the output cannot import a stale report into another run.
        with mock.patch.object(sys, "argv", argv):
            with self.assertRaises(FileExistsError):
                handoff.main()


if __name__ == "__main__":
    unittest.main()
