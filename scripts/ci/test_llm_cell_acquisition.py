#!/usr/bin/env python3
"""Reusable acquisition boundary controls; mocked CLI is not native evidence."""

import importlib.util
import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "run_llm_cell_native_handoff.py"
SPEC = importlib.util.spec_from_file_location("cell_acquisition", SCRIPT)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class CompleteAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cell-acquisition-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.release_file = self.root / "source.tcr1"
        self.release_file.write_bytes(b"controlled-release-not-native-tcr1")
        self.closure_file = self.root / "source.tcd1"
        self.closure_file.write_bytes(b"controlled-closure-not-native-tcd1")
        self.payloads = {}
        self.members = []
        for index in range(11):
            data = bytes([index + 1])
            digest = handoff.hashlib.sha256(data).hexdigest()
            self.payloads[digest] = data
            self.members.append({"destination": str(self.output / str(index)),
                "pack": {"manifest": digest, "payload_sha256": digest,
                         "bytes": 1, "chunks": 1}})
        self.release = {"release": "12" * 32}
        self.closure = handoff.ClosureAcquisition(
            source_file=self.closure_file,
            destination=self.output / "consumer.tcd1",
            sha256=handoff.sha(self.closure_file), closure_id="34" * 32,
            generation=2, loader_profile="56" * 32,
            context=tuple((key, "family" if key == "family" else "78" * 32)
                for key in ("family", "base", "parent", "tokenizer", "layout", "runtime")),
            authentication_arguments=("--authentication-profile", "content-cache-v1"))
        self.evidence = {"members": self.members, "installation_authority": False,
                         "selection_authority": False, "use_authority": False}
        self.calls = []
        self.clock = 100.0
        self.result_change = {}
        self.materialization_change = {}
        self.producer = mock.Mock()
        self.producer.stdout = self.startup_stream()
        self.producer.poll.return_value = None
        self.producer.returncode = 0

        def drain(**kwargs):
            self.assertEqual(kwargs, {"timeout": 50})
            self.producer.poll.return_value = self.producer.returncode
            return "", None

        self.producer.communicate.side_effect = drain
        for patch in (
            mock.patch.object(handoff.time, "monotonic", side_effect=lambda: self.clock),
            mock.patch.object(handoff.subprocess, "run", side_effect=self.run_cli),
            mock.patch.object(handoff.subprocess, "Popen", return_value=self.producer),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def startup_stream(self):
        # The selected current provider announces both its listener and actual
        # ready event. Use an owned pipe so the unchanged bounded reader runs.
        read_fd, write_fd = os.pipe()
        try:
            address = "127.0.0.1:12345"
            data = "".join(json.dumps({"schema": schema, "address": address}) + "\n"
                for schema in ("trnm.cell.listen.v1", "trnm.cell.ready.v1"))
            os.write(write_fd, data.encode())
        finally:
            os.close(write_fd)
        stream = os.fdopen(read_fd, "r")
        self.addCleanup(stream.close)
        return stream

    def run_cli(self, command, **kwargs):
        self.calls.append(command)
        flags = dict(zip(command[2::2], command[3::2]))
        self.assertLessEqual(int(flags["--overall-ms"]), int((135 - self.clock) * 1000))
        self.assertLessEqual(int(flags["--request-ms"]), 2000)
        self.assertLessEqual(kwargs["timeout"], 135 - self.clock + 2)
        self.clock += 0.25
        if command[1] == "fetch-closure":
            self.assertEqual(flags["--authentication-profile"], "content-cache-v1")
            self.assertEqual(flags["--closure"], self.closure.closure_id)
            self.assertEqual(flags["--loader-profile"], self.closure.loader_profile)
            self.assertEqual(flags["--loader-generation"], "2")
            self.assertEqual(flags["--parallelism"], "2")
            self.assertEqual(flags["--required-roles"], "base,tokenizer,adapter,configuration")
            for key, value in self.closure.context:
                self.assertEqual(flags["--" + key], value)
            Path(flags["--output"]).write_bytes(self.closure_file.read_bytes())
            result = {"schema": "trnm.cell.closure.fetch.v1", "release": self.release["release"],
                "closure": self.closure.closure_id, "generation": 2, "cells": 11,
                "payload_bytes": 11, "chunks": 11, "cached_chunks": 0,
                "downloaded_chunks": 11, "received_response_bytes": 11,
                "connection_attempts": 22, "selection_authority": False, "use_authority": False}
            result.update(self.result_change)
        elif command[1] == "fetch":
            self.assertEqual(flags["--peers"], "")
            self.assertEqual(flags["--max-response-bytes"], "0")
            self.assertEqual(flags["--parallelism"], "1")
            Path(flags["--output"]).write_bytes(self.payloads[flags["--manifest"]])
            result = {"downloaded_chunks": 0, "cached_chunks": 1,
                "received_response_bytes": 0, "connection_attempts": 0}
            result.update(self.materialization_change)
        else:
            self.fail("explicit closure acquisition cannot fall back to another operation")
        return subprocess.CompletedProcess(command, 0, json.dumps(result), "")

    def acquire(self):
        return handoff.acquire_complete_release(cell_bin=self.root / "cell",
            output=self.output, cache_limits=(), producer=self.root / "producer.sqlite",
            consumer=self.root / "consumer.sqlite", members=self.members,
            release_file=self.release_file, release=self.release,
            evidence=self.evidence, closure=self.closure)

    def test_exact_closure_returns_only_after_every_local_readback_and_provider_exit(self):
        self.assertEqual(self.acquire(), self.closure.destination)
        self.assertEqual(len(self.calls), 12)
        self.assertTrue(self.evidence["transfer"]["all_members_verified"])
        self.assertTrue(self.evidence["transfer"]["within_original_deadline"])
        self.assertEqual(self.evidence["transfer"]["limit_seconds"], 35)
        self.assertIs(self.evidence["transfer"]["provider_ready_observed"], True)
        self.assertEqual(self.evidence["transfer"]["provider_ready_seconds"], 0.0)
        self.assertIn("--announce-ready", handoff.subprocess.Popen.call_args.args[0])
        self.assertEqual(self.evidence["producer_exit_code_before_consumer_load"], 0)
        for flag in ("installation_authority", "selection_authority", "use_authority"):
            self.assertIs(self.evidence[flag], False)
        self.producer.terminate.assert_not_called()

    def test_wrong_generation_or_asserted_use_authority_cannot_materialize_or_fallback(self):
        for change in ({"generation": 3}, {"selection_authority": True}, {"use_authority": True}):
            with self.subTest(change=change):
                self.result_change = change
                self.calls.clear()
                self.clock = 100.0
                self.producer.stdout = self.startup_stream()
                with self.assertRaisesRegex(ValueError, "independent loader pins"):
                    self.acquire()
                self.assertEqual([call[1] for call in self.calls], ["fetch-closure"])
                self.assertFalse(self.evidence["transfer"]["all_members_verified"])
                self.assertTrue(self.evidence["producer_cleanup_after_failure"])

    def test_materialization_cannot_spend_new_network_budget(self):
        self.materialization_change = {"connection_attempts": 1}
        with self.assertRaisesRegex(ValueError, "escaped the verified release store"):
            self.acquire()
        self.assertEqual([call[1] for call in self.calls], ["fetch-closure", "fetch"])
        self.assertTrue(self.evidence["producer_cleanup_after_failure"])

    def test_provider_failure_is_not_promoted_after_complete_readback(self):
        self.producer.returncode = 2
        with self.assertRaisesRegex(RuntimeError, "producer did not stop"):
            self.acquire()
        self.assertTrue(self.evidence["transfer"]["all_members_verified"])
        self.assertNotIn("producer_exit_code_before_consumer_load", self.evidence)

    def test_existing_cache_cannot_be_reported_as_cold_acquisition(self):
        (self.root / "consumer.sqlite").write_bytes(b"existing-cache")
        with self.assertRaisesRegex(ValueError, "initially be absent"):
            self.acquire()
        self.producer.communicate.assert_not_called()
        self.assertEqual(self.calls, [])


    def test_ready_wait_cannot_renew_original_transfer_deadline(self):
        original = handoff.read_provider_event
        observed = []

        def read_ready(stream, deadline, schema, address=None):
            observed.append((schema, deadline))
            if schema == "trnm.cell.ready.v1":
                self.clock = 135.0
            return original(stream, deadline, schema, address)

        with mock.patch.object(handoff, "read_provider_event", side_effect=read_ready):
            with self.assertRaises(TimeoutError):
                self.acquire()
        self.assertEqual(observed, [("trnm.cell.listen.v1", 105.0),
                                    ("trnm.cell.ready.v1", 135.0)])
        self.assertEqual(self.calls, [])
        self.assertIs(self.evidence["transfer"]["provider_ready_observed"], False)
        self.assertIs(self.evidence["transfer"]["within_original_deadline"], False)
        self.assertTrue(self.evidence["producer_cleanup_after_failure"])



if __name__ == "__main__":
    unittest.main()
