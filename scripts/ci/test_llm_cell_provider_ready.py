#!/usr/bin/env python3
"""Actual pipe framing controls; these do not qualify a WAN or model load."""
import importlib.util
import json
import os
from pathlib import Path
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "run_llm_cell_native_handoff.py"
SPEC = importlib.util.spec_from_file_location("cell_provider_ready", SCRIPT)
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class ProviderReadyTests(unittest.TestCase):
    address = "127.0.0.1:12345"

    def pipe(self, data, close=True):
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        os.write(writer, data)
        if close:
            os.close(writer)
        else:
            self.addCleanup(os.close, writer)
        stream = os.fdopen(os.dup(reader), "rb", buffering=0)
        self.addCleanup(stream.close)
        return stream

    def event(self, schema, address=None):
        return (json.dumps(dict(schema=schema, address=address or self.address)) + "\n").encode()

    def test_coalesced_events_preserve_the_next_line_and_one_deadline(self):
        listen = self.event("trnm.cell.listen.v1")
        ready = self.event("trnm.cell.ready.v1")
        stream = self.pipe(listen + ready)
        deadline = time.monotonic() + 2
        first, raw_first = handoff.read_provider_event(stream, deadline, "trnm.cell.listen.v1")
        second, raw_second = handoff.read_provider_event(stream, deadline, "trnm.cell.ready.v1", first["address"])
        self.assertEqual(raw_first.encode(), listen)
        self.assertEqual(raw_second.encode(), ready)
        self.assertEqual(second["address"], self.address)

    def test_listener_event_is_not_a_ready_event(self):
        stream = self.pipe(self.event("trnm.cell.listen.v1"))
        with self.assertRaisesRegex(ValueError, "schema or listener"):
            handoff.read_provider_event(stream, time.monotonic() + 2, "trnm.cell.ready.v1", self.address)

    def test_ready_for_another_listener_is_rejected(self):
        stream = self.pipe(self.event("trnm.cell.ready.v1", "127.0.0.1:12346"))
        with self.assertRaisesRegex(ValueError, "schema or listener"):
            handoff.read_provider_event(stream, time.monotonic() + 2, "trnm.cell.ready.v1", self.address)

    def test_partial_open_pipe_spends_original_window_without_waiting_for_newline(self):
        stream = self.pipe(b'{"schema":', close=False)
        with self.assertRaisesRegex(TimeoutError, "original deadline"):
            handoff.read_provider_event(stream, time.monotonic() + 0.05, "trnm.cell.ready.v1", self.address)

    def test_eof_and_oversized_events_are_refused(self):
        for data, error in ((b'{"schema":', RuntimeError), (b"x" * 4097, ValueError)):
            with self.subTest(size=len(data)):
                stream = self.pipe(data)
                with self.assertRaises(error):
                    handoff.read_provider_event(stream, time.monotonic() + 2, "trnm.cell.ready.v1", self.address)

    def test_expired_window_does_not_consume_even_a_complete_ready(self):
        data = self.event("trnm.cell.ready.v1")
        stream = self.pipe(data)
        with self.assertRaisesRegex(TimeoutError, "original deadline"):
            handoff.read_provider_event(stream, time.monotonic() - 1, "trnm.cell.ready.v1", self.address)
        self.assertEqual(os.read(stream.fileno(), len(data)), data)


if __name__ == "__main__":
    unittest.main()
