"""Compose native Worker output pieces against the exact active Rust renderer."""
import struct
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_worker_audit_active_scope import ROOT, compile_active

SOURCES = ROOT / "hia/src/worker_agent"
SCRATCH = b"\x7e\xa3"
FILL = b"\xa5"
TASK = 2**64 - 1
BASE_TEXT = ("request|鏈", "ready\r\n", None, "", *(None,) * 6)
MISSING = bytes(21 - len(b"WAR2"))
PRESENT = b"\x3f" + struct.pack("<iBHiBi", -(2**31), 255, 65535, 2**31 - 1, 0, -1)
LARGE = "|" * ((1 << 20) - 1) + "\r\n鏈😀|"


def call_frames(module, frames):
    answers = module.call_many([("f0", [frame, FILL * cap, SCRATCH]) for frame, cap in frames])
    for answer, (frame, cap) in zip(answers, frames, strict=True):
        answer.require_returned()
        actual_input, output, scratch = answer.arguments
        length = answer.value
        if not 0 <= length <= cap or actual_input != frame or scratch != SCRATCH:
            raise AssertionError("Native fragment did not produce a valid return")
        if output[length:] != FILL * (cap - length):
            raise AssertionError("Native fragment altered a byte beyond the returned prefix")
        yield output[:length]


def render_fixture_row(tokens, cells, numeric, text_fields, numeric_fields):
    header, open_row, sep, end_row, task = call_frames(tokens, [
        (b"\0", 446), (b"\1", 2), (b"\2", 3), (b"\3", 3),
        (b"\4" + struct.pack("<Q", TASK), 20),
    ])
    frames = []
    counts = []
    for value in text_fields:
        if value is None:
            wire = [(b"\0", 1)]
        else:
            raw = value.encode()
            step = MAX_EXTENT // 2
            chunks = [raw[i:i + step] for i in range(0, len(raw), step)] or [b""]
            wire = [(bytes([1 if i == 0 else 2]) + chunk, len(chunk) * 2)
                    for i, chunk in enumerate(chunks)]
        frames.extend(wire)
        counts.append(len(wire))
    pieces = iter(call_frames(cells, frames))
    text = [b"".join(next(pieces) for _ in range(count)) for count in counts]
    numbers, = call_frames(numeric, [(b"WAR2" + numeric_fields, 62)])
    # Python supplies only the test's existing typed records and their order.
    # Every emitted byte, including punctuation and escapes, came from HIA.
    return header + open_row + sep.join([text[0], task, *text[1:]]) + numbers + end_row


class WorkerAuditActiveComposition(unittest.TestCase):
    def test_native_pieces_reconstruct_active_reports_including_oversized_cell(self):
        with tempfile.TemporaryDirectory(prefix="trnm-active-composition-") as tmp:
            ref = compile_active(Path(tmp))
            baseline, large = [
                subprocess.run([str(ref), *args], check=True, capture_output=True, timeout=30)
                for args in ((), ("--large",))
            ]
        self.assertEqual((baseline.stderr, large.stderr), (b"", b""))
        self.assertGreater(len(large.stdout), 2 * MAX_EXTENT)
        for backend in ("selfhost", "direct"):
            with self.subTest(backend=backend), ExitStack() as stack:
                def open_module(name):
                    return stack.enter_context(NativeModule(
                        SOURCES / name, backend=backend, byte_exports=("f0",)))

                pieces = [open_module(name) for name in ("audit_active_table_tokens.hepta",
                          "audit_cell_fragment.hepta", "audit_reputation_fragment.hepta")]
                missing = render_fixture_row(*pieces, (*BASE_TEXT, None), MISSING)
                populated = render_fixture_row(*pieces, (*BASE_TEXT, "a|b\r\n"), PRESENT)
                actual_large = render_fixture_row(*pieces, (LARGE, *BASE_TEXT[1:], "a|b\r\n"), PRESENT)
                self.assertEqual(missing + populated, baseline.stdout)
                self.assertEqual(actual_large, large.stdout)
