"""Real native fragments compared to the active original Rust Markdown cell."""
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/worker_agent/audit_cell_fragment.hepta"
ACTIVE_RUST = ROOT / "trillionnium/crates/trnm-worker-agent/src/audit.rs"
LIMIT = 1 << 19
INVALID = 0xFFFFFFFF
SHORT = 0xFFFFFFFE
SCRATCH = b"\xa3" * 17
SENTINEL = b"\xcc"


def original_reference(directory):
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             text=True, timeout=10).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("Original Worker oracle requires pinned rustc")
    original = ACTIVE_RUST.read_bytes()
    bodies = re.findall(rb"(?ms)^pub\(crate\) fn markdown_escape\(.*?^}\n", original)
    if len(bodies) != 1:
        raise ValueError("Cannot identify the active original Worker cell helper")
    source = directory / "reference.rs"
    executable = directory / "reference"
    source.write_bytes(bodies[0] + br"""
use std::io::{self, Read, Write};

fn main() {
    let mut request = Vec::new();
    io::stdin().read_to_end(&mut request).expect("request");
    let text = match request.as_slice() {
        [0] => None,
        [1, rest @ ..] => Some(std::str::from_utf8(rest).expect("UTF-8 input")),
        _ => panic!("bad oracle request"),
    };
    io::stdout().write_all(markdown_escape(text).as_bytes()).expect("result");
}
""")
    subprocess.run(["rustc", "--edition=2021", "-Dwarnings", str(source), "-o", str(executable)],
                   check=True, capture_output=True, timeout=30)
    return executable


class WorkerAuditCellFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-worker-escape-reference-")
        cls.addClassCleanup(temporary.cleanup)
        cls.original = original_reference(Path(temporary.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            native = NativeModule(SOURCE, backend=backend, byte_exports=("f0",))
            cls.addClassCleanup(native.close)
            cls.backends[backend] = native

    def oracle(self, value):
        request = b"\0" if value is None else b"\1" + value.encode()
        result = subprocess.run([str(self.original)], input=request, check=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.stderr, b"")
        return result.stdout

    def emit(self, native, packets):
        results = native.call_many([
            ("f0", (packet, SENTINEL * length, SCRATCH)) for packet, length in packets
        ])
        for call, (packet, length) in zip(results, packets, strict=True):
            call.require_returned()
            restored_packet, output, scratch = call.arguments
            self.assertEqual(restored_packet, packet)
            self.assertEqual(scratch, SCRATCH)
            self.assertEqual(len(output), length)
            if call.value in (INVALID, SHORT):
                self.assertEqual(output, SENTINEL * length)
                yield call.value, b""
            else:
                self.assertLessEqual(call.value, length)
                self.assertEqual(output[call.value:], SENTINEL * (length - call.value))
                yield call.value, output[:call.value]

    def test_framing_exact_fit_and_no_partial_bytes(self):
        packets = [(b"\0", 0), (b"\0", 3), (b"\1", 0), (b"\1", 3),
                   (b"\1|", 1), (b"\1|", 2), (b"\2||", 4), (b"\2||", 3),
                   (b"", 0), (b"\0extra", 8), (b"\2", 8), (b"\xff", 0),
                   (b"\1" + b"a" * (LIMIT + 1), 1)]
        expected = [(SHORT, b""), (1, self.oracle(None)), (0, b""), (0, self.oracle("")),
                    (SHORT, b""), (2, b"\\|"), (4, b"\\|\\|"), (SHORT, b"")] + [(INVALID, b"")] * 5
        for backend, native in self.backends.items():
            with self.subTest(backend=backend):
                self.assertEqual(list(self.emit(native, packets)), expected)

    def test_every_single_seam_and_byte_at_a_time(self):
        text = "é\r\n|链\\|😀\0\t\u0301\u2028\x85"
        raw = text.encode()
        expected = self.oracle(text)
        for backend, native in self.backends.items():
            for cut in range(len(raw)):
                with self.subTest(backend=backend, cut=cut):
                    packets = [(b"\1" + raw[:cut], 2 * cut + 1),
                               (b"\2" + raw[cut:], 2 * (len(raw) - cut) + 1)]
                    self.assertEqual(b"".join(chunk for _, chunk in self.emit(native, packets)),
                                     expected)
            packets = [(bytes([1 if index == 0 else 2, octet]), 3)
                       for index, octet in enumerate(raw)]
            self.assertEqual(b"".join(chunk for _, chunk in self.emit(native, packets)), expected)
            self.assertEqual(expected.decode(), text.replace("\r", " ").replace("\n", " ").replace("|", "\\|"))

    def test_large_single_cell_and_full_abi_output(self):
        # More than 2 MiB of one cell, with max-expanding fragments and a CR/LF
        # seam exactly at the strict payload bound.
        text = "|" * (3 * LIMIT) + "|" * (LIMIT - 1) + "\r\n😀|"
        raw = text.encode()
        expected = self.oracle(text)
        self.assertGreater(len(raw), 2 << 20)
        self.assertGreater(len(expected), 4 << 20)
        for backend, native in self.backends.items():
            with self.subTest(backend=backend):
                pieces = []
                for index, start in enumerate(range(0, len(raw), LIMIT)):
                    part = raw[start:start + LIMIT]
                    request = bytes([1 if index == 0 else 2]) + part
                    [(size, output)] = list(self.emit(native, [(request, 2 * len(part))]))
                    if index < 3:
                        self.assertEqual(size, 1 << 20)
                    pieces.append(output)
                self.assertEqual(b"".join(pieces), expected)
                request = b"\1" + b"|" * LIMIT
                self.assertEqual(list(self.emit(native, [(request, (1 << 20) - 1)])),
                                 [(SHORT, b"")])


if __name__ == "__main__":
    unittest.main()
