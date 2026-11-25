"""Real native calls against the byte-exact original M13 namespace predicate."""
from __future__ import annotations

import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/state_import/reserved_namespace.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-state-import/src/lib.rs"
ADAPTER = ROOT / "hia/tests/rust_state_import_namespace_reference.rs"
ORIGINAL_START = b"#[must_use]\npub fn forbidden_authority_namespace(namespace: &[u8]) -> bool {\n"
ORIGINAL_END = b"\n\n#[must_use]\npub fn merkle_root_v0("
PREFIXES = (b"validator_signing_state", b"consensus_private_key", b"signer_journal",
            b"safety_store", b"remote_signer_watermark", b"node_commit_ledger",
            b"operator_recovery_key")


def original_function(raw):
    """Extract only the dependency-free original body, never a reimplementation."""
    if raw.count(ORIGINAL_START) != 1:
        raise ValueError("exact original StateImport namespace entry is absent or ambiguous")
    offset = raw.index(ORIGINAL_START)
    end = raw.index(ORIGINAL_END, offset)
    if raw[end - 2:end] != b"\n}":
        raise ValueError("original standalone namespace function boundary moved")
    return raw[offset:end]


def original_cases(rows):
    with tempfile.TemporaryDirectory(prefix="trnm-state-import-namespace-oracle-") as tmp:
        code = Path(tmp) / "state_import_namespace_oracle.rs"
        executable = Path(tmp) / "state_import_namespace_oracle"
        code.write_bytes(original_function(ORIGINAL.read_bytes()) + b"\n\n" + ADAPTER.read_bytes())
        rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
        subprocess.run([rustc, "--edition=2024", "-O", str(code), "-o", str(executable)],
                       check=True, capture_output=True, timeout=60)
        request = b"".join(struct.pack("<I", len(row)) + row for row in rows)
        completed = subprocess.run([str(executable)], input=request, check=True,
                                   capture_output=True, timeout=30)
        if completed.stderr or len(completed.stdout) != len(rows) or set(completed.stdout) - {0, 1}:
            raise ValueError("incomplete original StateImport differential output")
        return completed.stdout


def corpus():
    rows = {b"", b"validator", b"account", b"account/validator_signing_state",
            b"\x00validator_signing_state", b"\xff", b"chain/\xff/\x80", b"\x00\x00"}
    for prefix in PREFIXES:
        rows.update(prefix[:end] for end in range(len(prefix) + 1))
        rows.update((prefix.upper(), prefix.title(), b"x" + prefix, b"\x00" + prefix))
        rows.update(prefix + bytes((b,)) for b in range(256))
        for index in range(len(prefix)):
            rows.update(prefix[:index] + bytes((prefix[index] ^ mask,)) + prefix[index + 1:]
                        for mask in (1, 2, 4, 8, 16, 32, 64, 128))
        for index in (0, len(prefix) - 1):
            rows.update(prefix[:index] + bytes((b,)) + prefix[index + 1:] for b in range(256))
        for length in (127, 128, 129, 255, 256):
            rows.add(prefix + b"\xff" * (length - len(prefix)))
    rng = random.Random(0x4D3133)
    rows.update(rng.randbytes(rng.randrange(0, 160)) for _ in range(256))
    return sorted(rows) + [PREFIXES[0] + b"\0" * ((1 << 20) - len(PREFIXES[0])), b"\xff" * (1 << 20)]


class StateImportNamespace(unittest.TestCase):
    def test_exact_original_rust_predicate_matches_both_native_images(self):
        rows = corpus()
        observed = original_cases(rows)
        self.assertEqual(observed, bytes(any(row.startswith(p) for p in PREFIXES) for row in rows))
        with NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost") as selfhost, NativeModule(
                SOURCE, byte_exports=("f0",), backend="direct") as direct:
            for module in (selfhost, direct):
                for start in range(0, len(rows), 128):
                    batch = rows[start:start + 128]
                    calls = module.call_many([("f0", [raw, b"output", b"scratch"]) for raw in batch])
                    for index, (row, call) in enumerate(zip(batch, calls), start):
                        call.require_returned()
                        self.assertEqual(call.value, observed[index], (index, row[:40].hex()))
                        self.assertEqual(call.arguments, [row, b"output", b"scratch"])

    def test_original_source_extraction_never_falls_back(self):
        source = ORIGINAL.read_bytes()
        extracted = original_function(source)
        self.assertTrue(extracted.startswith(ORIGINAL_START))
        self.assertIn(b"namespace.starts_with(prefix)", extracted)
        for invalid in (source.replace(ORIGINAL_START, b"", 1), source + ORIGINAL_START,
                        source.replace(ORIGINAL_END, b"", 1)):
            with self.assertRaises(ValueError):
                original_function(invalid)
