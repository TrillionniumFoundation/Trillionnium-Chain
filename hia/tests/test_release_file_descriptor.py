"""Exact Unix held-file policy; the host, not HIA, acquires the observations."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_header import ALIASES
from hia.tests import test_release_transcript_composition as transcript

from hia.platform.release_file_shadow.owner import (
    DESCRIPTOR as SOURCE, FILE_IDENTITY, LIMIT, SPENT, STREAM, Budget,
    HeldReleaseOwner, after_frame, before_frame,
)


def rust_input(case, scenario):
    return (bytes([scenario]) + case.profile + case.instance
            + struct.pack("<QBQQQ", case.generation, case.kind, case.max_reads, case.max_bytes, case.size)
            + case.locator + b"".join(ALIASES[1:]) + case.data)


@contextmanager
def held_fixture(case, scenario):
    with tempfile.TemporaryDirectory(prefix="trnm-held-native-artifact-") as directory:
        root = Path(directory) / "only-fixture"
        root.mkdir()
        path = root / "artifact"
        if scenario == 3:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd, None
            finally:
                os.close(fd)
            return
        path.write_bytes(case.data)
        with path.open("rb", buffering=0) as opened:
            if scenario == 1:
                path.rename(root / "moved-file")
                assert not path.exists()
            elif scenario == 2:
                opened.seek(1)
            elif scenario == 4:
                root.rename(Path(directory) / "moved-root")
                assert not path.exists()
            yield opened.fileno(), opened


class ReleaseFileDescriptor(unittest.TestCase):
    call = transcript.ReleaseTranscriptComposition.call

    @classmethod
    def setUpClass(cls):
        temporary = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-held-rust-oracle-")))
        cls.rust = transcript.original_reference(temporary, held_file=True)
        sources = (SOURCE, *STREAM)
        cls.modules = {backend: {source: cls.enterClassContext(
            NativeModule(source, backend=backend, byte_exports=("f0",))) for source in sources}
            for backend in ("direct", "selfhost")}
        if cls.modules["direct"][SOURCE].artifact_sha256 == cls.modules["selfhost"][SOURCE].artifact_sha256:
            raise ValueError("expected independent native policy images")

    def observe_rust(self, case, scenario):
        with tempfile.TemporaryDirectory(prefix="trnm-held-original-artifact-") as directory:
            outcome = subprocess.run([str(self.rust), directory], input=rust_input(case, scenario),
                                     check=True, capture_output=True, timeout=20)
        self.assertEqual(outcome.stderr, b"")
        data = outcome.stdout
        self.assertIn(len(data), (162, 162 + 213))
        return struct.unpack_from("<BBQQQQ", data), data[34:98], data[98:162], data[162:]

    def observe_native(self, modules, case, scenario, _, status_expect):
        with held_fixture(case, scenario) as (fd, file), HeldReleaseOwner(fd) as owner:
            budget = Budget(case.max_reads, case.max_bytes)
            result = owner.observe(modules, case.candidate(), budget)
            self.assertEqual(result.status, status_expect)
            self.assertIsNone(owner._fd)
            if file is not None:
                self.assertEqual(file.tell(), result.consumed)
            if result.status:
                self.assertEqual(result.claim, b"")
            return ((result.status, result.exhausted, result.initial_offset, result.consumed,
                     result.reads_reserved, result.bytes_reserved), result.claim)

    def assert_checked(self, native, frame, status):
        canaries = [frame, b"unchanged-proposal", b"unchanged-scratch"]
        result = native.call("f0", canaries).require_returned()
        self.assertEqual(result.value, status)
        self.assertEqual(result.arguments, canaries)

    def test_fresh_original_descriptor_and_native_held_bytes(self):
        data = transcript.sample(transcript.BLOCK + 9)
        item = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        wrong = replace(item, locator=bytes([0x81]) * 32)
        alternative_scope = replace(item, generation=item.generation + 1)
        rows = (
            (item, 0, 0, 0), (item, 1, 0, 0), (item, 4, 0, 0),
            (alternative_scope, 0, 0, 0),
            (item, 2, 101, 101), (item, 3, 101, 101),
            (replace(wrong, size=item.size + 1, kind=1, max_bytes=1), 0, 101, 101),
            (replace(wrong, kind=1, max_bytes=1), 0, 0, 1),
            (replace(wrong, max_bytes=1), 0, 0, 2), (wrong, 0, 0, 6),
        )
        original = [self.observe_rust(case, scenario) for case, scenario, _, _ in rows]
        self.assertEqual(original[0][-1], original[1][-1])
        self.assertEqual(original[0][-1], original[2][-1])
        self.assertNotEqual(original[0][-1][149:], original[3][-1][149:])

        for name, modules in self.modules.items():
            for row, (status, before, after, claim) in zip(rows, original, strict=True):
                case, scenario, pre, expected = row
                with self.subTest(backend=name, scenario=scenario, pre=pre, expected=expected):
                    self.assertEqual(status[0], expected)
                    self.assert_checked(modules[SOURCE], before_frame(case.size, status[2], before), pre)
                    if not expected:
                        self.assertEqual(before, after)
                        self.assert_checked(modules[SOURCE], after_frame(before, after), 0)
                    self.assertEqual(self.observe_native(modules, *row), (status, claim))

    def test_held_owner_is_single_use_and_bounded_without_partial_claim(self):
        data = transcript.sample(transcript.BLOCK + 9)
        item = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        for backend, modules in self.modules.items():
            with self.subTest(backend=backend), held_fixture(item, 0) as (fd, file), HeldReleaseOwner(fd) as owned:
                ledger = Budget(1, 1 << 20)
                owned_fd = owned._fd
                result = owned.observe(modules, item.candidate(), ledger, max_calls=1)
                self.assertEqual((result.status, result.requested, result.claim),
                                 (LIMIT, (transcript.BLOCK,), b""))
                self.assertEqual(file.tell(), result.consumed)
                self.assertEqual(result.consumed, transcript.BLOCK)
                self.assertEqual(ledger.counts[1], 1)
                with self.assertRaises(OSError):
                    os.fstat(owned_fd)
                spent = owned.observe(modules, item.candidate(), ledger)
                self.assertEqual((spent.status, spent.requested, spent.claim), (SPENT, (), b""))
                self.assertEqual(ledger.counts[1], 1)

            # The same ledger is sticky across independently held descriptors.
            for _ in range(2):
                with held_fixture(item, 0) as (fd, file), HeldReleaseOwner(fd) as owned:
                    refused = owned.observe(modules, item.candidate(), ledger)
                    self.assertEqual((refused.status, refused.exhausted, refused.requested, refused.claim),
                                     (2, True, (), b""))
                    self.assertEqual(file.tell(), 0)

            with held_fixture(item, 0) as (fd, file), HeldReleaseOwner(fd) as owned:
                elapsed = owned.observe(modules, item.candidate(), Budget(1, 1 << 20), allowance=1e-12)
                self.assertEqual((elapsed.status, elapsed.requested, elapsed.claim), (LIMIT, (), b""))
                self.assertEqual(file.tell(), 0)

            with tempfile.TemporaryFile(mode="w+b") as file, HeldReleaseOwner(file.fileno()) as owned:
                file.write(data)
                file.seek(0)
                refused = owned.observe(modules, item.candidate(), Budget(1, 1 << 20))
                self.assertEqual((refused.status, refused.requested, refused.claim), (FILE_IDENTITY, (), b""))
                self.assertEqual(file.tell(), 0)

    def test_changed_post_record_discards_completed_claim(self):
        data = b"short held release fixture"
        item = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        for backend, modules in self.modules.items():
            with self.subTest(backend=backend), held_fixture(item, 0) as (fd, file), \
                    held_fixture(item, 0) as (other_fd, _), HeldReleaseOwner(fd) as owned:
                probe = os.fstat
                private_fd = owned._fd
                existing, other = probe(fd), probe(other_fd)
                self.assertNotEqual((existing.st_dev, existing.st_ino), (other.st_dev, other.st_ino))
                observed_count = 0

                def mismatch(descriptor):
                    nonlocal observed_count
                    if descriptor != private_fd:
                        return probe(descriptor)
                    observed_count += 1
                    # Boundary test double: a real record from another synthetic fd,
                    # not an actual race or a replacement during the genuine read.
                    return other if observed_count == 2 else probe(descriptor)

                with patch("hia.platform.release_file_shadow.owner.os.fstat", side_effect=mismatch):
                    result = owned.observe(modules, item.candidate(), Budget(1, 1 << 20))
                self.assertEqual(observed_count, 2)
                self.assertEqual(result.consumed, len(data))
                self.assertEqual(file.tell(), len(data))
                self.assertEqual((result.status, result.requested, result.claim),
                                 (FILE_IDENTITY, (len(data), 1), b""))

    def test_each_typed_metadata_field_and_exact_extent(self):
        data = b"disposable metadata fixture"
        case = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        _, before, after, _ = self.observe_rust(case, 0)
        self.assertEqual(before, after)
        pre, post = before_frame(case.size, 0, before), after_frame(before, after)
        controls = [(b"", 100), (pre[:-1], 100), (post + b"\x00", 100),
                    (b"BAD!" + pre[4:], 100), (pre[:4] + b"\x02" + pre[5:], 100)]
        for offset in (0, 8, 16, 24, 32, 40, 48, 56):
            different = bytearray(after)
            different[offset] ^= 1
            controls.append((after_frame(before, bytes(different)), 101))
        for index, source in ((44, pre), (28, post), (92, post)):
            noncanonical = bytearray(source)
            noncanonical[index] = 1
            controls.append((bytes(noncanonical), 100))
        for modules in self.modules.values():
            self.assert_checked(modules[SOURCE], pre, 0)
            self.assert_checked(modules[SOURCE], post, 0)
            for packet, status in controls:
                self.assert_checked(modules[SOURCE], packet, status)


if __name__ == "__main__":
    unittest.main()
