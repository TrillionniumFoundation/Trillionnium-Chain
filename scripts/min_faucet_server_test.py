#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import hashlib
import os
import pathlib
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

import min_faucet_server as faucet


class CanonicalRequestTests(unittest.TestCase):
    def test_address_is_reconstructed_from_fixed_lowercase_hex(self) -> None:
        value = "trnm1" + "ab" * 20
        self.assertEqual(faucet.canonical_address(value), value)

    def test_address_rejects_option_and_control_character_injection(self) -> None:
        for value in (
            "",
            "--help",
            "trnm1" + "ab" * 19,
            "trnm1" + "AB" * 20,
            "trnm1" + "ab" * 20 + "\n--help",
            "trnm1" + "gg" * 20,
            1,
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(faucet.RequestValidationError):
                    faucet.canonical_address(value)

    def test_amount_is_canonical_positive_u128(self) -> None:
        self.assertEqual(faucet.canonical_amount("1"), "1")
        self.assertEqual(faucet.canonical_amount(123), "123")
        maximum = str((1 << 128) - 1)
        self.assertEqual(faucet.canonical_amount(maximum), maximum)

    def test_amount_rejects_noncanonical_and_out_of_range_values(self) -> None:
        for value in (
            "",
            "0",
            0,
            True,
            False,
            "-1",
            "+1",
            "01",
            "1 ",
            "1\n--help",
            "1.0",
            1.0,
            str(1 << 128),
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(faucet.RequestValidationError):
                    faucet.canonical_amount(value)

    def test_request_id_is_exact_lowercase_sha256_shape(self) -> None:
        value = "42" * 32
        self.assertEqual(faucet.canonical_request_id(value), value)
        for invalid in ("", "A" * 64, "0" * 63, "0" * 65, "../x", None):
            with self.subTest(value=invalid):
                with self.assertRaises(faucet.RequestValidationError):
                    faucet.canonical_request_id(invalid)

    def test_command_uses_only_pinned_descriptor_and_equals_bound_values(self) -> None:
        address = "trnm1" + "42" * 20
        command = faucet.faucet_command(17, address, "7")
        self.assertEqual(command[0], "/proc/self/fd/17")
        self.assertEqual(command[1], "faucet-request")
        self.assertEqual(command[-2], f"--address={address}")
        self.assertEqual(command[-1], "--amount=7")
        self.assertNotIn("cargo", command)

    def test_command_timeout_is_bounded(self) -> None:
        for value in ("1", "60"):
            with mock.patch.dict(
                os.environ,
                {"TRNM_FAUCET_COMMAND_TIMEOUT_SECONDS": value},
                clear=False,
            ):
                self.assertEqual(faucet.command_timeout_seconds(), int(value))
        for value in ("0", "61", "-1", "1.5", "invalid"):
            with mock.patch.dict(
                os.environ,
                {"TRNM_FAUCET_COMMAND_TIMEOUT_SECONDS": value},
                clear=False,
            ):
                with self.assertRaises(RuntimeError):
                    faucet.command_timeout_seconds()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux security boundary")
class LinuxBoundaryTests(unittest.TestCase):
    def _executable(self, root: pathlib.Path, body: str) -> pathlib.Path:
        path = root / "trnm-rpc-fixture"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o500)
        return path

    def _environment(self, path: pathlib.Path) -> dict[str, str]:
        return {
            "TRNM_FAUCET_RPC_BIN": str(path),
            "TRNM_FAUCET_RPC_SHA256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def test_rpc_binary_is_copied_to_exactly_sealed_memfd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-faucet-binary-") as raw:
            path = self._executable(pathlib.Path(raw), "#!/bin/sh\nexit 0\n")
            with mock.patch.dict(os.environ, self._environment(path), clear=False):
                with faucet.pinned_rpc_executable() as descriptor:
                    _flags, _add, get_seals, expected = faucet._required_sealing()
                    self.assertEqual(fcntl.fcntl(descriptor, get_seals), expected)
                    self.assertEqual(os.pread(descriptor, path.stat().st_size, 0), path.read_bytes())
                    with self.assertRaises(OSError):
                        os.pwrite(descriptor, b"X", 0)

    def test_missing_sealing_capability_fails_closed(self) -> None:
        with mock.patch.object(faucet.fcntl, "F_GET_SEALS", None):
            with self.assertRaisesRegex(RuntimeError, "sealed Linux memfd support"):
                faucet._required_sealing()

    def test_rpc_binary_requires_absolute_digest_bound_nonwritable_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-faucet-binary-") as raw:
            path = self._executable(pathlib.Path(raw), "#!/bin/sh\nexit 0\n")
            cases = (
                ({"TRNM_FAUCET_RPC_BIN": "relative", "TRNM_FAUCET_RPC_SHA256": "0" * 64}, "absolute"),
                ({"TRNM_FAUCET_RPC_BIN": str(path), "TRNM_FAUCET_RPC_SHA256": "0" * 64}, "digest mismatch"),
            )
            for environment, expected in cases:
                with self.subTest(expected=expected):
                    with mock.patch.dict(os.environ, environment, clear=False):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            with faucet.pinned_rpc_executable():
                                pass
            path.chmod(0o520)
            environment = self._environment(path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaisesRegex(RuntimeError, "group/world writable"):
                    with faucet.pinned_rpc_executable():
                        pass

    def test_timeout_kills_and_reaps_forked_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-faucet-descendant-") as raw:
            root = pathlib.Path(raw)
            pidfile = root / "descendant.pid"
            interpreter = root / "python-fixture"
            interpreter.write_bytes(pathlib.Path(sys.executable).resolve(strict=True).read_bytes())
            interpreter.chmod(0o500)
            environment = self._environment(interpreter)
            helper = (
                "import os, pathlib, time; "
                "child = os.fork(); "
                "(time.sleep(60), os._exit(0)) if child == 0 else None; "
                "pathlib.Path(os.environ['TRNM_TEST_DESCENDANT_PID']).write_text(str(child)); "
                "time.sleep(60)"
            )
            with mock.patch.dict(os.environ, environment, clear=False):
                with faucet.pinned_rpc_executable() as descriptor:
                    executable = f"/proc/self/fd/{descriptor}"
                    with self.assertRaises(faucet.FaucetCommandTimeout):
                        faucet._execute_pinned_process(
                            descriptor,
                            (executable, "-c", helper),
                            1,
                            environment={"TRNM_TEST_DESCENDANT_PID": str(pidfile)},
                        )
            self.assertTrue(pidfile.is_file())
            child = int(pidfile.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and pathlib.Path(f"/proc/{child}").exists():
                time.sleep(0.02)
            self.assertFalse(pathlib.Path(f"/proc/{child}").exists())


class LedgerTests(unittest.TestCase):
    def test_ledger_is_exactly_once_and_replays_success(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-faucet-ledger-parent-") as raw:
            ledger_path = pathlib.Path(raw) / "ledger"
            ledger_path.mkdir(mode=0o700)
            request_id = "ab" * 32
            address = "trnm1" + "cd" * 20
            fingerprint = faucet.request_fingerprint(request_id, address, "9")
            with faucet.FaucetLedger(ledger_path) as ledger:
                first = ledger.admit(request_id, fingerprint)
                self.assertTrue(first.is_new)
                duplicate = ledger.admit(request_id, fingerprint)
                self.assertFalse(duplicate.is_new)
                self.assertEqual(duplicate.state, "started")
                ledger.finish(request_id, fingerprint, "succeeded", {"ok": True, "tx": "1"})
                replay = ledger.admit(request_id, fingerprint)
                self.assertEqual(replay.state, "succeeded")
                self.assertEqual(replay.response, {"ok": True, "tx": "1"})
                other = faucet.request_fingerprint(request_id, address, "10")
                with self.assertRaises(faucet.IdempotencyConflict):
                    ledger.admit(request_id, other)

    def test_ledger_requires_exact_private_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-faucet-ledger-parent-") as raw:
            path = pathlib.Path(raw) / "ledger"
            path.mkdir(mode=0o755)
            with self.assertRaisesRegex(RuntimeError, "mode 0700"):
                faucet.FaucetLedger(path)


if __name__ == "__main__":
    unittest.main()
