#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import tempfile
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

    def test_command_uses_fixed_executable_and_equals_bound_values(self) -> None:
        cargo = pathlib.Path("/trusted/bin/cargo")
        address = "trnm1" + "42" * 20
        command = faucet.faucet_command(cargo, address, "7")
        self.assertEqual(command[0], str(cargo))
        self.assertEqual(command[-2], f"--address={address}")
        self.assertEqual(command[-1], "--amount=7")
        self.assertNotIn("--help", command)

    def test_cargo_override_must_be_absolute_and_executable(self) -> None:
        with mock.patch.dict(os.environ, {"TRNM_FAUCET_CARGO_BIN": "cargo"}, clear=False):
            with self.assertRaises(RuntimeError):
                faucet.resolve_cargo_binary()

        with tempfile.TemporaryDirectory(prefix="trnm-faucet-test-") as raw:
            executable = pathlib.Path(raw) / "cargo"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            with mock.patch.dict(
                os.environ,
                {"TRNM_FAUCET_CARGO_BIN": str(executable)},
                clear=False,
            ):
                self.assertEqual(faucet.resolve_cargo_binary(), executable.resolve())

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


if __name__ == "__main__":
    unittest.main()
