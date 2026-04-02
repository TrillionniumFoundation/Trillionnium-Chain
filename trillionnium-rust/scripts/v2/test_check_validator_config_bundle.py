#!/usr/bin/env python3
"""Targeted regression tests for check_validator_config_bundle.py."""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_validator_config_bundle.py")
VALID_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class CheckValidatorConfigBundleTests(unittest.TestCase):
    def write_config(self, root: Path, name: str, *, node_id: str, rpc_addr: str, p2p_addr: str) -> Path:
        path = root / name
        path.write_text(
            textwrap.dedent(
                f'''\
                node_id = "{node_id}"
                rpc_addr = "{rpc_addr}"
                p2p_addr = "{p2p_addr}"
                '''
            ),
            encoding="utf-8",
        )
        return path

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_public_mainnet_input_rejects_placeholder_ceremony_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script(
                "--emit-ceremony-packet",
                "--ceremony-scope",
                "public-mainnet-input",
                "--ceremony-id",
                "<ceremony-id>",
                "--packet-generated-at",
                "2026-03-31T06:21:00Z",
                "--packet-distribution-path",
                "/tmp/packet.txt",
                "--validator-set-version",
                "release-1",
                "--startup-order-note",
                "seq-a",
                "--rollback-owner",
                "alice",
                "--genesis-artifact-path",
                "/tmp/genesis.json",
                "--genesis-artifact-sha256",
                VALID_SHA256,
                str(config),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires ceremony_id to be an explicit non-placeholder value",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
