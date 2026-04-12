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

    def make_public_mainnet_args(self, config: Path, *extra_args: str) -> tuple[str, ...]:
        return (
            "--emit-ceremony-packet",
            "--ceremony-scope",
            "public-mainnet-input",
            "--ceremony-id",
            "mn04-bootstrap-20260331-0621Z",
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
            *extra_args,
            str(config),
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
                *self.make_public_mainnet_args(
                    config,
                    "--ceremony-id",
                    "<ceremony-id>",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires ceremony_id to be an explicit non-placeholder value",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_template_default_ceremony_id(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--ceremony-id",
                    "mn04-bootstrap-YYYYMMDD-HHMMZ",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires an explicit ceremony_id instead of the template default",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_default_validator_set_version(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--validator-set-version",
                    "v1",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires explicit values for validator_set_version",
            result.stderr,
        )

    def test_bundle_rejects_node_id_with_packet_separator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node=1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script(str(config))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "invalid node config",
            result.stderr,
        )
        self.assertIn(
            "node_id must not contain packet/list separators (, ; | =)",
            result.stderr,
        )

    def test_emit_ceremony_packet_rejects_separator_in_validator_set_version(self) -> None:
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
                "--validator-set-version",
                "release=1",
                str(config),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "invalid ceremony packet arguments: validator_set_version must not contain ';' or '=' separators",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_placeholder_startup_order_note(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--startup-order-note",
                    "<startup-order-note>",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires explicit values for startup_order_note",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_placeholder_rollback_owner(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--rollback-owner",
                    "<owner>",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires explicit values for rollback_owner",
            result.stderr,
        )

    def test_emit_ceremony_packet_rejects_separator_in_rollback_owner(self) -> None:
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
                "--rollback-owner",
                "alice;bob",
                str(config),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "invalid ceremony packet arguments: rollback_owner must not contain ';' or '=' separators",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_non_utc_packet_generated_at(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--packet-generated-at",
                    "2026-03-31 06:21:00",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_generated_at in UTC ISO-8601 form",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_placeholder_packet_generated_at(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--packet-generated-at",
                    "<packet-generated-at>",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires explicit values for packet_generated_at",
            result.stderr,
        )

    def test_emit_ceremony_packet_rejects_packet_distribution_path_equal_to_genesis_artifact_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            shared_path = str(root / "shared.packet.txt")
            result = self.run_script(
                "--emit-ceremony-packet",
                "--packet-distribution-path",
                shared_path,
                "--genesis-artifact-path",
                shared_path,
                str(config),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "packet_distribution_path and genesis_artifact_path must name different files",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_relative_packet_distribution_path(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    "relative/packet.txt",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path to be an absolute path",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_relative_genesis_artifact_path(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--genesis-artifact-path",
                    "relative/genesis.json",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires genesis_artifact_path to be an absolute path",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_directory_packet_distribution_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            packet_dir = root / "handoff"
            packet_dir.mkdir()
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    str(packet_dir) + "/",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path to name one exact packet file",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_existing_directory_packet_distribution_path_without_trailing_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            packet_dir = root / "handoff"
            packet_dir.mkdir()
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    str(packet_dir),
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path to name one exact packet file",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_dot_segments_in_packet_distribution_path(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    str(root / "handoff" / ".." / "packet.txt"),
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path to avoid '.' or '..' path segments",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_leading_dot_segment_in_packet_distribution_path(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    "/./tmp/public-mainnet.packet.txt",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path to avoid '.' or '..' path segments",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_directory_genesis_artifact_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            artifact_dir = root / "genesis-bundle"
            artifact_dir.mkdir()
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--genesis-artifact-path",
                    str(artifact_dir) + "/",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires genesis_artifact_path to name one exact artifact path",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_existing_directory_genesis_artifact_path_without_trailing_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            artifact_dir = root / "genesis-bundle"
            artifact_dir.mkdir()
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--genesis-artifact-path",
                    str(artifact_dir),
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires genesis_artifact_path to name one exact artifact path",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_dot_segments_in_genesis_artifact_path(self) -> None:
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
                *self.make_public_mainnet_args(
                    config,
                    "--genesis-artifact-path",
                    f"{root}/artifacts/./genesis.json",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires genesis_artifact_path to avoid '.' or '..' path segments",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_same_packet_and_genesis_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            shared_path = root / "shared.packet.txt"
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    str(shared_path),
                    "--genesis-artifact-path",
                    str(shared_path),
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires packet_distribution_path and genesis_artifact_path to name different files",
            result.stderr,
        )

    def test_public_mainnet_input_rejects_dot_segment_alias_before_normalized_same_path_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            packet_dir = root / "packets"
            packet_dir.mkdir()
            shared_path = packet_dir / "shared.packet.txt"
            result = self.run_script(
                *self.make_public_mainnet_args(
                    config,
                    "--packet-distribution-path",
                    str(shared_path),
                    "--genesis-artifact-path",
                    f"{packet_dir}/../packets/shared.packet.txt",
                )
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public-mainnet-input requires genesis_artifact_path to avoid '.' or '..' path segments",
            result.stderr,
        )

    def test_public_mainnet_input_emits_absolute_config_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            relative_config = config.relative_to(root)
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    *self.make_public_mainnet_args(relative_config),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"config_path={config.resolve()}", result.stdout)

    def test_public_mainnet_input_operator_ack_reuses_absolute_config_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            relative_config = config.relative_to(root)
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    *self.make_public_mainnet_args(relative_config),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        ack_line = next(
            line for line in result.stdout.splitlines() if line.startswith("operator_ack=")
        )
        self.assertIn(f"config_path={config.resolve()}", ack_line)

    def test_public_mainnet_input_operator_ack_quotes_validator_entry_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script(*self.make_public_mainnet_args(config))

        self.assertEqual(result.returncode, 0, result.stderr)
        hash_line = next(
            line for line in result.stdout.splitlines() if line.startswith("validator_entry_hash=")
        )
        ack_line = next(
            line for line in result.stdout.splitlines() if line.startswith("operator_ack=")
        )
        validator_entry_hash = hash_line.split("=", 1)[1]
        self.assertIn("ceremony_id=mn04-bootstrap-20260331-0621Z", ack_line)
        self.assertIn(f"genesis_artifact_sha256={VALID_SHA256}", ack_line)
        self.assertIn("<owner-for-node1> checked", ack_line)
        self.assertIn("validator_name=node1", ack_line)
        self.assertIn(f"validator_entry_hash={validator_entry_hash}", ack_line)

    def test_public_mainnet_input_scopes_owner_contact_placeholders_per_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script(*self.make_public_mainnet_args(config))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "validator_entry=validator_name=node1;validator_owner=<owner-for-node1>;",
            result.stdout,
        )
        self.assertIn(
            "operator_contact=node1=<chat/email/oncall-for-node1>",
            result.stdout,
        )

    def test_public_mainnet_input_scopes_ack_artifact_placeholders_per_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script(*self.make_public_mainnet_args(config))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "operator_ack_signature_path=<optional-ack-path-for-node1>",
            result.stdout,
        )
        self.assertIn(
            "operator_ack_digest=<optional-sha256-of-node1-ack>",
            result.stdout,
        )

    def test_emit_ceremony_packet_uses_unambiguous_path_and_digest_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self.write_config(
                root,
                "node1.toml",
                node_id="node1",
                rpc_addr="127.0.0.1:7001",
                p2p_addr="127.0.0.1:7002",
            )
            result = self.run_script("--emit-ceremony-packet", str(config))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("packet_distribution_path=<absolute-path-to-ceremony-packet>", result.stdout)
        self.assertIn("startup_order_note=<controlled-4-node-bootstrap-order>", result.stdout)
        self.assertIn("genesis_artifact_path=<absolute-path-to-genesis-artifact>", result.stdout)
        self.assertIn("genesis_artifact_sha256=<64-character-genesis-sha256>", result.stdout)


if __name__ == "__main__":
    unittest.main()
