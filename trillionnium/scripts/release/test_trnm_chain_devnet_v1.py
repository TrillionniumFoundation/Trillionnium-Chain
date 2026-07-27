#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("trnm_chain_devnet_v1.py")
SPEC = importlib.util.spec_from_file_location("trnm_chain_devnet_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class TrnmChainDevnetV1Tests(unittest.TestCase):
    def test_release_template_is_tracked_packaging_input(self) -> None:
        workspace = package.workspace_root()
        static_root = workspace / "packaging/trnm_chain_devnet_v1"
        self.assertTrue(static_root.is_dir())
        self.assertFalse((workspace / "release/trnm_chain_devnet_v1").is_dir() and not static_root.is_dir())
        required = {
            "README.md",
            "ROLLBACK.md",
            "LEGAL-NOTICE.md",
            "schemas/trnm-chain-package-manifest-v1.schema.json",
            "schemas/trnm-finality-receipt-v1.schema.json",
            "schemas/trnm-signed-command-envelope-v1.schema.json",
        }
        self.assertEqual(
            required,
            {str(path.relative_to(static_root)) for path in static_root.rglob("*") if path.is_file()}
            & required,
        )

    def make_key(self, root: Path, name: str) -> tuple[Path, Path]:
        private = root / f"{name}.private.pem"
        public = root / f"{name}.public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private.chmod(0o600)
        package.openssl_public_key(private, public)
        return private, public

    def make_signed_bundle(
        self,
        root: Path,
        private: Path,
        public: Path,
    ) -> tuple[Path, Path, Path]:
        package_root = root / package.PACKAGE_ID
        for binary in package.REQUIRED_BINARIES:
            path = package_root / "bin" / binary
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fake:{binary}\n".encode("ascii"))
            path.chmod(0o755)
        schema = package_root / "schemas/example.json"
        schema.parent.mkdir(parents=True)
        schema.write_text("{}\n", encoding="ascii")
        package.canonical_json(
            package_root / "manifest/package.json",
            {
                "schema": package.PACKAGE_SCHEMA,
                "package_id": package.PACKAGE_ID,
                "scope": package.PACKAGE_SCOPE,
                "public_mainnet_ready": False,
                "private_keys_packaged": False,
                "required_binaries": list(package.REQUIRED_BINARIES),
                "git_head": "0" * 40,
                "source_state": "clean",
            },
        )
        checksums = package.write_payload_checksums(package_root)
        packaged_public = package_root / "signatures/release-public-key.pem"
        package.copy_regular(public, packaged_public)
        package.openssl_sign(
            private,
            checksums,
            package_root / "signatures/SHA256SUMS.ed25519",
        )

        archive = root / "bundle.tar.gz"
        package.deterministic_archive(package_root, archive, 1_700_000_000)
        checksum = root / "bundle.tar.gz.sha256"
        checksum.write_text(
            f"{package.sha256_file(archive)}  {archive.name}\n",
            encoding="ascii",
        )
        signature = root / "bundle.tar.gz.ed25519"
        package.openssl_sign(private, checksum, signature)
        return archive, checksum, signature

    def test_signed_bundle_requires_external_trust_anchor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-package-test-") as directory:
            root = Path(directory)
            private, public = self.make_key(root, "release")
            archive, checksum, signature = self.make_signed_bundle(
                root,
                private,
                public,
            )
            result = package.verify_archive_bundle(
                archive,
                public,
                checksum,
                signature,
            )
            self.assertTrue(result["verified"])

            _, unrelated_public = self.make_key(root, "unrelated")
            with self.assertRaises(package.PackageError):
                package.verify_archive_bundle(
                    archive,
                    unrelated_public,
                    checksum,
                    signature,
                )

    def test_archive_checksum_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-package-tamper-") as directory:
            root = Path(directory)
            private, public = self.make_key(root, "release")
            archive, checksum, signature = self.make_signed_bundle(
                root,
                private,
                public,
            )
            with archive.open("ab") as handle:
                handle.write(b"tamper")
            with self.assertRaises(package.PackageError):
                package.verify_archive_bundle(
                    archive,
                    public,
                    checksum,
                    signature,
                )

    def test_init_devnet_validation_checks_scope_loopback_and_secret_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-init-test-") as directory:
            root = Path(directory)
            for relative in package.REQUIRED_INIT_PUBLIC_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative.endswith("devnet-genesis.json"):
                    payload = {
                        "schema": "trnm_devnet_genesis_v1",
                        "scope": package.PACKAGE_SCOPE,
                        "development_only": True,
                    }
                elif relative.endswith("node.json"):
                    payload = {
                        "schema": "trnm_live_chain_config_v1",
                        "listen_addr": "127.0.0.1:26657",
                    }
                else:
                    payload = {
                        "schema": "trnm_validator_config_v1",
                        "listen_addr": "127.0.0.1:27001",
                        "vote_endpoint": "http://127.0.0.1:27001",
                    }
                path.write_text(
                    json.dumps(payload, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            for relative in package.REQUIRED_INIT_SECRET_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("01" * 32 + "\n", encoding="ascii")
                path.chmod(0o600)

            evidence = package.validate_init_devnet_output(root)
            self.assertEqual(evidence["secret_files_validated"], 4)
            self.assertFalse(evidence["secret_material_packaged"])
            self.assertEqual(len(evidence["public_files_validated"]), 6)
            self.assertNotIn("secrets", json.dumps(evidence))

            if os.name == "posix":
                insecure = root / package.REQUIRED_INIT_SECRET_FILES[0]
                insecure.chmod(0o644)
                with self.assertRaises(package.PackageError):
                    package.validate_init_devnet_output(root)

    def test_spdx_sbom_accepts_cargo_metadata_dependency_id_shapes(self) -> None:
        metadata = {
            "packages": [
                {"id": "root 0.1.0", "name": "trnm-node", "version": "0.1.0"},
                {"id": "dep 1.0.0", "name": "dep", "version": "1.0.0"},
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "root 0.1.0",
                        "dependencies": ["dep 1.0.0"],
                        "deps": [{"name": "dep", "pkg": "dep 1.0.0"}],
                    }
                ]
            },
        }

        sbom = package.build_spdx_sbom(
            metadata,
            head="0" * 40,
            target="x86_64-unknown-linux-gnu",
            created_at="2026-07-26T00:00:00Z",
        )
        dependency_relationships = [
            relationship
            for relationship in sbom["relationships"]
            if relationship["relationshipType"] == "DEPENDS_ON"
        ]
        self.assertEqual(len(dependency_relationships), 1)


if __name__ == "__main__":
    unittest.main()
