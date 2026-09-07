#!/usr/bin/env python3
"""M17 freeze-gate regressions in isolated fixtures; no checksum repair path."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = Path("scripts/ci/check_legacy_harness_freeze.sh")
FREEZE = Path("config/legacy-harness-freeze.sha256")
MANIFEST = Path("trillionnium/crates/trnm-node/Cargo.toml")
ENTRYPOINTS = (
    "src/main.rs",
    "src/bin/trnm-chain-node.rs",
    "src/bin/trnm-chain-validator.rs",
    "src/bin/trnm-chain-cli.rs",
)


class LegacyHarnessFreeze(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-legacy-freeze-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in (GATE, FREEZE, MANIFEST, *(MANIFEST.parent / p for p in ENTRYPOINTS)):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def run_gate(self, expected: str | None = None) -> None:
        result = subprocess.run(
            ["bash", str(self.root / GATE)],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout + result.stderr
        if expected is None:
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("legacy_harness_entrypoint_manifest_freeze=ok", output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(expected, output)
            self.assertNotIn("legacy_harness_entrypoint_manifest_freeze=ok", output)

    def test_reviewed_baseline(self) -> None:
        self.run_gate()

    def test_each_entrypoint_drift_is_rejected_without_repinning(self) -> None:
        for relative in ENTRYPOINTS:
            with self.subTest(entrypoint=relative):
                path = self.root / MANIFEST.parent / relative
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\n// unreviewed entrypoint change\n")
                    self.run_gate(f"{MANIFEST.parent / relative}: FAILED")
                finally:
                    path.write_bytes(original)

    def test_incomplete_duplicate_extra_and_malformed_checksum_inventories(self) -> None:
        path = self.root / FREEZE
        original = path.read_text(encoding="ascii")
        rows = original.splitlines()
        cases = (
            (rows[:-1], "exactly four entries"),
            ([rows[0], *rows[:-1]], "every frozen entrypoint once"),
            ([*rows, rows[0]], "exactly four entries"),
            (["z" + rows[0][1:], *rows[1:]], "malformed checksum entry"),
            ([rows[0].replace("  ", " *", 1), *rows[1:]], "malformed checksum entry"),
        )
        for mutated, expected in cases:
            with self.subTest(expected=expected, row=mutated[0]):
                path.write_text("\n".join(mutated) + "\n", encoding="ascii")
                self.run_gate(expected)
        path.write_text(original, encoding="ascii")

    def test_manifest_promotion_and_binary_redirection_are_rejected(self) -> None:
        path = self.root / MANIFEST
        original = path.read_text(encoding="utf-8")
        cases = (
            ("publish = false", "publish = true", "publish=false"),
            ("autobins = false", "autobins = true", "unfrozen binaries"),
            ("autobins = false", 'autobins = false\ndefault-run = "trnm-sim"', "default legacy binary"),
            ("default = []", 'default = ["legacy-harness"]', "default features"),
            ("legacy-harness = []", 'legacy-harness = ["another-feature"]', "feature must remain explicit"),
            ('lane = "legacy-harness"', 'lane = "production"', "metadata lane"),
            ("development_only = true", "development_only = false", "metadata development_only"),
            ("protocol_features_frozen = true", "protocol_features_frozen = false", "metadata protocol_features_frozen"),
            ("production_candidate = false", "production_candidate = true", "metadata production_candidate"),
            ('path = "src/main.rs"', 'path = "src/unfrozen.rs"', "frozen entrypoint"),
            ('required-features = ["legacy-harness"]', "required-features = []", "must require legacy-harness"),
            ('name = "trnm-chain-cli"', 'name = "trnm-sim"', "binary set changed"),
        )
        for old, new, expected in cases:
            with self.subTest(change=new):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.run_gate(expected)
        path.write_text(original, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
