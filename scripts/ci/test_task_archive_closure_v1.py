#!/usr/bin/env python3
"""M10 archive gate regressions for prose reflow and retained authority fences."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import check_task_archive_closure_v1 as closure


class TaskArchiveClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-archive-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.config_relative = closure.CONFIG_PATH.relative_to(closure.ROOT)
        self.config = closure.load_toml(closure.CONFIG_PATH)
        paths = {
            self.config_relative.as_posix(),
            self.config["package_manifest"],
            self.config["validation_script"],
            *(row["path"] for row in self.config["source_contracts"]),
        }
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(closure.ROOT / relative, target)
        self.document = self.root / self.config["architecture_document"]

    def run_gate(self) -> dict:
        output = io.StringIO()
        with (
            mock.patch.object(closure, "ROOT", self.root),
            mock.patch.object(closure, "CONFIG_PATH", self.root / self.config_relative),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(closure.main(), 0)
        return json.loads(output.getvalue())

    def test_wrapped_authority_contract_passes_without_promoting_any_flag(self) -> None:
        # Reflow the real document, including the authority disclaimer, across
        # newlines/tabs. The exact same words must still satisfy the contract.
        self.document.write_text(
            "\n \t".join(self.document.read_text(encoding="utf-8").split()),
            encoding="utf-8",
        )
        report = self.run_gate()
        self.assertEqual(report["result"], "PASS")
        for claim in (
            "storage_deletion_authority",
            "scale_campaign_complete",
            "production_candidate",
            "production_consensus_activation",
        ):
            self.assertIs(report[claim], False)
        matching = {row["path"]: row["token_matching"] for row in report["source_contracts"]}
        self.assertEqual(matching[self.config["architecture_document"]], "whitespace")
        self.assertTrue(all(mode == "exact" for path, mode in matching.items() if path.endswith(".rs")))

    def test_missing_authority_disclaimer_still_fails(self) -> None:
        text = " ".join(self.document.read_text(encoding="utf-8").split())
        text = text.replace(
            "candidate technical contract; no storage-deletion or activation authority",
            "candidate technical contract",
        )
        self.document.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(closure.TaskArchiveClosureError, "required archive contract missing"):
            self.run_gate()

    def test_wrapped_contradictory_promotions_are_rejected(self) -> None:
        original = self.document.read_text(encoding="utf-8")
        contract = next(row for row in self.config["source_contracts"] if row["path"] == self.config["architecture_document"])
        for token in contract["forbidden_tokens"]:
            with self.subTest(token=token):
                self.document.write_text(original + "\n" + "\n\t".join(token.split()) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(closure.TaskArchiveClosureError, "forbidden promotion token present"):
                    self.run_gate()

    def test_rust_contract_spacing_remains_exact(self) -> None:
        row = next(row for row in self.config["source_contracts"] if row["path"] == self.config["archive_implementation"])
        source = self.root / row["path"]
        token = row["required_tokens"][0]
        text = source.read_text(encoding="utf-8")
        self.assertIn(token, text)
        source.write_text(text.replace(token, token.replace(" ", "\n", 1)), encoding="utf-8")
        with self.assertRaisesRegex(closure.TaskArchiveClosureError, "required archive contract missing"):
            self.run_gate()

    def test_config_cannot_enable_whitespace_matching_for_rust(self) -> None:
        config_path = self.root / self.config_relative
        text = config_path.read_text(encoding="utf-8")
        needle = f'path = "{self.config["archive_implementation"]}"\n'
        self.assertIn(needle, text)
        config_path.write_text(text.replace(needle, needle + 'token_matching = "whitespace"\n'), encoding="utf-8")
        with self.assertRaisesRegex(closure.TaskArchiveClosureError, "restricted to Markdown prose"):
            self.run_gate()

    def test_unknown_matching_policy_fails_closed(self) -> None:
        config_path = self.root / self.config_relative
        text = config_path.read_text(encoding="utf-8")
        config_path.write_text(text.replace('token_matching = "whitespace"', 'token_matching = "ignore"'), encoding="utf-8")
        with self.assertRaisesRegex(closure.TaskArchiveClosureError, "unsupported token_matching policy"):
            self.run_gate()

    def test_config_promotion_flags_still_fail(self) -> None:
        config_path = self.root / self.config_relative
        original = config_path.read_text(encoding="utf-8")
        for claim in (
            "production_candidate",
            "production_consensus_activation",
            "public_testnet_ready",
            "release_ready",
            "storage_deletion_authority",
            "scale_campaign_complete",
        ):
            with self.subTest(claim=claim):
                needle = f"\n{claim} = false\n"
                self.assertIn(needle, original)
                config_path.write_text(original.replace(needle, f"\n{claim} = true\n"), encoding="utf-8")
                with self.assertRaisesRegex(closure.TaskArchiveClosureError, f"promoted {claim}"):
                    self.run_gate()


if __name__ == "__main__":
    unittest.main()
