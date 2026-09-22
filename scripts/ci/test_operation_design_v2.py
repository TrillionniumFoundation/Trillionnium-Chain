#!/usr/bin/env python3
"""Behavioral tests for honest, bounded operation-surface discovery."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import check_operation_design_v2 as gate


class OperationDesignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        parts = []
        coverage = []
        for mid in gate.MODULES:
            parts += [f"## {mid} — Fixture", "",
                      f"| {mid}-OP-RUN | Exact owner input | Source -> target | Commit then readback | Bound and reject | Compare original receipt |", ""]
            crate = "crate-" + mid.lower()
            coverage += ["[[module_coverage]]", f'id = "{mid}"', f'primary_crates = ["{crate}"]']
            self.put(f"trillionnium/crates/{crate}/Cargo.toml", f'[package]\nname = "{crate}"\n')
            self.put(f"trillionnium/crates/{crate}/src/lib.rs", "pub fn run() {}\n#[test]\nfn regression() {}\n")
        self.design = "\n".join(parts)
        self.put(gate.DESIGN, self.design)
        self.put(gate.ECONOMICS, "Candidate assumptions, not authority.\n")
        self.put(gate.COVERAGE, "\n".join(coverage))
        self.operation = {"id": "M00-OP-RUN", "module_id": "M00",
                          "implementation": {"package": "crate-m00", "path": "trillionnium/crates/crate-m00/src/lib.rs", "symbol": "run"},
                          "cases": [{"source_path": "trillionnium/crates/crate-m00/src/lib.rs"}]}
        self.catalog = {"production_authority": False, "semantic_acceptance": "not-assessed",
                        "implementation_acceptance": "not-assessed", "operations": [self.operation]}
        self.put(gate.CATALOGS[0], json.dumps(self.catalog))
        self.put(gate.CATALOGS[1], json.dumps({**self.catalog, "operations": []}))

    def put(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def test_design_rows_are_not_catalog_completeness(self) -> None:
        report = gate.inventory(self.root, scan_public=True)
        self.assertEqual(report["design_operation_count"], 18)
        self.assertEqual(report["registered_operation_count"], 1)
        self.assertEqual(sum(row["unclassified_public_declarations"] for row in report["modules"]), 17)
        self.assertFalse(report["whole_project_operation_catalog_complete"])
        self.assertFalse(report["production_authority"])

    def test_unexecuted_public_scan_is_unknown_not_zero(self) -> None:
        report = gate.inventory(self.root)
        self.assertFalse(report["public_scan_executed"])
        self.assertTrue(all(row["public_declarations"] is None for row in report["modules"]))

    def test_missing_module(self) -> None:
        self.put(gate.DESIGN, self.design[:self.design.index("## M17")])
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)

    def test_duplicate_operation(self) -> None:
        row = next(line for line in self.design.splitlines() if line.startswith("| M17"))
        self.put(gate.DESIGN, self.design + "\n" + row)
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)

    def test_missing_obligation(self) -> None:
        self.put(gate.DESIGN, self.design.replace("| Bound and reject |", "| |", 1))
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)

    def test_declared_module_differs_from_physical_adapter_owner(self) -> None:
        self.operation["id"] = "M02-OP-HOST"
        self.operation["module_id"] = "M02"
        self.put(gate.CATALOGS[0], json.dumps(self.catalog))
        report = gate.inventory(self.root)
        self.assertEqual(report["modules"][2]["registered_operations"], 1)

    def test_new_public_operation_is_visible_and_changes_source_digest(self) -> None:
        before = gate.inventory(self.root, scan_public=True)
        path = "trillionnium/crates/crate-m01/src/lib.rs"
        self.put(path, (self.root / path).read_text() + "pub fn cancel() {}\n")
        after = gate.inventory(self.root, scan_public=True)
        self.assertEqual(after["modules"][1]["unclassified_public_declarations"], 2)
        self.assertNotEqual(before["input_set_sha256"], after["input_set_sha256"])

    def test_comment_or_string_is_not_implementation(self) -> None:
        self.put(self.operation["implementation"]["path"], '// pub fn run() {}\nconst TEXT: &str = "pub fn run() {}";\n')
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)

    def test_lexer_masks_nested_comments_raw_strings_and_keeps_lifetimes(self) -> None:
        text = '''/* nested /* pub fn fake1() {} */ still comment */
const A: &str = r###"pub fn fake2() {}"###;
const B: &str = "escaped \\" pub fn fake3() {}";
// pub fn fake4() {}
pub fn real<'a>(v: &'a str) {}
pub(crate) fn private() {}
#[cfg(test)]
pub async fn conditional() {}
'''
        names = [name for name, _ in gate.public_functions(text)]
        self.assertEqual(names, ["real", "conditional"])
        self.assertEqual(gate.public_functions("\n\npub fn real() {}\n"), [("real", 3)])

    def test_symlink_and_path_escape_reject(self) -> None:
        target = self.root / gate.ECONOMICS
        target.unlink()
        target.symlink_to(self.root / gate.DESIGN)
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)
        for path in ("../escape", "/etc/passwd", "config/../escape", "config\\escape"):
            with self.assertRaises(gate.DesignError):
                gate.local(self.root, path)

    def test_duplicate_json_keys_reject(self) -> None:
        with self.assertRaises(gate.DesignError):
            json.loads('{"production_authority":false,"production_authority":true}', object_pairs_hook=gate.strict_object)

    def test_missing_replay_reference_reject(self) -> None:
        self.operation["cases"] = [{"source_path": "missing.rs"}]
        self.put(gate.CATALOGS[0], json.dumps(self.catalog))
        with self.assertRaises(gate.DesignError):
            gate.inventory(self.root)

    def test_acceptance_cannot_be_self_promoted(self) -> None:
        for field, value in (("production_authority", True), ("semantic_acceptance", "accepted")):
            self.put(gate.CATALOGS[0], json.dumps({**self.catalog, field: value}))
            with self.assertRaises(gate.DesignError):
                gate.inventory(self.root)

    def test_all_names_matched_still_is_not_semantic_completeness(self) -> None:
        operations = []
        for mid in gate.MODULES:
            crate = "crate-" + mid.lower()
            path = f"trillionnium/crates/{crate}/src/lib.rs"
            operations.append({"id": mid + "-OP-RUN", "module_id": mid,
                               "implementation": {"package": crate, "path": path, "symbol": "run"},
                               "cases": [{"source_path": path}]})
        self.put(gate.CATALOGS[0], json.dumps({**self.catalog, "operations": operations}))
        report = gate.inventory(self.root, scan_public=True)
        self.assertEqual(sum(row["unclassified_public_declarations"] for row in report["modules"]), 0)
        self.assertFalse(report["whole_project_operation_catalog_complete"])
        self.assertEqual(report["semantic_acceptance"], "not-assessed")


if __name__ == "__main__":
    unittest.main()
