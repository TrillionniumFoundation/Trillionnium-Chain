#!/usr/bin/env python3
"""Retained M17 false-pass mutants. Fixtures never count as module acceptance."""
from __future__ import annotations

import pathlib
import contextlib
import io
import json
from unittest import mock

import check_module_coverage_v1 as gate
import tempfile
import unittest

from module_coverage_guard_v1 import (
    ContractError, active_codeowners, dependency_graph, module_sections, repository_path,
)


class PathContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name) / "repo"
        self.root.mkdir()
        (self.root / "docs").mkdir()
        (self.root / "docs/spec.md").write_text("spec", encoding="utf-8")
        self.outside = pathlib.Path(self.tmp.name) / "outside.md"
        self.outside.write_text("outside", encoding="utf-8")

    def test_canonical_file_and_directory(self) -> None:
        for name in ("docs", "docs/spec.md"):
            self.assertEqual(repository_path(self.root, name, "test"), self.root / name)

    def test_noncanonical_and_hostile_paths(self) -> None:
        for path in ("", ".", "..", "../outside.md", "/etc/passwd", "docs/../docs/spec.md",
                     "docs//spec.md", "./docs/spec.md", "docs/", "C:/repo/spec.md",
                     "docs\\spec.md", "docs/\x00spec.md", None, 1, [], True):
            with self.subTest(path=path), self.assertRaises(ContractError):
                repository_path(self.root, path, "test")

    def test_absent_path_rejected(self) -> None:
        with self.assertRaises(ContractError):
            repository_path(self.root, "absent", "test")

    def test_internal_symlink_allowed(self) -> None:
        (self.root / "alias").symlink_to("docs/spec.md")
        self.assertEqual(repository_path(self.root, "alias", "test"), self.root / "docs/spec.md")

    def test_symlink_escape_rejected(self) -> None:
        (self.root / "alias").symlink_to(self.outside)
        with self.assertRaises(ContractError):
            repository_path(self.root, "alias", "test")

    def test_symlink_directory_escape_rejected(self) -> None:
        (self.root / "alias").symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(ContractError):
            repository_path(self.root, "alias/outside.md", "test")

    def test_broken_and_cyclic_symlink_rejected(self) -> None:
        (self.root / "broken").symlink_to("missing")
        (self.root / "cycle").symlink_to("cycle")
        for path in ("broken", "cycle"):
            with self.subTest(path=path), self.assertRaises(ContractError):
                repository_path(self.root, path, "test")

    def test_symlink_to_root_rejected(self) -> None:
        (self.root / "alias").symlink_to(".", target_is_directory=True)
        with self.assertRaises(ContractError):
            repository_path(self.root, "alias", "test")


class MarkdownContractTests(unittest.TestCase):
    def test_all_eighteen_visible_sections(self) -> None:
        text = "".join(f"## M{i:02d} — Module\n**Authority.** owner{i}\n" for i in range(18))
        sections = module_sections(text)
        self.assertEqual(list(sections), [f"M{i:02d}" for i in range(18)])
        self.assertIn("owner17", sections["M17"])
        self.assertNotIn("owner16", sections["M17"])

    def test_duplicate_cannot_overwrite(self) -> None:
        with self.assertRaisesRegex(ContractError, "duplicate"):
            module_sections("## M00 — shallow\nshort\n## M00 — hidden replacement\nlong")

    def test_peer_footer_not_borrowed(self) -> None:
        sections = module_sections("## M17 — Last\nshort\n## Module completion rule\n**Authority.**\n" + "x" * 2000)
        self.assertNotIn("Authority", sections["M17"])
        self.assertLess(len(sections["M17"]), 100)

    def test_fenced_heading_not_a_module(self) -> None:
        for fence in ("```", "~~~", "````", "   ```"):
            text = f"{fence}\n## M00 — fake\n{fence}\n## M01 — real\nbody\n"
            with self.subTest(fence=fence):
                self.assertEqual(list(module_sections(text)), ["M01"])

    def test_fenced_markers_and_padding_do_not_count(self) -> None:
        text = "## M00 — real\nshort\n```rust\n**Authority.**\n" + "x" * 4000 + "\n```\n"
        section = module_sections(text)["M00"]
        self.assertNotIn("Authority", section)
        self.assertLess(len(section), 100)

    def test_nested_shorter_fence_does_not_close(self) -> None:
        sections = module_sections("````md\n```\n## M00 — fake\n````\n## M01 — real\n")
        self.assertEqual(list(sections), ["M01"])

    def test_wrong_fence_kind_does_not_close(self) -> None:
        sections = module_sections("```md\n~~~\n## M00 — fake\n```\n## M01 — real\n")
        self.assertEqual(list(sections), ["M01"])

    def test_unterminated_fence_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "unterminated"):
            module_sections("## M00 — real\n```\nnever closed")

    def test_html_comments_not_counted(self) -> None:
        sections = module_sections("<!--\n## M00 — fake\n-->\n## M01 — real\n<!--**Authority.**-->\n")
        self.assertEqual(list(sections), ["M01"])
        self.assertNotIn("Authority", sections["M01"])

    def test_subheading_stays_in_module(self) -> None:
        sections = module_sections("## M00 — real\n### Contract\nbody\n## M01 — next\n")
        self.assertIn("### Contract", sections["M00"])


class OwnerContractTests(unittest.TestCase):
    def test_exact_owners_and_teams(self) -> None:
        self.assertEqual(active_codeowners("* @Alice @Bob\n/docs/ @org/team\n"), {"Alice", "Bob", "org/team"})

    def test_comments_are_not_owners(self) -> None:
        self.assertEqual(active_codeowners("# @Alice\n* @Bob # @Alice\n"), {"Bob"})

    def test_username_prefix_is_not_an_owner(self) -> None:
        self.assertNotIn("Alice", active_codeowners("* @AliceSuffix\n"))

    def test_owner_only_line_and_empty_rule(self) -> None:
        self.assertEqual(active_codeowners("@Alice @Bob\n/docs/\n\n"), set())

    def test_embedded_handle_is_not_owner(self) -> None:
        self.assertEqual(active_codeowners("/docs/ x@Alice @Bob,\n"), set())


class DependencyContractTests(unittest.TestCase):
    def test_dag(self) -> None:
        dependency_graph({"M00": [], "M01": ["M00"], "M02": ["M00", "M01"]})

    def test_cycles_rejected(self) -> None:
        for graph in ({"M00": ["M00"]}, {"M00": ["M01"], "M01": ["M00"]}):
            with self.subTest(graph=graph), self.assertRaisesRegex(ContractError, "cycle"):
                dependency_graph(graph)

    def test_bad_edge_rejected(self) -> None:
        for graph in ({"M00": ["M99"]}, {"M00": [None]}, {"M00": "M01"},
                      {"M00": [], "M01": ["M00", "M00"]}):
            with self.subTest(graph=graph), self.assertRaises(ContractError):
                dependency_graph(graph)


class FullGateFixtureTests(unittest.TestCase):
    """Run the actual main gate on synthetic input; not real-repository evidence."""
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        def write(name: str, text: str) -> None:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        self.write = write
        self.owners = "* @Alice @Bob\n"
        write(".github/CODEOWNERS", self.owners)
        write("scripts/ci/example.py", "# synthetic test fixture\n")
        write("docs/evidence/example.json", "{}")
        write("docs/spec.md", "synthetic contract fixture")
        write("web4-frontend/package.json", "{}")
        write("contracts/Cargo.toml", '[workspace]\nmembers = ["demo"]\n')
        write("contracts/demo/Cargo.toml", '[package]\nname = "contract-demo"\n')
        ids = [f"M{i:02d}" for i in range(18)]
        names = [f"crate-{i}" for i in range(18)]
        write("trillionnium/Cargo.toml", '[workspace]\nmembers = '+json.dumps(["crates/"+n for n in names])+"\n")
        for name in names:
            write(f"trillionnium/crates/{name}/Cargo.toml", f'[package]\nname = "{name}"\n')
        policy = "\n".join(key + " = true" for key in (
            "one_primary_module_per_workspace_crate", "one_primary_module_per_auxiliary_unit",
            "all_modules_require_technical_reference", "all_modules_require_slo_profile",
            "all_modules_require_testkit_profile", "all_modules_require_contract_paths",
            "all_modules_require_evidence_roots", "module_dependency_graph_must_be_acyclic",
        ))
        coverage = '\n'.join([
            'schema_version = 1', 'coverage_id = "trnm-module-coverage-v1"',
            'plan_id = "trnm-chain-development-plan-v2"', 'production_authority = false',
            'technical_reference = "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"',
            'workspace_manifest = "trillionnium/Cargo.toml"', 'contracts_manifest = "contracts/Cargo.toml"',
            'web_package_manifest = "web4-frontend/package.json"', 'maintainers = ["Alice", "Bob"]',
            'minimum_maintainers = 2', 'default_test_gate_root = "scripts/ci"',
            'default_evidence_roots = ["docs/evidence"]', '[policy]', policy,
            'production_may_depend_on_candidate_or_lab = false',
            'control_plane_may_hold_consensus_authority = false',
        ])+"\n"
        registry = ""
        reference = ""
        for module_id, name in zip(ids, names):
            coverage += f'\n[[module_coverage]]\nid = "{module_id}"\nanchor = "{module_id.lower()}"\n'
            coverage += 'slo_profile = "contract-library-v1"\ntestkit_profile = "fixture-v1"\n'
            coverage += f'primary_crates = ["{name}"]\ncontract_paths = ["docs/spec.md"]\n'
            registry += f'[[modules]]\nid = "{module_id}"\nowner_group = "fixture"\n'
            registry += 'allowed_module_dependencies = []\nforbidden_capabilities = ["sign"]\n'
            reference += f'## {module_id} — Synthetic fixture\n**Authority.** fixture\n**Primary code.** `{name}`\n'
            reference += '**Contract.** fixture\n**Verification.** fixture\nSLO profile: `contract-library-v1`.\n'
            reference += ('Synthetic padding is NOT a real detailed design or acceptance. '*20)+"\n"
        coverage += '\n[[auxiliary_units]]\nid = "contract-demo"\nprimary_module = "M00"\npath = "contracts/demo"\n'
        coverage += '\n[[auxiliary_units]]\nid = "web4"\nprimary_module = "M14"\npath = "web4-frontend"\n'
        self.coverage = coverage
        self.reference = reference
        write("config/module-coverage-v1.toml", coverage)
        write("docs/development/module-registry-v1.toml", registry)
        write("docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md", reference)
        write("docs/development/CURRENT_SNAPSHOT_V1.json", json.dumps({
            "schema": "trnm-current-snapshot-v1", "repository_implementation": {"module_coverage": {
                "module_count": 18, "workspace_crates_uniquely_mapped": 18,
                "auxiliary_unit_count": 2, "auxiliary_units_mapped": ["contract-demo", "web4"],
            }},
        }))
        patcher = mock.patch.multiple(gate, ROOT=self.root,
            COVERAGE=self.root/"config/module-coverage-v1.toml",
            REGISTRY=self.root/"docs/development/module-registry-v1.toml",
            REFERENCE=self.root/"docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md",
            SNAPSHOT=self.root/"docs/development/CURRENT_SNAPSHOT_V1.json",
            CODEOWNERS=self.root/".github/CODEOWNERS")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_gate(self) -> dict:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(gate.main(), 0)
        return json.loads(stdout.getvalue())

    def test_structural_pass_never_claims_design_acceptance(self) -> None:
        report = self.run_gate()
        self.assertEqual(report["result"], "PASS")
        self.assertFalse(report["technical_sections_semantically_checked"])
        self.assertTrue(report["technical_sections_structurally_checked"])
        self.assertEqual(report["detailed_design_acceptance"], "not-assessed")
        self.assertEqual(report["implementation_acceptance"], "not-assessed")
        self.assertFalse(report["production_authority"])
        self.assertEqual(report["workspace_crate_count"], 18)
        self.assertTrue(all(not row["test_roots_explicit"] for row in report["modules"]))

    def test_comment_maintainer_mutant(self) -> None:
        self.write(".github/CODEOWNERS", "# @Alice\n* @Bob\n")
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_prefix_maintainer_mutant(self) -> None:
        self.write(".github/CODEOWNERS", "* @AliceSuffix @Bob\n")
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_duplicate_section_mutant(self) -> None:
        self.write("docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md", self.reference+"## M00 — duplicate\n")
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_fenced_contract_mutant(self) -> None:
        mutated = self.reference.replace("**Authority.** fixture", "```text\n**Authority.** fixture\n```", 1)
        self.write("docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md", mutated)
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_aliased_test_roots_mutant(self) -> None:
        (self.root/"alias").symlink_to("scripts/ci", target_is_directory=True)
        mutated = self.coverage.replace('default_test_gate_root = "scripts/ci"',
                                        'default_test_gate_root = ["scripts/ci", "alias"]')
        self.write("config/module-coverage-v1.toml", mutated)
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_contract_cannot_escape_workspace(self) -> None:
        self.write("contracts/Cargo.toml", '[workspace]\nmembers = ["../trillionnium/crates/crate-0"]\n')
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_contract_manifest_symlink_cannot_escape_repository(self) -> None:
        manifest = self.root/"contracts/demo/Cargo.toml"
        manifest.unlink()
        with tempfile.TemporaryDirectory() as outside:
            target = pathlib.Path(outside)/"Cargo.toml"
            target.write_text('[package]\nname = "contract-demo"\n', encoding="utf-8")
            manifest.symlink_to(target)
            with self.assertRaises(gate.CoverageError):
                self.run_gate()

    def test_duplicate_json_member_rejected(self) -> None:
        self.write("docs/development/CURRENT_SNAPSHOT_V1.json", '{"schema":"old","schema":"new"}')
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_orphan_crate_still_rejected(self) -> None:
        self.write("config/module-coverage-v1.toml", self.coverage.replace('primary_crates = ["crate-0"]', 'primary_crates = []'))
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_production_flag_still_rejected(self) -> None:
        self.write("config/module-coverage-v1.toml", self.coverage.replace('production_authority = false', 'production_authority = true'))
        with self.assertRaises(gate.CoverageError):
            self.run_gate()

    def test_policy_cannot_be_weakened(self) -> None:
        self.write("config/module-coverage-v1.toml", self.coverage.replace('all_modules_require_contract_paths = true', 'all_modules_require_contract_paths = false'))
        with self.assertRaises(gate.CoverageError):
            self.run_gate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
