#!/usr/bin/env python3
"""Synthetic Cargo metadata with real Git binding; does not execute Cargo."""
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

import check_cargo_source_inventory_v1 as inventory


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.workspace = self.root / 'trillionnium'
        self.package = self.workspace / 'crates/example'
        (self.package / 'src').mkdir(parents=True)
        (self.workspace / 'Cargo.toml').write_text('[workspace]\nmembers=["crates/example"]\n')
        (self.workspace / 'Cargo.lock').write_text('version = 4\n')
        (self.package / 'Cargo.toml').write_text('[package]\nname="example"\nversion="0.1.0"\n')
        (self.package / 'src/lib.rs').write_text('pub fn identity(x: u64) -> u64 { x }\n')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        self.head = self.git('rev-parse', 'HEAD')
        self.metadata = {
            'version': 1, 'workspace_root': str(self.workspace), 'workspace_members': ['fixture-id'],
            'packages': [{'id': 'fixture-id', 'name': 'example',
                'manifest_path': str(self.package / 'Cargo.toml'),
                'targets': [{'name': 'example', 'kind': ['lib'], 'src_path': str(self.package / 'src/lib.rs')}]}],
        }

    def git(self, *args: str) -> str:
        return inventory.git(self.root, *args)

    def check(self):
        return inventory.validate_metadata(self.root, self.workspace, self.metadata, self.head)

    def test_valid_source_binding_is_not_test_acceptance(self) -> None:
        report = self.check()
        self.assertEqual(report['package_count'], 1)
        self.assertEqual(report['source_commit'], self.head)
        self.assertEqual(report['source_tree'], self.git('rev-parse', 'HEAD^{tree}'))
        self.assertEqual(report['test_acceptance'], 'not-assessed')
        self.assertIs(report['production_authority'], False)

    def test_wrong_source_sha(self) -> None:
        self.head = '0' * 40
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_dirty_tracked_source(self) -> None:
        (self.package / 'src/lib.rs').write_text('changed')
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_untracked_source(self) -> None:
        (self.package / 'src/extra.rs').write_text('untracked')
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_unknown_workspace_root(self) -> None:
        self.metadata['workspace_root'] = str(self.root)
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_absent_log_target_has_no_source_binding(self) -> None:
        self.metadata['packages'][0]['targets'].append({
            'name': 'abuse_budget_daemon', 'kind': ['test'],
            'src_path': str(self.package / 'tests/abuse_budget_daemon.rs'),
        })
        with self.assertRaises((inventory.InventoryError, OSError)): self.check()

    def test_unknown_and_duplicate_members(self) -> None:
        for members in ([], ['unknown'], ['fixture-id', 'fixture-id']):
            with self.subTest(members=members):
                self.metadata['workspace_members'] = members
                with self.assertRaises(inventory.InventoryError): self.check()

    def test_package_metadata_cannot_override_manifest(self) -> None:
        self.metadata['packages'][0]['name'] = 'forged-name'
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_duplicate_target_rejected(self) -> None:
        self.metadata['packages'][0]['targets'] *= 2
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_source_escape_rejected(self) -> None:
        self.metadata['packages'][0]['targets'][0]['src_path'] = '/etc/passwd'
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_duplicate_package_id(self) -> None:
        self.metadata['packages'].append(copy.deepcopy(self.metadata['packages'][0]))
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_duplicate_json_and_nonjson_numbers_rejected(self) -> None:
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(inventory.InventoryError):
                json.loads(raw, object_pairs_hook=inventory.strict_object, parse_constant=inventory.reject_constant)


if __name__ == '__main__':
    unittest.main(verbosity=2)
