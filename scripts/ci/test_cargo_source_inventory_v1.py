#!/usr/bin/env python3
"""Synthetic Cargo metadata with real Git binding; does not execute Cargo."""
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

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

    def move_fixture_to_contracts(self) -> None:
        previous = self.workspace
        self.workspace = self.root / 'contracts'
        previous.rename(self.workspace)
        self.package = self.workspace / 'crates/example'
        self.git('add', '-A')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'contract fixture')
        self.head = self.git('rev-parse', 'HEAD')
        self.metadata['workspace_root'] = str(self.workspace)
        self.metadata['packages'][0]['manifest_path'] = str(self.package / 'Cargo.toml')
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(self.package / 'src/lib.rs')

    def test_external_contract_workspace_has_distinct_source_binding(self) -> None:
        self.move_fixture_to_contracts()
        report = self.check()
        self.assertEqual(report['workspace_manifest'], 'contracts/Cargo.toml')
        self.assertEqual(report['workspace_lock'], 'contracts/Cargo.lock')
        self.assertEqual(report['package_count'], 1)
        self.assertEqual(report['test_acceptance'], 'not-assessed')
        self.assertIs(report['production_authority'], False)

    def test_external_contract_metadata_cannot_substitute_native_workspace(self) -> None:
        self.move_fixture_to_contracts()
        self.metadata['workspace_root'] = str(self.root / 'trillionnium')
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_absent_contract_log_target_is_not_an_admitted_package(self) -> None:
        self.move_fixture_to_contracts()
        self.metadata['packages'][0]['manifest_path'] = str(self.workspace / 'trnm-commit-reveal/Cargo.toml')
        with self.assertRaises((inventory.InventoryError, OSError)): self.check()

    def test_workspace_selection_cannot_escape_or_choose_an_arbitrary_path(self) -> None:
        for allowed in ('trillionnium', 'contracts'):
            self.assertEqual(inventory.select_workspace(self.root, allowed), self.root / allowed)
        for rejected in ('..', '../contracts', '/tmp', 'contracts/../trillionnium', 'unknown'):
            with self.subTest(name=rejected), self.assertRaises(inventory.InventoryError):
                inventory.select_workspace(self.root, rejected)

    def commit_fixture(self) -> None:
        self.git('add', '-A')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'source mutation fixture')
        self.head = self.git('rev-parse', 'HEAD')

    def set_declared_members(self, members: list[str]) -> None:
        (self.workspace / 'Cargo.toml').write_text(
            '[workspace]\nmembers=' + json.dumps(members) + '\n')
        self.commit_fixture()

    def test_duplicate_declared_member_cannot_be_collapsed_into_a_pass(self) -> None:
        self.set_declared_members(['crates/example', 'crates/example'])
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_declared_members_must_use_canonical_relative_paths(self) -> None:
        for member in ('./crates/example', 'crates//example',
                       'crates/../crates/example', str(self.package)):
            with self.subTest(member=member):
                self.set_declared_members([member])
                with self.assertRaises(inventory.InventoryError): self.check()

    def test_member_cannot_escape_its_workspace_inside_the_git_root(self) -> None:
        destination = self.root / 'foreign-package'
        self.package.rename(destination)
        self.package = destination
        self.metadata['packages'][0]['manifest_path'] = str(destination / 'Cargo.toml')
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(destination / 'src/lib.rs')
        self.set_declared_members(['../foreign-package'])
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_member_symlink_cannot_select_another_workspace(self) -> None:
        destination = self.root / 'foreign-package'
        self.package.rename(destination)
        self.package.symlink_to(destination, target_is_directory=True)
        self.metadata['packages'][0]['manifest_path'] = str(destination / 'Cargo.toml')
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(destination / 'src/lib.rs')
        self.commit_fixture()
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_manifest_symlink_cannot_select_another_workspace(self) -> None:
        path = self.package / 'Cargo.toml'
        foreign = self.root / 'foreign-Cargo.toml'
        path.rename(foreign)
        path.symlink_to(foreign)
        self.metadata['packages'][0]['manifest_path'] = str(foreign)
        self.commit_fixture()
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_ignored_source_alias_is_not_a_tracked_cargo_entrypoint(self) -> None:
        (self.root / '.gitignore').write_text('ignored-entry.rs\n')
        self.commit_fixture()
        alias = self.root / 'ignored-entry.rs'
        alias.symlink_to(self.package / 'src/lib.rs')
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(alias)
        self.assertEqual(self.git('status', '--porcelain', '--untracked-files=all'), '')
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_workspace_alias_cannot_change_the_selected_workspace(self) -> None:
        destination = self.root / 'contracts'
        self.workspace.rename(destination)
        self.workspace.symlink_to(destination, target_is_directory=True)
        self.metadata['workspace_root'] = str(destination)
        self.metadata['packages'][0]['manifest_path'] = str(destination / 'crates/example/Cargo.toml')
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(destination / 'crates/example/src/lib.rs')
        self.commit_fixture()
        with self.assertRaises(inventory.InventoryError): self.check()

    def test_head_movement_during_inventory_is_not_a_source_bound_pass(self) -> None:
        original = inventory.bound_file
        changed = False
        def move_after_binding(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if result[0].name == 'lib.rs' and not changed:
                changed = True
                (self.root / 'later-source.txt').write_text('new source tree\n')
                self.commit_fixture()
            return result
        with mock.patch.object(inventory, 'bound_file', side_effect=move_after_binding):
            with self.assertRaises(inventory.InventoryError): self.check()
        self.assertTrue(changed)

    def test_late_tracked_mutation_during_inventory_is_not_a_pass(self) -> None:
        original = inventory.bound_file
        def dirty_after_binding(*args, **kwargs):
            result = original(*args, **kwargs)
            if result[0].name == 'lib.rs':
                result[0].write_text('changed after its source was hashed\n')
            return result
        with mock.patch.object(inventory, 'bound_file', side_effect=dirty_after_binding):
            with self.assertRaises(inventory.InventoryError): self.check()

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
