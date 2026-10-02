#!/usr/bin/env python3
"""Equivalence and invalidation tests for source-check work reduction."""
import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check_repository import all_files
from report_module_evidence import check_symbol, check_test_selector, python_symbols, rust_code
from check_invariants import functions
from source_binding_fixture import copy_source_bindings


class SourceTraversalTests(unittest.TestCase):
    def test_pruned_walk_matches_previous_selection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            excluded = {'.git', 'target', '__pycache__', '.pytest_cache', 'node_modules'}
            for relative in ['src/main.rs', 'docs/a.md', 'evidence/raw.json', '.hidden/a',
                             *[f'src/{name}/nested/ignored' for name in excluded]]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('data')
            (root / 'linked.rs').symlink_to(root / 'src/main.rs')
            (root / 'linked-directory').symlink_to(root / 'src', target_is_directory=True)
            (root / 'broken').symlink_to(root / 'absent')
            old = sorted(p for p in root.rglob('*') if p.is_file()
                         and not any(part in excluded for part in p.relative_to(root).parts))
            visited = []
            scandir = os.scandir
            def observe(path):
                visited.append(Path(path))
                return scandir(path)
            with patch('os.scandir', side_effect=observe):
                self.assertEqual(all_files(root), old)
            self.assertFalse(any(excluded.intersection(p.relative_to(root).parts) for p in visited))


class SourceAnalysisCacheTests(unittest.TestCase):
    def test_identical_content_analyzed_once_with_bounded_caches(self):
        for analysis, source in [(python_symbols, 'def test_one(): pass'),
                                 (functions, 'def test_one(): pass'),
                                 (rust_code, '#[test]\nfn one() {}')]:
            analysis.cache_clear()
            self.assertEqual(analysis(source), analysis(source))
            self.assertEqual(analysis.cache_info().misses, 1)
            self.assertEqual(analysis.cache_info().hits, 1)
            self.assertEqual(analysis.cache_info().maxsize, 32)

    def test_cached_python_symbols_cannot_be_mutated(self):
        self.assertIsInstance(python_symbols('def owner(): pass'), frozenset)
        self.assertIsInstance(functions('def test_one(): pass'), frozenset)

    def test_changed_source_at_same_path_is_revalidated(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            python = root / 'owner.py'
            python.write_text('def owner(): pass')
            ref = {'path': 'owner.py', 'symbol': 'owner'}
            check_symbol(root, ref)
            python.write_text('def other(): pass')
            with self.assertRaises(ValueError):
                check_symbol(root, ref)
            rust = root / 'tests.rs'
            rust.write_text('#[test]\nfn behavior() {}')
            check_test_selector(root, 'tests.rs::behavior')
            rust.write_text('// #[test]\nfn behavior() {}')
            with self.assertRaises(ValueError):
                check_test_selector(root, 'tests.rs::behavior')


class SourceBindingFixtureTests(unittest.TestCase):
    def test_only_declared_evidence_metadata_is_copied_independently(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'original'
            destination = Path(folder) / 'fixture'
            registry = {'evidence_packages': {'a': {
                'manifest': 'evidence/a/manifest.json',
                'qualification': 'qualification/report.json'}}}
            originals = {'config/pon/module-maturity-v1.json': json.dumps(registry),
                         'src/main.rs': 'fn main() {}',
                         'evidence/a/manifest.json': '{"original": true}',
                         'evidence/a/qualification/report.json': '{"accepted": false}',
                         'evidence/a/raw.bin': 'large archived body',
                         'target/debug/ignored': 'build output'}
            for relative, content in originals.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            copy_source_bindings(root, destination)
            for relative in ['src/main.rs', 'evidence/a/manifest.json',
                             'evidence/a/qualification/report.json']:
                self.assertEqual((destination / relative).read_bytes(), (root / relative).read_bytes())
            self.assertFalse((destination / 'evidence/a/raw.bin').exists())
            self.assertFalse((destination / 'target').exists())
            (destination / 'evidence/a/manifest.json').write_text('mutant')
            self.assertEqual((root / 'evidence/a/manifest.json').read_text(), originals['evidence/a/manifest.json'])

    def test_escaping_manifest_or_qualification_is_rejected(self):
        for field, value in [('manifest', '../outside.json'),
                             ('qualification', '../../../outside.json'),
                             ('manifest', '/tmp/absolute-metadata.json')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / 'original'
                registry = root / 'config/pon/module-maturity-v1.json'
                registry.parent.mkdir(parents=True)
                package = {'manifest': 'evidence/a/manifest.json', 'qualification': None}
                manifest = root / package['manifest']
                manifest.parent.mkdir(parents=True)
                manifest.write_text('{}')
                package[field] = value
                registry.write_text(json.dumps({'evidence_packages': {'a': package}}))
                with self.assertRaises(ValueError):
                    copy_source_bindings(root, Path(folder) / 'fixture')

    def test_metadata_symlinks_cannot_escape_source_root(self):
        for field in ['manifest', 'qualification']:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / 'original'
                registry = root / 'config/pon/module-maturity-v1.json'
                registry.parent.mkdir(parents=True)
                package = {'manifest': 'evidence/a/manifest.json', 'qualification': 'report.json'}
                manifest = root / package['manifest']
                manifest.parent.mkdir(parents=True)
                manifest.write_text('{}')
                report = manifest.parent / 'report.json'
                report.write_text('{}')
                outside = Path(folder) / 'outside.json'
                outside.write_text('private')
                path = manifest if field == 'manifest' else report
                path.unlink()
                path.symlink_to(outside)
                registry.write_text(json.dumps({'evidence_packages': {'a': package}}))
                with self.assertRaises(ValueError):
                    copy_source_bindings(root, Path(folder) / 'fixture')

    def test_missing_declared_metadata_is_not_replaced_with_stub(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'original'
            registry = root / 'config/pon/module-maturity-v1.json'
            registry.parent.mkdir(parents=True)
            registry.write_text(json.dumps({'evidence_packages': {'a': {
                'manifest': 'evidence/missing.json', 'qualification': None}}}))
            with self.assertRaises(ValueError):
                copy_source_bindings(root, Path(folder) / 'fixture')


if __name__ == '__main__':
    unittest.main(verbosity=2)
