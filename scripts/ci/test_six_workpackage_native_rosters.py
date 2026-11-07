#!/usr/bin/env python3
"""Exercise actual selectors with historical and explicit source fixtures.

These are registration regressions, not fresh native or service acceptance.
The retained ZIP is the unchanged b173 head artifact, including its failure.
The newer history/Host/PQ names are synthetic fixtures from current Rust test
declarations; they are not a current ELF registry or evidence of execution.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'evidence/pon-six-workpackages-20261106/ci'
WORKSPACE = ROOT / '.github/workflows/pon-original-workspace-large-state-cpu.yml'
PQ = ROOT / '.github/workflows/pon-pq-system-continuation.yml'
PREFIX = 'store::native_authenticated::post_write_readback::tests::'


def heredoc(path: Path, marker: str, end: str) -> str:
    value = path.read_text()
    if value.count(marker) != 1:
        raise ValueError('workflow selector must have one owner')
    block = value.split(marker, 1)[1].split(end, 1)[0]
    lines = block.splitlines()
    indent = len(lines[0]) - len(lines[0].lstrip())
    return '\n'.join(line[indent:] for line in lines) + '\n'


def workspace_script() -> str:
    return heredoc(WORKSPACE, "<<'PYREGISTRY'\n", '        PYREGISTRY')


def pq_script() -> str:
    return heredoc(PQ, 'python3 - "$PQ_OUT/required-tests.tsv" <<\'PY\'\n', '          PY\n')


def source_fixture_extensions(crate='node'):
    """Current declarations for synthetic reader inputs, never native evidence."""
    extensions = {}
    package = {'node': 'trnm-pon-node', 'm06': 'trnm-mvcc-fee'}[crate]
    source_root = ROOT / 'trillionnium/crates' / package / 'src'
    specifications = (
        ('postwrite-history', 'store/native_authenticated/post_write_readback/history_tests.rs',
         'store::native_authenticated::post_write_readback::history_tests', 21),
        ('host-parent-relative', 'host_kernel_parent_relative_tests.rs',
         'host_kernel_parent::kernel_parent::relative_tests', 9),
        ('header-material', 'store/observed_history/tests.rs',
         'store::observed_history::tests', 8),
        ('shared-ready', 'ingress/public_v3/intake/shared_readiness_tests.rs',
         'ingress::public_v3::intake::shared_readiness_tests', 9),
        ('host-resource', 'host_kernel_parent_resource_tests.rs',
         'host_kernel_parent::kernel_parent::resource_tests', 7),
        ('pq-parallel-admission', 'ingress/pq_network/parallel_execution_tests.rs',
         'ingress::pq_network::parallel_execution_tests', 1),
    ) if crate == 'node' else (
        ('pq-parallel-preparation', 'pon_executor/pq_accounts_v2/parallel_preparation_tests.rs',
         'pon_executor::pq_accounts_v2::parallel_preparation_tests', 3),
    )
    for group, relative, module, count in specifications:
        def declarations(path, owner):
            source = path.read_text()
            tests = re.findall(
                r'^#\[test\]\n((?:#\[[^\n]*\]\n)*)fn ([A-Za-z_][A-Za-z0-9_]*)\(',
                source, re.M)
            names = [owner + '::' + name for attributes, name in tests
                     if not re.search(r'^#\[ignore\b', attributes, re.M)]
            for filename, child in re.findall(
                    r'^#\[path = "([^"]+)"\]\nmod ([A-Za-z_][A-Za-z0-9_]*);', source, re.M):
                names.extend(declarations(path.parent / filename, owner + '::' + child))
            return names

        names = declarations(source_root / relative, module)
        if len(names) != count or len(set(names)) != count:
            raise ValueError('unexpected current source fixture declarations: ' + group)
        extensions[group] = names
    if crate != 'node':
        return extensions
    live_name = 'shared_ready_fifo_two_live_listeners_preserves_order_and_original_grants'
    live_source = (source_root / 'ingress/public_v3/intake_domain_tests.rs').read_text()
    if len(re.findall(r'^fn ' + live_name + r'\(', live_source, re.M)) != 1:
        raise ValueError('expected one actual shared-readiness listener control declaration')
    extensions['shared-ready-live'] = [
        'ingress::public_v3::intake_domain_tests::' + live_name]
    return extensions


class NativeRosterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = EVIDENCE / 'workspace-head-original.zip'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != '6d48706b953d7d7dde3fbe384931081b7f2e7894ecca6551a1c4c7b6a299f079':
            raise ValueError('retained original artifact changed')
        with zipfile.ZipFile(archive) as source:
            cls.registries = {name: source.read(f'semantic-controls/{name}-registry.log').decode()
                              for name in ('m06', 'node')}
            cls.original_failure = source.read('semantic-controls/registry-check.stderr').decode()
        cls.required = json.loads((ROOT / 'config/pon/pq-system-required-tests-v1.json').read_text())
        cls.source_fixture_extensions = {}
        cls.source_fixture_registries = dict(cls.registries)
        for crate, expected in (('node', 56), ('m06', 3)):
            extensions = source_fixture_extensions(crate)
            if cls.source_fixture_extensions.keys() & extensions.keys():
                raise ValueError('source fixture group has more than one crate owner')
            cls.source_fixture_extensions.update(extensions)
            original_names = {line[:-6] for line in cls.registries[crate].splitlines()
                              if line.endswith(': test')}
            additions = [name for names in extensions.values() for name in names]
            if len(additions) != expected or len(set(additions)) != expected or original_names.intersection(additions):
                raise ValueError('source fixture additions must be separate from the retained registry')
            cls.source_fixture_registries[crate] += ''.join(name + ': test\n' for name in additions)
        # Preserve the original registry string; this separate input is explicitly
        # synthetic and exercises the complete current builder without skipping groups.
        cls.source_fixture_node = cls.source_fixture_registries['node']
        cls.source_fixture_m06 = cls.source_fixture_registries['m06']

    def run_workspace(self, *, script=None, node=None, m06=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controls = root / 'semantic-controls'
            controls.mkdir()
            for name, value in (('node', node), ('m06', m06)):
                (controls / f'{name}-registry.log').write_text(
                    self.registries[name] if value is None else value)
            env = dict(os.environ, TRNM_CI_RECEIPT_DIR=directory)
            result = subprocess.run([sys.executable, '-c', script or workspace_script()],
                                    env=env, text=True, capture_output=True, timeout=10)
            selected = controls / 'selected-tests.tsv'
            return result, selected.read_text() if selected.exists() else None

    def run_pq(self, *, script=None, value=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config/pon').mkdir(parents=True)
            (root / 'config/pon/pq-system-required-tests-v1.json').write_text(
                json.dumps(self.required if value is None else value))
            output = root / 'required.tsv'
            result = subprocess.run([sys.executable, '-c', script or pq_script(), str(output)],
                                    cwd=root, text=True, capture_output=True, timeout=10)
            return result, output.read_text() if output.exists() else None

    def test_original_workspace_failure_remains_reproducible(self):
        self.assertIn('expected 23 actual registered controls, got 25', self.original_failure)
        old = workspace_script().replace('post_write_readback::tests::", 25)',
                                         'post_write_readback::tests::", 23)')
        self.assertNotEqual(old, workspace_script())
        result, selected = self.run_workspace(script=old)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected 23 actual registered controls, got 25', result.stderr)
        self.assertIsNone(selected)

    def test_all_original_workspace_groups_execute_selection(self):
        # Historical libtest evidence cannot claim registration of newer controls.
        result, selected = self.run_workspace()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('postwrite-history: expected 21 actual registered controls, got 0', result.stderr)
        self.assertIsNone(selected)
        result, selected = self.run_workspace(node=self.source_fixture_node, m06=self.source_fixture_m06)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        original_groups = [row for row in report['groups']
                           if row['group'] not in self.source_fixture_extensions]
        self.assertEqual(sum(row['expected_count'] for row in original_groups), 60)
        for row in original_groups:
            retained = {line[:-6] for line in self.registries[row['crate']].splitlines()
                        if line.endswith(': test')}
            self.assertTrue(set(row['tests']).issubset(retained))
        for name, tests in self.source_fixture_extensions.items():
            extension = next(row for row in report['groups'] if row['group'] == name)
            self.assertCountEqual(extension['tests'], tests)
            self.assertEqual(extension['expected_count'], len(tests))
        self.assertEqual(report['selected_count'], 119)
        group = next(row for row in report['groups'] if row['group'] == 'postwrite-readback')
        self.assertEqual(group['expected_count'], 25)
        names = [line[:-6] for line in self.registries['node'].splitlines()
                 if line.startswith(PREFIX) and line.endswith(': test')]
        self.assertCountEqual(group['tests'], names)
        rows = selected.splitlines()
        self.assertEqual(len(rows), report['selected_count'])
        self.assertEqual(len(rows), len(set(rows)))
        self.assertIn('reorg-tail', selected)
        self.assertIn('current-sql-root', selected)
        self.assertIn('prepared-current-history', selected)

    def test_missing_extra_and_duplicate_native_registration_refused(self):
        node = self.source_fixture_node
        one = next(line for line in node.splitlines(True) if line.startswith(PREFIX))
        for value in (node.replace(one, '', 1), node + one,
                      node + PREFIX + 'unreviewed_additional_control: test\n', ''):
            with self.subTest(value=value[-100:]):
                result, selected = self.run_workspace(node=value, m06=self.source_fixture_m06)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(selected)
        m06 = self.source_fixture_m06
        pq_prefix = 'pon_executor::pq_accounts_v2::parallel_preparation_tests::'
        one = next(line for line in m06.splitlines(True) if line.startswith(pq_prefix))
        for value in (m06.replace(one, '', 1), m06 + one,
                      m06 + pq_prefix + 'unreviewed_additional_control: test\n', ''):
            with self.subTest(crate='m06', value=value[-100:]):
                result, selected = self.run_workspace(node=node, m06=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(selected)

    def test_original_pq_failure_and_repaired_52_names(self):
        self.assertEqual(self.required['expected_meaningful_controls'], 52)
        old = pq_script().replace('assert len(tests) == 52', 'assert len(tests) == 49')
        self.assertNotEqual(old, pq_script())
        failed, output = self.run_pq(script=old)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIsNone(output)
        result, output = self.run_pq()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line.split('\t')[1] for line in output.splitlines()], self.required['tests'])

    def test_pq_missing_duplicate_extra_harness_and_invalid_selector_refused(self):
        changes = [self.required['tests'][:-1], self.required['tests'] + ['new::test'],
                   self.required['tests'][:-1] + [self.required['tests'][0]],
                   self.required['tests'][:-1] + [self.required['child_process_harnesses_not_counted'][0]],
                   self.required['tests'][:-1] + ['--ignored']]
        for tests in changes:
            with self.subTest(last=tests[-1]):
                value = dict(self.required, tests=tests, expected_meaningful_controls=len(tests))
                result, output = self.run_pq(value=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)

    def test_original_execution_and_failure_gates_remain(self):
        text = PQ.read_text()
        self.assertIn('-- --exact --show-output --test-threads=1', text)
        self.assertIn('scripts/ci/check_required_native_test.py', text)
        self.assertIn('failed=1', text)
        self.assertNotIn('continue-on-error: true', text)
        text = WORKSPACE.read_text()
        self.assertIn('"expected_count": count', text)
        self.assertIn('"empty or duplicate libtest registry: " + crate', text)
        self.assertNotIn('continue-on-error: true', text)


if __name__ == '__main__':
    unittest.main()
