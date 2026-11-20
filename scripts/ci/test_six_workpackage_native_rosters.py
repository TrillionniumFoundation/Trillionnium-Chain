#!/usr/bin/env python3
"""Execute the actual workflow selectors against retained native registries.

These are registration regressions, not fresh native or service acceptance.
The retained ZIP is the unchanged b173 head artifact, including its failure.
"""
from __future__ import annotations

import gzip
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
CURRENT_NODE_REGISTRY = ROOT / 'evidence/chain-native-owned-append-20261119-2e9b/controls/node-registry.log.gz'
ORIGINAL_WORKSPACE_SELECTOR = ROOT / 'evidence/chain-w1-delay-controls-20261120-e9e051/fixtures/workspace-selector-b173.py'
ORIGINAL_SELECTOR_SHA256 = '50ea5c0f3fa312e084ec695107f468fee64ebc121816624b59cc019e84aeb73b'


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
    return heredoc(PQ, 'python3 - "$PQ_OUT/required-tests.tsv" "$PQ_OUT/native-registry.log" <<\'PY\'\n', '          PY\n')


class NativeRosterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = EVIDENCE / 'workspace-head-original.zip'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != '6d48706b953d7d7dde3fbe384931081b7f2e7894ecca6551a1c4c7b6a299f079':
            raise ValueError('retained original artifact changed')
        with zipfile.ZipFile(archive) as source:
            cls.original_registries = {name: source.read(f'semantic-controls/{name}-registry.log').decode()
                              for name in ('m06', 'node')}
            cls.original_failure = source.read('semantic-controls/registry-check.stderr').decode()
        # The b173 registry remains the historical failure's actual input.
        # The current 55-control selector uses the retained owned-append Node
        # registry. These registration fixtures do not claim a shared runtime run.
        current_node = gzip.decompress(CURRENT_NODE_REGISTRY.read_bytes())
        if hashlib.sha256(current_node).hexdigest() != '53145dd409aa99a75cab15fa96e66a102ccc19f731f2b016ae62e29cdeab3559':
            raise ValueError('retained current Node registry changed')
        cls.registries = dict(cls.original_registries, node=current_node.decode())
        original_selector = ORIGINAL_WORKSPACE_SELECTOR.read_bytes()
        if hashlib.sha256(original_selector).hexdigest() != ORIGINAL_SELECTOR_SHA256:
            raise ValueError('retained b173 workspace selector changed')
        cls.original_workspace_selector = original_selector.decode()
        cls.required = json.loads((ROOT / 'config/pon/pq-system-required-tests-v1.json').read_text())

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

    def run_pq(self, *, script=None, value=None, registry_names=None, existing_output=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config/pon').mkdir(parents=True)
            (root / 'config/pon/pq-system-required-tests-v1.json').write_text(
                json.dumps(self.required if value is None else value))
            output = root / 'required.tsv'
            registry = root / 'native-registry.log'
            names = self.required['tests'] if registry_names is None else registry_names
            registry.write_text(''.join(f'{name}: test\n' for name in names))
            if existing_output is not None:
                output.write_text(existing_output)
            result = subprocess.run(
                [sys.executable, '-c', script or pq_script(), str(output), str(registry)],
                cwd=root, text=True, capture_output=True, timeout=10)
            return result, output.read_text() if output.exists() else None

    def test_original_workspace_failure_remains_reproducible(self):
        self.assertIn('expected 23 actual registered controls, got 25', self.original_failure)
        old = self.original_workspace_selector
        self.assertNotEqual(old, workspace_script())
        result, selected = self.run_workspace(
            script=old, node=self.original_registries['node'],
            m06=self.original_registries['m06'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected 23 actual registered controls, got 25', result.stderr)
        self.assertIsNone(selected)

    def test_all_original_workspace_groups_execute_selection(self):
        result, selected = self.run_workspace()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        group = next(row for row in report['groups'] if row['group'] == 'postwrite-readback')
        self.assertEqual(group['expected_count'], 55)
        names = [line[:-6] for line in self.registries['node'].splitlines()
                 if line.startswith(PREFIX) and line.endswith(': test')]
        self.assertCountEqual(group['tests'], names)
        rows = selected.splitlines()
        self.assertEqual(len(rows), report['selected_count'])
        self.assertEqual(len(rows), len(set(rows)))
        self.assertIn('reorg-tail', selected)
        self.assertIn('current-sql-root', selected)
        self.assertIn('prepared-current-history', selected)

    def test_historical_node_registry_cannot_qualify_current_workspace(self):
        result, selected = self.run_workspace(node=self.original_registries['node'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected 55 actual registered controls, got 25', result.stderr)
        self.assertIsNone(selected)

    def test_missing_extra_and_duplicate_native_registration_refused(self):
        node = self.registries['node']
        one = next(line for line in node.splitlines(True) if line.startswith(PREFIX))
        for value in (node.replace(one, '', 1), node + one,
                      node + PREFIX + 'unreviewed_additional_control: test\n', ''):
            with self.subTest(value=value[-100:]):
                result, selected = self.run_workspace(node=value)
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


    def test_pq_registry_missing_duplicate_and_empty_required_entries_refused(self):
        required = self.required['tests']
        for registry in (required[:-1], required + [required[0]], []):
            with self.subTest(registry_count=len(registry)):
                result, output = self.run_pq(registry_names=registry)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)

    def test_pq_required_count_and_original_false_claims_are_exact(self):
        changes = [dict(self.required, expected_meaningful_controls=count)
                   for count in (52.0, True, None)]
        for key in ('whole_chain_quantum_security_qualified',
                    'original_business_budgets_changed'):
            for bad in (True, 0, None):
                changes.append(dict(self.required, **{key: bad}))
            missing = dict(self.required)
            del missing[key]
            changes.append(missing)
        for value in changes:
            with self.subTest(value=value):
                result, output = self.run_pq(value=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(output)

    def test_pq_roster_output_cannot_replace_an_existing_receipt(self):
        result, output = self.run_pq(existing_output='retained-original-receipt\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, 'retained-original-receipt\n')


if __name__ == '__main__':
    unittest.main()
