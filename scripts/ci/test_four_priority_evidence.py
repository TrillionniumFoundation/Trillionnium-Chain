#!/usr/bin/env python3
"""Mutation and Git-publication regressions for the source-bound package."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import check_four_priority_evidence as check


class FourPriorityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / check.PACKAGE
        shutil.copytree(check.ROOT / check.PACKAGE, self.folder)

    def change(self, name, mutate):
        path = self.folder / name
        record = check.load(path)
        mutate(record)
        path.write_text(json.dumps(record) + '\n')

    def rehash(self):
        for name in ('work-cost/paired/manifest.json', 'work-cost/manifest.json',
                     'work-cost/packet-manifest.json', 'manifest.json'):
            path = self.folder / name
            record = check.load(path)
            for member in record['files']:
                record['files'][member] = check.sha(path.parent / member)
            path.write_text(json.dumps(record) + '\n')

    def rejects(self):
        with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
            check.artifacts(self.folder)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.STDOUT)

    def stage(self):
        self.git('init', '-q')
        self.git('add', '-f', check.PACKAGE)

    def test_original_package(self):
        check.artifacts(self.folder)

    def test_missing_ignored_log(self):
        (self.folder / 'preview/benchmark.log').unlink()
        self.rejects()

    def test_extra_file(self):
        (self.folder / 'extra.json').write_text('{}')
        self.rejects()

    def test_changed_log(self):
        with (self.folder / 'preview/benchmark.log').open('a') as handle:
            handle.write('changed')
        self.rejects()

    def test_missing_declared_member_even_if_file_exists(self):
        self.change('manifest.json', lambda m: m['files'].pop('preview/benchmark.log'))
        self.rejects()

    def test_escape_manifest_path(self):
        self.change('manifest.json', lambda m: m['files'].update({'../outside': '0' * 64}))
        self.rejects()

    def test_symlink_even_with_same_bytes(self):
        path = self.folder / 'preview/benchmark.log'
        destination = self.root / 'outside.log'
        path.rename(destination)
        path.symlink_to(destination)
        self.rejects()

    def test_nested_hash_mutation(self):
        self.change('work-cost/paired/manifest.json', lambda m: m['files'].update({'build.log': '0' * 64}))
        # Rebind outer manifests only, so the nested checker must catch this.
        for name in ('work-cost/packet-manifest.json', 'manifest.json'):
            path = self.folder / name
            m = check.load(path)
            for member in m['files']:
                m['files'][member] = check.sha(path.parent / member)
            path.write_text(json.dumps(m))
        self.rejects()

    def test_source_relabel_with_recomputed_hashes(self):
        self.change('work-cost/paired/execution.json', lambda m: m.update(source_commit='0' * 40))
        self.rehash()
        self.rejects()

    def test_empty_native_source_map(self):
        self.change('work-cost/execution.json', lambda m: m.update(source_files_sha256={}))
        self.rehash()
        self.rejects()

    def test_empty_paired_source_map(self):
        self.change('work-cost/paired/execution.json', lambda m: m.update(source_files_sha256={}))
        self.rehash()
        self.rejects()

    def test_omitted_paired_source(self):
        self.change('work-cost/paired/execution.json', lambda m: m['source_files_sha256'].pop(check.PAIRED_POLICY))
        self.rehash()
        self.rejects()

    def test_empty_preview_source_map(self):
        self.change('preview/manifest.json', lambda m: m['source'].update(sha256={}))
        self.rehash()
        self.rejects()

    def test_omitted_preview_source(self):
        self.change('preview/manifest.json', lambda m: m['source']['sha256'].pop('rust-toolchain.toml'))
        self.rehash()
        self.rejects()

    def test_failed_paired_execution(self):
        self.change('work-cost/paired/execution.json', lambda m: m.update(returncode=1))
        self.rehash()
        self.rejects()

    def test_failed_paired_build(self):
        self.change('work-cost/paired/execution.json', lambda m: m.update(build_returncode=1))
        self.rehash()
        self.rejects()

    def test_unclean_paired_source(self):
        self.change('work-cost/paired/execution.json', lambda m: m.update(source_clean_after=False))
        self.rehash()
        self.rejects()

    def test_failed_preview_optional_returncode(self):
        self.change('preview/manifest.json', lambda m: m.update(returncode=1))
        self.rehash()
        self.rejects()

    def test_expected_exit_relabel(self):
        (self.folder / 'work-cost/diagnostic.exit').write_text('0\n')
        self.rehash()
        self.rejects()

    def test_acceptance_promotion(self):
        self.change('manifest.json', lambda m: m.update(production_activation=True))
        self.rejects()

    def test_nested_acceptance_with_recomputed_hashes(self):
        self.change('work-cost/paired/manifest.json', lambda m: m.update(independent_accepted=True))
        self.rehash()
        self.rejects()

    def test_integer_false_rejected(self):
        self.change('manifest.json', lambda m: m.update(work_hardness_accepted=0))
        self.rejects()

    def test_diagnostic_relabel_with_recomputed_hashes(self):
        self.change('work-cost/diagnostic.json', lambda m: m.update(local_observation_gate='pass'))
        self.rehash()
        self.rejects()

    def test_sample_removal_with_recomputed_hashes(self):
        self.change('work-cost/paired/prepared-cost.json', lambda m: m['samples'].pop())
        self.rehash()
        self.rejects()

    def test_invented_benchmark_median_with_recomputed_hashes(self):
        self.change('preview/manifest.json', lambda m: m['summary']['warm'].update(bound_median_ms=1))
        self.rehash()
        self.rejects()

    def test_duplicate_json_key(self):
        p = self.folder / 'manifest.json'
        p.write_text(p.read_text().replace('"schema":', '"schema":"duplicate", "schema":'))
        self.rejects()

    def test_staged_complete_package(self):
        self.stage()
        check.tracked_package(self.root, self.folder)

    def test_committed_clean_package(self):
        self.stage()
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
        check.tracked_package(self.root, self.folder)

    def test_ignored_log_exists_but_not_staged(self):
        self.git('init', '-q')
        (self.root / '.git/info/exclude').write_text('*.log\n')
        self.git('add', check.PACKAGE)
        # Filesystem-only validation succeeds; publication must still fail closed.
        check.artifacts(self.folder)
        with self.assertRaisesRegex(ValueError, 'Git index missing'):
            check.tracked_package(self.root, self.folder)

    def test_stale_staged_bytes(self):
        self.stage()
        with (self.folder / 'README.md').open('a') as handle:
            handle.write('unstaged change\n')
        with self.assertRaisesRegex(ValueError, 'Git index differs'):
            check.tracked_package(self.root, self.folder)


if __name__ == '__main__':
    unittest.main(verbosity=2)
