#!/usr/bin/env python3
"""Finite local component controls; no actual C4, merge, project or native run."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('corpus_union', HERE / 'prepare_union_corpus.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
BASE_RAW = (HERE / 'fixtures/base-corpus.json').read_bytes()
THEIRS_RAW = (HERE / 'fixtures/theirs-corpus.json').read_bytes()


def entry(blob, size=0):
    return {'mode': '100644', 'type': 'blob', 'blob': blob, 'bytes': size}


def fixture():
    base, theirs = map(json.loads, (BASE_RAW, THEIRS_RAW))
    ours = copy.deepcopy(base)
    for path in u.NEW_REQUIRED:
        ours['required_paths'].append(path)
        ours['pinned_blobs'][path] = u.object_id('blob', ('component-only:' + path).encode())
    tables = tuple({path: entry(blob) for path, blob in x['pinned_blobs'].items()} for x in (base, ours, theirs))
    return ours, tables


class CorpusUnionControls(unittest.TestCase):
    def test_exact_old_catalogues_and_24_additions_keep_all_fields(self):
        ours, tables = fixture()
        original, own, theirs, changes, upstream_changes = u.validate_corpora(
            BASE_RAW, u.encoded(ours), THEIRS_RAW, *tables)
        self.assertEqual((len(own['required_paths']), len(own['pinned_blobs']), len(upstream_changes)), (1011, 1103, 10))
        self.assertEqual(changes, [])
        self.assertEqual({k: v for k, v in original.items() if k != 'pinned_blobs'},
                         {k: v for k, v in theirs.items() if k != 'pinned_blobs'})
        self.assertEqual(own['required_paths'][:987], original['required_paths'])

    def test_double_deletion_and_reordered_or_unknown_addition_refuse(self):
        ours, tables = fixture()
        cases = []
        lost = copy.deepcopy(ours)
        path = lost['required_paths'].pop(0)
        del lost['pinned_blobs'][path]
        cases.append(lost)
        reordered = copy.deepcopy(ours)
        reordered['required_paths'][-2:] = reordered['required_paths'][-2:][::-1]
        cases.append(reordered)
        extra = copy.deepcopy(ours)
        extra['pinned_blobs']['unknown.py'] = '1' * 40
        extra['required_paths'].append('unknown.py')
        cases.append(extra)
        for value in cases:
            with self.subTest(kind=len(value['required_paths'])):
                with self.assertRaises(u.Refusal):
                    u.validate_corpora(BASE_RAW, u.encoded(value), THEIRS_RAW, *tables)

    def test_historical_fields_cannot_upgrade_or_change_json_type(self):
        ours, tables = fixture()
        for replacement in (True, 0, None):
            value = copy.deepcopy(ours)
            value['assertions']['production_activation'] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(u.Refusal, 'historical field'):
                    u.validate_corpora(BASE_RAW, u.encoded(value), THEIRS_RAW, *tables)
        value = dict(ours, unknown_status=False)
        with self.assertRaisesRegex(u.Refusal, 'historical field'):
            u.validate_corpora(BASE_RAW, u.encoded(value), THEIRS_RAW, *tables)

    def test_each_parent_pin_must_match_its_own_tree(self):
        ours, tables = fixture()
        for index in range(3):
            changed = copy.deepcopy(tables)
            path = next(iter(changed[index]))
            changed[index][path]['blob'] = '0' * 40
            with self.subTest(parent=index):
                with self.assertRaisesRegex(u.Refusal, 'actual Git tree'):
                    u.validate_corpora(BASE_RAW, u.encoded(ours), THEIRS_RAW, *changed)

    def test_upstream_is_exact_selected_ten_pin_delta(self):
        ours, tables = fixture()
        changed = json.loads(THEIRS_RAW)
        path = next(iter(u.THEIRS_PIN_DELTA))
        changed['pinned_blobs'][path] = u.THEIRS_PIN_DELTA[path][0]
        with self.assertRaisesRegex(u.Refusal, 'upstream corpus raw identity'):
            u.validate_corpora(BASE_RAW, u.encoded(ours), u.encoded(changed), *tables)
        self.assertEqual(len(u.THEIRS_PIN_DELTA), 10)

    def test_three_way_scope_rejects_unknown_edit_deletion_and_old_evidence(self):
        a, b, c = entry('a' * 40), entry('b' * 40), entry('c' * 40)
        base = {'source.py': a, 'evidence/old.log': a, u.CHECKER: entry(u.CHECKER_BLOB)}
        own = dict(base, **{'ours.py': b})
        theirs = dict(base, **{'source.py': c, 'evidence/new.log': c})
        final = dict(own, **{'source.py': c, 'evidence/new.log': c})
        self.assertEqual(u.merged_scope(base, own, theirs, final), [])
        variants = []
        bad = copy.deepcopy(final); bad['source.py'] = b; variants.append(bad)
        bad = copy.deepcopy(final); del bad['ours.py']; variants.append(bad)
        bad = copy.deepcopy(final); bad['unknown.py'] = a; variants.append(bad)
        bad = copy.deepcopy(final); bad['evidence/old.log'] = c; variants.append(bad)
        for index, bad in enumerate(variants):
            with self.subTest(variant=index):
                with self.assertRaises(u.Refusal):
                    u.merged_scope(base, own, theirs, bad)

    def test_both_plan_appends_are_preserved_once_without_rewriting(self):
        base = b'original plan\n'
        ours, theirs = base + b'\nC3 original failure facts\n', base + b'\nupstream exact claims\n'
        first = base + ours[len(base):] + theirs[len(base):]
        second = base + theirs[len(base):] + ours[len(base):]
        self.assertEqual(u.plan_union(base, ours, theirs, first)['order'], 'ours-then-theirs')
        self.assertEqual(u.plan_union(base, ours, theirs, second)['order'], 'theirs-then-ours')
        for bad in (ours, theirs, first + ours[len(base):], first.replace(b'failure', b'success')):
            with self.assertRaises(u.Refusal):
                u.plan_union(base, ours, theirs, bad)

    def test_pin_refresh_uses_actual_final_roster_and_only_pin_values(self):
        ours, (_, own, _) = fixture()
        path = ours['required_paths'][0]
        final = copy.deepcopy(own)
        final[path]['blob'] = 'f' * 40
        updated, changes = u.refresh_corpus(ours, final)
        self.assertEqual(changes, [{'path': path, 'before': ours['pinned_blobs'][path], 'after': 'f' * 40}])
        self.assertEqual({k: v for k, v in ours.items() if k != 'pinned_blobs'},
                         {k: v for k, v in updated.items() if k != 'pinned_blobs'})
        del final[path]
        with self.assertRaises(u.Refusal):
            u.refresh_corpus(ours, final)

    def test_real_fifo_and_ancestor_symlink_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory(prefix='pon-corpus-fd-') as temporary:
            root = Path(temporary)
            pipe = root / 'fifo'
            os.mkfifo(pipe)
            started = time.monotonic()
            with self.assertRaisesRegex(u.Refusal, 'nonregular'):
                u.read_regular(pipe)
            self.assertLess(time.monotonic() - started, 1.0)
            regular = root / 'data'; regular.write_bytes(b'component')
            link = root / 'link'; link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                u.read_regular(link / 'data')
            self.assertEqual(u.read_regular(regular), b'component')
            with self.assertRaises(FileExistsError):
                u.write_new(regular, b'overwrite')

    def test_real_git_blob_and_hidden_index_guard_are_observed(self):
        with tempfile.TemporaryDirectory(prefix='pon-corpus-git-') as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            source = root / 'source.py'; source.write_bytes(b'component-only\n')
            subprocess.run(['git', '-C', str(root), 'add', '--', 'source.py'], check=True)
            tree_id = u.gtext(root, 'write-tree')
            rows = u.tree(root, tree_id)
            self.assertEqual(u.actual_blob(root, 'source.py', rows['source.py'])['sha256'], u.sha(source.read_bytes()))
            u.root_guard(root)
            source.write_bytes(b'mutated source\n')
            with self.assertRaises(u.Refusal):
                u.actual_blob(root, 'source.py', rows['source.py'])
            source.write_bytes(b'component-only\n')
            subprocess.run(['git', '-C', str(root), 'update-index', '--assume-unchanged', 'source.py'], check=True)
            with self.assertRaisesRegex(u.Refusal, 'hidden index'):
                u.root_guard(root)


if __name__ == '__main__':
    unittest.main()
