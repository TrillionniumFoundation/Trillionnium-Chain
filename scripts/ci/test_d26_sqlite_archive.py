"""Adversarial byte-view controls; tiny fixtures are not D26 native evidence."""
from __future__ import annotations

from collections import Counter
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_d26_sqlite_archive as archive
import check_historical_archive as history


CHECKER = Path(archive.__file__).resolve()


class FrozenD26Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-d26-byte-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root/archive.PACKAGE
        self.package.mkdir(parents=True)
        self.git('init','-q')
        self.git('config','user.name','D26 fixture')
        self.git('config','user.email','archive@example.invalid')
        rows,sqlites = [],[]
        originals = {}
        for number,name in enumerate(sorted(archive.SQLITE_PATHS)):
            # Deliberately not a valid SQLite database. The byte verifier must
            # never open a database, recover it, or infer SQL acceptance.
            raw = ('opaque-original-database-'+str(number)).encode()*7
            prepared = gzip.compress(raw,mtime=0)
            lane = name.split('/')[1]
            member = name.split('/',2)[2][:-3]
            row = {'path':name,'bytes':len(prepared),'sha256':archive.digest(prepared),
                   'original_bytes':len(raw),'original_sha256':archive.digest(raw),
                   'encoding':'gzip-mtime-0-no-filename',
                   'origin':{'original_ci_database':True,'artifact_id':1000+number,
                             'archive_member':member}}
            rows.append(row)
            sqlites.append({'lane':lane,'artifact_id':1000+number,'archive_member':member,
                            'portable_path':name,'raw_bytes':len(raw),'raw_sha256':archive.digest(raw),
                            'compressed_bytes':len(prepared),'compressed_sha256':archive.digest(prepared)})
            originals[name] = prepared
        for name,raw,encoding in [('logs/original-failure.log',b'FAIL\n','raw'),
                                  ('logs/unknown.stderr.log.gz',b'UNKNOWN\n'*9,'gzip-mtime-0')]:
            prepared = raw if encoding == 'raw' else gzip.compress(raw,mtime=0)
            rows.append({'path':name,'bytes':len(prepared),'sha256':archive.digest(prepared),
                         'original_bytes':len(raw),'original_sha256':archive.digest(raw),'encoding':encoding})
            originals[name] = prepared
        originals['GATE_CORE.json'] = json.dumps({'schema':'trnm-d26-final-gate-core-v2',
            'status':'HOLD','native_gate_validated':False}).encode()
        originals['README.md'] = b'HOLD. All failures and UNKNOWN observations remain.\n'
        controls = [{'path':name,'bytes':len(originals[name]),'sha256':archive.digest(originals[name])}
                    for name in ('GATE_CORE.json','README.md')]
        plan = {'schema':'trnm-d26-light-evidence-copy-plan-v2','status':'HOLD',
                'native_gate_validated':False,'later_files_will_not_be_added':True,
                'all_encoded_original_bytes_read_back':True,'files':rows,'control_files':controls,
                'payload_file_count':len(rows),'payload_prepared_bytes':sum(r['bytes'] for r in rows),
                'payload_original_bytes':sum(r['original_bytes'] for r in rows),'sqlite':sqlites}
        originals['COPY_PLAN.json'] = json.dumps(plan,sort_keys=True).encode()
        for name,raw in originals.items():
            path = self.package/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
        self.git('add','.')
        self.git('commit','--no-gpg-sign','-qm','Original byte fixture')
        commit = self.git('rev-parse','HEAD').decode().strip()
        tree_id = self.git('rev-parse','HEAD^{tree}').decode().strip()
        tree = history.tree_rows(self.root,commit,[archive.PACKAGE])
        pins = {name:dict(bytes=len(originals[name]),sha256=archive.digest(originals[name]),
                         blob=tree[archive.PACKAGE+'/'+name]['blob']) for name in archive.CONTROL_PINS}
        all_rows = [dict(row,sha256=archive.digest(originals[name[len(archive.PACKAGE)+1:]]))
                    for name,row in sorted(tree.items())]
        selected = {archive.PACKAGE+'/'+name for name in archive.SQLITE_PATHS}
        self.data = {'schema':'trnm-historical-source-archive-v1','source_commit':commit,
            'source_tree':tree_id,'scopes':sorted(name.rsplit('/',1)[0] for name in selected),
            'files':[row for row in all_rows if row['path'] in selected],
            'file_count':8,'total_bytes':sum(row['bytes'] for row in all_rows if row['path'] in selected),
            'historical_manifests':[row for row in all_rows if row['path'].rsplit('/',1)[1] in pins
                                    and row['path'].rsplit('/',1)[0] == archive.PACKAGE],
            'retained_copies':[],'preserved_files':[row for row in all_rows if row['path'] not in selected],
            'qualification_changed':False,'production_activation':False}
        self.index = self.root/archive.INDEX_PATH
        self.index.write_text(json.dumps(self.data))
        for name in selected:
            (self.root/name).unlink()
        self.git('add','-A')
        direct = [row for row in rows if row['encoding'] == 'raw']
        encoded = [row for row in rows if row['encoding'] != 'raw']
        patcher = patch.multiple(archive,COMMIT=commit,TREE=tree_id,
            ORIGINAL_FILES=len(tree),ORIGINAL_BYTES=sum(row['bytes'] for row in tree.values()),
            PAYLOAD_FILES=len(rows),PREPARED_BYTES=plan['payload_prepared_bytes'],
            ORIGINAL_PAYLOAD_BYTES=plan['payload_original_bytes'],RAW_FILES=len(direct),
            RAW_BYTES=sum(row['bytes'] for row in direct),GZIP_FILES=len(encoded),
            GZIP_PREPARED_BYTES=sum(row['bytes'] for row in encoded),
            GZIP_RAW_BYTES=sum(row['original_bytes'] for row in encoded),
            ARCHIVED_BYTES=self.data['total_bytes'],SQLITE_RAW_BYTES=sum(row['raw_bytes'] for row in sqlites),
            ENCODINGS=dict(Counter(row['encoding'] for row in rows)),CONTROL_PINS=pins)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.originals,self.plan,self.tree,self.selected = originals,plan,tree,selected

    def git(self,*args,data=None):
        return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-c','core.autocrlf=false',
                                        *args],cwd=self.root,input=data,stderr=subprocess.PIPE)

    def save(self,data):
        self.index.write_text(json.dumps(data))

    def check(self):
        return archive.validate(self.root,self.index)

    def snapshot(self):
        return {path.relative_to(self.root).as_posix():archive.digest(path.read_bytes())
                for path in self.package.rglob('*') if path.is_file() and not path.is_symlink()}

    def test_complete_original_view_checks_all_encodings_without_opening_databases(self):
        before = self.snapshot()
        report = self.check()
        self.assertEqual(report['result'],'PASS')
        self.assertEqual(report['payload_files_verified'],10)
        self.assertEqual(report['gzip_files_decoded'],9)
        self.assertEqual(report['original_package_files'],13)
        self.assertEqual(report['current_files_verified'],5)
        self.assertEqual(report['controls_verified'],2)
        for key in ('sqlite_opened','database_recovery_performed','historical_scripts_executed',
                    'current_work_or_service_qualification','production_activation','whole_chain_native'):
            self.assertIs(report[key],False,key)
        self.assertEqual(report['current_native_tests_executed'],0)
        self.assertEqual(report['evidence_files_written'],0)
        self.assertEqual(self.snapshot(),before)

    def test_original_preflight_and_archived_readback_have_identical_observations(self):
        archived = self.check()
        for name in self.selected:
            (self.root/name).write_bytes(self.originals[name[len(archive.PACKAGE)+1:]])
        self.git('add','-A')
        original = archive.validate(self.root,original_view=True)
        self.assertEqual(original['payload_observation_sha256'],archived['payload_observation_sha256'])
        self.assertEqual(original['current_files_verified'],13)
        self.assertEqual(original['original_native_gate_validated'],False)

    def test_missing_or_corrupt_original_blob_is_refused_without_mutating_retained_files(self):
        row = self.data['files'][0]
        path = self.root/'.git/objects'/row['blob'][:2]/row['blob'][2:]
        before = self.snapshot()
        path.unlink()
        with self.assertRaises((history.Invalid,ValueError)):
            self.check()
        self.assertEqual(self.snapshot(),before)

    def test_omitted_duplicate_or_reordered_archived_row_is_refused(self):
        for change in (lambda d:d['files'].pop(),
                       lambda d:d['files'].append(d['files'][0]),
                       lambda d:d['files'].reverse()):
            data = copy.deepcopy(self.data)
            change(data)
            self.save(data)
            with self.assertRaises(history.Invalid):self.check()

    def test_wrong_snapshot_scope_denominator_or_fake_index_path_is_refused(self):
        for key,value in [('source_commit','0'*40),('source_tree','0'*40),
                          ('scopes',[archive.PACKAGE+'/history']),('total_bytes',0),('file_count',True)]:
            data = copy.deepcopy(self.data)
            data[key] = value
            self.save(data)
            with self.subTest(key=key),self.assertRaises(history.Invalid):self.check()
        self.save(self.data)
        fake = self.root/'fake-index.json'
        fake.write_bytes(self.index.read_bytes())
        with self.assertRaises(history.Invalid):archive.validate(self.root,fake)

    def test_all_retained_roster_members_are_required_and_failures_cannot_be_resigned(self):
        data = copy.deepcopy(self.data)
        data['preserved_files'].pop()
        self.save(data)
        with self.assertRaises(history.Invalid):self.check()
        failure = self.package/'logs/original-failure.log'
        failure.write_bytes(b'PASS\n')
        data = copy.deepcopy(self.data)
        row = next(row for row in data['preserved_files'] if row['path'].endswith('/original-failure.log'))
        row['sha256'] = archive.digest(failure.read_bytes())
        self.save(data)
        with self.assertRaises(history.Invalid):self.check()

    def test_current_log_and_archive_index_must_be_tracked_with_exact_staged_bytes(self):
        paths = [archive.PACKAGE+'/logs/original-failure.log',archive.INDEX_PATH]
        for name in paths:
            self.git('rm','--cached','-q',name)
            with self.subTest(path=name),self.assertRaises(history.Invalid):self.check()
            self.git('add',name)
        name = paths[0]
        wrong = self.git('hash-object','-w','--stdin',data=b'other staged data').decode().strip()
        self.git('update-index','--cacheinfo','100644,'+wrong+','+name)
        with self.assertRaises(history.Invalid):self.check()

    def test_intent_to_add_index_is_not_counted_as_a_publishable_index(self):
        self.git('rm','--cached','-q',archive.INDEX_PATH)
        self.git('add','-N',archive.INDEX_PATH)
        with self.assertRaises(history.Invalid):self.check()

    def test_extra_restored_missing_symlinked_and_special_retained_paths_are_refused(self):
        for path in [self.package/'extra',self.root/next(iter(self.selected))]:
            path.write_bytes(b'extra')
            with self.assertRaises(history.Invalid):self.check()
            path.unlink()
        path = self.package/'logs/original-failure.log'
        path.unlink()
        with self.assertRaises(history.Invalid):self.check()
        path.symlink_to(self.package/'GATE_CORE.json')
        with self.assertRaises(history.Invalid):self.check()
        path.unlink()
        os.mkfifo(path,0o600)
        with self.assertRaises(history.Invalid):self.check()

    def test_qualification_promotion_duplicate_keys_and_nonfinite_metadata_are_refused(self):
        for key in ('qualification_changed','production_activation'):
            data = copy.deepcopy(self.data)
            data[key] = True
            self.save(data)
            with self.assertRaises(history.Invalid):self.check()
        self.index.write_text(json.dumps(self.data)[:-1]+',"schema":"shadow"}')
        with self.assertRaises(history.Invalid):self.check()
        self.index.write_text(json.dumps(self.data)[:-1]+',"injected":NaN}')
        with self.assertRaises(history.Invalid):self.check()
        self.save(self.data)
        core = self.package/'GATE_CORE.json'
        core.write_bytes(core.read_bytes().replace(b'false',b'true'))
        with self.assertRaises(history.Invalid):self.check()

    def test_sqlite_table_must_match_all_payload_raw_and_compressed_identities(self):
        for key,value in [('compressed_sha256','0'*64),('raw_sha256','0'*64),
                          ('artifact_id',999999),('archive_member','elsewhere.sqlite')]:
            plan = copy.deepcopy(self.plan)
            plan['sqlite'][0][key] = value
            with self.subTest(key=key),self.assertRaises(history.Invalid):
                archive.sqlite_rows(plan,{row['path']:row for row in plan['files']})

    def test_real_cli_missing_or_dangling_index_refuses_without_writing_evidence(self):
        before = self.snapshot()
        for variant in ('missing','dangling'):
            self.index.unlink()
            if variant == 'dangling':self.index.symlink_to(self.root/'absent')
            result = subprocess.run([sys.executable,'-B',str(CHECKER),'--root',str(self.root),
                                     '--manifest',str(self.index)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertEqual(result.stdout,'')
            self.assertIn('D26 archive check failed:',result.stderr)
            self.assertEqual(self.snapshot(),before)
            if self.index.is_symlink():self.index.unlink()
            self.save(self.data)


class GzipOriginalByteControls(unittest.TestCase):
    def verify(self,prepared,raw,*,encoding='gzip-mtime-0-no-filename',raw_size=None,raw_sha=None):
        row = {'path':'test.gz','bytes':len(prepared),'sha256':archive.digest(prepared),
               'original_bytes':len(raw) if raw_size is None else raw_size,
               'original_sha256':archive.digest(raw) if raw_sha is None else raw_sha,
               'encoding':encoding}
        original = {'path':'test.gz','bytes':len(prepared),'blob':archive.blob_digest(prepared)}
        return archive.verify_payload(io.BytesIO(prepared),row,original)

    def test_valid_gzip_stream_is_fully_read_and_original_sha_is_required(self):
        raw = bytes(range(256))*8193
        result = self.verify(gzip.compress(raw,mtime=0),raw)
        self.assertEqual(result['original_bytes'],len(raw))
        self.assertEqual(result['original_sha256'],hashlib.sha256(raw).hexdigest())
        for size,sha in [(len(raw)-1,archive.digest(raw)),(len(raw),'0'*64),(len(raw)+1,archive.digest(raw))]:
            with self.assertRaises(history.Invalid):
                self.verify(gzip.compress(raw,mtime=0),raw,raw_size=size,raw_sha=sha)

    def test_bad_crc_truncated_gzip_and_extra_invalid_stream_are_refused_after_prepared_pin_matches(self):
        raw = b'original binary\0\xff'*100
        compressed = gzip.compress(raw,mtime=0)
        changed = bytearray(compressed)
        changed[-8] ^= 1
        for bad in [bytes(changed),compressed[:-3],compressed+b'not-another-gzip']:
            with self.assertRaises((history.Invalid,OSError,EOFError)):
                self.verify(bad,raw)

    def test_declared_deterministic_header_and_no_filename_are_enforced(self):
        raw = b'original'
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream,mode='wb',filename='original.log',mtime=0) as output:
            output.write(raw)
        bad_flags = bytearray(gzip.compress(raw,mtime=0))
        bad_flags[3] |= 0x20
        for prepared in [gzip.compress(raw,mtime=1),stream.getvalue(),bytes(bad_flags)]:
            with self.assertRaises(history.Invalid):self.verify(prepared,raw)
        self.assertEqual(self.verify(stream.getvalue(),raw,encoding='gzip-mtime-0')['original_sha256'],
                         archive.digest(raw))


if __name__ == '__main__':
    unittest.main()
