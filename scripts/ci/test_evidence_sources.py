#!/usr/bin/env python3
import json,subprocess,tempfile,unittest
from pathlib import Path
from prepare_evidence_sources import identity,prepare,REMOTE

class EvidenceSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for version,commit,tree in [('pon-v3','1'*40,'2'*40),('pon-v4','3'*40,'4'*40),('pon-evaluation-bundle-v1','5'*40,'6'*40)]:
            p=self.root/'evidence'/version;p.mkdir(parents=True)
            (p/'manifest.json').write_text(json.dumps(dict(implementation_commit=commit,implementation_tree=tree)))
        self.trees={'5d59b9540268914794a62e8fa237caf999499314':'30ee65c0752693f4eecc90f924972279f00c0c73','1'*40:'2'*40,'3'*40:'4'*40,'5'*40:'6'*40}
    def tearDown(self):self.tmp.cleanup()
    def test_non_sha_cannot_be_a_fetch_argument(self):
        for value in ['main','--all','1'*39,'A'*40,'1'*40+'; echo BAD',None]:
            with self.subTest(value=value),self.assertRaises(ValueError):identity(value)
    def test_existing_objects_do_not_fetch(self):
        commands=[]
        def run(args,**kw):
            commands.append(args)
            return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]] if args[1]=='rev-parse'else '', '')
        result=prepare(self.root,run)
        self.assertEqual(result['fetched'],[]);self.assertFalse(result['acceptance_granted'])
        self.assertFalse(any(x[1]=='fetch'for x in commands))
    def test_missing_sources_fetch_only_exact_repo_and_commit(self):
        calls=[]
        def run(args,**kw):
            calls.append((args,kw))
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1,'','missing')
            if args[1]=='rev-parse':return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertEqual(len(result['fetched']),4)
        for args,kw in calls:
            if args[1]=='fetch':
                self.assertEqual(args[2:5],['--no-tags','--no-write-fetch-head',REMOTE]);identity(args[5]);self.assertEqual(kw['timeout'],90)
    def test_tree_mismatch_is_not_evidence(self):
        def run(args,**kw):return subprocess.CompletedProcess(args,0,'0'*40,'')
        with self.assertRaisesRegex(ValueError,'mismatch'):prepare(self.root,run)
    def test_failed_fetch_does_not_succeed(self):
        def run(args,**kw):return subprocess.CompletedProcess(args,1,'','unavailable')
        with self.assertRaisesRegex(ValueError,'fetch failed'):prepare(self.root,run)
    def test_invalid_declared_identity_rejects_before_any_command(self):
        p=self.root/'evidence/pon-v4/manifest.json';d=json.loads(p.read_text());d['implementation_commit']='refs/heads/main';p.write_text(json.dumps(d))
        def run(*args,**kw):raise AssertionError('must not execute')
        with self.assertRaises(ValueError):prepare(self.root,run)
if __name__=='__main__':unittest.main(verbosity=2)
