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
    def test_new_cost_package_retains_exact_original_source(self):
        p=self.root/'evidence/pon-contract-authority-v1';p.mkdir()
        (p/'manifest.json').write_text(json.dumps(dict(implementation_commit='7'*40,implementation_tree='8'*40)))
        self.trees['7'*40]='8'*40
        calls=[]
        def run(args,**kw):
            calls.append(args)
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1,'','missing')
            if args[1]=='rev-parse':return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertIn('7'*40,result['fetched'])
        self.assertIn(['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,'7'*40],calls)
        self.assertFalse(result['branch_refs_changed'])
    def test_new_cost_package_rejects_branch_as_measurement(self):
        p=self.root/'evidence/pon-contract-authority-v1';p.mkdir()
        (p/'manifest.json').write_text(json.dumps(dict(implementation_commit='main',implementation_tree='8'*40)))
        def run(*a,**kw):raise AssertionError('must validate before any Git command')
        with self.assertRaises(ValueError):prepare(self.root,run)
    def test_new_cost_package_cannot_rebind_existing_source_tree(self):
        p=self.root/'evidence/pon-contract-authority-v1';p.mkdir()
        (p/'manifest.json').write_text(json.dumps(dict(implementation_commit='1'*40,implementation_tree='8'*40)))
        def run(*a,**kw):raise AssertionError('conflicting source must reject before commands')
        with self.assertRaises(ValueError):prepare(self.root,run)
    def test_client_receipt_retains_exact_source_after_squash(self):
        p=self.root/'evidence/pon-client-confirmation-v1';p.mkdir()
        (p/'manifest.json').write_text(json.dumps(dict(implementation_commit='9'*40,implementation_tree='a'*40)))
        self.trees['9'*40]='a'*40
        calls=[]
        def run(args,**kw):
            calls.append(args)
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1,'','missing')
            if args[1]=='rev-parse':return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertIn(['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,'9'*40],calls)
        self.assertFalse(result['branch_refs_changed'])
        self.assertFalse(result['acceptance_granted'])
    def test_client_receipt_cannot_rebind_source_or_fetch_a_branch(self):
        p=self.root/'evidence/pon-client-confirmation-v1';p.mkdir()
        for commit,tree in [('main','a'*40),('1'*40,'a'*40)]:
            with self.subTest(commit=commit):
                (p/'manifest.json').write_text(json.dumps(dict(implementation_commit=commit,implementation_tree=tree)))
                def run(*args,**kwargs):raise AssertionError('must reject before commands')
                with self.assertRaises(ValueError):prepare(self.root,run)

    def test_nested_cost_collection_has_its_own_exact_source(self):
        p = self.root/'evidence/pon-native-session-v1/work-cost'
        p.mkdir(parents=True)
        (p/'execution.json').write_text(json.dumps(dict(schema='pon-native-cost-execution-v1',
            source_commit='b'*40, source_tree='c'*40)))
        self.trees['b'*40] = 'c'*40
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[1] == 'cat-file': return subprocess.CompletedProcess(args, 1, '', 'missing')
            if args[1] == 'rev-parse': return subprocess.CompletedProcess(args, 0, self.trees[args[2].split('^')[0]], '')
            return subprocess.CompletedProcess(args, 0, '', '')
        result = prepare(self.root, run)
        self.assertIn(['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,'b'*40], calls)
        self.assertEqual(result['verified_object_trees']['b'*40], 'c'*40)
        self.assertFalse(result['acceptance_granted'])

    def test_cost_collection_cannot_fetch_branch_or_conflicting_tree(self):
        p = self.root/'evidence/pon-native-session-v1/work-cost'
        p.mkdir(parents=True)
        for commit, tree in [('main','c'*40), ('1'*40,'c'*40)]:
            with self.subTest(commit=commit):
                (p/'execution.json').write_text(json.dumps(dict(schema='pon-native-cost-execution-v1',
                    source_commit=commit, source_tree=tree)))
                def run(*args, **kwargs): raise AssertionError('reject before commands')
                with self.assertRaises(ValueError): prepare(self.root, run)

    def write_input_source(self, commit='7'*40, tree='8'*40, package='pon-evaluation-bundle-v1'):
        path=self.root/'evidence'/package/'qualification.json'
        path.write_text(json.dumps(dict(input_source_commit=commit,input_source_tree=tree)))
        return path

    def test_corpus_fetch_uses_only_declared_exact_object_and_tree(self):
        self.write_input_source();self.trees['7'*40]='8'*40;calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[1]=='cat-file':
                return subprocess.CompletedProcess(args,1 if args[3].startswith('7'*40) else 0,'','')
            if args[1]=='rev-parse':
                return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertEqual(result['fetched'],['7'*40])
        self.assertEqual(result['verified_object_trees']['7'*40],'8'*40)
        self.assertEqual([args for args in calls if args[1]=='fetch'],
            [['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,'7'*40]])
        self.assertFalse(result['branch_refs_changed']);self.assertFalse(result['acceptance_granted'])

    def test_existing_corpus_is_checked_without_fetch(self):
        self.write_input_source();self.trees['7'*40]='8'*40;calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,
                self.trees[args[2].split('^')[0]] if args[1]=='rev-parse' else '','')
        result=prepare(self.root,run)
        self.assertEqual(result['fetched'],[])
        self.assertIn(['git','rev-parse','7'*40+'^{tree}'],calls)
        self.assertFalse(any(args[1]=='fetch' for args in calls))

    def test_corpus_commit_and_tree_each_require_strict_lowercase_sha(self):
        def run(*args,**kwargs):raise AssertionError('must reject before any Git command')
        for field in ['input_source_commit','input_source_tree']:
            for value in ['main','--all','7'*39,'A'*40,'7'*40+'; echo BAD',None,7]:
                with self.subTest(field=field,value=value):
                    path=self.write_input_source();data=json.loads(path.read_text())
                    data[field]=value;path.write_text(json.dumps(data))
                    with self.assertRaisesRegex(ValueError,'invalid measured Git identity'):
                        prepare(self.root,run)

    def test_corpus_requires_complete_pair_before_any_command(self):
        def run(*args,**kwargs):raise AssertionError('must reject before any Git command')
        for missing in ['input_source_commit','input_source_tree']:
            with self.subTest(missing=missing):
                path=self.write_input_source();data=json.loads(path.read_text())
                del data[missing];path.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'incomplete input source pair'):
                    prepare(self.root,run)

    def test_corpus_cannot_rebind_implementation_or_another_corpus(self):
        def run(*args,**kwargs):raise AssertionError('must reject before any Git command')
        self.write_input_source(commit='1'*40,tree='8'*40)
        with self.assertRaisesRegex(ValueError,'conflicting source tree'):prepare(self.root,run)
        self.write_input_source(commit='7'*40,tree='8'*40)
        self.write_input_source(commit='7'*40,tree='9'*40,package='pon-v4')
        with self.assertRaisesRegex(ValueError,'conflicting source tree'):prepare(self.root,run)

    def test_corpus_matching_implementation_pair_deduplicates(self):
        self.write_input_source(commit='1'*40,tree='2'*40);calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1,'','missing')
            if args[1]=='rev-parse':
                return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertEqual(len(result['verified_object_trees']),4)
        self.assertEqual(result['fetched'].count('1'*40),1)

    def test_corpus_fetch_does_not_accept_mismatched_tree(self):
        self.write_input_source()
        def run(args,**kwargs):
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1,'','missing')
            if args[1]=='rev-parse':
                commit=args[2].split('^')[0]
                return subprocess.CompletedProcess(args,0,'9'*40 if commit=='7'*40 else self.trees[commit],'')
            return subprocess.CompletedProcess(args,0,'','')
        with self.assertRaisesRegex(ValueError,'measured tree unavailable or mismatched: '+'7'*40):
            prepare(self.root,run)

    def test_no_pair_or_nested_failure_does_not_invent_source(self):
        (self.root/'evidence/pon-evaluation-bundle-v1/qualification.json').write_text(
            json.dumps(dict(note='qualification with no corpus pair')))
        for path in [self.root/'evidence/pon-evaluation-bundle-v1/failures/run/qualification.json',
                     self.root/'evidence/unlisted-package/qualification.json']:
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(dict(input_source_commit='main',input_source_tree='8'*40)))
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,
                self.trees[args[2].split('^')[0]] if args[1]=='rev-parse' else '','')
        result=prepare(self.root,run)
        self.assertEqual(result['verified_object_trees'],self.trees)
        self.assertFalse(any(args[1]=='fetch' for args in calls))

if __name__=='__main__':unittest.main(verbosity=2)
