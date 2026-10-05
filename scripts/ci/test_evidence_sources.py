#!/usr/bin/env python3
import json,subprocess,tempfile,unittest
from pathlib import Path
from prepare_evidence_sources import identity,declarations,prepare,REMOTE

AUDIT_PACKAGE='pon-four-priority-audit-v1'
AUDIT_COMMIT='3c63c8368187de895e1dc0df8bbc105c6f39f842'
AUDIT_TREE='54d2f12c0d783f827d43bc626489f58ab75d7c31'

def audit_records(commit,tree):
    return (dict(schema='pon-four-priority-audit-local-observations-v1',
                 measured_source_commit=commit,measured_source_tree=tree),
            dict(schema='pon-native-cost-execution-v1',source_commit=commit,source_tree=tree))

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

    def write_audit(self,commit=AUDIT_COMMIT,tree=AUDIT_TREE):
        path=self.root/'evidence'/AUDIT_PACKAGE
        (path/'work-cost').mkdir(parents=True,exist_ok=True)
        files=(path/'manifest.json',path/'work-cost/execution.json')
        for file,data in zip(files,audit_records(commit,tree)):
            file.write_text(json.dumps(data))
        return files

    def test_four_priority_audit_fetches_only_its_exact_historical_object_once(self):
        self.write_audit();self.trees[AUDIT_COMMIT]=AUDIT_TREE;calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[1]=='cat-file':
                return subprocess.CompletedProcess(args,1 if args[3]==AUDIT_COMMIT+'^{commit}' else 0,'','')
            if args[1]=='rev-parse':return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertEqual(result['verified_object_trees'],self.trees)
        self.assertEqual(result['fetched'],[AUDIT_COMMIT])
        self.assertEqual([args for args in calls if args[1]=='fetch'],
            [['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,AUDIT_COMMIT]])
        self.assertFalse(result['branch_refs_changed']);self.assertFalse(result['acceptance_granted'])

    def test_four_priority_audit_fixed_declarations_keep_optional_file_semantics(self):
        for missing in (0,1):
            with self.subTest(missing=missing):
                files=self.write_audit();files[missing].unlink()
                self.assertEqual(declarations(self.root),{**self.trees,AUDIT_COMMIT:AUDIT_TREE})

    def test_four_priority_audit_rejects_invalid_or_partial_pairs_before_commands(self):
        def run(*args,**kwargs):raise AssertionError('must validate all declarations before Git commands')
        fields=((0,'measured_source_commit'),(0,'measured_source_tree'),(1,'source_commit'),(1,'source_tree'))
        for index,field in fields:
            for value in ('main','refs/heads/main','--all','a'*39,'A'*40,None,7):
                with self.subTest(field=field,value=value):
                    files=self.write_audit();data=json.loads(files[index].read_text());data[field]=value
                    # Old implementation fields cannot rescue a bad historical identity.
                    data.update(implementation_commit=AUDIT_COMMIT,implementation_tree=AUDIT_TREE)
                    files[index].write_text(json.dumps(data))
                    with self.assertRaisesRegex(ValueError,'invalid measured Git identity'):prepare(self.root,run)
            with self.subTest(missing=field):
                files=self.write_audit();data=json.loads(files[index].read_text());del data[field]
                files[index].write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'incomplete .*source pair'):prepare(self.root,run)

    def test_four_priority_audit_rejects_wrong_schemas_and_conflicting_pairs(self):
        def run(*args,**kwargs):raise AssertionError('must reject before Git commands')
        for index in (0,1):
            for value in ([],dict(schema='other')):
                with self.subTest(index=index,value=value):
                    files=self.write_audit();files[index].write_text(json.dumps(value))
                    with self.assertRaisesRegex(ValueError,'invalid .*schema'):prepare(self.root,run)
        # Different valid commits are also a conflict, even when neither pair
        # collides with another package's commit-to-tree mapping.
        for commit,tree in [('b'*40,'c'*40),(AUDIT_COMMIT,'c'*40)]:
            with self.subTest(commit=commit,tree=tree):
                _,cost=self.write_audit()
                cost.write_text(json.dumps(audit_records(commit,tree)[1]))
                with self.assertRaisesRegex(ValueError,'conflicting historical cost source pair'):prepare(self.root,run)
        self.write_audit(commit='1'*40,tree='c'*40)
        with self.assertRaisesRegex(ValueError,'conflicting source tree'):prepare(self.root,run)

    def test_four_priority_audit_does_not_infer_sources_from_nested_or_unlisted_json(self):
        ignored=['evidence/unlisted-audit/manifest.json','evidence/unlisted-audit/work-cost/execution.json',
                 'evidence/'+AUDIT_PACKAGE+'/failures/run/manifest.json',
                 'evidence/'+AUDIT_PACKAGE+'/observations/run/work-cost/execution.json',
                 'evidence/'+AUDIT_PACKAGE+'/work-cost/paired/execution.json',
                 'evidence/'+AUDIT_PACKAGE+'/qualification.json']
        for relative in ignored:
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(dict(schema='pon-native-cost-execution-v1',source_commit='main',source_tree='TREE',
                measured_source_commit='--all',measured_source_tree='TREE',input_source_commit='main',input_source_tree='TREE')))
        self.assertEqual(declarations(self.root),self.trees)
        self.write_audit()
        self.assertEqual(declarations(self.root),{**self.trees,AUDIT_COMMIT:AUDIT_TREE})

    def test_existing_runtime_and_later_cost_sources_remain_separate(self):
        path=self.root/'evidence/pon-native-node-v1';(path/'work-cost').mkdir(parents=True)
        (path/'manifest.json').write_text(json.dumps(dict(implementation_commit='7'*40,implementation_tree='8'*40)))
        (path/'work-cost/execution.json').write_text(json.dumps(audit_records('b'*40,'c'*40)[1]))
        self.assertEqual(declarations(self.root),{**self.trees,'7'*40:'8'*40,'b'*40:'c'*40})

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

    def test_public_root_source_is_fetched_but_nested_observations_are_ignored(self):
        path=self.root/'evidence/pon-public-readiness-v1';path.mkdir()
        (path/'manifest.json').write_text(json.dumps(dict(implementation_commit='7'*40,implementation_tree='8'*40)))
        nested=path/'observations/pre-correction-b';nested.mkdir(parents=True)
        (nested/'manifest.json').write_text(json.dumps(dict(implementation_commit='main',implementation_tree='9'*40)))
        (nested/'qualification.json').write_text(json.dumps(dict(input_source_commit='--all',input_source_tree='9'*40)))
        self.trees['7'*40]='8'*40;calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[1]=='cat-file':return subprocess.CompletedProcess(args,1 if args[3].startswith('7'*40) else 0,'','')
            if args[1]=='rev-parse':return subprocess.CompletedProcess(args,0,self.trees[args[2].split('^')[0]],'')
            return subprocess.CompletedProcess(args,0,'','')
        result=prepare(self.root,run)
        self.assertEqual(result['fetched'],['7'*40])
        self.assertEqual([args for args in calls if args[1]=='fetch'],
            [['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,'7'*40]])
        self.assertEqual(result['verified_object_trees'],self.trees)

    def test_public_root_rejects_invalid_identity_or_conflicting_tree(self):
        path=self.root/'evidence/pon-public-readiness-v1';path.mkdir()
        for commit,tree in [('main','8'*40),('7'*40,'TREE'),('1'*40,'8'*40)]:
            with self.subTest(commit=commit,tree=tree):
                (path/'manifest.json').write_text(json.dumps(dict(implementation_commit=commit,implementation_tree=tree)))
                def run(*args,**kwargs):raise AssertionError('reject before Git fetch')
                with self.assertRaises(ValueError):prepare(self.root,run)


class MeasuredDeclarationSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.git('init','-q');self.git('config','user.email','fixture@example.invalid');self.git('config','user.name','Fixture')
        (self.root/'source.txt').write_text('retained implementation\n')
        self.git('add','.');self.git('commit','-qm','real retained implementation')
        self.implementation=self.git('rev-parse','HEAD');self.implementation_tree=self.git('rev-parse','HEAD^{tree}')
        for name in ['pon-v3','pon-v4','pon-evaluation-bundle-v1']:
            self.write('evidence/'+name+'/manifest.json',dict(implementation_commit=self.implementation,
                       implementation_tree=self.implementation_tree))
        self.snapshot=self.commit('measured fixed declarations')
        self.snapshot_tree=self.git('rev-parse',self.snapshot+'^{tree}')
        self.original=declarations(self.root,source=self.snapshot)

    def tearDown(self):self.tmp.cleanup()
    def git(self,*args):
        return subprocess.check_output(['git',*args],cwd=self.root,text=True).strip()
    def commit(self,message):
        self.git('add','.');self.git('commit','-qm',message);return self.git('rev-parse','HEAD')
    def write(self,relative,value):
        path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value));return path

    def test_real_measured_snapshot_is_exact_when_publication_adds_its_own_root(self):
        self.assertEqual(declarations(self.root),self.original)
        self.write('evidence/pon-public-readiness-v1/manifest.json',
                   dict(implementation_commit=self.snapshot,implementation_tree=self.snapshot_tree))
        self.commit('publish new root evidence after its measurement')
        current=declarations(self.root)
        self.assertEqual(current,{**self.original,self.snapshot:self.snapshot_tree})
        self.assertNotEqual(current,self.original)
        self.assertEqual(declarations(self.root,source=self.snapshot),self.original)

    def test_measured_corpus_and_cost_blobs_survive_current_rewrites_and_deletion(self):
        qualification=self.write('evidence/pon-evaluation-bundle-v1/qualification.json',
            dict(input_source_commit=self.snapshot,input_source_tree=self.snapshot_tree))
        cost=self.write('evidence/pon-native-node-v1/work-cost/execution.json',
            dict(schema='pon-native-cost-execution-v1',source_commit=self.snapshot,source_tree=self.snapshot_tree))
        measured=self.commit('retain independent corpus and cost source')
        expected={**self.original,self.snapshot:self.snapshot_tree}
        self.assertEqual(declarations(self.root,source=measured),expected)
        qualification.write_text(json.dumps(dict(input_source_commit='main',input_source_tree='TREE')));cost.unlink()
        with self.assertRaises(ValueError):declarations(self.root)
        self.assertEqual(declarations(self.root,source=measured),expected)

    def test_public_root_is_in_snapshot_but_nested_failure_declarations_never_are(self):
        self.write('evidence/pon-public-readiness-v1/manifest.json',
            dict(implementation_commit=self.snapshot,implementation_tree=self.snapshot_tree))
        prefix='evidence/pon-public-readiness-v1/observations/pre-correction-b/'
        self.write(prefix+'manifest.json',dict(implementation_commit='main',implementation_tree='TREE'))
        self.write(prefix+'qualification.json',dict(input_source_commit='--all',input_source_tree='TREE'))
        measured=self.commit('root plus retained untrusted historical observation')
        expected={**self.original,self.snapshot:self.snapshot_tree}
        self.assertEqual(declarations(self.root),expected)
        self.assertEqual(declarations(self.root,source=measured),expected)

    def test_measured_commit_must_be_exact_and_really_a_commit(self):
        for source in ['main','--all','A'*40,'0'*40,self.snapshot_tree]:
            with self.subTest(source=source),self.assertRaises(ValueError):
                declarations(self.root,source=source)

    def test_conflict_in_committed_public_root_is_rejected_without_using_current_repair(self):
        path=self.write('evidence/pon-public-readiness-v1/manifest.json',
            dict(implementation_commit=self.implementation,implementation_tree=self.snapshot_tree))
        conflicting=self.commit('committed conflicting tree')
        path.unlink()
        self.assertEqual(declarations(self.root),self.original)
        with self.assertRaisesRegex(ValueError,'conflicting source tree'):
            declarations(self.root,source=conflicting)

    def test_committed_declaration_symlink_is_not_followed(self):
        path=self.root/'evidence/pon-public-readiness-v1/manifest.json'
        path.parent.mkdir(parents=True)
        path.symlink_to('../pon-v3/manifest.json')
        linked=self.commit('invalid declaration symlink')
        with self.assertRaisesRegex(ValueError,'unsafe measured declaration file'):
            declarations(self.root,source=linked)

    def write_audit(self,commit,tree):
        manifest,cost=audit_records(commit,tree)
        return (self.write('evidence/'+AUDIT_PACKAGE+'/manifest.json',manifest),
                self.write('evidence/'+AUDIT_PACKAGE+'/work-cost/execution.json',cost))

    def test_historical_audit_uses_its_committed_declarations_after_current_rewrite(self):
        manifest,cost=self.write_audit(self.snapshot,self.snapshot_tree)
        measured=self.commit('retain fixed historical audit source')
        expected={**self.original,self.snapshot:self.snapshot_tree}
        self.assertEqual(declarations(self.root),expected)
        self.assertEqual(declarations(self.root,source=measured),expected)
        self.assertEqual(declarations(self.root,source=self.snapshot),self.original)
        manifest.write_text(json.dumps(dict(schema='pon-four-priority-audit-local-observations-v1',
            measured_source_commit='main',measured_source_tree='TREE')));cost.unlink()
        with self.assertRaises(ValueError):declarations(self.root)
        self.assertEqual(declarations(self.root,source=measured),expected)

    def test_committed_audit_conflict_cannot_be_repaired_by_current_files(self):
        manifest,_=self.write_audit(self.snapshot,self.snapshot_tree)
        manifest.write_text(json.dumps(audit_records(self.implementation,self.implementation_tree)[0]))
        conflicting=self.commit('individually valid but conflicting audit declarations')
        self.write_audit(self.snapshot,self.snapshot_tree)
        self.assertEqual(declarations(self.root),{**self.original,self.snapshot:self.snapshot_tree})
        with self.assertRaisesRegex(ValueError,'conflicting historical cost source pair'):
            declarations(self.root,source=conflicting)

    def test_committed_audit_declarations_cannot_be_symlink_objects(self):
        for index in (0,1):
            files=self.write_audit(self.snapshot,self.snapshot_tree)
            files[index].unlink();files[index].symlink_to('../unlisted.json')
            linked=self.commit('unsafe historical declaration '+str(index))
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'unsafe measured declaration file'):
                declarations(self.root,source=linked)
            files[index].unlink()

if __name__=='__main__':unittest.main(verbosity=2)
