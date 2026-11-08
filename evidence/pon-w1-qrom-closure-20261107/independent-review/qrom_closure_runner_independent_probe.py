#!/usr/bin/env python3
"""Read-only independent review of current named completion runner."""
from pathlib import Path
import copy, hashlib, importlib.util, json, subprocess, sys, tempfile
ROOT=Path('/workspace/scratch/4a83c49617d8/chain_pq')
RUNNER=ROOT/'scripts/ci/w1_qrom_closure_controls.py'
TESTS=ROOT/'scripts/ci/test_w1_qrom_closure_controls.py'
OUT=Path('/workspace/scratch/4a83c49617d8/qrom_closure_runner_independent_review.json')
spec=importlib.util.spec_from_file_location('review_closure_gate',RUNNER);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
identities={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (RUNNER,TESTS)}
results=[]
def case(label,source_change=None,record_change=None,roster_change=None,expected=2):
 with tempfile.TemporaryDirectory() as d:
  root=Path(d);folder=root/'scripts/ci';folder.mkdir(parents=True);(root/'config/pon').mkdir(parents=True);out=root/'out';out.mkdir()
  for module in gate.MODULES:
   (folder/(module+'.py')).write_text('import unittest\nclass Probe(unittest.TestCase):\n    def test_one(self):\n        self.assertEqual(2+3,5)\n')
  roster={'schema':'TRNM-W1-QROM-CLOSURE-REQUIRED-TESTS1','suites':[{'module':name,'tests':[name+'.Probe.test_one']} for name in gate.MODULES],'expected_tests':len(gate.MODULES),'qualification':dict(gate.QUALIFICATION)}
  raw=(json.dumps(roster,sort_keys=True)+'\n').encode();path=root/gate.ROSTER;path.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
  selected=folder/(gate.MODULES[0]+'.py')
  if source_change:source_change(selected)
  if roster_change:roster_change(path,roster)
  command=[sys.executable,str(RUNNER),'run','--root',str(root),'--output',str(out),'--roster-sha256',digest]
  proc=subprocess.run(command,capture_output=True,timeout=20,check=False)
  if record_change:
   assert proc.returncode==0,(label,proc.stderr)
   record=json.loads((out/'named-controls.json').read_text());record_change(record)
   (out/'named-controls.json').write_text(json.dumps(record))
   command[2]='check';proc=subprocess.run(command,capture_output=True,timeout=20,check=False)
  assert proc.returncode==expected,(label,proc.returncode,proc.stdout,proc.stderr)
  if expected==0:
   summary=json.loads(proc.stdout);assert summary['named_completion_validated'] is True and all(v is None or v is False for v in summary['qualification'].values())
  else:assert b'named_completion_validated' not in proc.stdout,(label,'success stdout leaked')
  results.append({'case':label,'exit_code':proc.returncode,'passed_expected_boundary':True})
def append(text):
 return lambda path:path.write_text(path.read_text()+text)
def replace_source(text):return lambda path:path.write_text(text)
case('real-all-six-fixture-suites',expected=0)
case('real-load-tests-exit-zero',append('\ndef load_tests(loader, tests, pattern):\n    raise SystemExit(0)\n'))
case('real-load-tests-empty',append('\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n'))
case('real-load-tests-duplicate',append('\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite([tests,tests])\n'))
case('real-module-missing',lambda path:path.unlink())
case('real-import-error',append('\nimport dependency_that_does_not_exist_qrom_probe\n'))
case('real-skip',replace_source('import unittest\nclass Probe(unittest.TestCase):\n    @unittest.skip("probe")\n    def test_one(self): pass\n'))
case('real-expected-failure',replace_source('import unittest\nclass Probe(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_one(self): self.fail("probe")\n'))
case('real-unexpected-success',replace_source('import unittest\nclass Probe(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_one(self): pass\n'))
case('real-setup-class-failure',append('\n    @classmethod\n    def setUpClass(cls): raise ValueError("probe")\n'))
case('real-test-body-exit-zero',replace_source('import unittest\nclass Probe(unittest.TestCase):\n    def test_one(self): raise SystemExit(0)\n'))
case('tampered-roster-bytes',roster_change=lambda path,_:path.write_bytes(path.read_bytes()+b' '))
for key in ('registered_ids','started_ids','success_ids'):
 case('record-empty-'+key,record_change=lambda v,k=key:v['suites'][0].__setitem__(k,[]))
 case('record-duplicate-'+key,record_change=lambda v,k=key:v['suites'][0].__setitem__(k,v['suites'][0][k]*2))
case('record-boolean-tests-run',record_change=lambda v:v['suites'][0].__setitem__('tests_run',True))
case('record-float-tests-run',record_change=lambda v:v['suites'][0].__setitem__('tests_run',1.0))
case('record-boolean-required-total',record_change=lambda v:v.__setitem__('required_tests',True))
case('record-nonboolean-false-qualification',record_change=lambda v:v['qualification'].__setitem__('production_qualified',0))
case('record-extra-pass-flag',record_change=lambda v:v.__setitem__('passed',True))
case('record-reordered-suites',record_change=lambda v:v['suites'].reverse())
case('record-empty-suites',record_change=lambda v:v.__setitem__('suites',[]))
# Known design boundary: a check of a self-contained matching report is not an execution attestation.
with tempfile.TemporaryDirectory() as d:
 root=Path(d);(root/'config/pon').mkdir(parents=True);out=root/'out';out.mkdir()
 roster={'schema':'TRNM-W1-QROM-CLOSURE-REQUIRED-TESTS1','suites':[{'module':name,'tests':[name+'.Probe.test_one']} for name in gate.MODULES],'expected_tests':len(gate.MODULES),'qualification':dict(gate.QUALIFICATION)}
 raw=json.dumps(roster).encode();(root/gate.ROSTER).write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
 record={'schema':'TRNM-W1-QROM-CLOSURE-CONTROLS1','roster_sha256':digest,'required_tests':len(gate.MODULES),'qualification':dict(gate.QUALIFICATION),'suites':[]}
 for row in roster['suites']:
  item={'module':row['module'],'registered_ids':row['tests'],'started_ids':row['tests'],'success_ids':row['tests'],'tests_run':1,'exception':None}
  item.update({key:[] for key in ('loader_errors','failures','errors','skipped','expected_failures','unexpected_successes')});record['suites'].append(item)
 (out/'named-controls.json').write_text(json.dumps(record))
 proc=subprocess.run([sys.executable,str(RUNNER),'check','--root',str(root),'--output',str(out),'--roster-sha256',digest],capture_output=True,timeout=20,check=False)
 assert proc.returncode==0 and not (root/'scripts').exists()
 format_only={'standalone_check_accepts_consistent_fixture_without_test_execution':True,'qualification_remains_false_or_null':all(v is False or v is None for v in json.loads(proc.stdout)['qualification'].values()),'boundary':'check validates structure and claimed completion, not origin. Workflow must bind fresh output to the actual controlled run and source; no cryptographic execution attestation.'}
assert identities=={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (RUNNER,TESTS)},'source changed during review'
result={'schema':'TRNM-QROM-CLOSURE-RUNNER-INDEPENDENT-REVIEW1','source_sha256':identities,'cases':results,'standalone_check_boundary':format_only,'blocking_bug_found_in_reviewed_named_completion_controls':False,'workflow_reviewed':False}
OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'cases':len(results),'all_expected_boundaries_passed':True,'output':str(OUT),'standalone_check_boundary':format_only,'hashes':identities}))
