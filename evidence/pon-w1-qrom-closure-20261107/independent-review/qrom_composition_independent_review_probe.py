#!/usr/bin/env python3
"""Independent arithmetic/input probes of the two NEW QROM research tools."""
from pathlib import Path
import copy, hashlib, importlib.util, itertools, json, random, subprocess, sys
from fractions import Fraction
ROOT=Path('/workspace/scratch/4a83c49617d8/chain_pq')
OUT=Path('/workspace/scratch/4a83c49617d8/qrom_composition_independent_review.json')
files={name:ROOT/'scripts'/name for name in ('w1_qrom_composition_budget.py','w1_qrom_joint_oracle_diagnostic.py')}
identities={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}
def load(name):
 spec=importlib.util.spec_from_file_location(name[:-3],files[name]); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
c=load('w1_qrom_composition_budget.py');j=load('w1_qrom_joint_oracle_diagnostic.py')
def f(v):return Fraction(int(v['numerator']),int(v['denominator']))
def unqualified(report):
 assert all(value is False or value is None for value in report['qualification'].values())
# Evaluate independently as sums of monomials, not the implementation's Horner loop.
def poly(model,q):
 return sum((f(a) if isinstance(a,dict) else Fraction(a))*q**i for i,a in enumerate(model['coefficients']))
rng=random.Random(20261107)
for _ in range(256):
 raw=copy.deepcopy(c.example_input());q=raw['queries']
 for key in q:q[key]=rng.randrange(0,12)
 for side in ('left','right'):
  for kind in ('simulation','commutativity','extractability'):
   raw[side]['errors'][kind]['coefficients']=[{'numerator':rng.randrange(0,8),'denominator':2**rng.randrange(16,31)} for i in range(rng.randrange(1,5))]
 a=q['t']+q['q_v1']+q['q_v2']+q['q_e2'];b=q['t']+q['q_v1'];d=q['t']+2*q['q_v1']+q['q_v2']+q['q_e2']+q['q_r2']+q['q_r3']
 coeff=2*(q['q_v1']**2*q['q_e2']**2+q['q_e2']**2*(q['q_r2']+q['q_r3'])**2)
 expected=2*poly(raw['left']['errors']['extractability'],a)+2*poly(raw['right']['errors']['extractability'],b)+coeff*min(poly(raw['left']['errors']['commutativity'],d),poly(raw['right']['errors']['commutativity'],d))
 report=c.make_report(raw)
 assert f(report['conditional_extraction_upper_expression'])==expected
 assert f(report['simulation_upper_expression'])==min(poly(raw[side]['errors']['simulation'],q['q_sim']) for side in ('left','right'))
 assert f(report['commutativity_upper_expression'])==min(poly(raw[side]['errors']['commutativity'],q['q_com']) for side in ('left','right'))
 unqualified(report)
# Missing dependencies do not become zero, including an exact zero cross coefficient.
for key in ('t','q_v1','q_v2','q_e2','q_r2','q_r3'):
 raw=copy.deepcopy(c.example_input());raw['queries'][key]=None
 assert c.make_report(raw)['conditional_extraction_upper_expression'] is None
raw=copy.deepcopy(c.example_input());raw['queries']['q_e2']=0;raw['right']['errors']['commutativity']['coefficients']=[0,None]
assert c.make_report(raw)['terms']['commutator_addend'] is None
# Known relation/oracle mismatch is refused even with a separate unknown field.
for group,key in [('input_relation','strict_specification_sha256'),('emulated_oracle','ordinary_oracle_specification_sha256')]:
 raw=copy.deepcopy(c.example_input());raw['right'][group][key]='f'*64
 raw['left']['input_relation']['relaxed_specification_sha256']=None
 try:c.make_report(raw)
 except c.CompositionError:pass
 else:raise AssertionError('known mismatch bypassed')
# Unknown descriptor blocks the conditional theorem expression; raw arithmetic may remain known.
raw=copy.deepcopy(c.example_input());raw['left']['emulated_oracle']=None
report=c.make_report(raw);assert report['conditional_extraction_upper_expression'] is None and report['expression_meets_hypothetical_target'] is None;unqualified(report)
# Distinguishing experiment: enumerate both complete joint distributions for small M.
for m in range(1,9):
 for alias in (True,False):
  pairs=list(itertools.product(range(m),repeat=2));ind={p:Fraction(1,m*m) for p in pairs}
  shared={p:(Fraction(1,m) if p[0]==p[1] else Fraction(0)) if alias else Fraction(1,m*m) for p in pairs}
  tv=sum(abs(shared[p]-ind[p]) for p in pairs)/2
  gap=sum(shared[(v,v)]-ind[(v,v)] for v in range(m))
  raw=j.example_input('alias' if alias else 'separated');raw['range_cardinality']=m
  report=j.make_report(raw)
  assert f(report['joint_total_variation_distance'])==tv and f(report['equality_test']['acceptance_probability_gap'])==gap
  assert f(report['equal_prior_optimal_guess_success'])==(1+tv)/2
  unqualified(report)
# API and CLI malformed inputs: no stdout report and structured refused output only.
malformed=[b'{"schema":1,"schema":2}',b'{"x":NaN}',b'{"x":Infinity}',b'['*8000+b'0'+b']'*8000,b'\xff',b' '*(131072+1),b'{"x":'+b'9'*5000+b'}']
malformed_counts={}
for name,module in [('w1_qrom_composition_budget.py',c),('w1_qrom_joint_oracle_diagnostic.py',j)]:
 cases=list(malformed)
 example=module.example_input()
 for value in (True,False,1.0,-1,'01','1e9',{},[]):
  raw=copy.deepcopy(example)
  if module is c:raw['queries']['t']=value
  else:raw['range_cardinality']=value
  cases.append(json.dumps(raw).encode())
 cases.append(json.dumps(example).replace('"hypothetical"','"project_qualified"').encode())
 for data in cases:
  proc=subprocess.run([sys.executable,str(files[name]),'--input','-'],input=data,capture_output=True,timeout=10,check=False)
  assert proc.returncode==2 and not proc.stdout,(name,proc.returncode,proc.stdout[:200],proc.stderr[:200])
  err=json.loads(proc.stderr);assert err['status']=='invalid_input';unqualified(err)
 malformed_counts[name]=len(cases)
assert identities=={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()},'source changed during review'
result={'schema':'TRNM-NEW-QROM-INDEPENDENT-REVIEW1','source_sha256':identities,'comparison_cases':256,'finite_joint_law_cases':16,'malformed_cli_cases':malformed_counts,'known_incompatibility_refused':True,'unknown_zero_cross_term_remains_unknown':True,'blocking_counterexample_found':False,'primary_formula_reference':'January 1 2026 manuscript, Theorem 10.6 and Construction 10.5, CORE index lines 7281-7417 and 8290-8309; not March version','whole_cryptographic_proof_audit':False,'production_qualification':False}
OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
