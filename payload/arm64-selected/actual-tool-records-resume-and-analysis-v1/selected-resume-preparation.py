import ast,difflib,hashlib,json,sys,time
from pathlib import Path
old,new=json.loads(sys.argv[1])
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
out=base/'selected-resume-preparation-001';out.mkdir(mode=0o700)
p=base/'selected-producer.py';b=p.read_bytes()
if b!=old.encode()or len(b)!=26265 or hashlib.sha256(b).hexdigest()!='016e306f086be343fb59d2b6f47c1fb39053c0ea90b53ec87ebb96b46354a717':raise ValueError('REFERENCE_PIN')
compile(new,str(base/'selected-resume-001-producer.py'),'exec',dont_inherit=True,optimize=0)
funcs=lambda s:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)}
a,z=funcs(old),funcs(new)
if set(a)!=set(z)or any(a[k]!=z[k]for k in a if k!='main'):raise ValueError('HELPER_CHANGE')
def put(p,r):
 with p.open('xb')as f:f.write(r)
 if p.read_bytes()!=r:raise ValueError('READBACK')
 return {'path':str(p),'bytes':len(r),'sha256':hashlib.sha256(r).hexdigest()}
src=put(base/'selected-resume-001-producer.py',new.encode())
diff=put(out/'selected-v1-to-resume-001.patch',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='selected-v1/producer.py',tofile='selected-resume-001/producer.py')).encode())
d=json.loads((base/'directory-v1/summary.json').read_bytes())
summary={'schema':'trnm-H5DF-arm-selected-explicit-resume-preparation-v1','status':'PREPARED_NOT_EXECUTED','source':src,'diff':diff,'same_25_members':True,'same_8_ranges':True,'metadata_directory_new_GETs':0,'previous_actual_GETs':3,'maximum_new_GETs':8,'planned_combined_GETs':11,'original_combined_limit':21,'original_900_second_deadline':d['monotonic_deadline'],'deadline_reset':False,'remaining_seconds_at_preparation':d['monotonic_deadline']-time.monotonic(),'automatic_retry':False,'original_attempt_unchanged':True,'unchanged_helpers':[k for k in a if k!='main'],'static_compile_only':True}
p=put(out/'preparation.json',(json.dumps(summary,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'producer':src,'diff':diff,'preparation':p,'remaining_seconds':summary['remaining_seconds_at_preparation']},sort_keys=True))
