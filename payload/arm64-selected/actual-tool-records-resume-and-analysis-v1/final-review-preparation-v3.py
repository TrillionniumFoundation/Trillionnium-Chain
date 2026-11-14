import ast,difflib,hashlib,json,sys
from pathlib import Path
old,new,term=json.loads(sys.argv[1])
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v3');base.mkdir(mode=0o700)
def put(n,b):
 p=base/n
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
t=put('original-v2-output-cap-terminal.json',(json.dumps(term,sort_keys=True,indent=2)+'\n').encode())
compile(new,str(base/'producer-v3.py'),'exec',dont_inherit=True,optimize=0);ast.parse(new)
p=put('producer-v3.py',new.encode())
d=put('v2-to-v3.patch',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='offline-facts-v2',tofile='offline-facts-v3')).encode())
print(json.dumps({'producer':p,'original_v2_terminal':t,'diff':d,'change':'split per-replay derived details so each output retains 64KiB bound; no original changes'},sort_keys=True))
