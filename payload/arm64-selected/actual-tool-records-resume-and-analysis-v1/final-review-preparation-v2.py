import ast,difflib,hashlib,json,sys
from pathlib import Path
old,new,terminal=json.loads(sys.argv[1]);base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v2');base.mkdir(mode=0o700)
def put(name,b):
 p=base/name
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
a=put('original-first-producer.py.original',old.encode());t=put('original-first-actual-terminal.json',(json.dumps(terminal,sort_keys=True,indent=2)+'\n').encode())
compile(new,str(base/'producer-v2.py'),'exec',dont_inherit=True,optimize=0);ast.parse(new)
b=put('producer-v2.py',new.encode());d=put('v1-to-v2.patch',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='offline-facts-v1',tofile='offline-facts-v2')).encode())
print(json.dumps({'producer':b,'first_original':a,'first_terminal':t,'diff':d,'syntax_compiled_only':True},sort_keys=True))
