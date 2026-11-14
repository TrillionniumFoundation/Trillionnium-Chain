import ast,hashlib,json,sys
from pathlib import Path
code,terminal=json.loads(sys.argv[1])
out=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v4');out.mkdir(mode=0o700)
p=out/'original-v3-output-cap-terminal.json'
with p.open('xb')as f:f.write((json.dumps(terminal,sort_keys=True,indent=2)+'\n').encode())
compile(code,str(out/'producer-v4.py'),'exec',dont_inherit=True,optimize=0);ast.parse(code)
p=out/'producer-v4.py';b=code.encode()
with p.open('xb')as f:f.write(b)
print(json.dumps({'producer':{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()},'syntax_only':True},sort_keys=True))
