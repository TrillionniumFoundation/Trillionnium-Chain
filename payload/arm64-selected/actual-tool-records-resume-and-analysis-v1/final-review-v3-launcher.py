import hashlib,sys
from pathlib import Path
p=Path("/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v3/producer-v3.py")
b=p.read_bytes()
if len(b)!=24075 or hashlib.sha256(b).hexdigest()!="ed0d1736ba33885a1c523a59e2770f7b8ffc5f3e905fbc8e21b1a6bf92bae66f":raise SystemExit('PRODUCER_PIN')
sys.argv=[str(p),b.decode('utf-8')]
exec(compile(b,str(p),'exec',dont_inherit=True,optimize=0),{'__name__':'__main__','__file__':str(p)})
