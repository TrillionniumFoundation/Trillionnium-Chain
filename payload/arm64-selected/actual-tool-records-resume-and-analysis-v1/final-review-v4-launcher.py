import hashlib,sys
from pathlib import Path
p=Path("/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v4/producer-v4.py")
b=p.read_bytes()
if len(b)!=12527 or hashlib.sha256(b).hexdigest()!="381302c74302bb883671e1ee559dca8918650cb62ae1917b8a4950a7baa83adf":raise SystemExit('PRODUCER_PIN')
sys.argv=[str(p),b.decode('utf-8')]
exec(compile(b,str(p),'exec',dont_inherit=True,optimize=0),{'__name__':'__main__','__file__':str(p)})
