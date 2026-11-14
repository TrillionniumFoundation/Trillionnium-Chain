import hashlib,sys
from pathlib import Path
p=Path("/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1/final-review-preparation-v2/producer-v2.py")
b=p.read_bytes()
if len(b)!=23890 or hashlib.sha256(b).hexdigest()!="c08933f5d7c8f731ce4ca34f0361d619ffeec05547629152c5f530688d9feb15":raise SystemExit('PRODUCER_PIN')
sys.argv=[str(p),b.decode('utf-8')]
exec(compile(b,str(p),'exec',dont_inherit=True,optimize=0),{'__name__':'__main__','__file__':str(p)})
