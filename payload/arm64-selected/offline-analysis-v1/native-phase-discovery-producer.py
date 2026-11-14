import hashlib,json,sys
from pathlib import Path
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
m=json.loads((base/'selected-resume-001/members/from-zero-native/manifest.json').read_bytes())
r=json.loads((base/'selected-resume-001/members/from-zero-native/confirmation/report.json').read_bytes())
out=base/'offline-analysis-v1'
native=r['phases'][1]['independent_history_page_replay'][-1]['native_import_observation']
raw=(json.dumps(native,sort_keys=True,indent=2)+'\n').encode()
p=out/'pressure-replay-3-native-observation.json'
with p.open('xb')as f:f.write(raw)
with(out/'native-phase-discovery-producer.py').open('xb')as f:f.write(sys.argv[1].encode())
print(json.dumps({'native_pin':{'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'page_phases':native['phases'],'packet_phases':[x['phases']for x in native['packets']],'host_checks':native['host_checks'],'host_buckets':native['host_checkpoint_attribution'],'attribution':native['native_attribution'],'confirmation_observation':m['confirmation_observation']},sort_keys=True))
