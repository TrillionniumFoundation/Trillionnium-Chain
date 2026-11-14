import hashlib,json,sys
from pathlib import Path
b=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/selected-resume-001/members')
out=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/offline-analysis-v1')
m=json.loads((b/'from-zero-native/manifest.json').read_bytes());r=json.loads((b/'from-zero-native/confirmation/report.json').read_bytes())
def sh(v,d=0):
 if isinstance(v,dict):return{k:sh(x,d+1)for k,x in v.items()}if d<2 else{'keys':list(v)}
 if isinstance(v,list):return{'length':len(v),'first':sh(v[0],d+1)if v else None}
 if isinstance(v,str)and len(v)>160:return v[:80]+'[length='+str(len(v))+']'
 return v
value={'runs_type':type(m['runs']).__name__,'runs':sh(m['runs']),'files_count':len(m['files']),'files_examples':list(m['files'].items())[:3],'source_before':m['source_before'],'source_after':m['source_after'],'binary_sha256_before':m['binary_sha256_before'],'binary_sha256_after':m['binary_sha256_after'],'confirmation_report':m['confirmation_report'],'pressure_replay_top':[dict((k,v)for k,v in q.items()if k!='native_import_observation')for q in r['phases'][1]['independent_history_page_replay']],'pressure_last_native_shape':sh(r['phases'][1]['independent_history_page_replay'][-1]['native_import_observation']),'host':{}}
for name in('controller-result.json','child-result.json','inside-before.json','inside-after.json','outside-after.json'):
 value['host'][name]=sh(json.loads((b/'from-zero-native-host'/name).read_bytes()))
raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
with(out/'focused-structure.json').open('xb')as f:f.write(raw)
with(out/'focused-discovery-producer.py').open('xb')as f:f.write(sys.argv[1].encode())
print(json.dumps({'pin':{'path':str(out/'focused-structure.json'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'value':value},sort_keys=True))
