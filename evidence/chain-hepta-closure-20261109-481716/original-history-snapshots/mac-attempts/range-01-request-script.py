import subprocess,json,hashlib,datetime,re
from pathlib import Path
root=Path('/Users/qianqi/chain-hepta-closure-481716/history-snapshot-recovery')
gh='/opt/homebrew/bin/gh'
endpoint='repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/13662172930'
a=json.loads(subprocess.check_output([gh,'api',endpoint],timeout=45))
assert a['expired'] is False and a['digest']=='sha256:4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c' and a['size_in_bytes']==76441344
partial=root/'artifact-13662172930-download-01.part'
assert partial.stat().st_size==11272192
assert hashlib.sha256(partial.read_bytes()).hexdigest()=='4088d2accfc11f2335687107c7c3730a7302216e4288cf1cd930a71d8489fd2d'
start=11272192;end=start+65536-1
argv=[gh,'api','--include','--header','Range: bytes='+str(start)+'-'+str(end),endpoint+'/zip']
p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
header_lines=[]
while True:
 line=p.stdout.readline()
 if not line:break
 header_lines.append(line)
 if line in (b'\n',b'\r\n'):break
 if sum(map(len,header_lines))>32768:raise RuntimeError('header bound exceeded')
status=header_lines[0].decode('ascii','replace').strip() if header_lines else ''
headers={}
for raw in header_lines[1:]:
 if b':' in raw:
  k,v=raw.decode('latin1').split(':',1);headers[k.lower().strip()]=v.strip()
safe={k:v for k,v in headers.items() if k in ['content-range','content-length','accept-ranges','content-type','etag','last-modified']}
valid=bool(re.match(r'^HTTP/[^ ]+ 206(?: |$)',status)) and headers.get('content-range')=='bytes '+str(start)+'-'+str(end)+'/76441344'
chunk=None
if valid:
 data=p.stdout.read(65537)
 rc=p.wait(timeout=45)
 err=p.stderr.read()
 assert rc==0 and len(data)==65536,(rc,len(data))
 q=root/'range-probe-11272192-11337727.bin'
 with q.open('xb') as f:f.write(data)
 chunk={'path':str(q),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'start':start,'end':end}
else:
 p.terminate()
 try:p.wait(timeout=10)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 err=p.stderr.read()
result={'schema':'trnm.original-artifact-range-read.v1','observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status_line':status,'response_headers':safe,'exact_range_response':valid,'chunk':chunk,'stderr_bytes':len(err),'stderr_sha256':hashlib.sha256(err).hexdigest(),'first_partial_bytes':partial.stat().st_size,'prior_failed_attempt_preserved':True,'github_writes_performed':False,'campaign_executed':False}
out=root/'range-read-01.json'
out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if valid else 3)
