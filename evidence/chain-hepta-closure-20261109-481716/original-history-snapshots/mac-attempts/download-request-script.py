import subprocess,json,hashlib,datetime,zipfile,shutil,os
from pathlib import Path
root=Path('/Users/qianqi/chain-hepta-closure-481716/history-snapshot-recovery')
expected_zip='4e8a243caf2aadf4a195b4cb96dbb0229a0e001a830f0e9de2c4f853ee7dff5c'
size_zip=76441344
expected=[
 {'path':'run-1-raw/report.json','bytes':48614177,'sha256':'39c4098846dbbb802f962989a0774d09c95a80c0db3b04a69923adfce8b5c307'},
 {'path':'run-2-raw/report.json','bytes':48774711,'sha256':'43c8fb8fa28c560522be595b58e98e483c62631a76766f42efa24f088e366822'},
 {'path':'run-3-raw/report.json','bytes':48449148,'sha256':'5699de385790f39f3e5684140b97fb81ebba892036442295a3628591de9e0156'}]
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  while True:
   b=f.read(1048576)
   if not b:break
   h.update(b)
 return {'bytes':p.stat().st_size,'sha256':h.hexdigest()}
def save(name,data):
 b=(json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode()
 p=root/name
 with p.open('xb') as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
a=json.loads((root/'artifact-metadata-original.json').read_text())
assert a['id']==13662172930 and a['expired'] is False and a['digest']=='sha256:'+expected_zip and a['size_in_bytes']==size_zip
assert a['workflow_run']['id']==42591962205 and a['workflow_run']['head_sha']=='0746a462e80067b78317597f2fa4bacf5e3db958'
zp=root/'artifact-13662172930-4e8a243c.zip'
reused=zp.exists()
if not reused:
 part=root/'artifact-13662172930-download-01.part'
 with part.open('xb') as f:
  p=subprocess.run(['/opt/homebrew/bin/gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/13662172930/zip'],stdout=f,stderr=subprocess.PIPE,timeout=300)
 (root/'download-01.stderr.log').write_bytes(p.stderr)
 if p.returncode:
  print(json.dumps({'download_exit':p.returncode,'partial_archive':str(part),'partial_identity':digest(part)}))
  raise SystemExit(p.returncode)
 got=digest(part)
 assert got=={'bytes':size_zip,'sha256':expected_zip},got
 part.rename(zp)
else:
 assert digest(zp)=={'bytes':size_zip,'sha256':expected_zip}
reports=root/'report-originals'
reports.mkdir(exist_ok=True)
rec=[]
with zipfile.ZipFile(zp) as z:
 names=z.namelist()
 archive_member_count=len(names)
 for e in expected:
  assert names.count(e['path'])==1,(e['path'],names.count(e['path']))
  info=z.getinfo(e['path'])
  assert info.file_size==e['bytes']
  out=reports/(e['path'].replace('/','-'))
  if not out.exists():
   with z.open(e['path']) as src,out.open('xb') as dst:
    shutil.copyfileobj(src,dst,1048576)
  got=digest(out)
  assert got=={'bytes':e['bytes'],'sha256':e['sha256']},(str(out),got)
  with out.open() as f:d=json.load(f)
  assert isinstance(d,dict)
  layout={}
  for k,v in d.items():
   q={'type':type(v).__name__}
   if isinstance(v,(list,dict,str)):q['length']=len(v)
   if isinstance(v,dict):q['keys']=list(v)[:80]
   elif not isinstance(v,list) and (not isinstance(v,str)or len(v)<500):q['value']=v
   if isinstance(v,list) and v:
    q['first_element_type']=type(v[0]).__name__
    if isinstance(v[0],dict):q['first_element_keys']=list(v[0])[:100]
   layout[k]=q
  rec.append({'zip_member':e['path'],'local_path':str(out),'bytes':got['bytes'],'sha256':got['sha256'],'manifest_match':True,'zip_crc32':format(info.CRC,'08x'),'top_level_layout':layout})
  del d
result={'schema':'trnm.original-campaign-report-recovery.v1','started_at_utc':started,'completed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'artifact_id':13662172930,'run_id':42591962205,'original_source_commit':'0746a462e80067b78317597f2fa4bacf5e3db958','manifest_source':'closure-evidence/original-campaign/artifact-files.json.gz','manifest_sha256':'e60672ed9000139c0a8adba8da489f5577d57f3bd6c2d7bd13a1b1fd3e69f6f7','archive':{'path':str(zp),'bytes':size_zip,'sha256':expected_zip,'metadata_digest_matched':True,'member_count':archive_member_count,'reused_existing':reused},'selected_reports':rec,'only_selected_members_extracted':True,'all_archive_members_extracted':False,'campaign_executed':False,'github_writes_performed':False,'disk_free_after':shutil.disk_usage(root).free}
artifact=save('recovery-report-01.json',result)
print(json.dumps({'recovery':result,'retention':artifact},ensure_ascii=False,sort_keys=True))
