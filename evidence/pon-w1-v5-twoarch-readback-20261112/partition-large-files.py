#!/usr/bin/env python3
"""Partition only owned packet duplicates, keeping external originals unchanged."""
import hashlib,json
from pathlib import Path
OUT=Path('/home/qian-qi/work/w1-v5-packet-20261112-b34d')
CAP=4194304
def need(t,m):
 if not t: raise ValueError(m)
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def identity(p):return {'bytes':p.stat().st_size,'sha256':digest(p)}
def put(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
def js(p,v):put(p,(json.dumps(v,sort_keys=True,indent=2)+'\n').encode())
old=OUT/'packet-manifest.json'
oldraw=old.read_bytes();oldid=identity(old);prior=json.loads(oldraw)
need(oldid['sha256']=='744e33dc4c97236f209d29e995511b929e3e7a4ab427c3cde6879036f15f537b','unexpected initial manifest')
for name,wanted in prior['files'].items():need(identity(OUT/name)==wanted,'initial packet changed: '+name)
put(OUT/'packet-manifest-initial.json',oldraw)
large=[]
for p in sorted(OUT.rglob('*')):
 if not p.is_file() or p.stat().st_size<=CAP:continue
 name=p.relative_to(OUT).as_posix();wanted=identity(p);parts=[]
 with p.open('rb') as f:
  for i,b in enumerate(iter(lambda:f.read(CAP),b'')):
   target=p.with_name(p.name+f'.rawpart-{i:03d}')
   put(target,b);parts.append({'path':target.relative_to(OUT).as_posix(),**identity(target)})
 h=hashlib.sha256();size=0
 for x in parts:
  raw=(OUT/x['path']).read_bytes();need(len(raw)==x['bytes'] and hashlib.sha256(raw).hexdigest()==x['sha256'],'part changed')
  h.update(raw);size+=len(raw)
 need({'bytes':size,'sha256':h.hexdigest()}==wanted,'reconstruction mismatch')
 need(identity(p)==wanted,'source changed during partition')
 large.append({'original_path':name,'original_identity':wanted,'ordered_parts':parts})
 p.unlink()
ledger={'schema':'ordered-large-packet-file-parts-v1','maximum_part_bytes':CAP,'entries':large,
 'external_originals_unchanged':True,'original_packet_duplicates_removed_only_after_full_reconstruction_validation':True}
js(OUT/'large-file-parts.json',ledger)
put(OUT/'reconstruct-parts.py',"#!/usr/bin/env python3\n\"\"\"Reconstruct exact ordered parts into a new external destination directory.\"\"\"\nimport argparse,hashlib,json\nfrom pathlib import Path,PurePosixPath\nroot=Path(__file__).resolve().parent\np=argparse.ArgumentParser(description=__doc__);p.add_argument('manifest',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()\nvalue=json.loads(a.manifest.read_text())\nif value['schema']=='ordered-original-zip-parts-v1':\n entries=[{'original_path':a.manifest.parent.name+'/original.zip','original_identity':value['original_zip'],'ordered_parts':value['ordered_parts']}]\nelif value['schema']=='ordered-large-packet-file-parts-v1':entries=value['entries']\nelse:raise ValueError('unsupported part schema')\na.destination.mkdir(parents=True,exist_ok=False)\nfor e in entries:\n rel=PurePosixPath(e['original_path'])\n if rel.is_absolute() or '..' in rel.parts:raise ValueError('unsafe output')\n target=a.destination.joinpath(*rel.parts);target.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();size=0\n with target.open('xb') as f:\n  for item in e['ordered_parts']:\n   rel=PurePosixPath(item['path'])\n   if rel.is_absolute() or '..' in rel.parts:raise ValueError('unsafe input')\n   raw=root.joinpath(*rel.parts).read_bytes()\n   if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('part changed')\n   f.write(raw);h.update(raw);size+=len(raw)\n if {'bytes':size,'sha256':h.hexdigest()}!=e['original_identity']:raise ValueError('full reconstruction mismatch')\n print(json.dumps({'path':str(target),'bytes':size,'sha256':h.hexdigest()},sort_keys=True))\n".encode())
put(OUT/'partition-large-files.py',Path(__file__).resolve().read_bytes())
readme=OUT/'README.md';before=readme.read_bytes()
with readme.open('wb') as f:f.write(before+"\n## Per-file size cap and reconstruction\n\nEvery final packet file is at most 4,194,304 bytes. Oversized standalone metadata copies are preserved as ordered raw parts described by large-file-parts.json; their original path, complete length and SHA256 are bound. The new packet duplicate monoliths were removed only after byte-identical reconstruction validation. All external original artifacts/readbacks remain untouched. packet-manifest-initial.json retains the initial packaging observation and its historical file roster; packet-manifest.json is the current packet roster.\n\nUse python3 reconstruct-parts.py large-file-parts.json NEW_EXTERNAL_DIRECTORY to reconstruct standalone metadata. Use the same helper with arm64/original-zip-parts.json or x64/original-zip-parts.json and a separate new directory to reconstruct the original ZIP. Verify the resulting full length/hash before extraction. The compact T1/H8 tables still include both CPU and wall for all 11 materials on each architecture.\n".encode())
files={p.relative_to(OUT).as_posix():identity(p) for p in sorted(OUT.rglob('*')) if p.is_file() and p!=old}
need(all(v['bytes']<=CAP for v in files.values()),'oversized file remains')
manifest={'schema':'pon-w1-v5-external-readback-packet-v2','source_commit':prior['source_commit'],'source_tree':prior['source_tree'],
 'native_executions_started_by_packaging':0,'original_zip_count':2,'original_member_count':440,'maximum_file_bytes':CAP,
 'initial_packet_manifest_identity':oldid,'large_file_ledger':identity(OUT/'large-file-parts.json'),
 'file_count_without_manifest':len(files),'files':files}
new=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();need(len(new)<=CAP,'manifest cap')
with old.open('wb') as f:f.write(new)
for name,wanted in files.items():need(identity(OUT/name)==wanted,'final packet changed: '+name)
allfiles=[p for p in OUT.rglob('*') if p.is_file()]
print(json.dumps({'status':'PACKET_ALL_FILES_WITHIN_ORIGINAL_CAP','path':str(OUT),'files':len(allfiles),
 'bytes':sum(p.stat().st_size for p in allfiles),'maximum_file_bytes':max(p.stat().st_size for p in allfiles),
 'manifest':identity(old),'large_file_parts':ledger,'tables':identity(OUT/'t1-h8-tables.md')},sort_keys=True,indent=2))
