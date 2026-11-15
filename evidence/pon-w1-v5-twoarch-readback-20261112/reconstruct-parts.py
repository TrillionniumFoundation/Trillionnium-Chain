#!/usr/bin/env python3
"""Reconstruct exact ordered parts into a new external destination directory."""
import argparse,hashlib,json
from pathlib import Path,PurePosixPath
root=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('manifest',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
value=json.loads(a.manifest.read_text())
if value['schema']=='ordered-original-zip-parts-v1':
 entries=[{'original_path':a.manifest.parent.name+'/original.zip','original_identity':value['original_zip'],'ordered_parts':value['ordered_parts']}]
elif value['schema']=='ordered-large-packet-file-parts-v1':entries=value['entries']
else:raise ValueError('unsupported part schema')
a.destination.mkdir(parents=True,exist_ok=False)
for e in entries:
 rel=PurePosixPath(e['original_path'])
 if rel.is_absolute() or '..' in rel.parts:raise ValueError('unsafe output')
 target=a.destination.joinpath(*rel.parts);target.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();size=0
 with target.open('xb') as f:
  for item in e['ordered_parts']:
   rel=PurePosixPath(item['path'])
   if rel.is_absolute() or '..' in rel.parts:raise ValueError('unsafe input')
   raw=root.joinpath(*rel.parts).read_bytes()
   if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('part changed')
   f.write(raw);h.update(raw);size+=len(raw)
 if {'bytes':size,'sha256':h.hexdigest()}!=e['original_identity']:raise ValueError('full reconstruction mismatch')
 print(json.dumps({'path':str(target),'bytes':size,'sha256':h.hexdigest()},sort_keys=True))
