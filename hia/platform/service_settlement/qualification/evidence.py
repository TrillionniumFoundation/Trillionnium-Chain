"""Canonical relative paths and full bytes for a relocatable qualification."""
from pathlib import Path,PurePosixPath
import hashlib,os,stat,re
from ..contract import ROOT,document,identity,file_identity,canonical
EXCLUDED={'report.json','evidence.json'}
def valid(name):
 p=PurePosixPath(name)
 assert type(name) is str and name and not p.is_absolute() and '..' not in p.parts and p.as_posix()==name
 return name
def regular(path):
 path=Path(path);assert path.resolve(strict=True)==path and path.is_file() and not path.is_symlink(),str(path)
 return path
def inventory(root,exclude=()):
 rows={}
 for path in sorted(root.rglob('*')):
  if path.is_symlink():raise AssertionError(('symlink in evidence',str(path)))
  if path.is_dir():continue
  name=path.relative_to(root).as_posix()
  assert path.is_file() and '__pycache__' not in path.parts,str(path)
  if name not in EXCLUDED and not any(name.startswith(p) for p in exclude):rows[name]=file_identity(path)
 return rows
class Evidence:
 def __init__(self,root,*,pending=False):
  self.root=Path(root).resolve(strict=True);self.session=document(regular(self.root/'session.json').read_bytes())
  self.origin=self.session['output_root'];self.source_root=self.session['source_root']
  self.manifest=document(regular(self.root/'evidence.json').read_bytes())
  assert self.manifest['schema']=='trnm.hia.service-settlement-engine.evidence.v1'
  assert self.manifest['origin']==self.origin and self.manifest['source_root']==self.source_root
  self.files=self.manifest['files'];self.external=self.manifest['external'];self.checked={};self.objects={};self.pending=pending
  assert inventory(self.root,('integrity/','stages/integrity/') if self.pending else ())==self.files
  for name,row in self.files.items():
   valid(name);assert set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
  for path,row in self.external.items():
   assert Path(path).is_absolute() and set(row)=={'stored','bytes','sha256'}
   assert self.files[valid(row['stored'])]=={k:row[k] for k in ['bytes','sha256']}
  self.view={'roots':{'original':self.origin+'/original','generator':self.origin+'/generator','source':self.source_root}}
 def read(self,name):
  name=valid(name);p=regular(self.root/name);raw=p.read_bytes()
  assert identity(raw)==self.files[name],name
  self.checked[name]=self.files[name];return raw
 def doc(self,name):return document(self.read(name))
 def identity(self,name):
  name=valid(name)
  if name not in self.checked:
   assert file_identity(regular(self.root/name))==self.files[name],name
   self.checked[name]=self.files[name]
  return self.files[name]
 def source(self,name):return self.identity('source/'+valid(name))
 def actual_name(self,path):
  p=PurePosixPath(path)
  if p.is_relative_to(PurePosixPath(self.origin)):
   return valid(p.relative_to(PurePosixPath(self.origin)).as_posix())
  if p.is_relative_to(PurePosixPath(self.source_root)):
   return 'source/'+valid(p.relative_to(PurePosixPath(self.source_root)).as_posix())
  assert path in self.external,('uncaptured dependency',path)
  return self.external[path]['stored']
 def actual(self,path):return self.identity(self.actual_name(path))
 def actual_bytes(self,path):return self.read(self.actual_name(path))
 def final(self):
  assert inventory(self.root)==self.files
  return {'files':len(self.files),'checked':len(self.checked)}
def capture(root,source_inputs,external):
 root=Path(root).resolve(strict=True)
 source=root/'source';source.mkdir(exist_ok=True)
 for name,wanted in source_inputs.items():
  original=regular(ROOT/valid(name));assert file_identity(original)==wanted,name
  target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
  if target.exists():assert file_identity(target)==wanted
  else:
   with original.open('rb') as src,target.open('xb') as dst:
    while block:=src.read(1<<20):dst.write(block)
  assert file_identity(target)==wanted
 objects=root/'objects';objects.mkdir(exist_ok=True);mapping={}
 for path,wanted in sorted(external.items()):
  source_path=Path(path).resolve(strict=True);assert source_path.as_posix()==path
  assert file_identity(source_path)==wanted,path
  if source_path.is_relative_to(root) or source_path.is_relative_to(ROOT):continue
  stored='objects/'+wanted['sha256'];target=root/stored
  if not target.exists():
   with source_path.open('rb') as src,target.open('xb') as dst:
    while block:=src.read(1<<20):dst.write(block)
  assert file_identity(target)==wanted
  mapping[path]={'stored':stored,**wanted}
 session=document((root/'session.json').read_bytes())
 value={'schema':'trnm.hia.service-settlement-engine.evidence.v1','origin':session['output_root'],'source_root':session['source_root'],'external':mapping,'files':inventory(root)}
 (root/'evidence.json').write_bytes(canonical(value)+b'\n')
 return value
