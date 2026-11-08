import os,json,hashlib,shutil,stat,tarfile,time
from pathlib import Path
os.umask(0o077)
work=Path('/home/qq/chain-real-iteration-20261108-8b4f0eedf006')
original=work/'artifacts/development-iteration-v1'
backup=work/'artifacts/development-iteration-v1-readonly-evidence-8b4f'
assert not backup.exists()
assert (work/'logs/integrated-cold-query-v1-exit.json').is_file()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
def inventory(root):
 records=[]
 for p in sorted(root.rglob('*')):
  s=p.lstat();rel=str(p.relative_to(root))
  assert stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),rel
  if stat.S_ISREG(s.st_mode):
   records.append({'path':rel,'bytes':s.st_size,'sha256':digest(p)})
 return records
print(json.dumps({'snapshot_started':str(backup),'scope':'read-only-evidence-backup-never-open-or-execute-copied-authority'}),flush=True)
before=inventory(original)
shutil.copytree(original,backup,copy_function=shutil.copy2,symlinks=False)
copied=inventory(backup);after=inventory(original)
assert before==copied==after
for p in sorted(backup.rglob('*'),key=lambda p:len(p.parts),reverse=True):p.chmod(0o500 if p.is_dir() else 0o400)
backup.chmod(0o500)
receipt={'schema':'chain-pre-fault-readonly-evidence-backup-v1','original':str(original),'backup':str(backup),'scope':'read-only-evidence-backup-never-open-or-execute-copied-authority','original_not_modified':True,'never_restore_journals_over_original':True,'bytes':sum(x['bytes'] for x in before),'files':before,'original_main_result_sha256':digest(original/'result.json'),'cold_query_stdout_sha256':digest(work/'logs/integrated-cold-query-v1.stdout.log')}
receipt_path=work/'logs/pre-fault-backup-v1.json'
with receipt_path.open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2);f.write('\n')
metadata=work/'artifacts/development-metadata-before-faults-v1.tar.gz'
included=[]
with tarfile.open(metadata,'x:gz',compresslevel=6) as t:
 for p in sorted(backup.rglob('*')):
  if p.is_file() and p.suffix in ('.json','.jsonl','.log','.txt','.py') and p.stat().st_size<=1024*1024:
   name='development-iteration-v1/'+str(p.relative_to(backup));t.add(p,arcname=name,recursive=False);included.append(name)
 for p in sorted((work/'logs').iterdir()):
  if p.is_file() and p.suffix in ('.json','.jsonl','.log','.txt','.py') and p.stat().st_size<=1024*1024:
   name='logs/'+p.name;t.add(p,arcname=name,recursive=False);included.append(name)
 for p in sorted((work/'inputs').iterdir()):
  if p.is_file():
   name='inputs/'+p.name;t.add(p,arcname=name,recursive=False);included.append(name)
 for name in ['runtime-source-manifest.json','runtime-supplement-manifest-v2.json']:
  t.add(work/'source'/name,arcname='source/'+name,recursive=False);included.append('source/'+name)
info={'schema':'chain-pre-fault-metadata-export-v1','archive':str(metadata),'archive_size':metadata.stat().st_size,'archive_sha256':digest(metadata),'read_only_backup':str(backup),'backup_files':len(before),'backup_bytes':receipt['bytes'],'included_text_files':len(included),'model_and_database_bytes_remain_in_private_backup':True,'copied_authority_not_opened_or_executed':True,'snapshot_receipt_sha256':digest(receipt_path)}
with (work/'logs/pre-fault-metadata-export-v1.json').open('x') as f:json.dump(info,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(info),flush=True)
