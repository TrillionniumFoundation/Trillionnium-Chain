import datetime,hashlib,json,os,pathlib,stat,subprocess,sys
p=json.load(sys.stdin);m=p['manifest'];d=pathlib.Path(m['part_directory']);target=pathlib.Path(m['target']);expected_sha='65835d8b22e2a506ace76a4adcae377499580ed72a0ad91ee7362f836a2a5084';expected_size=2348492
if m['size']!=expected_size or m['sha256']!=expected_sha or len(m['parts'])!=36 or len(p['part_receipts'])!=36:raise ValueError('fixed manifest differs')
if json.loads((d/'manifest.json').read_text())!=m:raise ValueError('retained manifest differs')
chunks=[];offset=0
for part,receipt in zip(m['parts'],p['part_receipts']):
 if part['offset']!=offset or part['filename']!='part-'+str(offset).zfill(8)+'.bin' or part['bytes']<1 or part['bytes']>65536:raise ValueError('part geometry')
 if receipt['offset']!=offset or receipt['result']['size']!=part['bytes'] or receipt['result']['sha256']!=part['sha256']:raise ValueError('write receipt differs')
 fd=os.open(d/part['filename'],os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno())
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size!=part['bytes']:raise ValueError('part file identity')
  b=f.read(part['bytes']+1);after=os.fstat(f.fileno())
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('part changed')
 if len(b)!=part['bytes'] or hashlib.sha256(b).hexdigest()!=part['sha256']:raise ValueError('part bytes differ')
 chunks.append(b);offset+=len(b)
b=b''.join(chunks)
if offset!=expected_size or len(b)!=expected_size or hashlib.sha256(b).hexdigest()!=expected_sha:raise ValueError('complete bytes differ')
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:
 f.write(b);f.flush();os.fsync(f.fileno())
fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 observed=f.read(expected_size+1);info=os.fstat(f.fileno())
if len(observed)!=expected_size or hashlib.sha256(observed).hexdigest()!=expected_sha or info.st_size!=expected_size or info.st_nlink!=1:raise ValueError('published readback differs')
checks=[]
for label,args in [('verify',['git','bundle','verify',str(target)]),('heads',['git','bundle','list-heads',str(target)])]:
 result=subprocess.run(args,cwd='/home/qian-qi/work/chain-qrom-closure-publish-20261107',capture_output=True);(d/(label+'.stdout')).write_bytes(result.stdout);(d/(label+'.stderr')).write_bytes(result.stderr);checks.append({'label':label,'exit_code':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
 if result.returncode:raise RuntimeError('bundle '+label+' failed')
 if label=='heads' and result.stdout.decode().strip()!='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53 HEAD':raise ValueError('bundle advertised head differs')
report={'schema':'TRNM-W1-CANDIDATE-A-TRANSFER1','completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'candidate':m['candidate'],'requires':m['requires'],'target':str(target),'bytes':len(observed),'sha256':expected_sha,'create_only_O_EXCL':True,'part_count':len(chunks),'parts':p['part_receipts'],'prior_upload_failures':p['failed_uploads'],'client_check_note':p['client_check_note'],'git_read_only_checks':checks,'publication_fetch_performed':False,'native_clone_modified':False,'GitHub_push_performed':False}
with (d/'transfer-report.json').open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('parts','prior_upload_failures','client_check_note')}),flush=True)
