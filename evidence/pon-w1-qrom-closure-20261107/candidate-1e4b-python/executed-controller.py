import concurrent.futures,datetime,hashlib,json,os,pathlib,re,stat,subprocess,sys,time,traceback
R=pathlib.Path('/home/qian-qi/work/chain-qrom-closure-publish-20261107')
E=pathlib.Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence')
O=E/'candidate-A-python-499-v1'
HEAD='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
TREE='23c95cb4acfcfd2b1355d9d6e33c4c18b3f332a0'
ENV=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH='scripts/ci:scripts',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git','--no-replace-objects',*args],cwd=R,env=ENV)
def dump(name,value):
 with (O/name).open('x') as f:json.dump(value,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')
def fingerprint(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def read_entry(root_fd,name,mode,oid):
 parts=name.encode().split(b'/');need(all(x not in (b'',b'.',b'..',b'.git') for x in parts),'noncanonical selected path')
 parent=os.dup(root_fd)
 try:
  for part in parts[:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=nxt
  before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
  if mode=='120000':
   need(stat.S_ISLNK(before.st_mode),'tracked symlink type');data=os.readlink(parts[-1],dir_fd=parent)
  else:
   need(stat.S_ISREG(before.st_mode) and bool(before.st_mode&0o111)==(mode=='100755'),'tracked regular source type/mode')
   fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
   with os.fdopen(fd,'rb') as f:
    need(fingerprint(os.fstat(f.fileno()))==fingerprint(before),'source changed before read')
    data=f.read(before.st_size+1)
    need(fingerprint(os.fstat(f.fileno()))==fingerprint(before) and len(data)==before.st_size,'source changed during read')
  need(fingerprint(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))==fingerprint(before),'source path changed')
  actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data,usedforsecurity=False).hexdigest()
  need(actual==oid,'selected bytes differ from A Git blob: '+name)
  return {'path':name,'mode':mode,'git_blob':oid,'bytes':len(data),'sha256':sha(data)}
 finally:os.close(parent)
def snapshot(label,selected,entries):
 need(git('rev-parse','HEAD').decode().strip()==HEAD and git('rev-parse','HEAD^{tree}').decode().strip()==TREE,'source moved from A')
 root_fd=os.open(R,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:rows=[read_entry(root_fd,name,*entries[name]) for name in sorted(selected)]
 finally:os.close(root_fd)
 status=git('status','--porcelain=v1','-z','--untracked-files=all');missing=[]
 for entry in status.split(b'\0'):
  if not entry:continue
  name=entry[3:].decode();need(entry[:3]==b' D ' and name.startswith('evidence/') and name not in selected,'unexpected source/index/worktree drift');missing.append(name)
 value={'schema':'TRNM-W1-SELECTED-A-PYTHON-SOURCE1','candidate':HEAD,'tree':TREE,'files':rows,'missing_historical_evidence':missing,'whole_tracked_worktree_verified':False,'scope':'Exact A Git-blob bytes for all non-evidence source, A publication selected files, corpus source pins and statically resolved W1 fixtures. Missing historical evidence remains explicit; this is not a complete worktree certificate.'}
 dump(label+'.json',value);(O/(label+'-status.bin')).write_bytes(status);return value
def execute(label,args,limit,expected_count=None):
 start=time.monotonic();timed=False
 stdout=O/(label+'.stdout.log');stderr=O/(label+'.stderr.log')
 with stdout.open('xb') as out,stderr.open('xb') as err:
  process=subprocess.Popen(args,cwd=R,env=ENV,stdout=out,stderr=err,start_new_session=True)
  try:code=process.wait(timeout=limit)
  except subprocess.TimeoutExpired:
   timed=True;os.killpg(process.pid,15)
   try:code=process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(process.pid,9);code=process.wait()
 raw=stderr.read_bytes();out=stdout.read_bytes();text=raw.decode(errors='replace')
 counts=[int(x) for x in re.findall(r'(?m)^Ran ([0-9]+) tests? in [0-9.]+s$',text)]
 final_ok=bool(re.search(r'(?m)^OK$',text))
 verbose=[x for x in text.splitlines() if re.match(r'^test_\S+ \(.+\) \.\.\. ',x)]
 success_lines=[x for x in verbose if x.endswith(' ... ok')]
 unexpected=[x for x in verbose if not x.endswith(' ... ok')]
 record={'label':label,'args':args,'timeout_seconds':limit,'expected_tests':expected_count,'exit_code':code,'timed_out':timed,'seconds':time.monotonic()-start,'reported_counts':counts,'final_plain_OK':final_ok,'verbose_test_line_count':len(verbose),'successful_verbose_test_lines':len(success_lines),'non_ok_verbose_lines':unexpected,'stdout_bytes':len(out),'stdout_sha256':sha(out),'stderr_bytes':len(raw),'stderr_sha256':sha(raw)}
 if expected_count is None:record['command_passed']=code==0 and not timed
 else:record['command_passed']=code==0 and not timed and counts==[expected_count] and final_ok and len(verbose)==expected_count and not unexpected
 dump(label+'.json',record);print(json.dumps({'stage':label,'exit_code':code,'timed_out':timed,'reported_counts':counts,'verbose_lines':len(verbose),'command_passed':record['command_passed']}),flush=True);return record
report={'schema':'TRNM-W1-A-DESKTOP-PYTHON-4991','candidate':HEAD,'tree':TREE,'records':[],'all_requested_checks_passed':False,'whole_source_qualified':False,'post_quantum_soundness_qualified':False,'production_qualified':False}
try:
 payload=json.load(sys.stdin);O.mkdir(mode=0o700)
 (O/'executed-controller.py').write_text(payload['driver_source']);report['driver_sha256']=sha(payload['driver_source'].encode())
 entries={}
 for entry in git('ls-tree','-r','-z',HEAD).split(b'\0'):
  if entry:
   metadata,path=entry.split(b'\t',1);mode,kind,oid=metadata.decode().split();need(kind=='blob' and mode in ('100644','100755','120000'),'tracked type');entries[path.decode()]=(mode,oid)
 previous=json.loads((E/'publication-prepare-A-1e4bffc-v1/selected-source-manifest.json').read_text())
 inventory=json.loads((E/'publication-A-fixtures-v1/fixture-inventory.json').read_text())
 pins=json.loads((R/'config/pon/pq-cross-branch-corpus-v1.json').read_text())['pinned_blobs']
 selected={name for name in entries if not name.startswith('evidence/')}|{x['path'] for x in previous}|set(pins)
 selected|={name for name in entries if any(name==p or name.startswith(p+'/') for p in inventory['resolved_fixture_prefixes'])}
 need(selected<=set(entries),'selected path absent from A tree')
 before=snapshot('selected-source-before',selected,entries);report['selected_source_count']=len(selected);report['selected_source_bytes']=sum(x['bytes'] for x in before['files'])
 configs=[
 ('w1-314',['python3','-m','unittest','discover','-s','scripts/ci','-p','test_w1_*.py','-v'],600,314),
 ('ci-contract-source-147',['python3','-m','unittest','-v','test_ci_contract','test_ci_source_integrity'],300,147),
 ('pq-research-38',['python3','-m','unittest','-v','test_pq_research_integration'],300,38)]
 print(json.dumps({'stage':'start-three-exact-groups','selected_source_count':len(selected),'selected_source_bytes':report['selected_source_bytes'],'groups':[{'label':x[0],'expected_tests':x[3],'timeout_seconds':x[2]} for x in configs]}),flush=True)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  futures=[pool.submit(execute,*config) for config in configs]
  report['records']=[f.result() for f in futures]
 for config in [
  ('preflight-dev',['bash','scripts/project-preflight.sh','--dev'],120,None),
  ('preflight-audit',['bash','scripts/project-preflight.sh','--audit'],120,None),
  ('source-pin-check',['python3','scripts/ci/check_pq_research_integration.py'],300,None),
  ('inventory-check',['python3','scripts/refresh_distributed_source_inventory.py','--check'],300,None)]:
  report['records'].append(execute(*config))
 links=[str(p.relative_to(R)) for p in sorted((R/'scripts').rglob('*link*.py')) if p.is_file()]
 report['repository_link_checker_candidates']=links
 after=snapshot('selected-source-after',selected,entries)
 need(before==after,'selected A source/fixture identity changed')
 report['selected_source_and_fixture_before_after_identical']=True
 report['all_three_python_groups_passed']=all(x['command_passed'] for x in report['records'][:3])
 report['all_executed_checks_passed']=all(x['command_passed'] for x in report['records'])
 report['repository_link_check_pending']=True
 report['all_requested_checks_passed']=False
 report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();dump('report.json',report)
 print(json.dumps({k:v for k,v in report.items() if k!='records'}),flush=True)
 need(report['all_executed_checks_passed'],'one or more exact A Python/static checks failed; retained originals')
except BaseException as error:
 report['error']=type(error).__name__+': '+str(error)
 if O.is_dir():
  dump('failure.json',report);(O/'failure-traceback.log').write_text(traceback.format_exc())
 raise
