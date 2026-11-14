import os,sys,json,stat,hashlib,time,datetime,collections,re
from pathlib import Path
ROOT=Path('/private/tmp/chain-consolidation-20261114-root')
OUT=ROOT/'H5DF-required-ci-progress-v1-ready-003-offline-delta-v1'
OLD=ROOT/'H5DF-required-ci-progress-v1-ready-002'
NEW=ROOT/'H5DF-required-ci-progress-v1-ready-003'
LAUNCH=ROOT/'H5DF-required-ci-progress-ready003-launch-v1'
H='5df7ae6f482157c5f7fdcbcd52222117a965053f'
RID=43621754143
READS={}
def need(c,m):
    if not c: raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,n=None,h=None):
    p=Path(path)
    need(p.is_absolute() and p.resolve(strict=True)==p,'noncanonical evidence')
    before=p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=16*1024*1024,'evidence type/size')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        with os.fdopen(fd,'rb') as f:
            need(ident(os.fstat(f.fileno()))==ident(before),'opened identity changed')
            raw=f.read(16*1024*1024+1)
            need(ident(os.fstat(f.fileno()))==ident(before),'read identity changed')
    finally:pass
    need(ident(p.lstat())==ident(before) and len(raw)==before.st_size,'evidence changed')
    need(n is None or len(raw)==n,'bytes differ '+str(p))
    need(h is None or sha(raw)==h,'hash differs '+str(p))
    rec={'path':str(p),'bytes':len(raw),'sha256':sha(raw),'version':list(ident(before))}
    if str(p) in READS:need(READS[str(p)]==rec,'reread changed')
    READS[str(p)]=rec
    return raw
def load(pin):
    return json.loads(read(pin['path'],pin['bytes'],pin['sha256']))
def P(p,n,h):return {'path':str(p),'bytes':n,'sha256':h}
def put(name,value):
    p=OUT/name
    raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return P(p,len(raw),sha(raw))
need(not OUT.exists(),'create-only directory exists')
OUT.mkdir(mode=0o700)
producer=put('producer.py',sys.argv[1].encode())
def audit(event,args):
    if event in ('subprocess.Popen','os.system','os.posix_spawn','os.posix_spawnp','os.exec','os.fork','os.forkpty') or event.startswith('socket.'):
        raise PermissionError('offline review disallows '+event)
sys.addaudithook(audit)
oldpin=P(OLD/'summary.json',14262,'222d90ad169c08fc1a73a91f042169fa88bd005197d69587945af03c5c65e005')
newpin=P(NEW/'summary.json',14327,'e15256e1a2369b12dae1a29bef7d0864e4511f4de10a235f8ecb7570a517cf66')
old=load(oldpin);new=load(newpin)
idxpin=P(NEW/'EVIDENCE_INDEX.json',4375,'e3dc3b64d61a9cacd5f5d57c3b39a49b277e931c0eab2c68cbed5ff90c74e21c')
idx=load(idxpin)
for q in idx['files']:
    need(Path(q['path']).parent==NEW,'current index scope')
    read(q['path'],q['bytes'],q['sha256'])
priorpin=P('/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1/ready002-offline-delta-v1/progress-delta.json',14248,'a4c6ce54752a2633e3f0d75a50fe02bbf94e2b67c5e7c840a729a556d519707f')
prior=load(priorpin)
term_pin=P(LAUNCH/'actual-terminal.json',6155,'a6715bc25f3967c97e15973a83e2d42582bb8e7baa1d15b9d8ce5640fc084e71')
term=load(term_pin);page=term['pages'][0]
need(len(term['pages'])==1 and term['complete'] is True,'terminal completeness')
need(page['status']['state']=='exited' and page['status']['exit_code']==0 and page['output_complete'] is True and page['offset']==0 and page['next_offset']==page['available_end']==1419,'actual terminal')
need(page['session_id']=='dpty-86c0fec36a041c346073508112ea8591a3d6680efce307fafb6d0811d2afc54e','session')
terminal_raw=bytes.fromhex(page['bytes_hex'])
need(sha(terminal_raw)==page['chunk_sha256']=='34b5a73e3be5980abbd95cc0f72d357d382dce0a99d0191b6c2e0f01f23bfc5f','terminal raw')
for name in ('launcher.py','pinned-collector.py.original','launch.json','pin-check.json','result.json'):
    read(LAUNCH/name)
need(READS[str(LAUNCH/'pinned-collector.py.original')]['sha256']=='3f50aa71fa06f37e64c1ed1e669ad1b1b45ebe27acfddb5004957ef3a43c68fb','pinned source')
need(new['status']==old['status']=='OBSERVED' and not new['errors'] and len(new['steps'])==6 and all(s['exit']==0 and not s['timed_out'] and s['argv'][3]=='GET' for s in new['steps']),'collector actual GET closure')
need(new['metadata_pages_complete'] is True and new['hosted_qualification_granted'] is False,'metadata closure')
orun=old['required_runs']['run_jobs'][0];nrun=new['required_runs']['run_jobs'][0]
for r in (orun,nrun):
    need(r['run_id']==RID and r['observed_attempt']==1 and r['metadata']['head_sha']==H and r['metadata']['path']=='.github/workflows/trnm-required-baseline.yml' and r['metadata']['event']=='pull_request','run identity')
ojobs=load(orun['jobs']);njobs=load(nrun['jobs'])
ocheck=load(old['latest_checks']['normalized']);ncheck=load(new['latest_checks']['normalized'])
need(len(ojobs)==len(njobs)==19 and len(ocheck)==len(ncheck)==165,'known complete counts')
need(all(j['head_sha']==H and j['run_id']==RID and j['run_attempt']==1 for j in njobs),'jobs metadata identity')
need(all(c['head_sha']==H for c in ncheck),'checks metadata identity')
need(prior['run_id']==RID and prior['attempt']==1 and len(prior['required'])==14 and len({r['name'] for r in prior['required']})==14,'prior exact14 map')
def state(row):
    if row is None:return 'absent'
    return 'running' if row['status']=='in_progress' else ('queued' if row['status']=='queued' else str(row['conclusion']))
def brief(row):
    return {k:row.get(k) for k in ('id','name','status','conclusion','started_at','completed_at','html_url')}
required=[]
for oldrow in prior['required']:
    rows=[j for j in njobs if j['name']==oldrow['name']]
    need(len(rows)<=1,'ambiguous required job')
    j=rows[0] if rows else None
    r={'name':oldrow['name'],'source_kind_name_hint':oldrow['source_kind_name_hint'],'job_id':j['id'] if j else None,'state':state(j),'actual_tested_source_verified':False,'actual_tested_commit':None,'actual_tested_tree':None}
    if j:
        r.update({k:j[k] for k in ('status','conclusion','started_at','completed_at','html_url')})
        r['current_steps']=[s for s in j['steps'] if s['status']=='in_progress']
        r['failed_steps']=[s for s in j['steps'] if s['conclusion']=='failure']
    required.append(r)
changes=[]
for before,after in zip(prior['required'],required):
    keys=('name','job_id','state')
    if any(before.get(k)!=after.get(k) for k in keys):
        changes.append({'before':before,'after':after})
requirednames={r['name'] for r in required}
failedjobs=[]
for j in njobs:
    if j['conclusion'] in ('failure','cancelled'):
        r=brief(j);r['within_required14']=j['name'] in requirednames
        r['failed_steps']=[s for s in j['steps'] if s['conclusion'] in ('failure','cancelled')]
        r['actual_tested_source_verified']=False
        failedjobs.append(r)
oldchecks={c['id']:c for c in ocheck}
newchecks={c['id']:c for c in ncheck}
def cb(c):
    r={k:c.get(k) for k in ('id','name','status','conclusion','started_at','completed_at','details_url','html_url')}
    r['app_id']=c['app']['id']
    r['metadata_head_sha']=c['head_sha']
    r['actual_tested_source_verified']=False
    url=c.get('details_url') or c.get('html_url') or ''
    m=re.search(r'/actions/runs/([0-9]+)/job/([0-9]+)',url)
    r['run_id_from_url']=int(m.group(1)) if m else None
    r['job_id_from_url']=int(m.group(2)) if m else None
    r['required14_name_match']=c['name'] in requirednames
    return r
checkchanges=[]
for c in ncheck:
    oldc=oldchecks.get(c['id'])
    if oldc is None or (oldc['status'],oldc['conclusion'])!=(c['status'],c['conclusion']):
        checkchanges.append({'before':cb(oldc) if oldc else None,'after':cb(c)})
for rec in READS.values():
    p=Path(rec['path']);need(p.resolve(strict=True)==p and list(ident(p.lstat()))==rec['version'],'final input fence')
summary={'schema':'trnm-H5DF-ready003-offline-delta-v1','status':'OBSERVED_METADATA_ONLY',
 'closed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'original_summary':newpin,'original_index':idxpin,'previous_summary':oldpin,'previous_required14_mapping':priorpin,
 'actual_terminal':term_pin,'actual_exit':0,'actual_terminal_bytes':1419,'actual_terminal_chunk_sha256':page['chunk_sha256'],
 'snapshot_start':new['started_at'],'snapshot_end':new['finished_at'],'previous_snapshot_start':old['started_at'],'previous_snapshot_end':old['finished_at'],
 'run_id':RID,'attempt':1,'run_metadata':nrun['metadata'],'PR':new['pr'],
 'required':required,'required_counts':dict(collections.Counter(r['state'] for r in required)),'required_changes_since_ready002':changes,
 'all_run_job_count':len(njobs),'all_run_job_counts':nrun['observed_attempt_job_counts'],
 'jobs_normalized_bytes_identical_to_ready002':orun['jobs']['sha256']==nrun['jobs']['sha256'],
 'all_failed_or_cancelled_run_jobs':failedjobs,
 'latest_checks_count':len(ncheck),'latest_check_counts':new['latest_checks']['status_counts'],
 'previous_latest_check_counts':old['latest_checks']['status_counts'],
 'app15368_counts':new['latest_checks']['app15368_status_counts'],
 'latest_checks_changes_since_ready002':checkchanges,
 'latest_check_ids_added':sorted(set(newchecks)-set(oldchecks)),
 'latest_check_ids_removed':sorted(set(oldchecks)-set(newchecks)),
 'latest_failed_or_cancelled_checks':[cb(c) for c in ncheck if c['conclusion'] in ('failure','cancelled')],
 'raw_GET_exits':[{'label':s['label'],'exit':s['exit']} for s in new['steps']],
 'metadata_pages_complete':True,'current_index_all_files_hash_verified':True,'stable_input_fence':True,
 'source_kind_labels_are_metadata_hints_only':True,'actual_tested_source_verified':False,'qualification':False,
 'no_network_or_subprocess_in_offline_review':True,'no_source_Git_ref_index_stage_or_config_writes':True,
 'no_log_or_artifact_expansion':True,'no_R1_N_N2_status_inherited':True,
 'prior_PR_body_not_required':True,'inputs':list(READS.values())}
sp=put('progress-delta.json',summary)
ip=put('EVIDENCE_INDEX.json',{'schema':'trnm-offline-CI-delta-evidence-index-v1','files':[producer,sp],'inputs':list(READS.values()),'self_excluded':True})
print(json.dumps({'summary':sp,'index':ip,'required_counts':summary['required_counts'],'required_changed':len(changes),'latest_checks':summary['latest_check_counts'],'new_failures':[x['after'] for x in checkchanges if x['after']['conclusion'] in ('failure','cancelled')],'failed_jobs':failedjobs},sort_keys=True),flush=True)
