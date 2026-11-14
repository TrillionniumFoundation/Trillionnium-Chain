import pathlib,os,subprocess,json,hashlib,time,traceback,sys
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114');E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'final-contract-validation-v1';assert not O.exists();O.mkdir()
TMP=O/'canonical-tmp';TMP.mkdir()
env=os.environ.copy();env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0',TMPDIR=str(TMP))
state={'schema':'trnm-policy-prefix-final-contract-validation-v1','status':'HOLD','steps':[],'errors':[],'source_is_uncommitted_component':True,'hosted_qualification':False}
def sha(b):return hashlib.sha256(b).hexdigest()
def put(n,b):
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':sha(b)}
def run(n,a,t=180):
 start=time.time();r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=t)
 state['steps'].append({'label':n,'argv':a,'cwd':str(S),'exit':r.returncode,'timeout_seconds':t,'elapsed_seconds':time.time()-start,'stdout':put(n+'.stdout',r.stdout),'stderr':put(n+'.stderr',r.stderr)})
 assert r.returncode==0,(n,r.returncode,r.stderr.decode(errors='replace')[-2000:]);return r
try:
 run('preflight',['bash','scripts/project-preflight.sh'])
 paths=run('changed-paths-before',['git','diff','--name-only']).stdout.decode().splitlines();assert len(paths)==10
 before={p:{'bytes':len((S/p).read_bytes()),'sha256':sha((S/p).read_bytes())}for p in paths};state['source_before']=before
 corpus=run('actual-corpus',['/opt/homebrew/bin/python3','-B','scripts/ci/check_pq_research_integration.py'])
 c=json.loads(corpus.stdout);assert c['status']=='HOLD_NO_GO' and c['cryptographic_acceptance']is False and c['node_activated']is False
 repo=run('actual-repository-including-ci-contract',['/opt/homebrew/bin/python3','-B','scripts/ci/check_repository.py'])
 r=json.loads(repo.stdout);assert r['result']=='PASS' and r['activation']is False and r['source_state']=='dirty-candidate'
 run('diff-check',['git','diff','--check'])
 after={p:{'bytes':len((S/p).read_bytes()),'sha256':sha((S/p).read_bytes())}for p in paths};assert before==after
 state.update(status='PASS',corpus=c,repository=r,source_after=after,source_before_after_equal=True,prior_helper_name_error_preserved='../final-document-and-corpus-v1/summary.json')
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',(json.dumps(state,indent=2)+'\n').encode())
print(json.dumps({'status':state['status'],'summary':str(O/'summary.json'),'sha256':sha((O/'summary.json').read_bytes()),'errors':state['errors']},indent=2),flush=True)
sys.exit(0 if state['status']=='PASS'else 1)
