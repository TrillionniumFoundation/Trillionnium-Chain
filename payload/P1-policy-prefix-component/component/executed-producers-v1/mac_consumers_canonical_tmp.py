import pathlib,os,subprocess,json,hashlib,time,re,ast,sys,traceback
S=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-20261114');E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'current-consumer-validation-v2'
assert not O.exists();O.mkdir()
TMP=O/'canonical-tmp';TMP.mkdir();assert TMP.resolve()==TMP
env=os.environ.copy();env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0',TMPDIR=str(TMP))
state={'schema':'trnm-policy-prefix-current-consumer-validation-v1','status':'RUNNING','steps':[],'suites':[],'errors':[],'hosted_qualification':False,'canonical_TMPDIR':str(TMP),'prior_environment_failure_preserved':'../current-consumer-validation-v1/summary.json'}
def sha(b):return hashlib.sha256(b).hexdigest()
def put(n,b):
 (O/n).write_bytes(b);return {'path':str(O/n),'bytes':len(b),'sha256':sha(b)}
def run(n,a,t=180):
 start=time.time();r=subprocess.run(a,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=t)
 state['steps'].append({'label':n,'argv':a,'cwd':str(S),'timeout_seconds':t,'elapsed_seconds':time.time()-start,'exit':r.returncode,'stdout':put(n+'.stdout',r.stdout),'stderr':put(n+'.stderr',r.stderr)})
 assert r.returncode==0,(n,r.returncode,r.stderr.decode(errors='replace')[-2000:])
 return r
try:
 run('preflight',['bash','scripts/project-preflight.sh'])
 paths=['config/pon/pq128-source-correspondence-current-v2.json','scripts/ci/pq_lifetime_current_v2.py','config/pon/pq128-lifetime-composition-current-v3.json','scripts/ci/pq_lifetime_composition.py','trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs']
 before={p:{'bytes':len((S/p).read_bytes()),'sha256':sha((S/p).read_bytes())}for p in paths};state['source_before']=before
 for label,path,expected in [('original-frozen-budget-58','scripts/ci/test_pq_lifetime_budget.py',58),('original-current-correspondence-25','scripts/ci/test_pq_lifetime_current_v2.py',25),('original-current-composition-60','scripts/ci/test_pq_lifetime_composition.py',60),('original-direct-chain-claim-guard','scripts/ci/test_pq_chain_claim_guard.py',None)]:
  raw=(S/path).read_bytes();orig=run(label+'-original',['git','show','HEAD:'+path]).stdout;assert raw==orig
  methods=[n.name for n in ast.walk(ast.parse(raw))if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')]
  r=run(label,['/opt/homebrew/bin/python3','-B',path,'-v'])
  text=r.stderr.decode();m=re.search(r'Ran (\d+) tests? in ',text);assert m and re.search(r'\nOK\s*$',text) and 'skipped='not in text,text[-2000:]
  count=int(m.group(1));assert count==(expected if expected is not None else len(methods)),(label,count,len(methods))
  state['suites'].append({'label':label,'path':path,'test_file_unchanged_from_M8':True,'sha256':sha(raw),'original_methods':methods,'passed':count,'failed':0,'skipped':0})
 for label,path in [('actual-current-correspondence','scripts/ci/pq_lifetime_current_v2.py'),('actual-current-composition','scripts/ci/pq_lifetime_composition.py'),('actual-chain-claim-guard','scripts/ci/pq_chain_claim_guard.py')]:
  r=run(label,['/opt/homebrew/bin/python3','-B',path]);data=json.loads(r.stdout)
  assert data.get('production_activation') is False,(label,data.get('production_activation'))
  assert data.get('status') in ('HOLD','HOLD_NO_GO'),(label,data.get('status'))
  state[label]={'status':data['status'],'production_activation':False,'stdout_sha256':sha(r.stdout)}
 after={p:{'bytes':len((S/p).read_bytes()),'sha256':sha((S/p).read_bytes())}for p in paths};assert before==after;state['source_after']=after
 state['status']='PASS';state['total_passed']=sum(x['passed']for x in state['suites'])
except BaseException as exc:state['status']='HOLD';state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
put('summary.json',(json.dumps(state,indent=2)+'\n').encode())
print(json.dumps({'status':state['status'],'suites':[{'label':x['label'],'passed':x['passed']}for x in state['suites']],'total':state.get('total_passed'),'summary':str(O/'summary.json'),'sha256':sha((O/'summary.json').read_bytes()),'errors':state['errors']},indent=2),flush=True)
sys.exit(0 if state['status']=='PASS'else 1)
