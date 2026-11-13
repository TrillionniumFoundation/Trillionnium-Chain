import pathlib,subprocess,os,json,datetime,time,hashlib,resource
ROOT=pathlib.Path('/home/qq/work/chain-rejection-resource-owner-956149-20261108')
OUT=pathlib.Path('/home/qq/work/chain-rejection-resource-owner-956149-results/c1-native');OUT.mkdir(exist_ok=True)
HEAD='8fed7514193e06058f4eaf18f362a8fb968ce96f'
CARGO='/home/qq/.cargo/bin/cargo'
def identity():
 return {k:subprocess.check_output(['git',*v],cwd=ROOT,text=True).strip() for k,v in {'head':['rev-parse','HEAD'],'tree':['rev-parse','HEAD^{tree}'],'status':['status','--porcelain=v1','--untracked-files=all']}.items()}
assert identity()['head']==HEAD and not identity()['status']
env=os.environ.copy();env.update(CARGO_TARGET_DIR='/home/qq/work/chain-rejection-resource-owner-956149-target',CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='1')
base=[CARGO,'test','--manifest-path','trillionnium/Cargo.toml','--locked','--offline','-p','trnm-pon-node']
commands=[
 ('preflight',['bash','scripts/project-preflight.sh']),
 ('source-before',['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',HEAD,'--output',str(OUT/'source-before.json')]),
 ('cargo-fmt',[CARGO,'fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check']),
 ('scalar-cpu',base+['--lib','ingress::public_v3::scalar_cpu','--','--nocapture']),
 ('root-rejection',base+['--lib','store::root_rejection_cache_tests','--','--nocapture']),
 ('r14-profile',base+['--lib','ingress::public_v3::tests::resource_revision_r14_rejects_signed_old_cookies_and_preserves_control_output_reserve','--','--exact','--nocapture']),
 ('native-observers',base+['--test','native_packet_observer','--test','accepted_task_observation','--','--nocapture']),
 ('observer-process-envelope',base+['--bin','trnm-pon-node','packet_observer_cli::tests','--','--nocapture']),
 ('artifact-profiles',base+['--lib','--no-run','--message-format=json']),
 ('strict-workspace-clippy',[CARGO,'clippy','--manifest-path','trillionnium/Cargo.toml','--locked','--offline','--workspace','--all-targets','--all-features','--','-D','warnings']),
 ('source-after',['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',HEAD,'--output',str(OUT/'source-after.json')])]
rows=[]
for name,args in commands:
 before=identity();assert before['head']==HEAD and not before['status']
 log=OUT/(name+'.log');started=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic()
 usage0=resource.getrusage(resource.RUSAGE_CHILDREN)
 with log.open('wb') as f:p=subprocess.run(args,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT)
 usage1=resource.getrusage(resource.RUSAGE_CHILDREN)
 row={'name':name,'argv':args,'cwd':str(ROOT),'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'wall_seconds':time.monotonic()-t,'exit_code':p.returncode,'child_user_cpu_seconds':usage1.ru_utime-usage0.ru_utime,'child_system_cpu_seconds':usage1.ru_stime-usage0.ru_stime,'children_maxrss_highwater_kib':usage1.ru_maxrss,'source_before':before,'source_after':identity(),'log_bytes':log.stat().st_size,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
 rows.append(row);(OUT/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n');(OUT/'summary.json').write_text(json.dumps({'schema':'resource-owner-native-gates-v1','head':HEAD,'environment':{k:env.get(k) for k in ['CARGO_TARGET_DIR','CARGO_BUILD_JOBS','RUST_TEST_THREADS','CARGO_PROFILE_TEST_OPT_LEVEL','RUSTFLAGS']},'results':rows},indent=2)+'\n')
 print(json.dumps({'name':name,'exit':p.returncode,'seconds':round(row['wall_seconds'],3),'log_sha256':row['log_sha256']}),flush=True)
 assert row['source_after']==before,'source changed'
 if name in ['preflight','source-before','source-after'] and p.returncode:raise SystemExit(p.returncode)
print('NATIVE_GATES_COMPLETE',sum(r['exit_code']==0 for r in rows),len(rows),flush=True)
