import datetime,hashlib,json,os,pathlib,signal,subprocess,sys,time
root=pathlib.Path('/home/qian-qi/work/chain-next-architecture-security-20261108-8720')
base=pathlib.Path('/home/qian-qi/work/chain-next-architecture-security-20261108-8720-validation')
label=sys.argv[1]
assert label.replace('-','').isalnum()
out=base/label
out.mkdir(parents=True,exist_ok=False)
env=dict(os.environ)
env.update(PATH='/home/qian-qi/.cargo/bin:'+env.get('PATH',''),CARGO_TARGET_DIR='/home/qian-qi/work/chain-next-architecture-security-20261108-8720-target',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1',CARGO_TERM_COLOR='never',LC_ALL='C')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
env['TRNM_EXPECTED_SOURCE_SHA']=head
records=[]
def run(name,args,timeout=1800):
 start=time.monotonic_ns()
 began=datetime.datetime.now(datetime.timezone.utc).isoformat()
 timed_out=False
 with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
  process=subprocess.Popen(args,cwd=root,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
  try:code=process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   timed_out=True
   os.killpg(process.pid,signal.SIGTERM)
   try:code=process.wait(timeout=10)
   except subprocess.TimeoutExpired:
    os.killpg(process.pid,signal.SIGKILL);code=process.wait(timeout=30)
 elapsed=time.monotonic_ns()-start
 row={'name':name,'args':args,'started_utc':began,'elapsed_wall_ns':elapsed,'exit_code':code,'timeout':timed_out,'source_commit':head}
 for stream in ('stdout','stderr'):
  p=out/(name+'.'+stream);raw=p.read_bytes()
  row[stream]={'path':p.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 records.append(row)
 (out/'commands.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'stage':name,'exit_code':code,'timeout':timed_out,'elapsed_seconds':elapsed/1e9}),flush=True)
 return code==0 and not timed_out
cargo=['cargo','+1.95.0']
test=cargo+['test','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml']
node=test+['-p','trnm-pon-node']
commands=[
 ('preflight',['bash','scripts/project-preflight.sh','--audit']),
 ('cargo-graph',cargo+['metadata','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','--format-version','1']),
 ('format',cargo+['fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check']),
 ('repository',['python3','-B','scripts/ci/check_repository.py']),
 ('source-negative-controls',['python3','-B','scripts/ci/test_ci_source_integrity.py']),
 ('pq-source-composition',['python3','-B','scripts/ci/check_pq_research_integration.py']),
 ('python-controls',['python3','-B','-m','unittest','discover','-s','formal/next-architecture-security','-p','test_*.py','-v']),
 ('exact-research-fixture',['python3','-B','formal/next-architecture-security/counterexamples.py','--check-fixture']),
 ('p2p-complete',test+['-p','trnm-data-availability','--','--test-threads=1']),
 ('native-packet-observer',node+['--test','native_packet_observer','--','--test-threads=1']),
 ('native-node-packet-status',node+['--test','native_node','packet_status','--','--test-threads=1']),
]
for selector in ['test_every_reorg_process_cut_and_admission_gap_recovers_once','test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner','test_confirmed_transfer_is_removed_by_a_real_heavier_fork']:
 commands.append((selector,node+['--test','native_node',selector,'--','--exact','--test-threads=1']))
for selector in ['native_growth_v2_exact_packet_observation','native_growth_v2_packet_observer','native_growth_v2_cold_observer']:
 commands.append((selector,node+['--lib',selector,'--','--test-threads=1']))
commands.extend([
 ('growth-cli-packet-cold',node+['--test','native_growth_cli','native_growth_v2_cli_signed_packet_remote_admission_and_cold_current_snapshot','--','--exact','--test-threads=1']),
 ('hepta-classical-receiver',test+['-p','trnm-research-protocol','--test','protocol_v1','hepta_','--','--test-threads=1']),
 ('hepta-pq-receiver',test+['-p','trnm-research-protocol','--test','hepta_handoff_pq','--','--test-threads=1']),
 ('native-accepted-task',node+['--lib','store::task_observation::tests::','--','--test-threads=1']),
 ('transport-replay',node+['--lib','store::authenticated_replay_tests::','--','--test-threads=1']),
])
for package in ['trnm-data-availability','trnm-pon-node']:
 commands.append(('clippy-'+package,cargo+['clippy','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p',package,'--all-targets','--','-D','warnings']))
for example in ['cell_bep52_cost_v1','cell_rs46_cost_v1']:
 commands.append((example,cargo+['run','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-data-availability','--example',example]))
(out/'planned-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
machine={'schema':'trnm-next-local-machine-v1','source_commit':head,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'architecture':os.uname().machine,'kernel':os.uname().release,'logical_cpus_visible':os.cpu_count(),'physical_memory_visible_bytes':os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES'),'build_jobs':2,'test_threads':1,'profile':'release/default-features','toolchain':subprocess.check_output(['rustc','+1.95.0','-Vv'],env=env,text=True),'cargo':subprocess.check_output(['cargo','+1.95.0','-V'],env=env,text=True),'scope':'shared development host; not original Host root cgroup, independent WAN or product qualification','qualification':'HOLD_NO_GO'}
(out/'machine.json').write_text(json.dumps(machine,indent=2,sort_keys=True)+'\n')
ok=run('source-before',['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',head,'--output',str(out/'source-before.json')],600)
if ok:
 for name,args in commands:
  if not run(name,args):
   ok=False
   break
after=run('source-after',['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',head,'--output',str(out/'source-after.json')],600)
source_equal=(out/'source-before.json').is_file() and (out/'source-after.json').is_file() and (out/'source-before.json').read_bytes()==(out/'source-after.json').read_bytes()
summary={'schema':'trnm-next-component-execution-v1','source_commit':head,'all_planned_commands_completed':len(records)==len(commands)+2,'observed_commands':len(records),'planned_commands':len(commands)+2,'command_success':ok and after,'source_before_after_identical':source_equal,'unexecuted':[name for name,_ in commands if name not in {r['name'] for r in records}],'qualification':'HOLD_NO_GO','original_host_contract_executed':False,'independent_wan_executed':False,'external_hepta_finaluse_executed':False,'pq128_qualified':False,'sustainable_rewards_qualified':False}
(out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,sort_keys=True),flush=True)
sys.exit(0 if ok and after and source_equal else 1)
