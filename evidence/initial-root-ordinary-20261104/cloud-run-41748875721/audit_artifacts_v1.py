from pathlib import Path, PurePosixPath
import ast, collections, csv, hashlib, io, json, os, re, shlex, stat, sys, textwrap, traceback, zipfile
OUT=Path('/home/qian-qi/work/chain-initial-root-cloud-41748875721-audit')
PINS={'head':'4c46eca89a006616e9240d983c66919071f79b41','merge':'e0f831d0af21cc9eea69b5ec84788ef66e0b025c','base':'2e72a989d001cf51bd0aed0e1401526e45db31f1','tree':'a32c5e3b169370b1c923bb9a6ef7094a3d3ef041','harness':'01404de030c0d560e32a4b86620cea027878d2df','harness_tree':'66cf0419c2b654ebf77ff655fc3342588e1ddb83','workflow_sha256':'af6f66151bba9dc3d7d58218b2dbf84b570e75cd2acc2eec86b165200f8d5983'}
CPU=['store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner','store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator']
LIFETIME=['ingress::public_v2::tests::public_loop_exit_records_lifetime_before_internal_stop','ingress::public_v2::tests::public_loop_exit_records_external_stop_after_signed_read']
BUILD=['cargo','+1.95.0','test','--locked','--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets','--all-features','--no-run','--message-format=json']
EXPECTED_ROWS=[
(13285312643,'ubuntu-24.04','head',126308679902,302305,'db3c36eeb85f3d25d4c3c265c12e5c19233722388d25126fc1970d4ee6da40a0'),
(13285398555,'ubuntu-24.04','prospective-merge',126308679928,302532,'0ed10048afd1a9eb5a6c985972f544e31f78318d3d98b92f290913e6b68b708a'),
(13285472881,'ubuntu-24.04-arm','head',126308679850,302055,'528fdcd6627a7d73fdc5c9e6a8a0a0346bd34e27bf1071eb7542a60ebb800ca4'),
(13285614471,'ubuntu-24.04-arm','prospective-merge',126308679673,302200,'0723ed3296af00718bc2d84f7575a3adbb75be11aefa49c170814c2f561a5e61')]
def need(v,msg):
 if not v:raise AssertionError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def write_json(path,v):
 raw=(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
 with path.open('xb') as f:f.write(raw)
 return {'path':str(path),'size':len(raw),'sha256':sha(raw)}
fd=os.open(OUT/'artifact-audit-v1.once.lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
inp=json.load(sys.stdin)
with (OUT/'audit_artifacts_v1.py').open('x') as f:f.write(inp.pop('auditor_source'))
write_json(OUT/'audit-input-v1.json',inp)
def parsed_objects(t):
 out=[]
 for line in t.splitlines():
  start=line.find('{')
  if start<0:continue
  try:o=json.loads(line[start:])
  except json.JSONDecodeError:continue
  if isinstance(o,dict):out.append(o)
 return out
def parse_resources(t):
 command=re.search(r'^\s*Command being timed: "(.*)"\s*$',t,re.M);need(command is not None,'missing time command')
 fields={}
 for line in t.splitlines():
  line=line.strip()
  for key in ['User time (seconds)','System time (seconds)','Percent of CPU this job got','Elapsed (wall clock) time (h:mm:ss or m:ss)','Maximum resident set size (kbytes)','Exit status']:
   if line.startswith(key+':'):fields[key]=line[len(key)+1:].strip()
 need(fields.get('Exit status')=='0','resource native exit not zero')
 return shlex.split(command.group(1)),fields
def registry(t):
 names=re.findall(r'^([A-Za-z_][A-Za-z0-9_:]*): test$',t,re.M)
 need(names and len(names)==len(set(names)),'registry empty/duplicate');return set(names)
def tsv(t):return list(csv.DictReader(io.StringIO(t),delimiter='\t'))
def check_exit_rows(rows,expected,columns):
 need(len(rows)==len(expected),'exit row count')
 for row,want in zip(rows,expected):
  need(all(row.get(k)==v for k,v in want.items()),'exit selector identity')
  need(all(row.get(k)=='0' for k in columns),'recorded nonzero native/log/reader')
try:
 run=inp['run']
 need(run['id']==41748875721 and run['status']=='completed' and run['conclusion']=='success','run terminal')
 need(run['run_attempt']==1 and run['event']=='push' and run['head_sha']==PINS['harness'],'run attempt/source/event')
 need(run['head_branch']=='test/chain-history-initial-root-normal-20261103','run branch')
 need(inp['jobs']['total_count']==4,'job count')
 jobs={j['id']:j for j in inp['jobs']['jobs']}
 for row in EXPECTED_ROWS:
  job=jobs[row[3]]
  need(job['status']=='completed' and job['conclusion']=='success' and job['run_id']==run['id'],'job terminal')
  need(row[1] in job['name'] and row[2] in job['name'],'job lane identity')
  need(all(s['conclusion']=='success' for s in job['steps'] if s['name'].startswith(('Build the original','Execute both','Execute the original','Verify the eight','Recheck the same','Reverify exact source'))),'required step status')
 git=inp['git_objects']
 for key,sha_key,tree in [('H','head',PINS['tree']),('M','merge',PINS['tree']),('S','harness',PINS['harness_tree'])]:
  need(git[key]['sha']==PINS[sha_key] and git[key]['tree']['sha']==tree,'Git object tree '+key)
 need([x['sha'] for x in git['M']['parents']]==[PINS['base'],PINS['head']],'actual merge ordered parents')
 need([x['sha'] for x in git['S']['parents']]==[PINS['head']],'harness parent')
 harness_path=Path('/home/qian-qi/work/chain-initial-root-cloud-harness-recovery-20261104/chain_initial_root_normal_20261103.final.yml')
 harness=harness_path.read_bytes();need(sha(harness)==PINS['workflow_sha256'],'independent final workflow hash')
 m=re.search(r"<<'PYREGISTRY'\n(.*?)\n        PYREGISTRY",harness.decode(),re.S)
 need(m is not None,'trusted registry source block')
 specifications=[]
 for node in ast.parse(textwrap.dedent(m.group(1))).body:
  if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id in ('prefix','exact'):
   specifications.append((node.value.func.id,[ast.literal_eval(a) for a in node.value.args]))
 need(len(specifications)==12,'semantic selection groups')
 lanes=[]
 for artifact_id,runner,kind,job_id,size,digest in EXPECTED_ROWS:
  official=json.loads((OUT/f'artifact-{artifact_id}.official.json').read_text())
  need(official['id']==artifact_id and not official['expired'] and official['workflow_run']['id']==run['id'],'official artifact identity')
  need(official['workflow_run']['head_sha']==PINS['harness'] and official['digest']=='sha256:'+digest and official['size_in_bytes']==size,'official artifact binding/digest')
  zipped=(OUT/f'artifact-{artifact_id}.zip').read_bytes()
  need(len(zipped)==size and sha(zipped)==digest,'local complete ZIP size/hash')
  members={}
  with zipfile.ZipFile(io.BytesIO(zipped)) as z:
   infos=z.infolist();need(len(infos)<4096 and sum(i.file_size for i in infos)<256*1024*1024,'ZIP read bounds')
   for info in infos:
    p=PurePosixPath(info.filename)
    need(not p.is_absolute() and '..' not in p.parts and '\\' not in info.filename,'ZIP path')
    need(stat.S_IFMT(info.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR),'ZIP link/type')
    need(info.filename not in members,'ZIP duplicate member')
    if info.is_dir():continue
    data=z.read(info);need(len(data)==info.file_size and not data.startswith(b'\x7fELF'),'ZIP member/ELF presence')
    members[info.filename]=data
  need(len(members)==433,'original artifact member count')
  used=set()
  def raw(name):used.add(name);return members[name]
  def txt(name):return raw(name).decode('utf-8')
  def js(name):return json.loads(txt(name))
  def zero(name):need(txt(name).strip()=='0','nonzero exit '+name)
  before=js('source-before.json');after=js('source-after.json');need(before==after,'source identity changed')
  tested=PINS['head'] if kind=='head' else PINS['merge']
  need(before['kind']==kind and before['tested_commit']==tested and before['tested_tree']==PINS['tree'] and before['candidate']==PINS['head'],'source pin')
  need(before['tracked_worktree_verified'] is True and before['tests_executed_by_identity_check'] is False,'source verification scope')
  need(before['tracked_entries']==6862 and before['tracked_bytes']==784979280,'tracked source inventory')
  if kind=='head':need(before['base'] is None and before['prospective_merge'] is None,'head source fields')
  else:need(before['base']==PINS['base'] and before['prospective_merge']==PINS['merge'],'merge source fields')
  wh=js('workflow-harness.json')
  need(wh['harness_commit']==PINS['harness'] and wh['github_workflow_sha']==PINS['harness'] and wh['harness_parents']==[PINS['head']],'harness immutable identity')
  need(wh['harness_delta']==['A\t.github/workflows/pon-pinned-history-initial-root-normal.yml'],'harness sole file')
  need(wh['harness_workflow_sha256']==PINS['workflow_sha256'] and wh['harness_ref']=='refs/heads/test/chain-history-initial-root-normal-20261103','harness bytes/ref')
  need(wh['candidate']==PINS['head'] and wh['base']==PINS['base'] and wh['prospective_merge']==PINS['merge'],'harness source pins')
  need(wh['tested_commit']==tested and wh['tested_tree']==PINS['tree'] and wh['candidate_tree']==PINS['tree'] and wh['expected_prospective_merge_tree']==PINS['tree'],'harness source trees')
  if kind=='prospective-merge':need(wh['prospective_merge_tree']==PINS['tree'] and wh['prospective_merge_parents']==[PINS['base'],PINS['head']],'harness actual ordered merge')
  else:need(wh['prospective_merge_tree'] is None and wh['prospective_merge_parents'] is None,'head merge inspection scope')
  cmd=js('build-command.json')
  need(cmd['argv']==BUILD and cmd['process_measurement_wrapper']==['/usr/bin/time','-v'],'original complete workspace command')
  env=cmd['environment']
  need({k:env[k] for k in ['CI','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','RUST_TEST_THREADS']}=={'CI':'true','CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','RUST_TEST_THREADS':'1'},'original build environment')
  for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTC_BOOTSTRAP','RUSTDOC','RUSTDOCFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER']:need(env.get(k) is None,'override '+k)
  need(not any(k.startswith('CARGO_PROFILE_') for k in env),'profile override')
  need(not any(v for k,v in env.items() if k.startswith('CARGO_TARGET_') and k!='CARGO_TARGET_DIR'),'target override')
  need(env['TRNM_PQ_OPENSSL_VERSION']=='3.5.9' and env['OPENSSL_STATIC']=='1' and env['OPENSSL_CONF']=='/dev/null','original PQ provider config')
  expected_profiles={'trnm-pon-node':{'opt-level':3,'debug-assertions':True,'overflow-checks':True},'trnm-mvcc-fee':{'opt-level':1,'debug-assertions':True,'overflow-checks':True}}
  need(cmd['test_profile_packages']==expected_profiles,'original package test profiles')
  for n in ['build.exit','build-input-check.exit','build-artifact-check.exit','binary-before.exit','binary-after.exit','m06-binary-after.exit','test-step.exit','semantic-controls/registry-check.exit','semantic-controls/semantic-step.exit','protocol-controls/registry.exit']:zero(n)
  for n in ['build-input-check.stderr','build-artifact-check.stderr','semantic-controls/registry-check.stderr']:need(raw(n)==b'','nonempty verifier error '+n)
  rows=[json.loads(l) for l in txt('build.jsonl').splitlines() if l.strip()]
  need([x for x in rows if x.get('reason')=='build-finished']==[{'reason':'build-finished','success':True}],'Cargo build finished')
  buildargv,buildresources=parse_resources(txt('build.resources.txt'));need(buildargv==BUILD,'time recorded build command')
  target=PurePosixPath(env['CARGO_TARGET_DIR'])/'debug/deps';binaries={}
  for crate,package,artifactname,opt,features in [('node','trnm-pon-node','trnm_pon_node','3',['default','pq-native-openssl']),('m06','trnm-mvcc-fee','trnm_mvcc_fee','1',['default','pq-native-openssl']),('protocol','trnm-protocol','trnm_protocol','3',[])]:
   filename={'node':'binary.json','m06':'m06-binary.json','protocol':'protocol-controls/binary.json'}[crate]
   receipt=js(filename);a=receipt['artifact']
   selected=[x for x in rows if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')==artifactname and x['target'].get('kind')==['lib'] and x.get('profile',{}).get('test') is True and x.get('executable')]
   need(selected==[a],'unique same-build library test ELF '+crate);need(a['features']==features,'features '+crate)
   need(a['profile']=={'opt_level':opt,'debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':True},'test profile '+crate)
   exe=a['executable'];package_cwd=str(PurePosixPath(a['manifest_path']).parent)
   need(PurePosixPath(exe).is_absolute() and PurePosixPath(exe).parent==target,'test artifact target')
   need(package_cwd.endswith('/trillionnium/crates/'+package) and a['target']['src_path']==package_cwd+'/src/lib.rs','actual test library source')
   need(re.fullmatch('[0-9a-f]{64}',receipt['sha256']) is not None,'recorded ELF digest')
   if crate!='node':need(receipt['package_cwd']==package_cwd,'package cwd receipt')
   if crate=='m06':
    deps=[x for x in rows if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')==artifactname and x['target'].get('kind')==['lib'] and x.get('profile',{}).get('test') is False and not x.get('executable')]
    need(deps==[receipt['dependency_artifact']],'M06 dependency from same build')
    need(deps[0]['profile']['opt_level']=='1' and deps[0]['features']==features,'M06 dependency profile/features')
   expected_line=receipt['sha256']+'  '+exe
   hashfiles={'node':['binary.sha256','binary-before.sha256','binary-after.sha256','semantic-controls/node-binary-before.sha256'],'m06':['m06-binary.sha256','m06-binary-after.sha256','semantic-controls/m06-binary-before.sha256'],'protocol':['protocol-controls/binary-before.sha256','protocol-controls/binary-after.sha256']}[crate]
   need(all(txt(n).strip()==expected_line for n in hashfiles),'recorded ELF before/after identity '+crate)
   if crate in ('node','m06'):
    basename='binary' if crate=='node' else 'm06-binary'
    need(txt(basename+'.txt').strip()==exe,'ELF path receipt')
    need(txt('semantic-controls/'+crate+'-cwd.txt').strip()==package_cwd,'registry cwd')
   binaries[crate]={'executable':exe,'sha256':receipt['sha256'],'profile':a['profile'],'features':features,'package_cwd':package_cwd,'build_artifact':a}
  need(len({b['executable'] for b in binaries.values()})==3,'distinct test ELFs')
  check=js('build-artifact-check.json')
  need(check['result']=='PASS' and check['binary_sha256']==binaries['node']['sha256'] and check['m06_binary_sha256']==binaries['m06']['sha256'],'build ELF result receipt')
  need(check['node_opt_level']=='3' and check['m06_opt_level']=='1' and check['debug_assertions'] and check['overflow_checks'] and check['features']==['default','pq-native-openssl'],'build profile check')
  rustc=txt('rustc.txt');cargo=txt('cargo.txt');arch='aarch64-unknown-linux-gnu' if runner.endswith('-arm') else 'x86_64-unknown-linux-gnu'
  need('rustc 1.95.0' in rustc and 'host: '+arch in rustc and 'cargo 1.95.0' in cargo,'native toolchain architecture')
  need(txt('rustc-path.txt').strip()==cmd['rustc_selected_by_rustup'],'selected rustc receipt')
  provider=js('pq-provider/provider.json')
  need(txt('test-cwd.txt').strip()==binaries['node']['package_cwd'],'original CPU/lifetime package cwd')
  tests=[]
  def check_test(crate,group,selector,prefix,cwd_file=None):
   b=binaries[crate];text=txt(prefix+'.log')
   reports=re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$',text,re.M)
   need(len(reports)==1 and reports[0][:5]==('ok','1','0','0','0'),'actual single native PASS '+selector)
   need(len(re.findall(r'^running 1 test$',text,re.M))==1,'actual native denominator '+selector)
   need(len(re.findall(r'^test '+re.escape(selector)+r' \.\.\. ',text,re.M))==1,'actual named native execution '+selector)
   need(bool(re.search(r'^test '+re.escape(selector)+r' \.\.\. ok$',text,re.M) or re.search(r'\nok\n\s*\ntest result: ok\.',text)),'native ok marker '+selector)
   receipt=js(prefix+'.execution.json')
   need(receipt=={'executed_tests':1,'result':'PASS','scope':'named-libtest-execution-only','test':selector},'named reader receipt '+selector)
   need(raw(prefix+'.execution.stderr')==b'','native reader stderr '+selector)
   argv,resources=parse_resources(txt(prefix+'.resources.txt'))
   need(argv==[b['executable'],selector,'--exact','--nocapture','--test-threads=1'],'actual native command/ELF '+selector)
   if cwd_file:need(txt(cwd_file).strip()==b['package_cwd'],'actual native cwd '+selector)
   tests.append({'crate':crate,'group':group,'selector':selector,'passed':1,'failed':0,'ignored':0,'measured':0,'filtered':int(reports[0][5]),'elapsed_seconds':reports[0][6],'log':prefix+'.log','log_sha256':sha(raw(prefix+'.log')),'execution_receipt_sha256':sha(raw(prefix+'.execution.json')),'resources_sha256':sha(raw(prefix+'.resources.txt')),'binary_sha256':b['sha256'],'command':argv,'package_cwd':b['package_cwd'],'resources':resources})
   return text
  check_exit_rows(tsv(txt('test-exits.tsv')),[{'selector':s} for s in CPU+LIFETIME],['native_exit','log_exit','reader_exit'])
  cpu_observations=[];lifetime_observations=[]
  for index,selector in enumerate(CPU+LIFETIME):
   prefix=selector.rsplit('::',1)[-1]
   log=check_test('node','cpu' if index<2 else 'lifetime',selector,prefix,'test-cwd.txt')
   objects=parsed_objects(log)
   if index>=2:lifetime_observations.append({'selector':selector,'structured_records':objects});continue
   diagnostics=[o for o in objects if o.get('schema')=='native-large-parent-original-dispatch-diagnostic-v1']
   parities=[o for o in objects if o.get('schema')=='native-large-parent-schedule-parity-v1']
   stages=[o for o in objects if o.get('schema')=='native-large-parent-arithmetic-stages-v1']
   expected=[False,True] if index==0 else [True]
   need([d['authenticated_backend'] for d in diagnostics]==expected,'original CPU backend denominator')
   need([d['authenticated_backend'] for d in parities]==expected and [d['authenticated_backend'] for d in stages]==expected,'CPU complete original records')
   for diagnostic,parity,stage in zip(diagnostics,parities,stages):
    need(diagnostic['original_dispatch_result']=={'Ok':'ok'} and parity['native_result']=={'Ok':'ok'},'outer/inner CPU acceptance')
    need(diagnostic['refusal_readback_error'] is None and diagnostic['active_state_unchanged_on_refusal'] is None,'CPU refusal observation')
    need(diagnostic['complete_key_utf8_and_canonical_value_bytes']==8625548 and diagnostic['observed_held_capacity_lower_bound_bytes']==8391103,'original legal large State')
    need(parity['host_qualified'] is False and parity['all_honest_service_qualified'] is False,'original scope qualification')
    for point in ['before','after']:
     budget=diagnostic['cpu_budget_'+point]
     need({k:budget[k] for k in ['burst_ns','refill_ns_per_second','start_reserve_ns','worker_limit']}=={'burst_ns':2000000000,'refill_ns_per_second':250000000,'start_reserve_ns':100000000,'worker_limit':2},'unchanged original CPU budget')
     need(budget['accounting_unavailable'] is False and budget['in_flight']==0,'settled original budget')
    b=diagnostic['actual_cpu_flow_before'];a=diagnostic['actual_cpu_flow_after']
    need(b['paid_cpu_debit_ns']==0 and b['credited_refill_ns']==0 and b['remaining_paid_credit_ns']==2000000000,'initial CPU balance')
    need(a['balance_identity_verified'] is True and a['initial_credit_ns']+a['credited_refill_ns']-a['paid_cpu_debit_ns']==a['remaining_paid_credit_ns'],'independent paid CPU balance arithmetic')
    need(a['remaining_paid_credit_ns']==a['stored_credit_ns']==diagnostic['cpu_budget_after']['stored_credit_ns'] and a['remaining_paid_credit_ns']>0,'positive settled CPU credit')
    need(a['live_owners']==0 and a['booked_reservation_ns']==0 and a['unsettled_known_live_cpu_ns']==0,'no outstanding CPU owner')
    cpu=parity['original_cpu_receipt']
    need(cpu['total_cpu_ns']==a['paid_cpu_debit_ns']==a['settled_full_cpu_ns'],'full settled paid CPU')
    need(cpu['owner_cpu_ns']+cpu['scoped_worker_cpu_ns']==cpu['total_cpu_ns'],'owner+worker CPU arithmetic')
    need(cpu['live_paid_cpu_ns']+cpu['residual_cpu_ns']==cpu['total_cpu_ns'],'live+residual CPU arithmetic')
    need(cpu['accounting_unavailable'] is False and cpu['live_refused'] is False and all(cpu[k]==2 for k in ['known_workers','spawned_workers','started_workers','finished_workers']),'original worker receipt')
    ab=diagnostic['arithmetic_before'];aa=diagnostic['arithmetic_after']
    need(stage['before']==ab and stage['after']==aa,'CPU arithmetic stage originals agree')
    need(not aa['stage_observation_failed'],'stage accounting available')
    cb=ab['complete_root_arithmetic']['counters'];ca=aa['complete_root_arithmetic']['counters']
    delta={k:ca[k]-cb[k] for k in ca};prior={x['stage']:x['totals'] for x in ab['stages']}
    stage_delta={x['stage']:{k:v-prior[x['stage']][k] for k,v in x['totals'].items()} for x in aa['stages']}
    if diagnostic['authenticated_backend']:
     expected_delta={'calculations':25,'complete_computations':11,'operation_full_root_reuses':2,'operation_initial_root_reuses':3,'partition_inputs_hashed':29534,'partition_projection_compared_keys':23145,'partition_projection_uses':11,'partition_roots_computed':96,'partition_roots_reused':40765}
     need(all(delta[k]==v for k,v in expected_delta.items()),'actual Auth work/reuse/hash counters')
     need(stage_delta['complete_commitment']['calls']==11 and stage_delta['complete_state_root']['calls']==11,'actual complete workload')
    cpu_observations.append({'selector':selector,'backend':'Authenticated' if diagnostic['authenticated_backend'] else 'Legacy','outer_result':diagnostic['original_dispatch_result'],'inner_result':parity['native_result'],'dispatch_elapsed_ns':int(diagnostic['dispatch_elapsed_ns']),'paid_cpu_ns':a['paid_cpu_debit_ns'],'credited_refill_ns':a['credited_refill_ns'],'remaining_credit_ns':a['remaining_paid_credit_ns'],'cpu_flow_before':b,'cpu_flow_after':a,'budget_before':diagnostic['cpu_budget_before'],'budget_after':diagnostic['cpu_budget_after'],'original_cpu_receipt':cpu,'complete_root_counter_delta':delta,'stage_deltas_overlap_not_additive':stage_delta,'host_or_whole_service_qualified':False})
  registries={c:registry(txt('semantic-controls/'+c+'-registry.log')) for c in ['m06','node']}
  need({c:len(v) for c,v in registries.items()}=={'m06':110,'node':938},'full actual libtest registries')
  selected=[];groups=[]
  for mode,args in specifications:
   crate,group=args[:2]
   if mode=='prefix':
    prefix,count=args[2:];names=sorted(x for x in registries[crate] if x.startswith(prefix));need(len(names)==count,'prefix original/additive count')
    g={'crate':crate,'group':group,'prefix':prefix,'expected_count':count,'tests':names}
   else:
    names=args[2];need(len(names)==len(set(names)) and set(names)<=registries[crate],'exact original controls')
    g={'crate':crate,'group':group,'expected_count':len(names),'tests':names}
   groups.append(g);selected.extend((crate,group,n) for n in names)
  need(len(selected)==64 and len(set((c,n) for c,g,n in selected))==64,'64 unique semantic selections')
  need(collections.Counter(c for c,g,n in selected)=={'m06':18,'node':46},'Node46/M0618 actual semantic denominator')
  registered=js('semantic-controls/registry-check.json')
  need(registered['result']=='PASS' and registered['groups']==groups and registered['selected_count']==64 and registered['registry_counts']=={'m06':110,'node':938},'independent trusted workflow selection versus actual registry')
  need(txt('semantic-controls/selected-tests.tsv')==''.join('\t'.join(x)+'\n' for x in selected),'exact semantic selected list')
  need(txt('semantic-controls/executed-selector-count.txt').strip()=='64','actual executed semantic count')
  check_exit_rows(tsv(txt('semantic-controls/elf-before-exits.tsv')),[{'crate':c} for c in ['node','m06']],['reader_exit'])
  check_exit_rows(tsv(txt('semantic-controls/registry-exits.tsv')),[{'crate':c} for c in ['m06','node']],['native_exit','log_exit'])
  check_exit_rows(tsv(txt('semantic-controls/test-exits.tsv')),[{'crate':c,'group':g,'selector':s} for c,g,s in selected],['native_exit','log_exit','reader_exit'])
  for index,(crate,group,selector) in enumerate(selected,1):
   prefix='semantic-controls/'+f'{index:02d}-{crate}-{selector.rsplit("::",1)[-1]}'
   check_test(crate,group,selector,prefix,prefix+'.cwd.txt')
  proto_registry=registry(txt('protocol-controls/registry.log'))
  proto_selected=sorted(n for n in proto_registry if n.startswith('pon_wire::state_root_arithmetic::tests::'))
  need(len(proto_registry)==53 and len(proto_selected)==8,'protocol actual registry/selection')
  need(js('protocol-controls/selected-tests.json')=={'prefix':'pon_wire::state_root_arithmetic::tests::','expected_count':8,'registered_count':53,'tests':proto_selected},'protocol selected list')
  need(js('protocol-controls/test-exits.json')==[{'selector':s,'native_exit':0,'reader_exit':0} for s in proto_selected],'protocol actual native/reader exits')
  psum=js('protocol-controls/summary.json')
  need(psum['result']=='PASS' and psum['expected_count']==psum['executed_count']==8 and psum['same_elf_before_after'] is True,'protocol summary')
  for index,selector in enumerate(proto_selected,1):
   prefix='protocol-controls/'+f'{index:02d}-{selector.rsplit("::",1)[-1]}';check_test('protocol','protocol-arithmetic',selector,prefix)
  need(len(tests)==76 and len(set(x['selector'] for x in tests))==76,'exact total 76 native executions')
  need(sum(x['passed'] for x in tests)==76 and sum(x['failed']+x['ignored']+x['measured'] for x in tests)==0,'all actual executions pass without ignored')
  need(len(cpu_observations)==3 and len(lifetime_observations)==2,'CPU backend and lifetime denominators')
  member_manifest=[{'path':n,'size':len(b),'sha256':sha(b)} for n,b in sorted(members.items())]
  member_receipt=write_json(OUT/f'artifact-{artifact_id}.independent-member-manifest.json',member_manifest)
  lane={'artifact_id':artifact_id,'artifact_name':official['name'],'job_id':job_id,'runner':runner,'source_kind':kind,'zip_size':size,'zip_sha256':digest,'all_433_members_fully_read_crc_checked':True,'member_manifest':member_receipt,'harness':wh,'source_before':before,'source_after':after,'build_command':cmd,'build_jsonl_sha256':sha(raw('build.jsonl')),'build_message_count':len(rows),'build_finished_success':True,'build_time_resources':buildresources,'build_artifact_check':check,'rustc':rustc,'cargo':cargo,'pq_provider_receipt':provider,'binaries':binaries,'semantic_groups':groups,'counts':{'node_semantic':46,'m06_semantic':18,'protocol':8,'cpu':2,'lifetime':2,'total_native':76,'passed':76,'failed':0,'ignored':0,'measured':0},'actual_named_executions':tests,'cpu_backend_observations':cpu_observations,'lifetime_observations':lifetime_observations,'independently_parsed_member_count':len(used),'artifact_contains_ELF_bytes':False,'binary_sha256_scope':'original CI-recorded same-ELF hashes before/after; artifact does not include executables for independent binary rehash','native_or_artifact_code_executed_by_this_reader':False}
  lane_receipt=write_json(OUT/f'artifact-{artifact_id}.independent-audit-v1.json',lane)
  lanes.append({'artifact_id':artifact_id,'runner':runner,'source_kind':kind,'job_id':job_id,'zip_size':size,'zip_sha256':digest,'counts':lane['counts'],'report':lane_receipt,'source_before':before,'node_elf_sha256':binaries['node']['sha256'],'m06_elf_sha256':binaries['m06']['sha256'],'protocol_elf_sha256':binaries['protocol']['sha256'],'cpu':[{'selector':x['selector'],'backend':x['backend'],'paid_cpu_ns':x['paid_cpu_ns'],'credited_refill_ns':x['credited_refill_ns'],'remaining_credit_ns':x['remaining_credit_ns'],'dispatch_elapsed_ns':x['dispatch_elapsed_ns'],'counter_delta':x['complete_root_counter_delta']} for x in cpu_observations]})
  print(json.dumps({'artifact_id':artifact_id,'runner':runner,'kind':kind,'result':'PASS','actual_native_count':76,'audit_report':lane_receipt}),flush=True)
 result={'schema':'chain-initial-root-four-lane-independent-data-audit-v1','result':'PASS','run_id':run['id'],'run_attempt':1,'run_conclusion':'success','run_url':run['html_url'],'pins':PINS,'git_object_ordered_parents':{k:[p['sha'] for p in v['parents']] for k,v in git.items()},'lanes':lanes,'counts':{'lanes':4,'node_semantic':184,'m06_semantic':72,'protocol':32,'cpu':8,'lifetime':8,'actual_native_total':304,'passed':304,'failed':0,'ignored':0,'measured':0,'cpu_backend_observations':12},'native_invocations_by_auditor':0,'artifact_code_execution_by_auditor':False,'BEP':'not applicable: this Chain workflow uses original Cargo build.jsonl compiler-artifact records, not Bazel','limits':['selected ordinary controls only; not full runtime, pressure, V5, DAG, or whole-chain PQ qualification','CI-recorded ELF hashes checked before/after; downloaded ZIPs contain no ELF bytes, so no independent downloaded-binary rehash','old local failures remain valid archived observations; source/architecture/profile-specific results are not interchangeable','stage CPU values are nested/overlapping and must not be added']}
 receipt=write_json(OUT/'FOUR_LANE_INDEPENDENT_AUDIT_V1.json',result)
 write_json(OUT/'AUDIT_V1_COMPLETION_RECEIPT.json',{'result':'PASS','report':receipt,'native_invocations':0,'artifact_code_execution':False})
 print(json.dumps({'result':'PASS','counts':result['counts'],'summary':receipt,'native_invocations':0}),flush=True)
except BaseException as e:
 write_json(OUT/'AUDIT_V1_FAILURE.json',{'result':'FAIL_AUDITOR','error_type':type(e).__name__,'error':str(e),'traceback':traceback.format_exc(),'native_invocations':0,'artifact_code_execution':False})
 raise
