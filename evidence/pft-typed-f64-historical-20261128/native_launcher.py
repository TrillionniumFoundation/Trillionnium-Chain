import pathlib,json,hashlib,base64,zlib,sys,subprocess,time,datetime,os,signal
raw=zlib.decompress(base64.b64decode(sys.argv[1]));assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
data=json.loads(raw);m=data['manifest'];assert m['input_sha256']['features']=='26456299b8fc9ac79914f8ac5762280329ebf3ced28c3e2d4420f7e95d1dd9e0'
assert m['files']['reference-output.le']['sha256']=='a254e8385df48372e9cc35ef307521976c3eca5f77e7c65b503018a626364285'
out=pathlib.Path('/tmp/hepta-chain-6523704f97df-native-f64-historical-attempt-1');out.mkdir(mode=0o700,exist_ok=False)
private=out/'private';private.mkdir(mode=0o700)
harness=out/'evidence/pft-typed-f64-historical-20261128/historical_harness.rs';harness.parent.mkdir(parents=True)
for name,encoded in data['files'].items():
 b=base64.b64decode(encoded);assert hashlib.sha256(b).hexdigest()==m['files'][name]['sha256'];assert len(b)==m['files'][name]['bytes']
 p=harness if name=='historical_harness.rs' else private/name
 p.write_bytes(b)
 if p!=harness:p.chmod(0o400)
source='trillionnium/crates/trnm-pon-node/src/pft_readout_f64_v1.rs'
tested=pathlib.Path('/tmp/hepta-chain-6523704f97df-native-f64-tests-attempt-1')/source
b=tested.read_bytes();assert hashlib.sha256(b).hexdigest()=='19225693c81e035384bc63c1b19c7958305b3872614b45f807f00679470cc86f'
p=out/source;p.parent.mkdir(parents=True);p.write_bytes(b)
record={'schema':'trnm-pft-typed-f64-fixed-historical-observation-v1','attempt':1,'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'input_manifest':m,'core_sha256':hashlib.sha256(b).hexdigest(),'engineering_deadline_seconds':120,'commands':[],'source_authentication':False,'normal_equation_reexecuted':False,'labels_read':False,'dev_read':False,'final_read':False,'feature_program_executed':False,'native_adoption':False,'native_final_use':False,'quality_improved':False,'real_user_b':False,'payment':False,'consensus_determinism':False,'full_crate_build':False}
(out/'FROZEN_BEFORE_FORMAT.json').write_text(json.dumps(record,indent=2))
deadline=time.monotonic()+120
environment=dict(os.environ)
for env,name in {'TRNM_PFT_ACTUAL_WEIGHT_FILE':'weight.actual.le','TRNM_PFT_EXPECTED_WEIGHT_FILE':'weight.expected.le','TRNM_PFT_ACTUAL_FEATURE_FILE':'features.actual.le','TRNM_PFT_EXPECTED_FEATURE_FILE':'features.expected.le','TRNM_PFT_REFERENCE_OUTPUT_FILE':'reference-output.le'}.items():environment[env]=str(private/name)
def run(name,argv):
 start=time.monotonic_ns();timed_out=False
 with (out/(name+'.stdout')).open('wb') as stdout,(out/(name+'.stderr')).open('wb') as stderr:
  p=subprocess.Popen(argv,cwd=out,stdout=stdout,stderr=stderr,start_new_session=True,env=environment)
  try:code=p.wait(timeout=max(0.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:timed_out=True;os.killpg(p.pid,signal.SIGKILL);code=p.wait()
 entry={'name':name,'argv':argv,'exit_code':code,'timed_out':timed_out,'wall_ns':time.monotonic_ns()-start,'stdout_sha256':hashlib.sha256((out/(name+'.stdout')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((out/(name+'.stderr')).read_bytes()).hexdigest()}
 record['commands'].append(entry);(out/'RESULT.json').write_text(json.dumps(record,indent=2))
 return code==0 and not timed_out
if run('format',['/home/qian-qi/.cargo/bin/rustfmt','--edition','2021','--config','skip_children=true',str(harness)]):
 record['harness_sha256']=hashlib.sha256(harness.read_bytes()).hexdigest()
 assert hashlib.sha256((out/source).read_bytes()).hexdigest()==record['core_sha256']
 (out/'FROZEN_BEFORE_COMPILE.json').write_text(json.dumps(record,indent=2))
 if run('compile',['/home/qian-qi/.cargo/bin/rustc','--edition=2021','-D','warnings',str(harness),'-o',str(out/'fixed_observation')]):
  if run('predict',[str(out/'fixed_observation')]):
   actual=(out/'predict.stdout').read_bytes();expected=(private/'reference-output.le').read_bytes()
   record['all_output_bytes_equal_previous_reference']=actual==expected
   record['prediction_bytes']=len(actual);record['prediction_sha256']=hashlib.sha256(actual).hexdigest();record['prediction_shape']=[4,3]
record['source_unchanged_after']=hashlib.sha256((out/source).read_bytes()).hexdigest()==record['core_sha256']
record['private_inputs_unchanged_after']=all(hashlib.sha256((private/n).read_bytes()).hexdigest()==pin['sha256'] for n,pin in m['files'].items() if n!='historical_harness.rs')
record['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(out/'RESULT.json').write_text(json.dumps(record,indent=2))
(out/'PUBLIC_OBSERVATION.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
