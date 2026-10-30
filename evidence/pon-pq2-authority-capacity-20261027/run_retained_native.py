import hashlib,json,os,pathlib,signal,subprocess,time
source=pathlib.Path('/workspace/scratch/301262829a43/pon-work-impl/integration/pq-accounts-v2')
binary=pathlib.Path('/workspace/scratch/301262829a43/pon-work-impl/provider-native-target/debug/deps/native_pq_v2-fdb24771d9658ad2')
root=pathlib.Path(__file__).parent/'native-remainder-01'
root.mkdir(exist_ok=False)
expected=json.loads((source.parent/'pq-accounts-v2-evidence/attempt-09-native-frozen/source-before.json').read_text())
def capture():
 return {f:{'bytes':(source/f).stat().st_size,'sha256':hashlib.sha256((source/f).read_bytes()).hexdigest()} for f in expected}
initial=capture();assert initial==expected
identity={'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary_bytes':binary.stat().st_size,'before_source_map':expected,'runner_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'scope':'new selected-case executions of original frozen native binary; incomplete earlier command remains UNKNOWN; no Cargo build or full-workspace execution'}
(root/'identity.json').write_text(json.dumps(identity,indent=2,sort_keys=True)+'\n')
cases=['interrupted_heavier_reorg_preserves_original_atomic_state_and_recovers_cold','prior_pq_commitment_actual_legacy_pon_checkpoint_claim_cold_reorg_and_permission_conserve','randomized_resign_duplicate_requires_real_signature_and_keeps_removal_history','unregistered_pure_pon_miner_matures_actual_rewards_then_registers_without_whitelist','full_4263_byte_rows_and_packet_have_actual_122_transfer_limit']
results=[]
for i,case in enumerate(cases):
 out=root/str(i);out.mkdir();argv=[str(binary),'--exact',case,'--test-threads=1','--show-output'];start=time.monotonic();timeout=False
 with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
  proc=subprocess.Popen(argv,cwd=source,stdout=stdout,stderr=stderr,start_new_session=True)
  try:rc=proc.wait(timeout=300)
  except subprocess.TimeoutExpired:
   timeout=True;os.killpg(proc.pid,signal.SIGTERM)
   try:rc=proc.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);rc=proc.wait()
 entry={'case':case,'argv':argv,'returncode':rc,'timeout':timeout,'wall_seconds':time.monotonic()-start,'native_stdout':(out/'stdout.log').read_text(),'source_before_after_equal':capture()==initial,'binary_before_after_equal':hashlib.sha256(binary.read_bytes()).hexdigest()==identity['binary_sha256']}
 (out/'terminal.json').write_text(json.dumps(entry,indent=2)+'\n');results.append(entry);print(json.dumps({k:entry[k] for k in ('case','returncode','timeout','wall_seconds')}),flush=True)
(root/'terminal.json').write_text(json.dumps({'results':results,'full_original_command_completed':False,'scope':identity['scope']},indent=2)+'\n')
