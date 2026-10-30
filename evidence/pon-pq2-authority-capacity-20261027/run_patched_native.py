import pathlib,subprocess,json,hashlib,time,os,signal
root=pathlib.Path('/workspace/scratch/3d4ec372c488/pq-accounts-audit');out=pathlib.Path(__file__).parent/'native-patched-01';out.mkdir(exist_ok=False)
deps=pathlib.Path('/workspace/scratch/301262829a43/pon-work-impl/provider-native-target/debug/deps');tool=pathlib.Path('/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin')
source=root/'trillionnium/crates/trnm-pon-node/tests/native_pq_v2.rs';(out/'native-pq-v2-source.rs').write_bytes(source.read_bytes())
argv=[str(tool/'rustc'),'--edition=2021','--test',str(source),'-o',str(out/'native-pq-v2'),'-L','dependency='+str(deps),'-C','opt-level=0','-C','debuginfo=0']
linked={str(p):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in sorted(deps.glob('*.rlib'))}
for crate in ['trnm_pon_node','trnm_mvcc_fee','trnm_protocol','trnm_crypto_primitives','ml_dsa','serde_json','hex','rusqlite','tempfile']:
 candidates=list(deps.glob('lib'+crate+'-*.rlib'));assert len(candidates)==1,(crate,candidates);argv+=['--extern',crate+'='+str(candidates[0])]
for p in (deps.parent/'build').glob('*/out'):
 if any(p.glob('*.a')):argv+=['-L','native='+str(p)]
source_hash=hashlib.sha256(source.read_bytes()).hexdigest();start=time.monotonic()
with (out/'build.log').open('wb') as log:proc=subprocess.run(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT,timeout=180)
report={'argv':argv,'returncode':proc.returncode,'wall_seconds':time.monotonic()-start,'test_source_sha256':source_hash,'all_rlibs_at_build':linked,'compiler':subprocess.check_output([str(tool/'rustc'),'-vV'],text=True),'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'scope':'actual patched full-nine native integration target linked to unchanged frozen original native PQ2 dependencies; not a new Cargo workspace or physical I/O qualification'}
(out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print('build',proc.returncode,flush=True)
if proc.returncode:print((out/'build.log').read_text());raise SystemExit(proc.returncode)
start=time.monotonic();timeout=False
with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
 proc=subprocess.Popen([str(out/'native-pq-v2'),'--test-threads=1','--show-output'],cwd=root,stdout=stdout,stderr=stderr,start_new_session=True)
 try:rc=proc.wait(timeout=300)
 except subprocess.TimeoutExpired:
  timeout=True;os.killpg(proc.pid,signal.SIGTERM)
  try:rc=proc.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);rc=proc.wait()
entry={'returncode':rc,'timeout':timeout,'wall_seconds':time.monotonic()-start,'binary_sha256':hashlib.sha256((out/'native-pq-v2').read_bytes()).hexdigest(),'test_source_before_after_equal':hashlib.sha256(source.read_bytes()).hexdigest()==source_hash,'all_rlibs_before_after_equal':all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==row['sha256'] for p,row in linked.items()),'scope':report['scope']}
(out/'terminal.json').write_text(json.dumps(entry,indent=2)+'\n');print(json.dumps(entry),flush=True);print((out/'stdout.log').read_text()[-5000:])
