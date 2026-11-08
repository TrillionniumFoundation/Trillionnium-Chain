import datetime,hashlib,json,os,pathlib,subprocess,time
root=pathlib.Path('/workspace/scratch/5faaca703596/chain-root'); out=root.parent/'validation/aa7ba29'
sha='aa7ba29a5485a6b04ccb909e34bb3d8ae2528669'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
env=dict(os.environ,RUSTUP_HOME=str(root.parent/'toolchain/rustup'),CARGO_HOME=str(root.parent/'toolchain/cargo'),CARGO_TARGET_DIR=str(root.parent/'cargo-target'),OPENSSL_DIR='/usr',OPENSSL_LIB_DIR='/usr/lib/x86_64-linux-gnu',OPENSSL_INCLUDE_DIR='/usr/include',CARGO_BUILD_JOBS='2',RUST_TEST_THREADS='1',CARGO_TERM_COLOR='never')
env['PATH']=env['CARGO_HOME']+'/bin:'+env['PATH']
argv=['cargo','clippy','--locked','--offline','--workspace','--all-targets','--all-features','--manifest-path','trillionnium/Cargo.toml','--','-D','warnings']
start=datetime.datetime.now(datetime.timezone.utc).isoformat(); t=time.monotonic()
log=out/'rust-clippy-multiarch.log'
with log.open('wb') as stream: result=subprocess.run(argv,cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=1200)
raw=log.read_bytes()
record={'source_sha':sha,'argv':argv,'cwd':str(root),'started_utc':start,'elapsed_seconds':time.monotonic()-t,'exit_code':result.returncode,'log':log.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'environment_correction':{'OPENSSL_LIB_DIR':'/usr/lib/x86_64-linux-gnu','OPENSSL_INCLUDE_DIR':'/usr/include'},'retained_original_failure':'rust-05.log','scope':'same source and command; explicit installed multiarch library directory; no source, dependency, feature or budget change'}
(out/'rust-clippy-multiarch.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record));raise SystemExit(result.returncode)
