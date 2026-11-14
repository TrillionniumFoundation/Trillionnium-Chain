import os,sys,subprocess,json,hashlib,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/history-contract-documentation-v2');D.mkdir(mode=0o700)
(D/'producer.py').write_text(sys.argv[1])
H='2a86462a1ab20c68151719ba4635e3c294391e64';G='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_NO_REPLACE_OBJECTS='1')
cmd=['git','--git-dir='+G,'grep','-n','-I','-i','-e','loopback','-e','回环',H,'--','docs','trillionnium/crates/trnm-pon-node/README.md']
r=subprocess.run(cmd,env=e,capture_output=True,timeout=90);assert r.returncode in(0,1);assert len(r.stdout)<512*1024
(D/'source-search.stdout').write_bytes(r.stdout);(D/'source-search.stderr').write_bytes(r.stderr)
lines=r.stdout.decode().splitlines()
print(json.dumps({'search_lines':len(lines),'bytes':len(r.stdout)}))
for line in lines:
 if any(x in line.lower()for x in('history','host','w1','cgroup','public','untrusted','cpu')):print(line)
summary={'head':H,'argv':cmd,'exit_code':r.returncode,'stdout_bytes':len(r.stdout),'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_bytes':len(r.stderr),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest(),'source_changed':False,'tests_executed':False}
b=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode();(D/'summary.json').write_bytes(b)
print(json.dumps({'summary_path':str(D/'summary.json'),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
