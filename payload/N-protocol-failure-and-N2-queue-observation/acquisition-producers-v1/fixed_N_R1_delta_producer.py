import hashlib,json,os,pathlib,subprocess,time
R=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=R/"immutable-N-R1-source-delta-v1";D.mkdir(mode=0o700)
DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
N="5a4b7fe8de1adce803184f262fd9f704ead1930c";C="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy();env.update({"GIT_NO_LAZY_FETCH":"1","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"})
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
rows=[]
for name,args in [("N-commit",["cat-file","commit",N]),("R1-commit",["cat-file","commit",C]),("N-to-R1-raw",["diff","--raw","--no-abbrev",N,C]),("N-to-R1-names",["diff","--name-status",N,C])]:
 argv=["/usr/bin/git","--no-replace-objects","--git-dir="+DB,*args]
 p=subprocess.run(argv,cwd="/private/tmp",env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 assert len(p.stdout)<=4*1024*1024 and len(p.stderr)<=1048576
 for stream,b in [("stdout",p.stdout),("stderr",p.stderr)]:
  with (D/(name+"."+stream)).open("xb") as f:f.write(b)
 rows.append({"name":name,"argv":argv,"exit_code":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":hashlib.sha256(p.stdout).hexdigest(),"stderr_bytes":len(p.stderr)})
summary={"schema":"trnm-N-R1-immutable-readonly-delta-v1","N":N,"R1":C,"git_db":DB,"no_lazy_fetch":True,"optional_locks":False,"source_ref_config_mutated":False,"rows":rows}
with (D/"summary.json").open("xb") as f:f.write((json.dumps(summary,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(summary,sort_keys=True))
print((D/"N-to-R1-names.stdout").read_text())
