import ast,hashlib,json,os,pathlib,re,subprocess
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1")
O=E/"entry-excerpts-v1";O.mkdir(exist_ok=False)
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
H="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
files=[]
def source(path):
 a=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never","cat-file","blob",H+":"+path]
 c=subprocess.run(a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 dest=O/(path.replace("/","--")+".raw")
 dest.write_bytes(c.stdout)
 (O/(dest.name+".stderr")).write_bytes(c.stderr)
 files.append({"path":path,"argv":a,"exit":c.returncode,"capture":str(dest),"bytes":len(c.stdout),"sha256":hashlib.sha256(c.stdout).hexdigest(),"git_oid":hashlib.sha1(b"blob "+str(len(c.stdout)).encode()+b"\0"+c.stdout).hexdigest()})
 if c.returncode:raise RuntimeError(path)
 return c.stdout.decode()
source(".github/workflows/trnm-required-baseline.yml")
source("config/systemd/trnmponpublic.slice")
native=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1/protocol-source-comparison-v1/scripts--ci--run_from_zero_native.py.2aba481576bc5a09a2d546e467e1b19d6e9de7bd.raw").read_text()
def excerpt(name,raw,ranges):
 lines=raw.splitlines()
 out="\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,min(b,len(lines)))) for a,b in ranges)+"\n"
 p=O/name;p.write_text(out);return {"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
entries=[]
entries.append(excerpt("native-entry.txt",native,[(1,185),(1648,1852)]))
entries.append(excerpt("native-confirmation-acceptance.txt",native,[(573,630),(819,857),(910,917)]))
rust=(E/"source-capture-v1/trillionnium--crates--trnm-pon-node--tests--public_v3_from_zero.rs.raw").read_text()
lines=rust.splitlines()
outline=[]
for i,s in enumerate(lines,1):
 if re.match(r'^(?:pub(?:\([^)]*\))? )?(?:async )?fn |^#\[test\]|^#\[ignore',s) or any(k in s for k in ("GITHUB_ACTIONS","ensure_eligible","TRNM_","Host","Duration::from_secs(4)","16_usize","attack_workers")):
  outline.append({"line":i,"text":s})
(O/"fixture-outline.json").write_text(json.dumps(outline,indent=2)+"\n")
(O/"source-index.json").write_text(json.dumps({"head":H,"files":files,"excerpts":entries},indent=2)+"\n")
print(json.dumps({"directory":str(O),"sources":files,"excerpts":entries,"fixture_outline":outline},sort_keys=True))
