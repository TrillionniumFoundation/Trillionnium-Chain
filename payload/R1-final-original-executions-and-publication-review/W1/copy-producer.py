import os,sys,pathlib,hashlib,json,stat,datetime,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];C=pathlib.Path(D["destination"]);S=pathlib.Path(D["source_directory"])
assert C.parent.resolve(strict=True)==C.parent and not C.exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def js(v):return (json.dumps(v,indent=2)+"\n").encode()
iv=D["inventory_terminal"];ot=D["original_terminal"]
for t in (iv,ot):
 assert t["status"]["exit_code"]==0 and t["output_complete"] is True and t["offset"]==0 and t["next_offset"]==t["available_end"]
 assert sha(bytes.fromhex(t["bytes_hex"]))==t["chunk_sha256"]
assert ot["chunk_sha256"]=="21e84c64c31ab0e57bac982dac656c3a37afed58e1beaf0cdedaa53a00887092"
inventory=json.loads(iv["text"]);rows={r["path"]:r for r in inventory["files"]}
assert inventory["directory"]==str(S) and inventory["count"]==21 and inventory["bytes"]==14528 and inventory["directory_unchanged"] is True
assert len(D["files"])==len(rows)==21
raws={}
for f in D["files"]:
 r=rows[f["path"]];raw=f["text"].encode("utf-8")
 assert len(raw)==f["size"]==r["bytes"] and sha(raw)==f["sha256"]==r["sha256"] and f["eof"] is True
 v=r["version"];assert f["version"]==":".join(str(v[x]) for x in (0,1,4,5,6))
 rel=pathlib.PurePosixPath(r["relative_path"]);assert str(rel)==r["relative_path"] and not rel.is_absolute() and ".."not in rel.parts
 assert f["path"]==str(S/str(rel));raws[str(rel)]=raw
summary=json.loads(raws["summary.json"]);assert len(raws["summary.json"])==7754 and sha(raws["summary.json"])=="edb1e9f855450b5f330332b5dbdae17ea6546ad75d2f1dff81106b9b2382ee71"
assert summary["status"]=="passed" and summary["head"]=="2a86462a1ab20c68151719ba4635e3c294391e64" and summary["tree"]=="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4" and summary["errors"]==[] and summary["qualification"] is False and summary["tests_modified"] is False
assert len(summary["steps"])==8 and all(s["exit"]==0 for s in summary["steps"])
expected={"summary.json","source-before.json","source-after.json","producer.py","reviewed-inputs.json"}
for s in summary["steps"]:
 for ch in ("stdout","stderr"):
  p=s[ch];name=s["label"]+"."+ch;assert p["path"]==str(S/name);assert len(raws[name])==p["bytes"] and sha(raws[name])==p["sha256"];expected.add(name)
assert set(raws)==expected
sources=[raws[n]for n in ["source-before.json","source-after.json","source-before.stdout","source-after.stdout"]]
assert all(x==sources[0] for x in sources) and len(sources[0])==423 and sha(sources[0])=="1b8638f7d5e3fb28abc25c06208df4e189ba3b86c7d0d3a12fb2a431607b7e03"
assert raws["head.stdout"].decode().strip()==summary["head"] and raws["tree.stdout"].decode().strip()==summary["tree"] and raws["status-before.stdout"]==raws["status-after.stdout"]==b""
log=raws["original-31-controls.stderr"];assert len(log)==130 and sha(log)=="1d0c541731cd708065133a6764083fdf50684b25c0a366a296d0adaf862ad836"
assert re.findall(rb"Ran ([0-9]+) tests? in ([0-9.]+)s",log)==[(b"31",b"1.089")] and re.search(rb"(?m)^OK\s*$",log) and b"skipped"not in log and b"FAILED"not in log
C.mkdir(mode=0o700);created=[]
def put(rel,b,origin=None):
 p=C/rel;p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:r=f.read(len(b)+1)
 assert r==b
 row={"relative_path":rel,"source_path":str(p),"bytes":len(b),"sha256":sha(b),"origin":origin or {"host":"mac","path":str(p)}};created.append(row);return row
for n,b in sorted(raws.items()):put("original/"+n,b,{"host":"rog","path":str(S/n)})
put("inventory-producer.py",D["inventory_producer"].encode())
put("closed-inventory.json",js(inventory))
put("original-terminal.json",js(ot));put("original-terminal.log",bytes.fromhex(ot["bytes_hex"]))
put("inventory-terminal.json",js(iv));put("inventory-terminal.log",bytes.fromhex(iv["bytes_hex"]))
for i,r in enumerate(D["official_reads"]):put("official-read-%d.json"%i,js(r))
put("copy-producer.py",SELF.encode())
put("copy-verification.json",js({"schema":"trnm-R1-original-W1-31-official-copy-v1","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"status":"verified","source_head":summary["head"],"source_tree":summary["tree"],"original_status":"passed","original_commands":8,"original_methods_executed":31,"original_test_seconds":1.089,"original_skips":0,"source_identity_sha256":sha(sources[0]),"original_summary_sha256":sha(raws["summary.json"]),"original_files":21,"original_bytes":14528,"all_original_bytes_sha_and_versions_verified":True,"original_scope":"separate original W1 v2 controls; not part of the repository-truth lane","original_producer_executed_by_copy":False,"tests_rerun":False,"source_git_stage_mutation":False,"hosted_qualification":False}))
put("README.md",b"# R1 original W1 controls\n\nAll 21 files from the closed original ROG directory are retained with actual origins. The eight original commands completed, including 31 original methods / 1.089 seconds / OK / no skips, with four identical source records. This is separate local control evidence, not a full repository lane or hosted qualification. Original producer text is retained as data and is not executed by this copy.\n")
index={"schema":"trnm-R1-W1-preserved-files-v1","root":str(C),"file_count":len(created),"total_bytes":sum(r["bytes"]for r in created),"files":sorted(created,key=lambda r:r["relative_path"]),"manifest_excludes_itself":True,"stage_written":False}
mi=put("preserved-files.json",js(index))
print(json.dumps({"status":"verified","directory":str(C),"original_files":21,"original_bytes":14528,"manifest":mi,"file_count_including_manifest":len(created),"bytes_including_manifest":sum(r["bytes"]for r in created),"stage_written":False}),flush=True)
