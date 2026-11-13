from pathlib import Path
import hashlib,json,os,shutil,subprocess,time
base=Path("/home/qian-qi/work")
repo=base/"chain-w1-four-gates-20261108-ec265b"
out=base/"chain-w1-base62-m12-tools-20261108-ec265b"
pairs=[("backend",base/"chain-w1-four-gates-backend-target-20261108-ec265b",base/"chain-w1-base62-backend-target-20261108-ec265b"),("native",base/"chain-w1-four-gates-native-target-20261108-ec265b",base/"chain-w1-base62-native-target-20261108-ec265b")]
pins={"backend":{"release/w1-staged-prover-v2":"499b9e67297907cc5a2ab1062b17c57c60bb5a022240f27526451c1d9ff6ae91"},"native":{"release/examples/pon_w1_native_winner_v2":"753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03","release/w1-verify-v2":"91bbf96300d9b6d34cbf36415febae33908b8589de3004801e2a9e136153b7bd"}}
assert not out.exists() and all(not d.exists() for _,s,d in pairs)
disk=shutil.disk_usage(base)
sizes={role:int(subprocess.check_output(["du","-sb",str(src)]).split()[0]) for role,src,dst in pairs}
assert disk.free>sum(sizes.values())+32*1024**3
out.mkdir()
def pin(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return {"path":str(p),"bytes":p.stat().st_size,"sha256":h.hexdigest()}
def write(p,v):
 with p.open("x") as f:json.dump(v,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
with (out/"preflight-before-cache-copy.stdout").open("xb") as a,(out/"preflight-before-cache-copy.stderr").open("xb") as b:
 r=subprocess.run(["bash","scripts/project-preflight.sh"],cwd=repo,stdout=a,stderr=b,check=False)
assert r.returncode==0
results=[]
for role,src,dst in pairs:
 before={leaf:pin(src/leaf) for leaf in pins[role]}
 assert all(v["sha256"]==pins[role][leaf] for leaf,v in before.items())
 source_inodes={(p.stat().st_dev,p.stat().st_ino) for p in src.rglob("*") if p.is_file() and not p.is_symlink()}
 argv=["cp","-a","--reflink=auto","--no-preserve=links",str(src),str(dst)]
 subprocess.run(argv,check=True)
 after={leaf:pin(src/leaf) for leaf in pins[role]}
 copied={leaf:pin(dst/leaf) for leaf in pins[role]}
 assert before==after
 assert all(v["sha256"]==pins[role][leaf] for leaf,v in copied.items())
 count=0
 for p in dst.rglob("*"):
  if p.is_file() and not p.is_symlink():
   st=p.stat()
   assert (st.st_dev,st.st_ino) not in source_inodes
   assert st.st_nlink==1,(str(p),st.st_nlink)
   count+=1
 record={"schema":"TRNM-W1-C6-CACHE-COPY1","role":role,"source":str(src),"destination":str(dst),
 "source_commit":"034aa74358e0a5fa33f33e83cb63669e9738da4b","source_tree":"8dd452c376452224602fb202940ae84fc1f84d2e",
 "argv":argv,"source_binaries_before":before,"source_binaries_after":after,"copied_binaries":copied,
 "destination_regular_files_checked":count,"shared_source_inode_count":0,"destination_hardlink_count":0,
 "fresh_cargo_target":False,"independent_cleanroom_build":False,"cargo_started":False,"operation_created":False}
 path=out/(role+"-cache-copy.json");write(path,record)
 results.append(pin(path))
write(out/"cache-copy-summary.json",{"schema":"TRNM-W1-C6-CACHE-SETUP1","disk_before":{"total":disk.total,"used":disk.used,"free":disk.free},"source_apparent_bytes":sizes,"copies":results,"cargo_started":False,"operation_created":False,"preflight_exit":r.returncode})
print(json.dumps({"manifest":pin(out/"cache-copy-summary.json"),"copies":results,"new_targets":[str(d) for _,s,d in pairs]}))
