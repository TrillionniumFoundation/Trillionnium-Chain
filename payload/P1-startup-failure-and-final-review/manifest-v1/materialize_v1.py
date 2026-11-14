#!/usr/bin/env python3
"""Single authorized stage prefix; preserve every prior file/directory identity."""
import hashlib,json,os,stat
from pathlib import Path,PurePosixPath
PREP=Path("/private/tmp/chain-P1-startup-and-final-review-materialization-20261114-v1")
STAGE=Path("/private/tmp/chain-consolidation-20261114-root/execution-receipts-followup-v1")
PREFIX="P1-startup-failure-and-final-review"
BASE_FILES=4149
BASE_BYTES=207594299
ROOTS=[
 {"path":"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1",
  "prefix":"closed-sparse-results","count":165,"bytes":15679159,
  "index_sha":"b2e499a3a0895c1cb3d3845245c4dd202bc8074ddaf267fcffcb89d54fc563df",
  "seal_sha":"8795c02fe85431007d2f925b24abb461fd894b2b114b4630a15d6b826fe969f2"},
 {"path":"/private/tmp/chain-public-policy-P1-independent-closure-review-20261114-v1",
  "prefix":"P1-independent-closure-review","count":20,"bytes":330441,
  "index_sha":"52a9877e34d54b9795650eaf6a7618d9a1e1d0b9291bba0a1637516073366836",
  "seal_sha":"5120afcccb5901c262c203f53975be211f14df8fafe912554f145b07027d56a8"}
]
FLAGS=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
def req(v,msg):
 if not v:raise ValueError(msg)
def fp(s):return {"dev":s.st_dev,"ino":s.st_ino,"mode":s.st_mode,"nlink":s.st_nlink,"uid":s.st_uid,"gid":s.st_gid,"size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}
def relsafe(value):
 p=PurePosixPath(value);req(not p.is_absolute() and str(p)==value and value!=".","unsafe relative path")
 req(all(x not in (".","..",".git","") and "\\" not in x and all(ord(c)>=32 and ord(c)!=127 for c in x) for x in p.parts),"unsafe component")
 return p
def parents(p):
 req(p.is_absolute() and str(p.resolve())==str(p),"canonical path fence")
 for d in [p.parent,*p.parent.parents]:
  s=d.lstat();req(stat.S_ISDIR(s.st_mode) and not d.is_symlink(),"parent symlink")
def read(p):
 parents(p);s=p.lstat()
 req(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=16777216,"source type/cap")
 fd=os.open(p,FLAGS)
 try:
  req(fp(os.fstat(fd))==fp(s),"open identity changed");chunks=[];n=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   n+=len(b);req(n<=s.st_size,"file grew");chunks.append(b)
  req(n==s.st_size and fp(s)==fp(os.fstat(fd))==fp(p.lstat()),"unstable file read")
  return b"".join(chunks),fp(s)
 finally:os.close(fd)
def put(p,b):
 parents(p);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600)
 try:
  off=0
  while off<len(b):off+=os.write(fd,b[off:])
  os.fsync(fd)
 finally:os.close(fd)
 got,identity=read(p);req(got==b,"new target readback mismatch")
 return identity
def jb(x):return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
def scan(root):
 req(root.is_dir() and not root.is_symlink() and str(root.resolve())==str(root),"root canonical fence")
 files={};dirs={}
 def walk(d):
  a=fp(d.lstat());dirs[str(d.relative_to(root))]=a;names=sorted(x.name for x in d.iterdir())
  for name in names:
   relsafe(name);p=d/name;s=p.lstat()
   if stat.S_ISDIR(s.st_mode):walk(p)
   else:
    req(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"special/hardlink in scope")
    files[str(p.relative_to(root))]=fp(s)
  req(a==fp(d.lstat()) and names==sorted(x.name for x in d.iterdir()),"directory changed while scanned")
 walk(root);return {"files":files,"dirs":dirs}
def own_dirs(path):
 req(STAGE/PREFIX in path.parents,"target escaped unique prefix")
 current=STAGE/PREFIX
 for name in path.relative_to(current).parts[:-1]:
  current=current/name
  try:current.mkdir(mode=0o700)
  except FileExistsError:
   s=current.lstat();req(stat.S_ISDIR(s.st_mode) and not current.is_symlink(),"unsafe target directory")
  req(str(current.resolve())==str(current),"noncanonical target directory")
def main():
 req(str(Path(__file__).resolve())==str(PREP/"materialize_v1.py"),"producer path")
 source_rows=[];root_snapshots={}
 for root in ROOTS:
  p=Path(root["path"]);before=scan(p);root_snapshots[str(p)]=before
  index_raw,_=read(p/"EVIDENCE_INDEX.json");seal_raw,_=read(p/"seal.json")
  req(hashlib.sha256(index_raw).hexdigest()==root["index_sha"],"source index pin")
  req(hashlib.sha256(seal_raw).hexdigest()==root["seal_sha"],"source seal pin")
  index=json.loads(index_raw);rows=index["files"]
  req(index["file_count"]==len(rows) and index["total_bytes"]==sum(x["bytes"] for x in rows),"source index totals")
  names=set()
  for row in rows:
   req(set(row)=={"path","bytes","sha256","origin"} and set(row["origin"])=={"host","path"},"source row schema")
   relsafe(row["path"]);req(row["path"] not in names,"duplicate source row");names.add(row["path"])
   source_rows.append({"path":PREFIX+"/"+root["prefix"]+"/"+row["path"],"source_path":str(p/row["path"]),
                      "bytes":row["bytes"],"sha256":row["sha256"],"origin":row["origin"]})
  for name,raw in [("EVIDENCE_INDEX.json",index_raw),("seal.json",seal_raw)]:
   req(name not in names,"self-index collision");names.add(name)
   source_rows.append({"path":PREFIX+"/"+root["prefix"]+"/"+name,"source_path":str(p/name),
                      "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                      "origin":{"host":"mac","path":str(p/name)}})
  req(names==set(before["files"]) and len(names)==root["count"] and
      sum(x["size"] for x in before["files"].values())==root["bytes"],"closed source exact roster mismatch")
 for name in ["finalizer-request.json","finalizer-start.json","finalizer-terminal.json"]:
  p=PREP/"closed-copy-finalizer-tool-records"/name;b,_=read(p)
  source_rows.append({"path":PREFIX+"/manifest-v1/"+name,"source_path":str(p),
                     "bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"origin":{"host":"mac","path":str(p)}})
 selection_raw=jb({"schema":"trnm-P1-startup-archive-selection-v1","files":source_rows,
                   "source_count":len(source_rows),"source_bytes":sum(x["bytes"] for x in source_rows),
                   "no_live_directories":True,"source_git_tests_unchanged":True})
 put(PREP/"source-selection.json",selection_raw)
 for name in ["materialize_v1.py","static-review.json","source-selection.json"]:
  p=PREP/name;b,_=read(p)
  source_rows.append({"path":PREFIX+"/manifest-v1/"+name,"source_path":str(p),
                     "bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"origin":{"host":"mac","path":str(p)}})
 req(len({x["path"] for x in source_rows})==len(source_rows),"target duplicate")
 req(sum(x["bytes"] for x in source_rows)<=67108864,"new group cap")
 source_identities={}
 for row in source_rows:
  relsafe(row["path"]);b,identity=read(Path(row["source_path"]))
  req(len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"],"selected source mismatch")
  source_identities[row["source_path"]]=identity
 before=scan(STAGE)
 req(len(before["files"])==BASE_FILES and sum(x["size"] for x in before["files"].values())==BASE_BYTES,
     "stage baseline mismatch")
 req(PREFIX not in before["dirs"] and not (STAGE/PREFIX).exists(),"prefix already exists")
 put(PREP/"stage-before-identities.json",jb(before))
 (STAGE/PREFIX).mkdir(mode=0o700)
 target_identities={}
 for row in source_rows:
  b,identity=read(Path(row["source_path"]))
  req(identity==source_identities[row["source_path"]] and len(b)==row["bytes"] and
      hashlib.sha256(b).hexdigest()==row["sha256"],"source changed before materialization")
  target=STAGE/row["path"];own_dirs(target)
  target_identities[row["path"]]=put(target,b)
 # Preserve the recorded empty source directories; no placeholder files.
 for root in ROOTS:
  for relative in root_snapshots[root["path"]]["dirs"]:
   if relative=="." :continue
   target=STAGE/PREFIX/root["prefix"]/relative
   own_dirs(target/"empty-directory-sentinel")
 after=scan(STAGE)
 new_names={x["path"] for x in source_rows}
 req(set(after["files"])==set(before["files"])|new_names,"stage exact union mismatch")
 for p,identity in before["files"].items():req(after["files"][p]==identity,"prior file identity changed")
 for p,identity in before["dirs"].items():
  if p==".":
   req(all(after["dirs"][p][k]==identity[k] for k in ("dev","ino","mode","uid","gid")),"stage root identity changed")
  else:req(after["dirs"][p]==identity,"prior directory identity changed")
 for row in source_rows:
  b,identity=read(STAGE/row["path"])
  req(identity==target_identities[row["path"]] and len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"],
      "final target fence")
  b,identity=read(Path(row["source_path"]))
  req(identity==source_identities[row["source_path"]] and len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"],
      "final selected source fence")
 for root_path,old in root_snapshots.items():req(scan(Path(root_path))==old,"closed source directory changed")
 final=scan(STAGE);req(final==after,"stage changed after final readbacks")
 strict=[{k:row[k] for k in ("path","bytes","sha256","origin")} for row in sorted(source_rows,key=lambda x:x["path"])]
 raw=jb(strict);put(PREP/"files.json",raw);put(PREP/"stage-after-identities.json",jb(after))
 total=sum(x["bytes"] for x in strict)
 summary={"schema":"trnm-P1-startup-final-review-stage-materialization-v1","status":"MATERIALIZED_AND_HASH_VERIFIED",
          "prefix":PREFIX,"stage":str(STAGE),"new_files":len(strict),"new_bytes":total,
          "baseline_files":BASE_FILES,"baseline_bytes":BASE_BYTES,"baseline_directories":len(before["dirs"]),
          "prior_files_and_directories_identity_preserved":True,
          "complete_stage_files":len(after["files"]),"complete_stage_bytes":sum(x["size"] for x in after["files"].values()),
          "new_target_and_source_final_sha_fences_passed":True,"strict_manifest":{"path":str(PREP/"files.json"),
          "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},
          "all_file_descriptors_closed_per_file":True,"source_git_network_tests_untouched":True,
          "N2_or_live_evidence_included":False,"stage_writer_released_after_terminal":True}
 put(PREP/"summary.json",jb(summary));print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
