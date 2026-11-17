#!/usr/bin/env python3
"""Independently read a content-addressed development view. Executes no native/Rust code."""
from __future__ import annotations
import argparse,hashlib,json,lzma,math,os,stat,subprocess,tarfile,tempfile
from pathlib import Path,PurePosixPath
def need(value,message):
 if not value: raise ValueError(message)
def unique(pairs):
 d={}
 for k,v in pairs:
  need(k not in d,"Duplicate JSON key");d[k]=v
 return d
def reject(token):raise ValueError("Nonfinite JSON "+token)
def finite_float(token):
 value=float(token);need(math.isfinite(value),"Nonfinite JSON float");return value
def read_json(raw):return json.loads(raw,object_pairs_hook=unique,parse_float=finite_float,parse_constant=reject)
def same(a,b):
 if type(a) is not type(b):return False
 if type(a) is dict:return a.keys()==b.keys() and all(same(a[k],b[k]) for k in a)
 if type(a) is list:return len(a)==len(b) and all(same(x,y) for x,y in zip(a,b))
 return type(a) in (str,int,bool,type(None)) and a==b
def ident(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def file_id(value):
 return type(value) is dict and set(value)=={"bytes","sha256"} and type(value["bytes"]) is int and value["bytes"]>=0 and type(value["sha256"]) is str and len(value["sha256"])==64 and all(c in "0123456789abcdef" for c in value["sha256"])
def name(raw):
 need(type(raw) is str,"Non-string member")
 p=PurePosixPath(raw);need(p.parts and not p.is_absolute() and p.as_posix()==raw and ".." not in p.parts and "\x00" not in raw,"Unsafe member")
 return p
def opened(path):
 path=Path(path)
 need(path.is_absolute(),"Absolute path required")
 fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
  leaf=os.open(path.name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 finally:os.close(fd)
 meta=os.fstat(leaf)
 try:need(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1,"Regular single-link evidence required")
 except BaseException:os.close(leaf);raise
 return os.fdopen(leaf,"rb"),meta
def meta_fields(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink)
def file_identity(path):
 stream,pre=opened(path);h=hashlib.sha256();n=0
 with stream:
  for raw in iter(lambda:stream.read(1<<20),b""):h.update(raw);n+=len(raw)
  need(meta_fields(pre)==meta_fields(os.fstat(stream.fileno())),"File changed while reading")
 return {"bytes":n,"sha256":h.hexdigest()}
def full_read(path,bound=64<<20):
 stream,pre=opened(path)
 with stream:
  need(pre.st_size<=bound,"Small evidence exceeded bound");raw=stream.read(bound+1)
  need(len(raw)==pre.st_size and meta_fields(pre)==meta_fields(os.fstat(stream.fileno())),"File changed while reading")
 return raw
class Git:
 def __init__(self,repository):
  self.repository=Path(repository);self.err=tempfile.TemporaryFile()
  self.child=subprocess.Popen(["git","--no-replace-objects","cat-file","--batch"],cwd=self.repository,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err)
 def blob(self,oid):
  need(type(oid) is str and len(oid)==40 and all(c in "0123456789abcdef" for c in oid),"Invalid Git object")
  self.child.stdin.write((oid+"\n").encode());self.child.stdin.flush()
  h=self.child.stdout.readline().split();need(len(h)==3 and h[0].decode()==oid and h[1]==b"blob" and h[2].isdigit(),"Missing Git blob")
  n=int(h[2]);need(n<=64<<20,"Git blob exceeds fixed source profile")
  chunks=[];remaining=n
  while remaining:
   raw=self.child.stdout.read(min(remaining,1<<20));need(raw,"Truncated Git blob");chunks.append(raw);remaining-=len(raw)
  need(self.child.stdout.read(1)==b"\n","Bad Git blob frame")
  raw=b"".join(chunks);need(hashlib.sha1(b"blob "+str(n).encode()+b"\0"+raw).hexdigest()==oid,"Git object identity mismatch")
  return raw
 def close(self):
  self.child.stdin.close()
  need(not self.child.stdout.read() and self.child.wait(timeout=30)==0,"Git reader failed")
  self.child.stdout.close();self.err.close()
def verify(archive,manifest_path,repository,binary):
 manifest=read_json(full_read(manifest_path));need(manifest.get("schema")=="trnm.hia.work-owner-development-cas-view-manifest.v1" and manifest.get("scope")=="PRIVATE_DEVELOPMENT_NOT_HOSTED_QUALIFICATION","Wrong view schema/scope")
 before=file_identity(archive);need(same(before,manifest["archive"]),"View archive differs")
 entries=manifest["entries"];need(type(entries) is dict and entries and "index.json" in entries,"View entries absent")
 total=0;bound=2*tarfile.RECORDSIZE
 for key,row in entries.items():
  name(key);need(file_id(row),"View entry invalid");total+=row["bytes"]
  need(total<1<<30,"View payload over profile");bound+=((row["bytes"]+511)//512)*512+1024+((len(key.encode())+1023)//512)*512
 index=None;seen=set();object_ids={};last=0
 with tempfile.TemporaryFile() as expanded:
  incoming,pre=opened(archive);dec=lzma.LZMADecompressor(memlimit=128<<20);expanded_size=0
  with incoming:
   while not dec.eof:
    block=incoming.read(1<<20) if dec.needs_input else b""
    need(block or not dec.needs_input,"Truncated view XZ")
    raw=dec.decompress(block,max_length=min(1<<20,bound-expanded_size+1));expanded_size+=len(raw)
    need(expanded_size<=bound,"View XZ exceeds roster");expanded.write(raw)
   need(not dec.unused_data and not incoming.read(1),"Trailing view XZ")
   need(meta_fields(pre)==meta_fields(os.fstat(incoming.fileno())),"View changed while reading")
  expanded.seek(0)
  with tarfile.open(fileobj=expanded,mode="r:") as tar:
   for m in tar:
    need(m.name not in seen and m.name in entries,"Extra/duplicate view member");seen.add(m.name)
    need(m.isfile() and m.type==tarfile.REGTYPE and not m.sparse and not m.linkname and m.mode==0o600 and m.uid==m.gid==m.mtime==0 and m.uname==m.gname=="" and set(m.pax_headers)<={"path"},"Invalid view member metadata")
    need(type(m.size) is int and m.size==entries[m.name]["bytes"],"View member size changed")
    h=hashlib.sha256();n=0;chunks=[] if m.name=="index.json" else None
    with tar.extractfile(m) as stream:
     for raw in iter(lambda:stream.read(1<<20),b""):
      h.update(raw);n+=len(raw)
      if chunks is not None:chunks.append(raw)
    actual={"bytes":n,"sha256":h.hexdigest()};need(same(actual,entries[m.name]),"Changed view member bytes")
    if m.name=="index.json":index=read_json(b"".join(chunks))
    else:
     need(m.name=="objects/sha256/"+actual["sha256"][:2]+"/"+actual["sha256"][2:],"CAS path differs from complete bytes")
     need(actual["sha256"] not in object_ids,"Duplicate CAS identity");object_ids[actual["sha256"]]=actual
    last=m.offset_data+((m.size+511)//512)*512
  need(seen==set(entries),"Missing view member")
  expanded.seek(last);tail=expanded.read(tarfile.RECORDSIZE+1025)
  need(1024<=len(tail)<=tarfile.RECORDSIZE+1024 and not any(tail) and not expanded.read(1) and expanded_size%tarfile.RECORDSIZE==0,"Noncanonical view tar tail")
 need(type(index) is dict and index.get("schema")=="trnm.hia.work-owner-development-cas-view-index.v1" and index.get("scope")==manifest["scope"],"Wrong index")
 need(same(index.get("source_set_sha256"),"ded1230a8810c345bd705070045228b4b72078f35f007747351aa5a01c19908c"),"View source graph differs")
 logical=index["logical_files"];need(type(logical) is dict and logical,"Logical index absent")
 need(same(set_to_list:=sorted(k.removeprefix("evidence/") for k in logical if k.startswith("evidence/")),sorted(index["complete_package_entries"])),"Complete evidence roster changed")
 primary=index["complete_package_entries"];git_refs=index["git_objects"];need(type(git_refs) is dict,"Git reference index absent")
 commit=index["git_commit"];tree=index["git_tree"]
 need(all(type(v) is str and len(v)==40 and all(c in "0123456789abcdef" for c in v) for v in (commit,tree)),"Invalid exact Git commit/tree")
 actual_tree=subprocess.check_output(["git","--no-replace-objects","rev-parse",commit+"^{tree}"],cwd=repository).decode().strip();need(actual_tree==tree,"Referenced Git tree differs")
 tree_raw=subprocess.check_output(["git","--no-replace-objects","ls-tree","-r","-z",commit],cwd=repository)
 tree_map={}
 for entry in tree_raw.split(b"\0"):
  if not entry:continue
  head,rawpath=entry.split(b"\t",1);mode,kind,oid=head.split()
  if kind==b"blob":tree_map[rawpath.decode()]={"mode":mode.decode(),"oid":oid.decode()}
 g=Git(repository);verified_git={}
 try:
  for key,row in git_refs.items():
   need(type(row) is dict and set(row)=={"bytes","sha256","path","blob","git_mode"} and file_id({k:row[k] for k in ("bytes","sha256")}),"Invalid Git reference")
   name(row["path"]);need(key==row["sha256"] and tree_map.get(row["path"])=={"mode":row["git_mode"],"oid":row["blob"]},"Git reference path/object mismatch")
   need(same(ident(g.blob(row["blob"])),{k:row[k] for k in ("bytes","sha256")}),"Actual referenced Git bytes differ")
   verified_git[key]={k:row[k] for k in ("bytes","sha256")}
 finally:g.close()
 actual_binary=file_identity(binary);binary_info=index["external_original_binary"]
 need(same(actual_binary,{k:binary_info[k] for k in ("bytes","sha256")}),"External independent binary differs")
 st=Path(binary).lstat();need(stat.S_IMODE(st.st_mode)==0o500 and st.st_nlink==1,"External binary permissions/link count changed")
 used_cas=set();used_git=set();external=0
 for logical_name,row in logical.items():
  name(logical_name);need(type(row) is dict and set(row)=={"bytes","sha256","mode","storage"} and file_id({k:row[k] for k in ("bytes","sha256")}) and type(row["mode"]) is int,"Malformed logical row")
  wanted={k:row[k] for k in ("bytes","sha256")};storage=row["storage"];need(type(storage) is dict and set(storage)=={"kind","key"},"Malformed storage reference")
  if storage["kind"]=="cas":
   need(storage["key"]==row["sha256"] and same(object_ids.get(storage["key"]),wanted),"Missing/changed CAS object");used_cas.add(storage["key"])
  elif storage["kind"]=="git":
   need(storage["key"]==row["sha256"] and same(verified_git.get(storage["key"]),wanted),"Missing/changed Git object");used_git.add(storage["key"])
  else:
   need(storage=={"kind":"external-original-binary","key":"original-test-binary"} and logical_name=="evidence/original/original-test-binary" and same(actual_binary,wanted) and row["mode"]==0o500,"Unexpected external data");external+=1
  if logical_name.startswith("evidence/"):
   original_name=logical_name.removeprefix("evidence/")
   need(same(primary[original_name],wanted) and row["mode"]==(0o500 if original_name=="original/original-test-binary" else 0o600),"Logical evidence differs from captured full package")
 need(used_cas==set(object_ids) and used_git==set(verified_git) and external==1,"Unused/missing CAS/Git/external object")
 need(same(file_identity(archive),before),"View archive changed")
 return {"status":"COMPLETE_DEVELOPMENT_VIEW_READBACK_PASS","archive":before,"logical_files":len(logical),"complete_evidence_members":len(primary),"complete_evidence_bytes":sum(v["bytes"] for v in primary.values()),"CAS_objects":len(object_ids),"CAS_bytes":sum(v["bytes"] for v in object_ids.values()),"Git_referenced_objects":len(verified_git),"Git_referenced_logical_files":sum(v["storage"]["kind"]=="git" for v in logical.values()),"complete_original_binary_retained_externally":actual_binary,"whole_complete_CI_archive_retained_externally":index["complete_package_archive"],"new_native_or_original_execution":False,"hosted_qualification_claimed":False}
def main():
 need(__debug__,"Development view reader refuses optimized Python")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--archive",required=True,type=Path);p.add_argument("--manifest",required=True,type=Path);p.add_argument("--repository",required=True,type=Path);p.add_argument("--original-binary",required=True,type=Path);a=p.parse_args()
 print(json.dumps(verify(a.archive,a.manifest,a.repository,a.original_binary),sort_keys=True))
if __name__=="__main__":main()
