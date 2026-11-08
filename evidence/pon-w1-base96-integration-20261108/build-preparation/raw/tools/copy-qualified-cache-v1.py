#!/usr/bin/env python3
"""One isolated cache copy from qualified C6; never Cargo or an operation."""
import argparse,hashlib,json,os,shutil,stat,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--role",choices=("backend","native"),required=True)
p.add_argument("--inventory",type=Path,required=True)
p.add_argument("--inventory-sha256",required=True)
p.add_argument("--record-prefix",required=True)
p.add_argument("--outer-timeout-seconds",type=int,choices=(1800,),required=True)
a=p.parse_args()
TOOLS=Path(__file__).resolve().parent
assert a.record_prefix==a.role+"-cache-copy-01"
def pin(p):
    assert p.is_file() and not p.is_symlink()
    h=hashlib.sha256()
    with p.open("rb") as f:
        b=os.fstat(f.fileno())
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        z=os.fstat(f.fileno())
    assert (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
    return {"path":str(p),"bytes":z.st_size,"sha256":h.hexdigest(),"device":z.st_dev,"inode":z.st_ino,"nlink":z.st_nlink}
def write(p,v):
    with p.open("x") as f:json.dump(v,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def identify(pid):
    try:
        fields=(Path("/proc")/str(pid)/"stat").read_text().rsplit(") ",1)[1].split()
        return {"pid":pid,"boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"start_ticks":int(fields[19]),"state":fields[0]}
    except FileNotFoundError:return {"pid":pid,"identity_unavailable":True}
def inventory(root):
    files={};links={};dirs=[]
    for base,ds,fs in os.walk(root,followlinks=False):
        for leaf in ds+fs:
            path=Path(base)/leaf;st=path.lstat();rel=str(path.relative_to(root))
            if stat.S_ISREG(st.st_mode):files[rel]=[st.st_dev,st.st_ino,st.st_nlink,st.st_size,st.st_mode,st.st_mtime_ns,st.st_ctime_ns]
            elif stat.S_ISLNK(st.st_mode):links[rel]=os.readlink(path)
            elif stat.S_ISDIR(st.st_mode):dirs.append(rel)
            else:raise ValueError("special cache entry: "+str(path))
    return {"files":files,"symlinks":links,"directories":sorted(dirs)}
def stat_digest(data):return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
assert pin(a.inventory)["sha256"]==a.inventory_sha256
original=json.loads(a.inventory.read_text());assert original["schema"]=="TRNM-W1-C7-CACHE-SOURCE-INVENTORY1"
roles=[r for r in original["roles"] if r["role"]==a.role];assert len(roles)==1
role=roles[0];src=Path(role["source_target"]);dst=Path(role["destination_target"])
assert src.is_absolute() and src.resolve()==src and src.is_dir()
assert dst.is_absolute() and dst.resolve()==dst and not os.path.lexists(dst)
assert dst.parent==TOOLS.parent and not dst.is_relative_to(src) and not src.is_relative_to(dst)
qualification=pin(Path(role["qualification"]));assert qualification["sha256"]==role["qualification_sha256"]
q=json.loads(Path(role["qualification"]).read_text());assert q["qualification_complete"] is True and q["source"]==role["source"] and q["target"]==str(src)
before={rel:pin(src/rel) for rel in role["binaries"]}
assert all(before[rel]==role["observed_binaries"][rel] for rel in before)
src_inventory=inventory(src)
assert len(src_inventory["files"])==role["source_regular_file_count"]
assert src_inventory["symlinks"]=={}
size=sum(meta[3] for meta in src_inventory["files"].values())
usage=shutil.disk_usage(dst.parent);assert usage.free>size*2+5*1024**3
out=TOOLS/(a.record_prefix+".json")
assert not out.exists()
start=time.monotonic_ns()
declaration={"schema":"TRNM-W1-C7-CACHE-COPY-DECLARATION1","role":a.role,"source_target":str(src),"destination":str(dst),"source":role["source"],"source_qualification":qualification,"source_inventory":pin(a.inventory),"outer_hepta_timeout_seconds":a.outer_timeout_seconds,"started_monotonic_ns":start,"owner_identity":identify(os.getpid()),"supervisor_identity":identify(os.getppid()),"owner_cgroup":Path("/proc/self/cgroup").read_text().strip(),"source_binaries_before":before,"source_regular_file_count":len(src_inventory["files"]),"source_regular_logical_bytes":size,"source_stat_inventory_sha256":stat_digest(src_inventory),"disk_free_bytes_before":usage.free,"copy_argv":["/usr/bin/cp","-a","--reflink=auto","--no-preserve=links","--",str(src),str(dst)],"reflink_auto_may_share_copy_on_write_extents":True,"hardlinks_to_source_allowed":False,"deadline_extension_allowed":False,"scope":"this independent preparation attempt only","cargo_started":False,"operation_created":False,"destination_binaries_qualified_for_c7":False}
write(TOOLS/(a.record_prefix+".declaration.json"),declaration)
cp_started=time.monotonic_ns()
with (TOOLS/(a.record_prefix+".stdout")).open("xb") as so,(TOOLS/(a.record_prefix+".stderr")).open("xb") as se:
    child=subprocess.Popen(declaration["copy_argv"],stdout=so,stderr=se)
    intent={"schema":"TRNM-W1-C7-CACHE-COPY-CHILD1","role":a.role,"identity":identify(child.pid),"observed_monotonic_ns":time.monotonic_ns(),"parent_identity":identify(os.getpid()),"source_target":str(src),"destination":str(dst)}
    write(TOOLS/(a.record_prefix+".child.json"),intent)
    code=child.wait()
cp_finished=time.monotonic_ns()
copy_return={"exit_code":code,"direct_child_waited":True,"started_monotonic_ns":cp_started,"finished_monotonic_ns":cp_finished,"child_intent":pin(TOOLS/(a.record_prefix+".child.json")),"stdout":pin(TOOLS/(a.record_prefix+".stdout")),"stderr":pin(TOOLS/(a.record_prefix+".stderr"))}
write(TOOLS/(a.record_prefix+".return.json"),copy_return)
assert code==0,copy_return
after={rel:pin(src/rel) for rel in before};assert before==after
src_after=inventory(src);assert src_inventory==src_after
destination=inventory(dst)
assert set(destination["files"])==set(src_inventory["files"])
assert destination["symlinks"]==src_inventory["symlinks"]=={} and destination["directories"]==src_inventory["directories"]
assert all(destination["files"][rel][3:5]==src_inventory["files"][rel][3:5] for rel in src_inventory["files"])
src_inodes={(m[0],m[1]) for m in src_inventory["files"].values()}
dst_inodes={(m[0],m[1]) for m in destination["files"].values()}
shared=len(src_inodes&dst_inodes)
hardlinks=sum(m[2]!=1 for m in destination["files"].values())
duplicate_inodes=len(destination["files"])-len(dst_inodes)
assert shared==hardlinks==duplicate_inodes==0
copied={rel:pin(dst/rel) for rel in before}
assert all(copied[rel]["bytes"]==before[rel]["bytes"] and copied[rel]["sha256"]==before[rel]["sha256"] and copied[rel]["nlink"]==1 and (copied[rel]["device"],copied[rel]["inode"])!=(before[rel]["device"],before[rel]["inode"]) for rel in before)
assert pin(Path(role["qualification"]))==qualification
result={"schema":"TRNM-W1-ISOLATED-QUALIFIED-CACHE-COPY1","role":a.role,"source_target":str(src),"destination":str(dst),"source":role["source"],"source_qualification":qualification,"source_inventory":pin(a.inventory),"declaration":pin(TOOLS/(a.record_prefix+".declaration.json")),"copy_return":copy_return,"outer_hepta_timeout_seconds":a.outer_timeout_seconds,"started_monotonic_ns":start,"finished_monotonic_ns":time.monotonic_ns(),"source_binaries_before":before,"source_binaries_after":after,"destination_binaries":copied,"regular_files_checked":len(destination["files"]),"logical_bytes_counting_each_directory_entry":sum(m[3] for m in destination["files"].values()),"shared_source_inode_count":shared,"destination_hardlink_count":hardlinks,"destination_duplicate_inode_count":duplicate_inodes,"symlink_count":len(destination["symlinks"]),"source_stat_inventory_before_sha256":stat_digest(src_inventory),"source_stat_inventory_after_sha256":stat_digest(src_after),"source_regular_metadata_unchanged":True,"source_target_written":False,"copy_complete":True,"copy_exit_code":0,"fresh_cargo_target":False,"registry_cache_reused":True,"toolchain_reused":True,"independent_cleanroom_build":False,"reflink_auto_may_share_copy_on_write_extents":True,"scope":"this independent preparation attempt only","cargo_started":False,"operation_created":False,"destination_binaries_qualified_for_c7":False}
write(out,result)
print(json.dumps({"record":pin(out),"role":a.role,"copy_complete":True,"copy_exit_code":0,"checked_regular_files":len(destination["files"]),"shared_source_inode_count":shared,"destination_hardlink_count":hardlinks,"destination_binaries":copied}),flush=True)
