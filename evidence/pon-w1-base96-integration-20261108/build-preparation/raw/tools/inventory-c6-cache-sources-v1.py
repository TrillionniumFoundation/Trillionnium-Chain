#!/usr/bin/env python3
"""Read-only qualified C6 cache source inventory for separate C7 copy attempts."""
import hashlib,json,os,shutil,stat,time
from pathlib import Path
TOOLS=Path("/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b")
OUT=TOOLS/"cache-source-inventory-01.json"
assert not OUT.exists()
SOURCE={"commit":"2bdd252aa6c300b7431b9ee897b254b7953cf562","tree":"ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"}
roles=[
{"role":"backend","source_target":"/home/qian-qi/work/chain-w1-base62-backend-target-20261108-ec265b","destination_target":"/home/qian-qi/work/chain-w1-base96-backend-target-20261108-ec265b","qualification":"/home/qian-qi/work/chain-w1-c6-backend-qualification-20261108-ec265b-02/manifest.json","qualification_sha256":"f7c538e360541f15ebea2f8aea7e2fc50bde53ee1cdcd1354b3624b042c2979c","binaries":{"release/w1-staged-prover-v2":"9ff491a702f6833a73c10129d688ad77a905fc7ebaedfbc8784c7f8c485b77ac"}},
{"role":"native","source_target":"/home/qian-qi/work/chain-w1-base62-native-empty-target-20261108-ec265b-03","destination_target":"/home/qian-qi/work/chain-w1-base96-native-target-20261108-ec265b","qualification":"/home/qian-qi/work/chain-w1-c6-native-qualification-20261108-ec265b-01/manifest.json","qualification_sha256":"1a7bec56da77f9d0fc0fc647adb618f705c42f03e7e40c2728773cc55844e352","binaries":{"release/examples/pon_w1_native_winner_v2":"753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03","release/w1-verify-v2":"f9de534d894e4d0e012d31055fdc4a626addd5efd12ad19d61ff9d7d9867e7a1"}}
]
def pin(p):
    assert p.is_file() and not p.is_symlink()
    h=hashlib.sha256()
    with p.open("rb") as f:
        b=os.fstat(f.fileno())
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        a=os.fstat(f.fileno())
    assert (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)==(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
    return {"path":str(p),"bytes":a.st_size,"sha256":h.hexdigest(),"device":a.st_dev,"inode":a.st_ino,"nlink":a.st_nlink}
observations=[]
for role in roles:
    src=Path(role["source_target"]);dst=Path(role["destination_target"]);assert src.is_dir() and not src.is_symlink()
    assert not os.path.lexists(dst)
    qualification=pin(Path(role["qualification"]));assert qualification["sha256"]==role["qualification_sha256"]
    q=json.loads(Path(role["qualification"]).read_text());assert q["qualification_complete"] is True and q["source"]==SOURCE and q["target"]==str(src)
    binaries={rel:pin(src/rel) for rel in role["binaries"]}
    assert all(binaries[rel]["sha256"]==sha for rel,sha in role["binaries"].items())
    regular_count=regular_bytes=0;symlinks=[];special=[]
    for base,dirs,files in os.walk(src,followlinks=False):
        for leaf in dirs+files:
            p=Path(base)/leaf;st=p.lstat()
            if stat.S_ISREG(st.st_mode):regular_count+=1;regular_bytes+=st.st_size
            elif stat.S_ISLNK(st.st_mode):symlinks.append({"relative_path":str(p.relative_to(src)),"target":os.readlink(p)})
            elif not stat.S_ISDIR(st.st_mode):special.append({"relative_path":str(p.relative_to(src)),"mode":st.st_mode})
    assert not special
    observations.append({**role,"source":SOURCE,"source_qualification":qualification,"observed_binaries":binaries,"source_regular_file_count":regular_count,"source_regular_logical_bytes_counting_each_directory_entry":regular_bytes,"source_symlinks":symlinks,"source_special_files":special,"destination_existed_at_inventory":False})
usage=shutil.disk_usage(TOOLS.parent)
required=sum(r["source_regular_logical_bytes_counting_each_directory_entry"] for r in observations)*2+10*1024**3
assert usage.free>required,(usage.free,required)
result={"schema":"TRNM-W1-C7-CACHE-SOURCE-INVENTORY1","observed_monotonic_ns":time.monotonic_ns(),"boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"roles":observations,"disk":{"total_bytes":usage.total,"used_bytes":usage.used,"free_bytes":usage.free,"conservative_copy_capacity_floor_bytes":required},"separate_copy_attempt_budgets_seconds":{"backend":1800,"native":1800},"copy_order":["backend","native"],"no_source_target_writes":True,"cargo_started":False,"operation_created":False,"copied":False,"fresh_cargo_target_after_copy":False,"independent_cleanroom_build":False}
with OUT.open("x") as f:json.dump(result,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
print(json.dumps({"inventory":pin(OUT),"disk":result["disk"],"roles":[{"role":r["role"],"source_regular_file_count":r["source_regular_file_count"],"logical_bytes":r["source_regular_logical_bytes_counting_each_directory_entry"],"symlinks":len(r["source_symlinks"]),"binaries":r["observed_binaries"]} for r in observations]}),flush=True)
