#!/usr/bin/env python3
"""Verify official bounded parts and extract only indexed closed evidence."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile
ROOT = Path("/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1")
PARTS = json.loads("[{\"offset\":0,\"path\":\"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1/official-transfer-v1/parts/0000000000.part\",\"bytes\":262144,\"sha256\":\"fcee69bf2a482e9c7e1f5552f22269a701375151204c945606daecfb3a2a6161\",\"version\":\"16777233:607014037:262144:1794655853514089719:1794655853514685799\"},{\"offset\":262144,\"path\":\"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1/official-transfer-v1/parts/0000262144.part\",\"bytes\":262144,\"sha256\":\"b4338601d6116ab1ba05f08638705305dfbaaabf1ae2a13ac39de9f79a9cb9d8\",\"version\":\"16777233:607014262:262144:1794655877556997000:1794655877557768454\"},{\"offset\":524288,\"path\":\"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1/official-transfer-v1/parts/0000524288.part\",\"bytes\":262144,\"sha256\":\"fd3fa8feec683056fb38e408b4742e544d8780adf63824faf1b29864b0379e02\",\"version\":\"16777233:607014382:262144:1794655897311203181:1794655897314445331\"},{\"offset\":786432,\"path\":\"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1/official-transfer-v1/parts/0000786432.part\",\"bytes\":262144,\"sha256\":\"527badc69342f57ebfadc4ade639140f842edd10a17d79dbf6f998938b4a771b\",\"version\":\"16777233:607014532:262144:1794655912789523281:1794655912790125027\"},{\"offset\":1048576,\"path\":\"/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1/official-transfer-v1/parts/0001048576.part\",\"bytes\":47140,\"sha256\":\"991652798d2d80a05edb375f65f93203b85c06e3722566e0c179b4afd54a72e2\",\"version\":\"16777233:607014637:47140:1794655916048203525:1794655916048788313\"}]")
READS = json.loads("[{\"chunk_sha256\":\"239be2b0bee856f96b94cea802a3445ef13db8dfcd43ceea284acf3b31105f63\",\"eof\":false,\"next_offset\":65536,\"offset\":0,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"85ff79901cdc6e3481c419a825b8acbf5c4f67339615cf631c32e18b7a7fb3ec\",\"eof\":false,\"next_offset\":131072,\"offset\":65536,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"059956bda6d09b38495741361838fce2042a3b020c813682da37401669fe3857\",\"eof\":false,\"next_offset\":196608,\"offset\":131072,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"300ead9485d2bcc789f93572726f79a8c2d9732a8ffba92ba765907d86e98886\",\"eof\":false,\"next_offset\":262144,\"offset\":196608,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"e600ee26c893b3fafa9c55115e224dbb79c11adc2f1956c20a09cad9f063a539\",\"eof\":false,\"next_offset\":327680,\"offset\":262144,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"6f8e379d0893d7098da559d42f25beed44309cfc2ac2a1924398c608dd6c8648\",\"eof\":false,\"next_offset\":393216,\"offset\":327680,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"b07384e3c3d89951918eb6b2619dd2e26bd9ecc7212d24bdb62c489f919bb6c8\",\"eof\":false,\"next_offset\":458752,\"offset\":393216,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"41bc1d9bcb0a6b2b5ad73d5bccbeed49d45d4e7fb344555071ab0980a28bf9b6\",\"eof\":false,\"next_offset\":524288,\"offset\":458752,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"580dcae2eef5c4fb6e8807ef3d2cdc43684e4d0985a398d18002aa65737a0aad\",\"eof\":false,\"next_offset\":589824,\"offset\":524288,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"d3486c497f825db05edcb7618b899cc2cf46092d5027246d8773a9653b96bb7e\",\"eof\":false,\"next_offset\":655360,\"offset\":589824,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"97b9d88812f3262b29fb2d8015d51bbda8fdca1f8d4d6a4d0bc21ec1cf853fd0\",\"eof\":false,\"next_offset\":720896,\"offset\":655360,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"e2be7545aad5790f2bddfffffae323c33e57ac0ef973e00eb48aeb8bc5af23d9\",\"eof\":false,\"next_offset\":786432,\"offset\":720896,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"4e8d1b1c349b61aa569de90479f5ea223a5483538996d7383cebb081bd988e49\",\"eof\":false,\"next_offset\":851968,\"offset\":786432,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"cbd18df6999612f8a47bb091558f6488ef03d783cd3922121c609869fe46f953\",\"eof\":false,\"next_offset\":917504,\"offset\":851968,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"5b890fbc9342556f5e239b073d38c4fae4651120fed4acc09e5bcde33cf50dbe\",\"eof\":false,\"next_offset\":983040,\"offset\":917504,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"16079ec5052a18fffb91b15979789a793476d291b6e1a7fefaa6e217b7ae22e6\",\"eof\":false,\"next_offset\":1048576,\"offset\":983040,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"},{\"chunk_sha256\":\"991652798d2d80a05edb375f65f93203b85c06e3722566e0c179b4afd54a72e2\",\"eof\":true,\"next_offset\":1095716,\"offset\":1048576,\"path\":\"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip\",\"size\":1095716,\"version\":\"66306:34757390:1095716:1794655745011178836:1794655745011178836\"}]")
ZIP_SHA = "a6057f107f220d146be4fbe70d6ef60b369bf29eaa40f65a640556fd4840b844"
ZIP_BYTES = 1095716
INDEX_SHA = "06c02ce72e1632f4b0004edd24c1383c3af016525ea90988978aaeec71b1c39c"
SUMMARY_SHA = "f8335bdcc74f7e2b095fe8582fa32e78252c04ca55fa82284363bea072e1b96a"
ROG_PACKAGE = "/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1"
FILE_CAP = 16 * 1024 * 1024
TOTAL_CAP = 64 * 1024 * 1024
RFLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
WFLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

def require(ok, message):
    if not ok:
        raise ValueError(message)

def fp(s):
    return {"dev":s.st_dev,"ino":s.st_ino,"mode":s.st_mode,"nlink":s.st_nlink,
            "size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}

def check_parents(path):
    path = Path(path)
    require(path.is_absolute() and str(path.resolve()) == str(path), "noncanonical path")
    for parent in [path.parent, *path.parent.parents]:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and not parent.is_symlink(), "unsafe parent")

def safe_relative(value):
    p=PurePosixPath(value)
    require(not p.is_absolute() and str(p)==value and value!=".", "unsafe member")
    require(all(x not in ("",".","..",".git") and "\\" not in x
                and all(ord(c)>=32 and ord(c)!=127 for c in x) for x in p.parts),
            "unsafe member component")
    return p

def read(path, cap=FILE_CAP):
    path=Path(path);check_parents(path)
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,
            "unsafe file or cap exceeded")
    fd=os.open(path,RFLAGS)
    try:
        require(fp(os.fstat(fd))==fp(before),"opened file changed")
        pieces=[];size=0
        while True:
            b=os.read(fd,65536)
            if not b:break
            size+=len(b);require(size<=cap and size<=before.st_size,"file grew")
            pieces.append(b)
        require(size==before.st_size and fp(os.fstat(fd))==fp(before)==fp(path.lstat()),
                "file changed during read")
        return b"".join(pieces),fp(before)
    finally:os.close(fd)

def put(path,data):
    path=Path(path);check_parents(path)
    fd=os.open(path,WFLAGS,0o600)
    try:
        offset=0
        while offset<len(data):offset+=os.write(fd,data[offset:])
        os.fsync(fd)
    finally:os.close(fd)
    got,identity=read(path)
    require(got==data,"target readback mismatch")
    return identity

def jbytes(obj):
    return (json.dumps(obj,indent=2,sort_keys=True)+"\n").encode()

def make_parent(path):
    require(ROOT/"payloads" in path.parents,"target escaped payload")
    current=ROOT/"payloads"
    for component in path.relative_to(current).parts[:-1]:
        current=current/component
        try:current.mkdir(mode=0o700)
        except FileExistsError:
            s=current.lstat()
            require(stat.S_ISDIR(s.st_mode) and not current.is_symlink(),"unsafe existing target parent")
        require(str(current.resolve())==str(current),"target parent not canonical")

def main():
    require(ROOT.is_dir() and not ROOT.is_symlink() and str(ROOT.resolve())==str(ROOT),"root fence")
    (ROOT/"copy-validation-v1").mkdir(mode=0o700)
    (ROOT/"payloads").mkdir(mode=0o700)
    part_fps={};data_parts=[];offset=0
    for p in PARTS:
        require(p["offset"]==offset,"part gap")
        data,identity=read(p["path"])
        require(len(data)==p["bytes"] and hashlib.sha256(data).hexdigest()==p["sha256"],"part mismatch")
        data_parts.append(data);part_fps[p["path"]]=identity;offset+=len(data)
    raw=b"".join(data_parts)
    require(offset==ZIP_BYTES and hashlib.sha256(raw).hexdigest()==ZIP_SHA,"whole ZIP mismatch")
    expected_offset=0
    versions={c["version"] for c in READS}
    require(len(versions)==1,"source read versions differ")
    for c in READS:
        require(c["offset"]==expected_offset and c["size"]==ZIP_BYTES,"read chunk gap/size")
        b=raw[c["offset"]:c["next_offset"]]
        require(hashlib.sha256(b).hexdigest()==c["chunk_sha256"],"read chunk SHA mismatch")
        expected_offset=c["next_offset"]
    require(expected_offset==ZIP_BYTES and READS[-1]["eof"] is True,"read coverage incomplete")
    zip_path=ROOT/"package"/"original-closed-P1-sparse-receipts-v1.zip"
    put(zip_path,raw)
    index_raw,index_fp=read(ROOT/"package"/"EVIDENCE_INDEX.json")
    summary_raw,summary_fp=read(ROOT/"package"/"summary.json")
    require(hashlib.sha256(index_raw).hexdigest()==INDEX_SHA,"index pin mismatch")
    require(hashlib.sha256(summary_raw).hexdigest()==SUMMARY_SHA,"summary pin mismatch")
    index=json.loads(index_raw);summary=json.loads(summary_raw)
    require(summary["status"]=="SOURCE_RAW_PACKAGE_VERIFIED" and summary["source_before_after_identical"] is True,
            "ROG package not verified")
    require(summary["original_files"]==95 and summary["original_bytes"]==12624662,"original count mismatch")
    require(index["file_count"]==98 and index["original_file_count"]==95 and
            index["original_total_bytes"]==12624662,"index scope mismatch")
    rows=index["files"]+[{"path":"EVIDENCE_INDEX.json","bytes":len(index_raw),"sha256":INDEX_SHA,
                          "origin":{"host":"rog","path":ROG_PACKAGE+"/EVIDENCE_INDEX.json"}}]
    names=[x["path"] for x in rows]
    require(len(names)==99 and len(set(names))==len(names),"duplicate expected names")
    for name in names:
        safe_relative(name)
        require(not any(other.startswith(name+"/") for other in names),"file/directory prefix collision")
    require(sum(x["bytes"] for x in rows)==12792499 and
            sum(x["bytes"] for x in rows)<=TOTAL_CAP,"uncompressed aggregate cap")
    outcomes=[];origins=[]
    with zipfile.ZipFile(io.BytesIO(raw),"r") as archive:
        require(len(archive.infolist())==len(rows) and set(archive.namelist())==set(names),
                "zip roster mismatch")
        for row in rows:
            info=archive.getinfo(row["path"])
            mode=info.external_attr>>16
            require(not info.is_dir() and stat.S_ISREG(mode) and
                    info.file_size==row["bytes"]<=FILE_CAP and not (info.flag_bits&1),
                    "zip type/size/encryption mismatch")
            data=archive.read(row["path"])
            require(len(data)==row["bytes"] and hashlib.sha256(data).hexdigest()==row["sha256"],
                    "member CRC/size/SHA mismatch")
            target=ROOT/"payloads"/row["path"]
            make_parent(target)
            identity=put(target,data)
            outcomes.append({"member":row["path"],"crc32":format(info.CRC,"08x"),"bytes":len(data),
                             "sha256":row["sha256"],"target_fingerprint":identity})
            origins.append({"path":str(target.relative_to(ROOT)),"bytes":len(data),
                            "sha256":row["sha256"],"origin":row["origin"]})
    for empty in index["empty_original_directories"]:
        absolute=empty["path"]
        prefix="/home/qian-qi/chain-final-consolidation-20261114-root/"
        require(empty["host"]=="rog" and absolute.startswith(prefix),"empty dir origin")
        rel="originals/"+absolute[len(prefix):]
        safe_relative(rel)
        target=ROOT/"payloads"/rel
        make_parent(target/"sentinel")
        require(target.is_dir() and list(target.iterdir())==[],"empty directory mismatch")
    for row in origins:
        data,identity=read(ROOT/row["path"])
        require(len(data)==row["bytes"] and hashlib.sha256(data).hexdigest()==row["sha256"],"final target mismatch")
        original=next(x["target_fingerprint"] for x in outcomes if "payloads/"+x["member"]==row["path"])
        require(identity==original,"target identity changed")
    for path,identity in part_fps.items():
        data,now=read(path)
        require(now==identity,"official part changed")
    require(read(ROOT/"package"/"EVIDENCE_INDEX.json")[1]==index_fp,"index source identity changed")
    require(read(ROOT/"package"/"summary.json")[1]==summary_fp,"summary source identity changed")
    original_root=ROOT/"payloads"/"originals"
    first=json.loads(read(original_root/"final-repository-truth-offline-6a8cd5-v1"/"summary.json")[0])
    correction=json.loads(read(original_root/"P1-sparse-checkout-correction-v1"/"summary.json")[0])
    require(first["status"]=="failed" and len(first["steps"])==17,"original failure not preserved")
    require(correction["status"]=="FULL_CHECKOUT_RESTORED_AND_ORIGINAL_SOURCE_VERIFIED",
            "correction terminal mismatch")
    require(not (original_root/"final-repository-truth-offline-6a8cd5-v1"/"source-before.json").exists()
            and not (original_root/"final-repository-truth-offline-6a8cd5-v1"/"source-after.json").exists(),
            "original absent sidecar fabricated")
    result={
        "schema":"trnm-P1-closed-sparse-official-copy-verification-v1",
        "status":"COMPLETE_ALL_99_MEMBERS_CRC_BYTES_SHA_AND_TARGET_IDENTITIES_VERIFIED",
        "source_original_count":95,"source_original_bytes":12624662,
        "zip_members":99,"zip_member_bytes":12792499,
        "zip":{"path":str(zip_path),"bytes":ZIP_BYTES,"sha256":ZIP_SHA,
               "origin":{"host":"rog","path":ROG_PACKAGE+"/"+zip_path.name}},
        "source_read_version":next(iter(versions)),"official_read_chunks":len(READS),
        "official_write_parts":len(PARTS),"member_results":outcomes,
        "first_failed_lane":{"status":first["status"],"steps":len(first["steps"]),
                             "source_sidecars_absent_preserved":True,"test_lane_not_started":True},
        "correction_status":correction["status"],
        "source_or_git_mutation":False,"tests_rerun":False,"active_full_v2_read":False,"stage_written":False,
        "scope":"Only four closed evidence directories and their raw package; no restored historical ZIP bodies or live run."
    }
    put(ROOT/"copy-validation-v1"/"member-verification.json",jbytes(result))
    put(ROOT/"copy-validation-v1"/"payload-origins.json",jbytes(origins))
    print(json.dumps({k:v for k,v in result.items() if k!="member_results"},sort_keys=True))

if __name__=="__main__":
    main()
