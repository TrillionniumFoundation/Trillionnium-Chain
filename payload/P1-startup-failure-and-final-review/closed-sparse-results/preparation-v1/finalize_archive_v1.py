#!/usr/bin/env python3
"""Seal the completed bounded archive copy, without touching any source or live run."""
import hashlib,json,os,stat
from pathlib import Path
ROOT=Path("/private/tmp/chain-P1-sparse-checkout-closed-results-20261114-v1")
RFLAGS=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
def req(ok,msg):
 if not ok:raise ValueError(msg)
def fp(s):return {"dev":s.st_dev,"ino":s.st_ino,"mode":s.st_mode,"nlink":s.st_nlink,"size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}
def read(p):
 req(str(p.resolve())==str(p),"path not canonical")
 a=p.lstat();req(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=16777216,"file type/cap")
 fd=os.open(p,RFLAGS)
 try:
  req(fp(os.fstat(fd))==fp(a),"open replaced")
  chunks=[];total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);req(total<=a.st_size,"file grew");chunks.append(b)
  req(total==a.st_size and fp(os.fstat(fd))==fp(a)==fp(p.lstat()),"read changed")
  return b"".join(chunks),fp(a)
 finally:os.close(fd)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600)
 try:
  offset=0
  while offset<len(b):offset+=os.write(fd,b[offset:])
  os.fsync(fd)
 finally:os.close(fd)
 req(read(p)[0]==b,"write readback mismatch")
def jb(x):return (json.dumps(x,indent=2,sort_keys=True)+"\n").encode()
req(ROOT.is_dir() and not ROOT.is_symlink() and str(ROOT.resolve())==str(ROOT),"root")
# The earlier helper saved this actual terminal with an imprecise generated label.
old=ROOT/"official-transfer-v1"/"preparation-start.json"
new=ROOT/"official-transfer-v1"/"preparation-static-terminal.json"
req(not new.exists(),"label target exists")
old.rename(new)
readme="""# Closed P1 sparse-checkout startup records

This archive preserves four completed ROG evidence directories as their original bytes.
It does not rerun the repository lane, its tests, the original producers, or any Git command.
It excludes the active full-v2 directory and the source worktree/Git database.

## Preserved originals

| Original directory | Files | Bytes |
|---|---:|---:|
| final-repository-truth-offline-6a8cd5-v1 | 35 | 24,402 |
| P1-index-flag-diagnostic-v1 | 22 | 4,199,223 |
| P1-sparse-checkout-precorrection-v1 | 5 | 4,133 |
| P1-sparse-checkout-correction-v1 | 33 | 8,396,904 |
| Total | 95 | 12,624,662 |

The first run remains failed: its 17 recorded stages stop at source verification and the
repository-truth test command did not start. Its source-before.json and source-after.json
were absent and are not fabricated here. The later correction remains separately recorded
as FULL_CHECKOUT_RESTORED_AND_ORIGINAL_SOURCE_VERIFIED. Root's normal sparse-checkout
disable restored two tracked historical ZIP files from existing local objects; neither
restored ZIP body nor the source/Git directory is included in this archive. No source
commit, gate logic, test expectations, quota, worker count, or deadline was changed by
this capture. A successful checkout verification is not a full lane or hosted performance pass.

All three 4,191,866-byte flags stdout files are retained in full, including their NUL bytes.
The empty first-run ci-observations and tmp directories are recorded and recreated.
The twelve selected original Mac root start/terminal/log records preserve all four actual
closed PTYs. Unrelated and active root tool records are excluded.

## Verification and transport

The ROG packager checked an exact previously observed inventory, all four original summary
SHA256 values, regular single-link files, canonical NOFOLLOW directory traversal, and
stable file/directory fingerprints. It reread all 95 original files for their SHA256 after
writing the ZIP. All 99 ZIP members (95 originals plus three package records and index)
were verified for CRC, bytes, and SHA256 on both ROG and Mac.

The ZIP is 1,095,716 bytes with SHA256
a6057f107f220d146be4fbe70d6ef60b369bf29eaa40f65a640556fd4840b844.
Seventeen official binary reads were pinned to one source version and copied through
five create-only official Mac binary writes. Every read chunk and write part was checked
against the assembled ZIP. Binary payloads reside in the exact parts/ZIP; read metadata
explicitly omits repeated base64 text. Full write receipts and actual packaging/receiver
PTY records are retained. The receiver used only the exact ZIP index, no extractall,
and checked each newly written target again through a stable descriptor.

The scope is the four explicit closed evidence directories, their transport/package
records, and the twelve selected original root tool records. It is not an audit of an
active run, the repository, its history, or all secrets. No stage was written during
this capture; any later materialization has its own receipt and baseline protection.
"""
put(ROOT/"README.md",readme.encode())
put(ROOT/"official-transfer-v1"/"save-transport-terminal.json",jb(json.loads("{\"content\":[{\"type\":\"text\",\"text\":\"{\\\"archive_path\\\":\\\"/Users/qianqi/.local/state/hepta-runtime-mac-worker/terminals/dpty-4b62cbc1ac61003c4e5a7e4da925cf7fc88c9e71b234e783e669bdb5447f3c8d/output.log\\\",\\\"available_end\\\":111,\\\"bytes_hex\\\":\\\"7b22737461747573223a2022414c4c5f5452414e53504f52545f414e445f41435455414c5f5445524d494e414c535f5341564544222c20226e65775f7472616e73706f72745f7265636f726473223a2031372c20226e65775f70726f64756365725f636f70696573223a20337d0d0a\\\",\\\"chunk_sha256\\\":\\\"b09ba3db8ab998b1b239cc754f65bbcbda32a31a4d8f2b0adb6b1b035142b605\\\",\\\"host\\\":\\\"mac\\\",\\\"next_offset\\\":111,\\\"offset\\\":0,\\\"output_complete\\\":true,\\\"persistent_across_runtime_restart\\\":true,\\\"session_id\\\":\\\"dpty-4b62cbc1ac61003c4e5a7e4da925cf7fc88c9e71b234e783e669bdb5447f3c8d\\\",\\\"status\\\":{\\\"boot\\\":\\\"{ sec = 1794536756, usec = 120098 } Fri Nov 13 10:25:56 2026\\\",\\\"bytes_seen\\\":111,\\\"bytes_stored\\\":111,\\\"capture_error\\\":null,\\\"closed\\\":false,\\\"created_unix_ms\\\":1794656041064,\\\"exit_code\\\":0,\\\"output_complete\\\":true,\\\"owner_pid\\\":2735,\\\"pid\\\":2736,\\\"state\\\":\\\"exited\\\"},\\\"storage\\\":\\\"target_archive\\\",\\\"text\\\":\\\"{\\\\\\\"status\\\\\\\": \\\\\\\"ALL_TRANSPORT_AND_ACTUAL_TERMINALS_SAVED\\\\\\\", \\\\\\\"new_transport_records\\\\\\\": 17, \\\\\\\"new_producer_copies\\\\\\\": 3}\\\\r\\\\n\\\",\\\"text_is_lossy\\\":false,\\\"truncated_before_offset\\\":false,\\\"utf8_pending\\\":false}\"}],\"structuredContent\":null,\"isError\":false}")))
origin={}
for source in [ROOT/"copy-validation-v1"/"payload-origins.json",
               ROOT/"official-transfer-v1"/"copied-source-origins.json"]:
 for row in json.loads(read(source)[0]):
  if row["path"] in origin:req(origin[row["path"]]==row,"origin conflict")
  origin[row["path"]]=row
origin["package/original-closed-P1-sparse-receipts-v1.zip"]={
 "path":"package/original-closed-P1-sparse-receipts-v1.zip","bytes":1095716,
 "sha256":"a6057f107f220d146be4fbe70d6ef60b369bf29eaa40f65a640556fd4840b844",
 "origin":{"host":"rog","path":"/home/qian-qi/chain-final-consolidation-20261114-root/closed-P1-sparse-checkout-results-package-v1/original-closed-P1-sparse-receipts-v1.zip"}}
rows=[];identities={};directories={}
def walk(p):
 initial=fp(p.lstat());req(stat.S_ISDIR(initial["mode"]) and not p.is_symlink(),"unsafe directory")
 rel=str(p.relative_to(ROOT));directories[rel]=initial
 names=sorted(x.name for x in p.iterdir())
 for name in names:
  q=p/name
  req(name not in (".git",".","..") and "\\" not in name and all(ord(c)>=32 and ord(c)!=127 for c in name),"unsafe name")
  s=q.lstat()
  if stat.S_ISDIR(s.st_mode):walk(q)
  else:
   b,identity=read(q);rel=str(q.relative_to(ROOT));sha=hashlib.sha256(b).hexdigest()
   row={"path":rel,"bytes":len(b),"sha256":sha,"origin":{"host":"mac","path":str(q)}}
   if rel in origin:
    req(origin[rel]["bytes"]==len(b) and origin[rel]["sha256"]==sha,"origin bytes mismatch")
    row["origin"]=origin[rel]["origin"]
   rows.append(row);identities[rel]=identity
 req(names==sorted(x.name for x in p.iterdir()) and initial==fp(p.lstat()),"directory changed")
walk(ROOT);rows.sort(key=lambda x:x["path"])
req(sum(x["bytes"] for x in rows)<=67108864,"closed archive aggregate cap")
req(sum(1 for x in rows if x["path"].startswith("payloads/originals/"))==95,"original coverage")
req(sum(x["bytes"] for x in rows if x["path"].startswith("payloads/originals/"))==12624662,"original bytes coverage")
req(sum(1 for x in rows if x["path"].startswith("root-closed-tool-records-v1/"))==12,"actual root tool coverage")
for row in rows:
 b,now=read(ROOT/row["path"]);req(now==identities[row["path"]] and hashlib.sha256(b).hexdigest()==row["sha256"],"final source fence")
index={"schema":"trnm-P1-closed-sparse-complete-archive-index-v1","evidence_root":str(ROOT),
       "file_count":len(rows),"total_bytes":sum(x["bytes"] for x in rows),"files":rows,
       "directories":sorted(directories),
       "scope":"Four closed ROG directories and complete bounded package/copy proof; no live source/Git/tests.",
       "original_file_count":95,"original_total_bytes":12624662,
       "root_original_tool_records":12,"first_failed_lane_status":"failed","first_test_lane_started":False}
index_raw=jb(index);put(ROOT/"EVIDENCE_INDEX.json",index_raw)
seal={"schema":"trnm-P1-closed-sparse-archive-seal-v1","status":"CLOSED_AND_VERIFIED",
      "index":{"path":str(ROOT/"EVIDENCE_INDEX.json"),"bytes":len(index_raw),"sha256":hashlib.sha256(index_raw).hexdigest()},
      "indexed_files":len(rows),"indexed_bytes":index["total_bytes"],"original_files":95,"original_bytes":12624662,
      "source_or_git_mutation":False,"tests_rerun":False,"active_full_v2_read":False,"stage_written":False}
seal_raw=jb(seal);put(ROOT/"seal.json",seal_raw)
print(json.dumps({"root":str(ROOT),"status":"CLOSED_AND_VERIFIED","indexed_files":len(rows),
 "indexed_bytes":index["total_bytes"],"complete_files":len(rows)+2,
 "complete_bytes":index["total_bytes"]+len(index_raw)+len(seal_raw),
 "index_sha256":hashlib.sha256(index_raw).hexdigest(),"index_bytes":len(index_raw),
 "seal_sha256":hashlib.sha256(seal_raw).hexdigest(),"seal_bytes":len(seal_raw)},sort_keys=True))
