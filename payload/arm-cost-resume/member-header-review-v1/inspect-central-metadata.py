import collections,hashlib,json,os,pathlib,stat,sys,zipfile
B=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-arm-resume-20261114-v1");P=B/"14119000610.complete.zip";O=B/"member-header-review-v1"
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def fid(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
need(not O.exists(),"create only");O.mkdir(mode=0o700)
def put(name,b):
 p=O/name
 with p.open("xb") as f:f.write(b)
 need(p.read_bytes()==b,"readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
put("inspect-central-metadata.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,"rb") as f:
 s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"regular")
 raw=f.read(9927039)
 need(fid(s)==fid(os.fstat(f.fileno()))==fid(P.lstat()),"stable")
need(len(raw)==9927038 and sha(raw)=="8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff","full official ZIP")
rows=[]
with zipfile.ZipFile(P) as z:
 for i in z.infolist():
  mode=i.external_attr>>16;kind=stat.S_IFMT(mode)
  rows.append({"path":i.filename,"mode_decimal":mode,"mode_octal":oct(mode),"kind_octal":oct(kind),"create_system":i.create_system,"external_attr":i.external_attr,"internal_attr":i.internal_attr,"flag_bits":i.flag_bits,"compression":i.compress_type,"bytes":i.file_size,"compressed_bytes":i.compress_size,"is_dir":i.is_dir(),"type_guard_would_reject":kind not in (0,stat.S_IFREG,stat.S_IFDIR),"encryption_guard_would_reject":bool(i.flag_bits&0x41)})
rejected=[r for r in rows if r["type_guard_would_reject"] or r["encryption_guard_would_reject"]]
out={"schema":"trnm-arm-resume-central-metadata-readonly-v1","zip":{"path":str(P),"bytes":len(raw),"sha256":sha(raw)},"member_count":len(rows),"rows":rows,"rejected_members":rejected,"no_member_body_read_or_extraction":True,"CRC_not_verified_in_this_observation":True,"original_resume_HOLD_preserved":True}
pin=put("central-metadata.json",jb(out))
print(json.dumps({"summary":pin,"member_count":len(rows),"rejected_members":rejected},sort_keys=True))
