import difflib,hashlib,json,pathlib,runpy,stat,sys
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
old=root/"incremental-2a6206-after-08c9be-v1";out=root/"incremental-ed0d35-after-2a6206-v1"
assert (old/"bounded_scan_driver.py").read_bytes()==sys.argv[2].encode()
out.mkdir(mode=0o700,exist_ok=False)
with (out/"preparation-producer.py").open("x") as f:f.write(sys.argv[1])
for name in ("prior-scan_driver.py","prior-patterns-and-scope.json"):
 p=old/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 raw=p.read_bytes()
 if name=="prior-scan_driver.py":assert hashlib.sha256(raw).hexdigest()=="5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368"
 with (out/name).open("xb") as f:f.write(raw)
code=sys.argv[3].encode();compile(code,str(out/"bounded_scan_driver.py"),"exec")
with (out/"bounded_scan_driver.py").open("xb") as f:f.write(code)
patch="".join(difflib.unified_diff(sys.argv[2].splitlines(True),sys.argv[3].splitlines(True),fromfile="M6-reviewed-producer.py",tofile="M8-fixed-range-producer.py"))
with (out/"reviewed-producer.diff").open("x") as f:f.write(patch)
with (out/"producer-preparation.json").open("x") as f:json.dump({"schema":"fixed-incremental-scan-preparation-v1","only_changes":"fixed HEAD/tree/base/parent/output scope; exact five regex definitions/caps/scanner logic retained","previous_producer_sha256":hashlib.sha256(sys.argv[2].encode()).hexdigest(),"producer_sha256":hashlib.sha256(code).hexdigest(),"new_source_or_ref_mutation":False},f,indent=2)
runpy.run_path(str(out/"bounded_scan_driver.py"),run_name="__main__")
