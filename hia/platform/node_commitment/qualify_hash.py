"""SHA256 padding/fork boundaries for the exact shared Node root functions."""
from pathlib import Path
import argparse,ctypes,hashlib,json,mmap,random,time,traceback,re
from hia.platform.execution_state.physical import Guarded
from hia.platform.mempool_node.build import ROOT,validate_build,functions
from hia.platform.mempool_node.safe import new_output
from hia.platform.build import Build
from .qualify_snapshot import Image
ident=lambda b:{"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def need(condition,message):
 if not condition:raise AssertionError(message)
from .bounded import enter
enter("hia.platform.node_commitment.qualify_hash")
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--build",required=True,type=Path);parser.add_argument("--output",required=True,type=Path)
args=parser.parse_args();need(__debug__,"Optimized Python refused")
BUILD=args.build.absolute();OUT=new_output(args.output,ROOT);prior=validate_build(BUILD)
inputs={str(ROOT/name):value for name,value in prior["source_inputs"].items()}
inputs[str(BUILD/"build.json")]=ident((BUILD/"build.json").read_bytes())
table=functions((BUILD/"root-composed.hepta").read_bytes())
table["f0"]=functions((ROOT/"hia/platform/node_commitment/hash_qualification_entry.hepta").read_bytes())["f0"]
used=set();todo=["f0"]
while todo:
 name=todo.pop()
 if name in used:continue
 used.add(name);todo.extend(m[1].decode() for m in re.finditer(rb'"function":"([^"]+)"',table[name]))
source=b"hia-asm.v1 hepta.hia.program.v8 trnm_snapshot_hash_qualification\n"+b"".join(table[n] for n in ["f0"]+sorted(used-{"f0"}))
(OUT/"sha-composed.hepta").write_bytes(source)
builder=Build(OUT/"compiler");flat=builder.stage(builder.compiler,source,"compile-sha");builder.check_pin();(OUT/"sha.flat").write_bytes(flat)
fixture_build={"source":ident(source),"image":ident(flat),"stages":builder.stages,"compiler_sha256":hashlib.sha256(builder.compiler).hexdigest()}
for path in [OUT/"sha-composed.hepta",OUT/"sha.flat"]:inputs[str(path)]=ident(path.read_bytes())
def fence():
 validate_build(BUILD)
 for path,value in inputs.items():need(ident(Path(path).read_bytes())==value,"Source drift "+path)

start=time.monotonic_ns();records=[];failure=None;errors=[];image=None
try:
 fence();image=Image((OUT/'sha.flat').read_bytes())
 rng=random.Random(8675309)
 lengths=[0,1,31,32,55,56,63,64,65,93,94,95,111,112,119,120,127,128,129,255,256,257,1024,4096,65536,131136]
 for n in lengths:
  patterns=[bytes(n),bytes([255])*n,rng.randbytes(n)]
  for mode,data in enumerate(patterns):
   i=Guarded(len(data),data,True);o=Guarded(32,bytes([91])*32);s=Guarded(132256)
   try:
    rc=image.fn(i.address,i.n,o.address,o.n,s.address,s.n)
    digest=o.read();expected=hashlib.sha256(data).digest()
    i.check();o.check();s.check();need(i.read()==data,'Input mutation')
    records.append({'length':n,'pattern':mode,'input':ident(data),'return':rc,'digest':digest.hex(),'expected':expected.hex()})
    need(rc==0 and digest==expected,('SHA mismatch',n,mode,rc))
   finally:i.close();o.close();s.close()
except BaseException as e:failure={'error':repr(e),'traceback':traceback.format_exc()}
finally:
 if image:image.close()
 try:fence()
 except BaseException as e:errors.append(repr(e))
 report={'status':'PASS' if failure is None and not errors else 'FAIL','source_inputs':inputs,'build':ident((BUILD/'build.json').read_bytes()),'fixture_build':fixture_build,'failure':failure,'errors':errors,'actual_calls':len(records),'observations':records,'elapsed_ns':time.monotonic_ns()-start,'scope':{'actual_native_sha':True,'hashlib_reference':True,'capacity':'NOT_RUN','node':'NOT_RUN'}}
 (OUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({k:report[k] for k in ['status','actual_calls','failure','errors','elapsed_ns']}),flush=True)
 if report['status']!='PASS':raise SystemExit(1)
