"""Actual original authority trust-anchor and raw binary-search behavior."""
from __future__ import annotations
import copy,hashlib,itertools,json,struct,subprocess,tempfile,unittest
from pathlib import Path
from hia.tests.native_support import NativeModule
from hia.tests.test_research_external_key import build_original
from hia.tests.test_research_payload import fixtures
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'hia/src/research_protocol/authority.hepta'
REFERENCE=ROOT/'hia/tests/rust_research_authority_reference.rs'
def identity(n=0,did=None):return dict(signer_did=f'did:authority:{n:04}' if did is None else did,seed=hashlib.sha256(str(n).encode()).hexdigest())
def bucket(op=2,nakama=None,hepta=None):return dict(op=op,nakama=[] if nakama is None else nakama,hepta=[] if hepta is None else hepta)
def wire(op,data):return b'RSA1'+bytes([op])+bytes(19)+data
class ResearchAuthorityNativeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.directory=tempfile.TemporaryDirectory(prefix='trnm-research-authority-')
  try:
   _,cls.original=build_original(cls.directory.name);deps=cls.original['dependency_sha256'];args=['rustc','--edition=2021','--deny=warnings',str(REFERENCE)]
   for name,prefix in [('trnm_research_protocol','libtrnm_research_protocol.rlib'),('serde_json','libserde_json-'),('ed25519_dalek','libed25519_dalek-')]:
    candidates=[Path(p) for p in deps if Path(p).name==prefix or Path(p).name.startswith(prefix)];assert len(candidates)==1;args+=['--extern',name+'='+str(candidates[0])]
   for path in sorted({Path(p).parent for p in deps}):args+=['-L','dependency='+str(path)]
   cls.oracle=Path(cls.directory.name)/'research-authority-original';args+=['-o',str(cls.oracle)];p=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=60)
   if p.returncode:raise AssertionError(p.stderr)
   cls.original['authority_adapter_sha256']=hashlib.sha256(cls.oracle.read_bytes()).hexdigest();cls.module=NativeModule(SOURCE,byte_exports=('f0',));cls.compared=cls.abi=0;cls.codes=set()
  except BaseException:cls.directory.cleanup();raise
 @classmethod
 def tearDownClass(cls):
  print(json.dumps({'schema':'trnm.hia.research-authority-observation.v1','original_native_pairs':cls.compared,'abi_controls':cls.abi,'observed_returns':sorted(cls.codes),'original':cls.original,'native':{'artifact_sha256':cls.module.artifact_sha256,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'compiler_sha256':cls.module.receipt['compiler_sha256']}},sort_keys=True));cls.module.close();cls.directory.cleanup()
 @classmethod
 def reference(cls,rows):
  p=subprocess.run([str(cls.oracle)],input=''.join(json.dumps(r)+'\n' for r in rows),capture_output=True,text=True,timeout=30)
  if p.returncode:raise AssertionError(p.stderr)
  result=[json.loads(x) for x in p.stdout.splitlines()];assert len(result)==len(rows);return result
 def compare(self,rows):
  for start in range(0,len(rows),6):
   batch=rows[start:start+6];refs=self.reference(batch);calls=[];wants=[];needs=[]
   for req,ref in zip(batch,refs):
    data=bytes.fromhex(ref['flat_input']);need=266752+16*len(data);size=128+4*len(data);want=bytearray(b'\xa5'*size);want[:32]=bytes(32)
    if not ref['code']:
     cb,flat=[bytes.fromhex(ref[x]) for x in ('canonical','flat')];struct.pack_into('<3Q',want,0,len(cb),len(flat),int(ref['authorized']));want[32:32+len(cb)+len(flat)]=cb+flat
    calls.append(('f0',[wire(req['op'],data),b'\xa5'*size,b'\x5a'*(need+19)]));wants.append(bytes(want));needs.append(need)
   for req,ref,call,want,need,got in zip(batch,refs,calls,wants,needs,self.module.call_many(calls,timeout=60)):
    got.require_returned()
    with self.subTest(op=req['op'],request=str(req)[:160]):
     self.assertEqual(got.value,ref['code']);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[2][need:],b'\x5a'*19)
     if got.arguments[1]!=want:
      p=next(i for i,(a,b) in enumerate(zip(got.arguments[1],want)) if a!=b);self.fail(f'output byte {p}: {got.arguments[1][p:p+40].hex()} != {want[p:p+40].hex()}')
    type(self).compared+=1;type(self).codes.add(got.value)
 def test_identity_original_character_key_and_length_validation(self):
  rows=[dict(op=1,identity=identity(0,'did:x'+chr(c))) for c in range(128)]
  rows += [dict(op=1,identity=identity(0,did)) for did in ['','did:','did:x','did:'+'x'*188,'did:'+'x'*189,'did:研究','did:\\permitted','DID:x','did:x\x7f']]
  prime=(1<<255)-19
  for y in list(range(20))+list(range(prime-2,prime+19)):
   for sign in (0,1):rows.append(dict(op=1,identity=dict(signer_did='did:key',public_key=list((y|(sign<<255)).to_bytes(32,'little')))))
  self.compare(rows)
 def test_constructor_sorts_exact_tuple_and_validation_rejects_unordered_duplicates(self):
  rows=[bucket(2),bucket(3)]
  ids=[identity(n,'did:same' if n<3 else f'did:{n}') for n in range(5)]
  for permutation in itertools.permutations(ids[:4]):
   rows += [bucket(op,list(permutation),list(reversed(permutation))) for op in (2,3)]
  for n in (1,2,127,128,129):
   values=[identity(0,f'did:capacity:{j:04}') for j in range(n)]
   rows += [bucket(op,list(reversed(values)),values) for op in (2,3)]
  rows += [bucket(op,[identity(1),identity(1)],[identity(2)]) for op in (2,3)]
  self.compare(rows)
 def test_authorizes_both_public_methods_use_original_raw_binary_search(self):
  ids=[identity(n) for n in range(4)];rows=[]
  for permutation in itertools.permutations(ids):
   for q in ids+[identity(50),identity(0,'did:not-found')]:
    for role in ('nakama_authority','hepta_authority'):
     req=bucket(4,list(permutation),list(reversed(permutation)));req.update(query=q,role=role,command=fixtures()[0]);rows.append(req)
  for values in ([],[identity(0),identity(0)],[dict(signer_did='invalid',public_key=[0]*32)]):
   req=bucket(4,values,values);req.update(query=dict(signer_did='invalid',public_key=[0]*32),role='nakama_authority',command=fixtures()[0]);rows.append(req)
  self.compare(rows)
 def test_bucket_boundaries_identity_field_precedence_and_public_key_order(self):
  rows=[]
  for op in (2,3):
   for side in ('nakama','hepta'):
    for v in [dict(signer_did='bad',public_key=[0]*32),dict(signer_did='did:x',public_key=[0]*32),identity(7,'did:x '),identity(9,'did:'+'x'*189)]:
     r=bucket(op,[identity(1)],[identity(2)]);r[side].append(v);rows.append(r)
   same=[identity(n,'did:shared') for n in range(32)];rows.append(bucket(op,list(reversed(same)),same))
  self.compare(rows)
 def test_shape_bounds_reserved_fields_and_every_typed_truncation(self):
  ref=self.reference([bucket(2,[identity(1)],[identity(2)])])[0];data=bytes.fromhex(ref['flat_input']);raw=wire(2,data);size=32+sum(len(bytes.fromhex(ref[k])) for k in ('canonical','flat'));need=266752+16*len(data);cases=[]
  cases += [(raw[:cut],size,need,65) for cut in range(24)]
  cases += [(wire(2,data[:cut]),size,266752+16*cut,65) for cut in range(len(data))]
  cases += [(wire(2,data+b'\0'),size,need+16,65)]
  for j in (0,1,2,3,5,8,23):
   r=bytearray(raw);r[j]^=1;cases.append((bytes(r),size,need,65))
  cases += [(raw[:4]+bytes([op])+raw[5:],size,need,65) for op in (0,5,255)]
  cases += [(raw,no,need,64) for no in (0,1,31,32,size-1)]
  cases += [(raw,size,ns,64) for ns in (0,1,512,262656,need-1)]
  for invalid in [(1<<64)-1,1000000]:cases.append((wire(2,struct.pack('<Q',invalid)+data[8:]),size,need,65))
  for start in range(0,len(cases),6):
   batch=cases[start:start+6];calls=[('f0',[r,b'\xa5'*no,b'\x5a'*ns]) for r,no,ns,_ in batch]
   for case,call,got in zip(batch,calls,self.module.call_many(calls,timeout=60)):
    got.require_returned();self.assertEqual(got.value,case[3]);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[1],call[1][1]);type(self).abi+=1
  result=self.module.call('f0',[raw,b'\xa5'*size,b'\x5a'*need],timeout=30).require_returned();self.assertEqual(result.value,0);type(self).abi+=1
if __name__=='__main__':unittest.main()
