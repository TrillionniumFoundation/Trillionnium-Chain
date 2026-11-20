"""Signed Research envelopes against actual retained Rust public methods.

The adapter only constructs original public values and marshals borrowed bytes.
Canonical encoding, signing, verification and both hashes execute in HIA.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest
from hia.tests.native_support import NativeModule
from hia.tests.test_research_external_key import build_original
from hia.tests.test_research_payload import fixtures, NAMES as PAYLOAD_NAMES, spans, uint

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'hia/src/research_protocol/command.hepta'
REFERENCE=ROOT/'hia/tests/rust_research_command_reference.rs'
NAMES=PAYLOAD_NAMES+['AuthorityRole','command_id']
FLAT=262656

def wire(op,data):
    return b'RSC1'+bytes((op,))+bytes(19)+data

def specimen(command):
    return dict(chain_id='trnm:research-1',command_id=list(bytes(range(1,33))),
                signer_did='did:hepta:research\\authority',
                signer_role='nakama_authority' if command['type']=='match_evidence_commitment' else 'hepta_authority',
                nonce=1,public_key=[1]*32,command=copy.deepcopy(command),signature=[])

class ResearchCommandNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='trnm-research-command-')
        try:
            _,cls.original=build_original(cls.directory.name)
            deps=cls.original['dependency_sha256']
            crate=[Path(p) for p,h in deps.items() if h==cls.original['crate_sha256'] and Path(p).name=='libtrnm_research_protocol.rlib']
            serde=[Path(p) for p in deps if Path(p).name.startswith('libserde_json-')]
            ed=[Path(p) for p in deps if Path(p).name.startswith('libed25519_dalek-')]
            if [len(v) for v in (crate,serde,ed)] != [1,1,1]:
                raise AssertionError('Ambiguous original dependency artifacts')
            cls.oracle=Path(cls.directory.name)/'research-command-original'
            args=['rustc','--edition=2021','--deny=warnings',str(REFERENCE),'-o',str(cls.oracle)]
            for name,path in [('trnm_research_protocol',crate[0]),('serde_json',serde[0]),('ed25519_dalek',ed[0])]:
                args += ['--extern',name+'='+str(path)]
            for path in sorted({Path(p).parent for p in deps}):args += ['-L','dependency='+str(path)]
            built=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=60)
            if built.returncode:raise AssertionError(built.stderr)
            cls.original['command_adapter_sha256']=hashlib.sha256(cls.oracle.read_bytes()).hexdigest()
            cls.module=NativeModule(SOURCE,byte_exports=('f0',))
            cls.compared=cls.abi=cls.hashes=0;cls.codes=set()
            cls.sign_rows=[dict(op=4,signed=specimen(c),seed=(bytes([j])*32).hex()) for j,c in enumerate(fixtures(),1)]
            cls.base=cls.reference(cls.sign_rows)
            if any(v['code'] for v in cls.base):raise AssertionError(cls.base)
        except BaseException:
            cls.directory.cleanup();raise
    @classmethod
    def tearDownClass(cls):
        print(json.dumps({'schema':'trnm.hia.research-signed-command-observation.v1',
                          'original_native_pairs':cls.compared,'independent_hashes':cls.hashes,
                          'abi_controls':cls.abi,'observed_returns':sorted(cls.codes),
                          'original':cls.original,'native':{'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                          'artifact_sha256':cls.module.artifact_sha256,'compiler_sha256':cls.module.receipt['compiler_sha256']}},sort_keys=True))
        cls.module.close();cls.directory.cleanup()
    @classmethod
    def reference(cls,rows):
        p=subprocess.run([str(cls.oracle)],input=''.join(json.dumps(r)+'\n' for r in rows),capture_output=True,text=True,timeout=30)
        if p.returncode:raise AssertionError(p.stderr)
        out=[json.loads(v) for v in p.stdout.splitlines()]
        if len(out)!=len(rows):raise AssertionError('Original dropped input')
        return out
    def compare(self,rows):
        for start in range(0,len(rows),6):
            batch=rows[start:start+6];originals=self.reference(batch);calls=[];wants=[];needs=[]
            for req,ref in zip(batch,originals):
                data=bytes.fromhex(req['cbor'] if req['op']==3 else ref['flat_input']);raw=wire(req['op'],data)
                need=FLAT+4096+16*len(data);size=160+6*len(data)+1024
                want=bytearray(b'\xa5'*size);want[:160]=bytes(160)
                if ref['code']:
                    struct.pack_into('<QQQ',want,32,NAMES.index(ref['name']),ref['detail1'],ref['detail2'])
                    if ref['code']==201:
                        enc=ref['encoding'].encode();struct.pack_into('<Q',want,56,len(enc));want[64:64+len(enc)]=enc
                else:
                    cb,flat,unsigned=[bytes.fromhex(ref[k]) for k in ('canonical','flat','unsigned')]
                    struct.pack_into('<4Q',want,0,len(cb),len(flat),ref['kind'],len(unsigned))
                    for offset,key in [(64,'fingerprint'),(96,'payload_hash'),(128,'public_key')]:want[offset:offset+32]=bytes.fromhex(ref[key])
                    want[160:160+len(cb)+len(flat)+len(unsigned)]=cb+flat+unsigned
                    for domain,msg,key in [(b'trnm-research-command-fingerprint-v1',unsigned,'fingerprint'),
                            (b'trnm-research-command-payload-v1',bytes.fromhex(ref['payload']),'payload_hash')]:
                        if key:
                            digest=hashlib.sha256(b'TRNM_RESEARCH_PROTOCOL_HASH_V1\0'+len(domain).to_bytes(4,'big')+domain+len(msg).to_bytes(8,'big')+msg).hexdigest()
                            self.assertEqual(digest,ref[key]);type(self).hashes+=1
                calls.append(('f0',[raw,b'\xa5'*size,b'\x5a'*(need+23)]));wants.append(bytes(want));needs.append(need)
            actual=self.module.call_many(calls,timeout=60)
            for req,ref,call,want,need,got in zip(batch,originals,calls,wants,needs,actual):
                got.require_returned()
                with self.subTest(op=req['op'],kind=req.get('signed',{}).get('command',{}).get('type'),prefix=call[1][0][:80].hex(),expected=ref.get('error')):
                    self.assertEqual(got.value,ref['code'])
                    self.assertEqual(got.arguments[0],call[1][0])
                    if got.arguments[1]!=want:
                        mismatch=next(i for i,(a,b) in enumerate(zip(got.arguments[1],want)) if a!=b)
                        self.fail(f'Output mismatch offset {mismatch}: got={got.arguments[1][max(0,mismatch-16):mismatch+48].hex()} expected={want[max(0,mismatch-16):mismatch+48].hex()}')
                    self.assertEqual(got.arguments[2][need:],b'\x5a'*23)
                    self.assertEqual(got.arguments[2][196608:196640],bytes(32))
                    if req['op']==4:self.assertEqual(got.arguments[2][:need],bytes(need))
                type(self).compared+=1;type(self).codes.add(got.value)
    def test_all_seven_original_signatures_canonical_hashes_and_public_roundtrips(self):
        rows=list(self.sign_rows)
        for ref in self.base:
            rows += [dict(op=op,signed=copy.deepcopy(ref['signed'])) for op in (1,2)]
            rows += [dict(op=3,cbor=ref['canonical'])]
        self.compare(rows)
    def test_chain_did_characters_lengths_nonce_and_original_error_precedence(self):
        rows=[];base=self.base[0]['signed']
        for field,prefix in [('chain_id','a'),('signer_did','did:a')]:
            for v in range(128):
                s=copy.deepcopy(base);s[field]=prefix+chr(v);rows.append(dict(op=2,signed=s))
            for text in ['', 'a'*64,'a'*65,'did:x','did:'+'x'*188,'did:'+'x'*189,'研究','é','did:\\allowed']:
                s=copy.deepcopy(base);s[field]=text;rows.append(dict(op=2,signed=s))
        for field,value in [('command_id',[0]*32),('nonce',0),('public_key',[0]*32),('signature',[]),('signature',[0]*63),('signature',[0]*65)]:
            s=copy.deepcopy(base);s[field]=value;rows.append(dict(op=2,signed=s))
        for n in [0,1,23,24,255,256,65535,65536,(1<<32)-1,1<<32,(1<<64)-1]:
            r=copy.deepcopy(self.sign_rows[0]);r['signed']['nonce']=n;rows.append(r)
        for bad in range(7):
            s=copy.deepcopy(base)
            for field,value in [('chain_id','!'),('command_id',[0]*32),('signer_did','bad'),('nonce',0),('public_key',[0]*32),('command',dict(type='match_evidence_commitment',payload={**base['command']['payload'],'event_count':0})),('signature',[])][bad:]:s[field]=value
            rows.append(dict(op=2,signed=s))
        self.compare(rows)
    def test_roles_payload_validation_and_signing_precedence(self):
        rows=[]
        for j,ref in enumerate(self.base):
            for role in ('nakama_authority','hepta_authority'):
                for op in (1,2,4):
                    s=copy.deepcopy(ref['signed']);s['signer_role']=role
                    rows.append(dict(op=op,signed=s,seed=(bytes([j+11])*32).hex()))
            s=copy.deepcopy(ref['signed']);first=['commitment_id','evaluation_id','receipt_id','claim_id','declaration_id','challenge_id','resolution_id'][j];s['command']['payload'][first]=[0]*32
            rows += [dict(op=op,signed=s,seed=(b'x'*32).hex()) for op in (1,2,4)]
        self.compare(rows)
    def test_every_canonical_truncation_and_trailing_bytes(self):
        rows=[]
        for ref in self.base:
            raw=bytes.fromhex(ref['canonical'])
            rows += [dict(op=3,cbor=raw[:j].hex()) for j in range(len(raw))]
            rows += [dict(op=3,cbor=(raw+extra).hex()) for extra in (b'\0',b'\xff',raw)]
        self.compare(rows)
    def test_canonical_headers_encoding_marker_and_deterministic_mutations(self):
        rows=[];rng=random.Random(0x52534331)
        for ref in self.base:
            raw=bytes.fromhex(ref['canonical'])
            for j,end,major,value in spans(raw):
                for first in (0x1c,0x1d,0x1e,0x1f,0xff):
                    rows.append(dict(op=3,cbor=(raw[:j]+bytes([first])+raw[j+1:]).hex()))
                if major==0 and value<24:rows.append(dict(op=3,cbor=(raw[:j]+b'\x18'+bytes([value])+raw[end:]).hex()))
            for _ in range(32):
                changed=bytearray(raw);j=rng.randrange(len(raw));changed[j]^=1<<rng.randrange(8);rows.append(dict(op=3,cbor=changed.hex()))
            n=len(b'rfc8949-deterministic-cbor-array-v1');start=4
            self.assertEqual(raw[start:start+n],b'rfc8949-deterministic-cbor-array-v1')
            for encoding in (b'',b'other',b'x'*64,b'x'*65,'研究'.encode()):
                head=uint(len(encoding));head=bytes([head[0]|0x60])+head[1:]
                rows.append(dict(op=3,cbor=(raw[:2]+head+encoding+raw[start+n:]).hex()))
        self.compare(rows)
    def test_public_key_normalization_weak_points_signature_scalar_and_corruption(self):
        base=self.base[0]['signed'];rows=[];p=(1<<255)-19
        for y in list(range(0,20))+list(range(p-2,p+19)):
            for sign in (0,1):
                s=copy.deepcopy(base);s['public_key']=list((y|(sign<<255)).to_bytes(32,'little'));rows.append(dict(op=2,signed=s))
        for j in range(64):
            s=copy.deepcopy(base);s['signature'][j]^=1<<(j%8);rows.append(dict(op=2,signed=s))
        order=(1<<252)+27742317777372353535851937790883648493
        for scalar in (0,1,order-1,order,order+1,(1<<256)-1):
            s=copy.deepcopy(base);s['signature'][32:]=list(scalar.to_bytes(32,'little'));rows.append(dict(op=2,signed=s))
        for seed in (bytes(32),bytes([255])*32,bytes(range(32)),hashlib.sha256(b'research command').digest()):
            rows.append(dict(op=4,signed=copy.deepcopy(base),seed=seed.hex()))
        self.compare(rows)
    def test_all_signing_exits_clear_private_seed_staging_and_preserve_canaries(self):
        request=copy.deepcopy(self.sign_rows[0]);request['seed']=hashlib.sha256(b'private failure-path seed').hexdigest()
        reference=self.reference([request])[0];flat=bytes.fromhex(reference['flat_input']);seed=bytes.fromhex(request['seed'])
        seed_offset=flat.index(seed);self.assertEqual(flat.count(seed),1)
        variants=[(flat,160+6*len(flat)+1024,0), (flat,160,64), (flat+b'\0',4096,65),
                  (flat[:-1],4096,65), (flat[:-8]+struct.pack('<Q',1)+b'x',4096,65),
                  (flat[:seed_offset+31],4096,65)]
        for cut in range(seed_offset,seed_offset+33):variants.append((flat[:cut],4096,65))
        for data,size,code in variants:
            need=FLAT+4096+16*len(data);raw=wire(4,data)
            got=self.module.call('f0',[raw,b'\xa5'*size,b'\x5a'*(need+29)],timeout=30).require_returned()
            self.assertEqual(got.value,code);self.assertEqual(got.arguments[0],raw)
            self.assertEqual(got.arguments[2][:need],bytes(need));self.assertEqual(got.arguments[2][need:],b'\x5a'*29)
            if code:self.assertEqual(got.arguments[1],b'\xa5'*size)
            self.assertNotIn(seed,got.arguments[2]);type(self).abi+=1
    def test_borrowed_abi_shape_capacity_atomicity_and_exact_scratch_extent(self):
        ref=self.reference([dict(op=2,signed=self.base[0]['signed'])])[0];data=bytes.fromhex(ref['flat_input']);raw=wire(2,data);need=FLAT+4096+16*len(data)
        valid_size=160+sum(len(bytes.fromhex(ref[k])) for k in ('canonical','flat','unsigned'))
        cases=[]
        for cut in range(24):cases.append((raw[:cut],valid_size,need,65))
        for j in (0,1,2,3,5,8,16,23):
            r=bytearray(raw);r[j]^=1;cases.append((bytes(r),valid_size,need,65))
        for op in (0,5,255):cases.append((raw[:4]+bytes([op])+raw[5:],valid_size,need,65))
        for size in (0,1,159,160,valid_size-1):cases.append((raw,size,need,64))
        for size in (0,1,512,FLAT,need-1):cases.append((raw,valid_size,size,64))
        for data2 in (data[:-1],data+b'\0'):
            r=wire(2,data2);cases.append((r,valid_size,FLAT+4096+16*len(data2),65))
        for start in range(0,len(cases),6):
            batch=cases[start:start+6];calls=[('f0',[r,b'\xa5'*no,b'\x5a'*ns]) for r,no,ns,_ in batch]
            for case,call,got in zip(batch,calls,self.module.call_many(calls,timeout=60)):
                got.require_returned();self.assertEqual(got.value,case[3]);self.assertEqual(got.arguments[0],call[1][0]);self.assertEqual(got.arguments[1],call[1][1]);type(self).abi+=1
        got=self.module.call('f0',[raw,b'\xa5'*valid_size,b'\x5a'*need],timeout=30).require_returned();self.assertEqual(got.value,0);type(self).abi+=1

if __name__=='__main__':unittest.main()
