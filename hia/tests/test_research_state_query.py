"""Native normalized snapshots, seven getters and strict object queries."""
from __future__ import annotations
import base64,copy,json,random,struct,unittest
from pathlib import Path
from hia.tests import test_research_state_graph as support
from hia.tests.test_research_payload import key,ref,MAX,KINDS
from hia.tests.test_research_state_values import BUCKETS,objects,snapshot

ROOT=Path(__file__).resolve().parents[2]
INDEX=ROOT/'hia/src/research_protocol/state_index.hepta'
GRAPH=ROOT/'hia/src/research_protocol/state_graph.hepta'
QUERY=ROOT/'hia/src/research_protocol/state_query.hepta'
VALUES=ROOT/'hia/src/research_protocol/state_values.hepta'
def wire(op,data=b''):return b'RSQ1'+bytes([op])+bytes(19)+data
def reference_bytes(r):return struct.pack('<Q',KINDS.index(r['kind'])+1)+bytes(r['key'])+struct.pack('<Q',r['object_version'])

class ResearchStateQueryNativeTests(unittest.TestCase):
    SOURCES=(INDEX,GRAPH,QUERY,VALUES)
    MODULE_NAMES=('index','graph','query','values')
    CAPTURE_ENV='HIA_RESEARCH_STATE_QUERY_OBSERVATIONS'
    OBSERVATION_SCHEMA='trnm.hia.research-state-query-observation.v1'
    setUpClass=classmethod(support.ResearchStateGraphNativeTests.setUpClass.__func__)
    tearDownClass=classmethod(support.ResearchStateGraphNativeTests.tearDownClass.__func__)
    reference=classmethod(support.ResearchStateGraphNativeTests.reference.__func__)
    retain=support.ResearchStateGraphNativeTests.retain
    def invoke(self,module,args):
        got=self.modules[module].call('f0',args,timeout=30).require_returned()
        self.retain(dict(type='native-call',module=self.MODULE_NAMES[module],request=[base64.b64encode(x).decode() for x in args],value=got.value,arguments=[base64.b64encode(x).decode() for x in got.arguments]))
        return got
    def prepare(self,s,queries=None):
        request=dict(op='query',snapshot=s,queries=[] if queries is None else queries)
        original=self.reference(0,[request])[0];self.assertEqual(original['code'],0,original)
        raw,normalized=self.reference(1,[dict(op=2,snapshot=s),dict(op=2,snapshot=original['state']['snapshot'])]);flat=bytes.fromhex(raw['flat']);need=266752+32*len(flat)
        got=self.invoke(0,[b'RSI1'+bytes(20)+flat,b'\xa5'*35,b'\x5a'*(need+19)]);self.assertEqual(got.value,0)
        admitted=self.invoke(1,[b'RSG1\1'+bytes(19),b'\xa5'*83,got.arguments[2]]);self.assertEqual(admitted.value,0)
        self.retain(dict(type='original-query',request=request,result=original,raw_value=raw,normalized_value=normalized))
        return original,normalized,flat,need,admitted.arguments[2]
    def query(self,raw,size,arena,flat,need):
        args=[raw,b'\xa5'*size,arena];got=self.invoke(2,args)
        self.assertEqual(got.arguments[0],raw);self.assertEqual(got.arguments[2][262656:262656+len(flat)],flat);self.assertEqual(got.arguments[2][need:],b'\x5a'*19)
        return got
    def test_normalized_snapshot_and_current_reference_order(self):
        rows=[support.connected(stage,journal) for stage in range(8) for journal in (False,True)]
        rng=random.Random(2011)
        for count in (2,7,23,24,64):
            s=snapshot();s['matches']=[objects()[0] for _ in range(count)]
            for j,o in enumerate(s['matches']):o['object_ref']['key']=key(j+1);o['commitment']['commitment_id']=key(j+1)
            rng.shuffle(s['matches']);rows.append(s)
        s=support.connected(7,True);s['applied_commands'].reverse();rows.append(s)
        for s in rows:
            original,normalized,flat,need,arena=self.prepare(s)
            want=bytes.fromhex(normalized['flat']);got=self.query(wire(1),128+len(want)+19,arena,flat,need)
            self.assertEqual(got.value,0);self.assertEqual(struct.unpack_from('<4Q',got.arguments[1]),(len(want),0,1,0));self.assertEqual(got.arguments[1][128:128+len(want)],want);self.assertEqual(got.arguments[1][128+len(want):],b'\xa5'*19)
            cb=bytes.fromhex(original['state']['canonical']);value=self.invoke(3,[b'RSV1\2'+bytes(19)+got.arguments[1][128:128+len(want)],b'\xa5'*(64+len(cb)+19),b'\x5a'*(8192+16*len(want)+19)])
            self.assertEqual(value.value,0);self.assertEqual(value.arguments[1][32:64].hex(),original['state']['hash']);self.assertEqual(value.arguments[1][64:64+len(cb)],cb)
            refs=b''.join(reference_bytes(r) for r in original['state']['refs']);got=self.query(wire(2),128+len(refs)+19,got.arguments[2],flat,need)
            self.assertEqual(got.value,0);self.assertEqual(struct.unpack_from('<4Q',got.arguments[1]),(len(refs),len(original['state']['refs']),1,0));self.assertEqual(got.arguments[1][128:],refs+b'\xa5'*19);type(self).pairs+=2
    def test_seven_getters_strict_current_versions_and_reused_arena(self):
        for stage in (0,4,7):
            s=support.connected(stage,stage==7);queries=[]
            for kind,primary in enumerate((1,9,13,17,20,22,25),1):
                for k in (0,primary,999):
                    queries.append(dict(operation=3,kind=kind,key=key(k)))
                    for version in (0,1,2,3,MAX):queries.append(dict(operation=4,object_ref=ref(kind,k,version)))
            original,normalized,flat,need,arena=self.prepare(s,queries)
            for query,want in zip(queries,original['queries']):
                op=query['operation'];kind=query['kind'] if op==3 else KINDS.index(query['object_ref']['kind'])+1
                data=struct.pack('<Q',kind)+bytes(query['key']) if op==3 else reference_bytes(query['object_ref'])
                expected=None
                if want['code']==0 and want['found']:expected=self.reference(1,[dict(op=1,kind=kind,object=want['object'])])[0]
                typed=b'' if expected is None else bytes.fromhex(expected['flat'])
                got=self.query(wire(op,data),128+len(typed)+19,arena,flat,need);arena=got.arguments[2]
                self.assertEqual(got.value,want['code'],(query,want));type(self).codes.add(got.value)
                if got.value:
                    self.assertEqual(support.graph_details(got.value,got.arguments[1][64:128],arena),want['details']);self.assertEqual(got.arguments[1][128:],b'\xa5'*19)
                else:
                    self.assertEqual(struct.unpack_from('<4Q',got.arguments[1]),(len(typed),int(want['found']),int(want['found']),kind));self.assertEqual(got.arguments[1][128:],typed+b'\xa5'*19)
                    if want['found']:
                        cb=bytes.fromhex(want['canonical']);value=self.invoke(3,[b'RSV1\1'+bytes(19)+typed,b'\xa5'*(64+len(cb)+19),b'\x5a'*(8192+16*len(typed)+19)])
                        self.assertEqual(value.value,0);self.assertEqual(value.arguments[1][32:64].hex(),want['hash']);self.assertEqual(value.arguments[1][64:64+len(cb)],cb)
                type(self).pairs+=1
            # Read-only queries share an arena; they cannot mutate stored bytes.
            typed=bytes.fromhex(normalized['flat']);got=self.query(wire(1),128+len(typed)+19,arena,flat,need);self.assertEqual(got.value,0);self.assertEqual(got.arguments[1][128:],typed+b'\xa5'*19)
    def test_private_query_shapes_capacities_and_atomic_refusal(self):
        original,normalized,flat,need,arena=self.prepare(support.connected())
        refs=b''.join(reference_bytes(r) for r in original['state']['refs']);cases=[]
        for op,data,output in [(1,b'',128+len(flat)),(2,b'',128+len(refs)),(3,struct.pack('<Q',1)+bytes(key(1)),128+8+len(bytes.fromhex(self.reference(1,[dict(op=1,kind=1,object=objects()[0])])[0]['flat']))-8),(4,reference_bytes(ref(1,1)),1024)]:
            raw=wire(op,data)
            for n in range(len(raw)):cases.append((raw[:n],max(output,1024),arena,65))
            cases.append((raw+b'\0',max(output,1024),arena,65))
            for n in (0,1,127):cases.append((raw,n,arena,64))
            for n in (0,1,266751,need-1):cases.append((raw,max(output,1024),arena[:n],64))
            for j in (0,1,2,3,4,5,23):
                b=bytearray(raw);b[j]=255;cases.append((bytes(b),max(output,1024),arena,65))
            if op>=3:
                for kind in (0,8,MAX):cases.append((wire(op,struct.pack('<Q',kind)+data[8:]),max(output,1024),arena,65))
        cases += [(wire(1),128+len(flat)-1,arena,64),(wire(2),128+len(refs)-1,arena,64)]
        for raw,size,workspace,code in cases:
            args=[raw,b'\xa5'*size,workspace];got=self.invoke(2,args);self.assertEqual(got.value,code);self.assertEqual(got.arguments[0],raw);self.assertEqual(got.arguments[1],args[1])
            if len(workspace)>=262656+len(flat):self.assertEqual(got.arguments[2][262656:262656+len(flat)],flat)
            type(self).abi+=1

if __name__=='__main__':unittest.main()
