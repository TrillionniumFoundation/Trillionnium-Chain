"""Exact frozen Rust TensorHeader semantics with compact native raw spans."""
import json
from pathlib import Path
import string
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_manifest import MARK, SCRATCH
from hia.tests.test_da_cell_tensor_header_json import ENTRY, JSON, PRIVATE_LIMIT, field, many, original_reference, packet
from hia.tests.tensor_header_spans_derivation import CAP, MAX_TENSORS, SOURCE, WORK, derive

MASK=(1<<21)-1
ALPHABET=string.ascii_letters+string.digits


def short_name(x):
    q,r=divmod(x,len(ALPHABET))
    return short_name(q-1)+ALPHABET[r] if q else ALPHABET[r]


def wide(n, *, rank, include_metadata=False):
    order = (((j*773+379) % n) for j in range(n)) if n==MAX_TENSORS else range(n-1,-1,-1)
    entry=b'{"dtype":"F32","shape":['+b",".join([b"1"]*rank)+b'],"data_offsets":[0,4]}'
    rows=[b'"'+short_name(j).encode()+b'":'+entry for j in order]
    if include_metadata:
        m=b",".join(f'"m{n:04d}":""'.encode() for n in range(1024))
        rows.insert(len(rows)//2,b'"__metadata__":{'+m+b"}")
    raw=b"{"+b",".join(rows)+b"}"
    assert len(raw)<=CAP
    return raw


def project_native(header, encoded):
    count,=struct.unpack_from("<Q",encoded)
    assert len(encoded)==8+count*8
    projection=bytearray(struct.pack("<Q",count))
    prior=None
    for (word,) in struct.iter_unpack("<Q",encoded[8:]):
        assert word>>63==0
        a,b,c=word&MASK,(word>>21)&MASK,(word>>42)&MASK
        assert 0<=a<b<c<=len(header)
        assert header[a:a+1]==b'"' and header[b:b+1]==b"{" and header[c-1:c]==b"}"
        prefix=header[a:b].rstrip()
        assert prefix.endswith(b":")
        name=json.loads(prefix[:-1]).encode()
        assert prior is None or prior<name
        prior=name
        item=json.loads(header[b:c])
        dtype=item["dtype"].encode()
        shape=item["shape"]
        offsets=item["data_offsets"]
        assert len(shape)<=8 and len(offsets)==2
        for item in (name,dtype):
            projection.extend(struct.pack("<Q",len(item)))
            projection.extend(item)
        projection.extend(struct.pack("<Q",len(shape)))
        projection.extend(struct.pack(f"<{len(shape)+2}Q",*shape,*offsets))
    return projection


def cases():
    full=wide(MAX_TENSORS,rank=5,include_metadata=True)
    assert len(full)<CAP
    full+=b" "*(CAP-len(full))
    large_dtype=field(b"a",ENTRY.replace(b'"F32"',b'"'+b"x"*(CAP-53)+b'"'))
    assert len(large_dtype)<=CAP and len(large_dtype)>CAP-100
    mixed=b'{ "Z":'+ENTRY+br', "\u00e9":'+ENTRY+br', "e\u0301":'+ENTRY+br', "\ud834\udd1e":'+ENTRY+b" }"
    tricky=field(b"nm",br'{"sh\u0061pe":[18446744073709551615,0,1,2,3,4,5,6],"data_offsets":[18446744073709551615,2],"dtype":"\u0000\t\u00e9\ud834\udd1e"}')
    small=wide(1031,rank=2,include_metadata=True)
    before=wide(MAX_TENSORS-1,rank=0)
    positives=[b"{}",b" \t{\r\n}\n",mixed,tricky,small,before,full,large_dtype,many(1024,True)]
    invalid=[
        b"null",b'{"a":{}}',b'{"a":'+ENTRY+rb',"\u0061":'+ENTRY+b'}',
        b'{"a":'+ENTRY+rb',"\u0061":37}',rb'{"__metadata__":{},"__metad\u0061ta__":{}}',
        rb'{"__metadata__":{"a":"x","\u0061":"y"}}',
        many(1025,True),wide(MAX_TENSORS+1,rank=0),
        before[:-1]+b',"a":'+ENTRY+b"}",
        field(b"x",ENTRY.replace(b'[]',b'[1,2,3,4,5,6,7,8,9]')),
        field(b"x",ENTRY.replace(b'[0,4]',b'[0,18446744073709551616]')),
        field(b"x",ENTRY.replace(b'[0,4]',b'[0,4,8]')),
        field(b"x",ENTRY[:-1]+rb',"dt\u0079pe":"F32"}'),
        field(b"x",ENTRY[:-1]+b',"other":false}'),
        field(b"x",ENTRY)+b" {}",field(br"\u0000"),field(b"x"*256),
    ]
    return [(x,0) for x in positives]+[(x,JSON) for x in invalid]+[(full+b" ",PRIVATE_LIMIT)]


class CellTensorHeaderSpans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.read_bytes().startswith(derive()):
            raise ValueError("Published span grammar or sorted-run derivation drifted")
        cls.d=cls.enterClassContext(NativeModule(SOURCE,backend="direct",byte_exports=("f0",)))
        cls.s=cls.enterClassContext(NativeModule(SOURCE,backend="selfhost",byte_exports=("f0",),
                                                max_input_extent=CAP+1))
        if cls.d.artifact_sha256==cls.s.artifact_sha256:
            raise ValueError("Two distinct stock emitters required")

    def invoke(self,m,raw,code,*,expected=b"",n=None,w=WORK+16):
        count=struct.unpack_from("<Q",expected)[0] if expected else 0
        exact=8+count*8
        output,scratch=MARK*(exact+11 if n is None else n),SCRATCH*w
        got=m.call("f0",[raw,output,scratch],timeout=59).require_returned()
        self.assertEqual(got.abi_status,0)
        self.assertEqual(got.value,code)
        self.assertEqual(got.arguments[0],raw)
        self.assertEqual(got.arguments[2][WORK:],scratch[WORK:])
        if code==0:
            self.assertEqual(got.arguments[1][exact:],output[exact:])
            self.assertEqual(project_native(raw,got.arguments[1][:exact]),expected)
        else:
            self.assertEqual(got.arguments[1],output)
        if w<WORK or len(raw)>CAP:
            self.assertEqual(got.arguments[2],scratch)

    def test_complete_original_semantics_on_both_stocks(self):
        rows=cases()
        with tempfile.TemporaryDirectory(prefix="trnm-tensor-16384-original-") as tmp:
            observed=original_reference(Path(tmp),packet([r for r,_ in rows]))
        start=0
        for i,(raw,code) in enumerate(rows):
            status,n=struct.unpack_from("<BI",observed,start)
            start+=5
            expected=observed[start:start+n]
            self.assertEqual(n,len(expected))
            start+=n
            self.assertEqual(status,0 if code==PRIVATE_LIMIT else code)
            if i==6:
                self.assertEqual(len(raw),CAP)
                self.assertGreater(len(expected),CAP)
                self.assertEqual(struct.unpack_from("<Q",expected)[0],MAX_TENSORS)
            with self.subTest(backend="selfhost",row=i):
                self.invoke(self.s,raw,code,expected=expected)
            if len(raw)<=CAP:
                with self.subTest(backend="direct",row=i):
                    self.invoke(self.d,raw,code,expected=expected)
        self.assertEqual(start,len(observed))

    def test_shape_capacity_and_no_partial_publication(self):
        full=wide(MAX_TENSORS,rank=0)
        for m in (self.d,self.s):
            self.invoke(m,full,102,n=8+8*MAX_TENSORS-1,w=WORK)
            self.invoke(m,b"{}",102,n=8,w=WORK-1)
            self.invoke(m,b"{}",0,expected=bytes(8),n=8,w=WORK)
            self.invoke(m,wide(MAX_TENSORS+1,rank=0),JSON,n=0,w=WORK)
