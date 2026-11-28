"""Original fixed numerical tile loop witness with no material or task call."""
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_checkpoint_tile_quantize import ROOT, original

SOURCE=ROOT/"hia/src/checkpoint/tile_assemble.hepta"
REFERENCE=Path(__file__).with_name("rust_checkpoint_tile_assemble_reference.rs")
NEED=32784


def witness(source):
    begin=b"    let mut a = Vec::with_capacity(4096);\n"
    end=b"    let bb = encode_matrix(&b);\n"
    if source.count(begin)!=1 or source.count(end)!=1:
        raise ValueError("Frozen numerical block is not unique")
    i=source.index(begin)
    j=source.index(end,i)+len(end)
    body=source[i:j]
    if b"pon_work" in body or b"derive_" in body:
        raise ValueError("Witness not confined to original numerical loops")
    return b"""
pub(super) fn assemble_witness(tile: &[u8], hidden: &[u8], tokens: usize)
    -> MaterialResult<(Vec<u8>, Vec<u8>, usize, usize)> {
    let mut callback = |_: MaterialProgress| Ok(());
    let observed = Rc::new(RefCell::new(Observer {
        callback: &mut callback, first_error: None, checkpoint_bytes_read: 0,
    }));
    let o = &observed;
"""+body+b"    Ok((aa,bb,ca,cb))\n}\n"


def packet(tokens):
    weights=[0xbf80,0x4000,0xc000,0x0000,0x8000,0x0001,0x7f7f,0xff7f]
    a=struct.pack("<4096H",*(weights*512))
    b=bytearray()
    for token in range(tokens):
        for k in range(576):
            value=[-1.0,8.09375,-8.03125,0.09375,-0.15625,0.0,1.0][(token*3+k)%7]
            if k>=64:
                value=91.0 # finite, must not contribute to clipping or coordinates
            b.extend(struct.pack("<f",value))
    return b"TMA1\0\0\0\0"+struct.pack("<Q",tokens)+a+bytes(b)


def replace(data,offset,new):
    return data[:offset]+new+data[offset+len(new):]


class CheckpointTileAssembleTests(unittest.TestCase):
    def test_original_frozen_exact_tile_residues_and_counts_two_stock(self):
        f1,f2,f64=(packet(n) for n in (1,2,64))
        stimuli=[f1,f2,f64,
                 replace(f2,16+2*4095,struct.pack("<H",0x7fc1)),
                 replace(f2,8208,struct.pack("<I",0x7f800000)),
                 replace(f2,8208+4*(576+575),struct.pack("<I",0xff800001))]
        encoded=b"".join(struct.pack("<I",len(x))+x for x in stimuli)
        with tempfile.TemporaryDirectory(prefix="trnm-checkpoint-tile-assemble-") as tmp:
            raw=original(Path(tmp),encoded,reference=REFERENCE,witness=witness)
        expected=[]
        while raw:
            s,n=struct.unpack_from("<II",raw)
            self.assertGreaterEqual(len(raw),8+n)
            expected.append((s,raw[8:8+n]))
            raw=raw[8+n:]
        self.assertEqual([s for s,_ in expected],[0,0,0,1,1,1])
        self.assertEqual([len(w) for _,w in expected],[NEED]*3+[0]*3)
        v=expected[0][1]
        self.assertEqual(struct.unpack_from("<Q",v)[0],2048)
        self.assertEqual(struct.unpack_from("<3I",v,16),(4294967291-16384,32767,4294967291-32767))
        # B's token-major input coordinates are laid out coord-major, with a zero tail.
        self.assertEqual(struct.unpack_from("<3I",v,16400),(4294967291-16,0,0))
        self.assertEqual(struct.unpack_from("<I",v,16400+64*4)[0],128)
        self.assertEqual(struct.unpack_from("<2I",expected[1][1],16400),(4294967291-16,2))
        self.assertEqual(len(f64),155664)
        o,w=b"Y"*(NEED+13),b"W"*21
        invalid=[f1[:-1],f1+b"X",replace(f1,8,struct.pack("<Q",0)),
                 replace(f1,8,struct.pack("<Q",65)),replace(f1,0,b"TMA2")]
        for backend in ("direct","selfhost"):
            with self.subTest(backend=backend),NativeModule(
                SOURCE,byte_exports=("f0",),backend=backend,
            ) as native:
                rows=list(zip(stimuli,expected,strict=True))+[(f,(100,b"")) for f in invalid]
                for data,(status,body) in rows:
                    g=native.call("f0",[data,o,w]).require_returned()
                    self.assertEqual((g.value,g.arguments[:2]),(status,[data,body+o[len(body):]]))
                    self.assertEqual(g.arguments[2][16:],w[16:])
                    if status: self.assertEqual(g.arguments[2],w)
                for out,work in ((o[:NEED-1],w),(o,w[:15])):
                    args=[f1,out,work]
                    g=native.call("f0",args).require_returned()
                    self.assertEqual((g.value,g.arguments),(102,args))
