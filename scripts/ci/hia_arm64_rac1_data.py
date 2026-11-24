"""Scoped RAC1 evidence helpers; no workflow or external byte ABI changes."""
from __future__ import annotations

import hashlib
import itertools
import struct

from hia_arm64_rac1_carrier import MAX_CAPACITY, MAX_INPUT

BAD = 2**32 - 1
SHORT = BAD - 1
SENTINEL = b"\xcd"
ALIASES = bytes(range(32)), bytes(range(32, 64)), bytes(range(224, 256))
RUST_INPUT_DIGESTS = {
    'hia/tests/test_release_artifact_header.py': '27e6bbb55d0b9282766383a9f1ec281de5d32c5be048a0add0fb1b68bb9a13df',
    'trillionnium/crates/trnm-release-bundle/src/lib.rs': 'e41410d1151ad6edf17cfa20cf2a592baf9fc23225b78d6596c838fa9445b5ce',
    'trillionnium/crates/trnm-release-bundle/src/content_v1.rs': 'dd4755bab39ba4f60887f298b7616493c389c39e299aa1e05eb22d4573d0e3cc',
    'rust-toolchain.toml': '24ef3b9d3edbd850aa386cb0a98e10450b0030991a4537cb359f54d49dbbb33a',
}

def source_bound(root):
    for name,want in RUST_INPUT_DIGESTS.items():
        p = root / name
        if not p.is_file() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest() != want:
            raise ValueError("original source drift: " + name)

def frame(name=b"archive", media=b"application/octet-stream", size=0x102030405, execute=1, aliases=ALIASES):
    return struct.pack("<HHQB",len(name),len(media),size,execute) + b"".join(aliases) + name + media

def typed_corpus():
    rows = [frame(b" ~",b"z",0x0102030405,1,aliases) for aliases in itertools.permutations(ALIASES)]
    rows.extend([frame(b" ",b"~",1,0), frame(b"~"*82,b" ",128*1024**3,1)])
    rows.extend([frame(b"",b"abc"),frame(b"abc",b""),frame(size=0),
                 frame(size=128*1024**3+1),frame(size=2**64-1)])
    for i in range(3):
        a = list(ALIASES)
        a[i] = bytes(32)
        rows.append(frame(aliases=a))
    for i in range(2):
        rows.extend(frame(bytes([b]),b"x") if i==0 else frame(b"x",bytes([b])) for b in range(256))
    assert len(rows)==528 and max(map(len,rows))==MAX_INPUT
    return rows

def oracle_request(rows):
    return b"".join(struct.pack("<I",len(r))+r for r in rows)

def oracle_parse(raw, count):
    result = []
    cursor = 0
    for _ in range(count):
        if cursor+4>len(raw): raise ValueError("short genuine oracle result")
        size, = struct.unpack_from("<I",raw,cursor)
        cursor += 4
        if size==BAD:
            result.append(None)
        elif 127<=size<=208 and cursor+size<=len(raw) and raw[cursor:cursor+4]==b"RAC1":
            result.append(raw[cursor:cursor+size])
            cursor += size
        else:
            raise ValueError("bad genuine oracle result length/magic")
    if cursor!=len(raw): raise ValueError("surplus genuine oracle result")
    return result

def cases(rows, outputs):
    observed=[]
    for data,out in zip(rows,outputs,strict=True):
        cap=MAX_CAPACITY
        observed.append((data,cap,BAD if out is None else len(out),(out or b"")+SENTINEL*(cap-len(out or b""))))
    for i in (0,6,7):
        data,out=rows[i],outputs[i]
        if out is None: raise ValueError("expected genuine successful literal bytes")
        for cap in (0,len(out)-1,len(out)):
            ok=cap==len(out)
            observed.append((data,cap,len(out) if ok else SHORT,out if ok else SENTINEL*cap))
    for raw in (b"",rows[6][:-1],rows[6]+b"\0",rows[6][:12]+b"\x02"+rows[6][13:]):
        # These cases fall outside the typed Rust FE; not labeled as an
        # original-reference match. Scope is native refusal + no output change.
        observed.append((raw,MAX_CAPACITY,BAD,SENTINEL*MAX_CAPACITY))
    return observed

def packed(data,cap,selector):
    if len(data)>MAX_INPUT or not 0<=cap<=MAX_CAPACITY or not 0<=selector<=27:
        raise ValueError("outside carrier scope")
    return [len(data),cap,selector,*struct.unpack("<24Q",data.ljust(MAX_INPUT,b"\0"))]

def native_request(cases):
    return b"".join(struct.pack("<HH",len(d),n)+d for d,n,_,_ in cases)

def native_expected(cases):
    return b"".join(struct.pack("<I",rc)+out for _,_,rc,out in cases)

# Future independent native ARM64 driver. It transports raw input bytes, calls
# the ELF export and copies scalar-return windows back into a byte transcript.
# It does not validate or reimplement RAC1.
def driver_source():
    formals=",".join(f"w{i}:u64" for i in range(24))
    args=",".join(f"w[{i}]" for i in range(24))
    source=r'''
use std::io::{self,Read,Write};
extern "C" { fn rac1_test_window(n:u64,cap:u64,sel:u64,WORDS)->u64; }
fn main()->io::Result<()> {
    let mut data=Vec::new();
    io::stdin().read_to_end(&mut data)?;
    assert!(data.len()<=262144);
    let mut out=io::stdout().lock();
    let mut cur=0;
    while cur<data.len() {
        let n=u16::from_le_bytes(data[cur..cur+2].try_into().unwrap()) as usize;
        let cap=u16::from_le_bytes(data[cur+2..cur+4].try_into().unwrap()) as usize;
        cur+=4;
        assert!(n<=192 && cap<=216 && cur+n<=data.len());
        let mut input=[0u8;192];
        input[..n].copy_from_slice(&data[cur..cur+n]);
        cur+=n;
        let mut w=[0u64;24];
        for (i,v) in input.chunks_exact(8).enumerate() {w[i]=u64::from_le_bytes(v.try_into().unwrap());}
        let call=|s| unsafe{rac1_test_window(n as u64,cap as u64,s,ARGS)};
        let status=u32::try_from(call(0)).expect("carrier invariant");
        out.write_all(&status.to_le_bytes())?;
        for (i,left) in (0..cap).step_by(8).enumerate() {
            let word=call(i as u64+1).to_le_bytes();
            let size=(cap-left).min(word.len());
            out.write_all(&word[..size])?;
        }
    }
    Ok(())
}
'''
    return source.replace("WORDS",formals).replace("ARGS",args)
