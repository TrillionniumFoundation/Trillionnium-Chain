"""Actual source-bound original retained history packet loop, inert lengths only."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/"hia/src/node/history_page_cutoff.hepta"
RUST=ROOT/"trillionnium/crates/trnm-pon-node/src/store/history_page.rs"
SHA="43c2f10765dd16c5f8b51ec9f667667866180b9963b10da7304095bea3ed3e16"
DOMAIN_PINS={
    "trnm-pon-node/src/lib.rs":"baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "trnm-pon-node/src/pq_application_v6.rs":"d782595915da93128ecf71cfd8f5a8a3a906f7f4e108d72d34b5299490b30499",
    "trnm-protocol/src/pon_wire.rs":"ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b",
    "trnm-crypto-primitives/src/pon_work.rs":"7af17da8488782bf403275b5fd401ad469dd460fd0ecda38a0edb4e714c5494e",
}
MIN,MAX,CAP=49508,1048576,800000


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_rust():
    raw=RUST.read_bytes()
    assert sha(raw)==SHA
    body=raw[raw.index(b"    fn history_with_decoders("):]
    start=body.index(b"        let mut packets = Vec::new();")
    loop=body[start:body.index(b"        progress(count)?;",start)]
    assert loop.count(b"for id in window.into_iter().rev()")==1
    assert loop.count(b"800_000")==1
    start=br"""
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::BufRead;
type Result<T> = std::result::Result<T,&'static str>;
type Hash=[u8;32];
#[derive(Clone)]
struct Packet {id:Hash, length:usize}
struct Fixture { packets:Vec<Packet>, read_trace:RefCell<Vec<Hash>> }
impl Fixture {
    fn packet(&self,id:Hash)->Result<Packet> {
        self.read_trace.borrow_mut().push(id);
        self.packets.iter().find(|packet|packet.id==id).cloned().ok_or("not in inert window")
    }
    fn observe(&self,window:VecDeque<Hash>,packet_length:impl Fn(&Packet)->Result<usize>)->Result<Vec<Packet>> {
"""
    tail=br"""
        Ok(packets)
    }
}
fn id(index:usize)->Hash {
    std::array::from_fn(|j|(17*index+13*j+3) as u8)
}
fn main() {
    for line in std::io::stdin().lock().lines() {
        let numbers:Vec<usize>=line.unwrap().split_whitespace().map(|n|n.parse().unwrap()).collect();
        assert!(numbers.len()<=16);
        let packets:Vec<_>=numbers.iter().enumerate().map(|(i,&length)|Packet{id:id(i),length}).collect();
        assert!(packets.iter().all(|p| (49508..=1048576).contains(&p.length)));
        let window=packets.iter().map(|p|p.id).collect();
        let read_trace=RefCell::new(Vec::new());
        let f=Fixture{packets,read_trace};
        let length_trace=RefCell::new(Vec::new());
        let selected=f.observe(window,|p|{length_trace.borrow_mut().push(p.id);Ok(p.length)}).unwrap();
        let calls=f.read_trace.borrow();
        assert_eq!(&*calls,&*length_trace.borrow());
        let count=selected.len();
        assert!(calls.len()==count || calls.len()==count+1);
        let bytes:usize=selected.iter().map(|p|p.length).sum();
        print!("{} {} {}",count,bytes,calls.len());
        for p in &selected {
            let index=f.packets.iter().position(|x|x.id==p.id).unwrap();
            print!(" {}",index);
        }
        println!();
    }
}
"""
    return start+loop+tail,sha(loop)


def packet_id(i):
    return bytes((17*i+13*j+3)%256 for j in range(32))


def encode(rows):
    return b"HPCB0001"+struct.pack("<Q",len(rows))+b"".join(packet_id(i)+struct.pack("<Q",n) for i,n in enumerate(rows))


def cases():
    known=[(),(MIN,),(CAP,),(CAP+1,),(MAX,),(MIN,MAX),(MAX,MIN),(MIN,)*16,
           (MIN+16,)+(MIN,)*15,(MIN,400000,400000),(MIN,400001,400000),
           (MIN,399999,400000),(MIN,399999,400001),
           (MIN,MAX,100000),(MIN,CAP-MIN,MIN),(MIN,CAP-MIN+1,MIN)]
    rng=random.Random(1763)
    for i in range(200):
        size=i%17
        lo,hi=((MIN,65000),(MIN,MAX),(MIN,CAP),(MIN,154000))[i%4]
        known.append(tuple(rng.randint(lo,hi) for _ in range(size)))
    return known


class HistoryPageCutoff(unittest.TestCase):
    def test_exact_frozen_order_first_and_byte_boundary_in_both_stocks(self):
        self.assertEqual({n:sha((ROOT/"trillionnium/crates"/n).read_bytes()) for n in DOMAIN_PINS},DOMAIN_PINS)
        vectors=cases()
        witness,loop=exact_rust()
        self.assertTrue(subprocess.check_output(["rustc","--version"]).startswith(b"rustc 1.95.0 (59807616e "))
        with tempfile.TemporaryDirectory(prefix="trnm-history-page-cutoff-") as t:
            directory=Path(t)
            exe=directory/"frozen"
            source=exe.with_suffix(".rs")
            source.write_bytes(witness)
            build=subprocess.run(["rustc","--edition=2021","-Dwarnings",str(source),"-o",str(exe)],capture_output=True,timeout=35)
            self.assertEqual((build.returncode,build.stderr),(0,b""))
            initial=set(directory.iterdir())
            raw_wire="".join(" ".join(map(str,line))+"\n" for line in vectors).encode()
            run=subprocess.run([str(exe)],env={},cwd=t,input=raw_wire,capture_output=True,timeout=10)
            self.assertEqual((run.returncode,run.stderr),(0,b""))
            self.assertEqual(set(directory.iterdir()),initial)
            binary=sha(exe.read_bytes())
        lines=[tuple(map(int,line.split())) for line in run.stdout.decode().splitlines()]
        self.assertEqual(len(lines),len(vectors))
        self.assertEqual(lines[3],(1,CAP+1,1,0))
        self.assertEqual(lines[4],(1,MAX,1,0))
        self.assertEqual(lines[7],(16,MIN*16,16,*range(15,-1,-1)))
        self.assertEqual(lines[9],(2,CAP,3,2,1))
        self.assertEqual(lines[10],(1,400000,2,2))
        frames=[encode(row) for row in vectors]
        expected=[]
        for count,total,observed,*selected in lines:
            self.assertEqual(len(selected),count)
            self.assertIn(observed,(count,count+1))
            expected.append((0,struct.pack("<2Q",count,total)+b"".join(packet_id(i) for i in selected)))
        supplied=[("f0",[f,b"\xa5"*(len(v[1])+i%2*11),b"\xd3"*17]) for i,(f,v) in enumerate(zip(frames,expected,strict=True))]
        seed=frames[7]
        bad=[seed[:15],seed[:-1],seed+b"?",b"x"+seed[1:],
             seed[:8]+struct.pack("<Q",17)+seed[16:],
             seed[:-8]+struct.pack("<Q",MIN-1),seed[:-8]+struct.pack("<Q",MAX+1)]
        supplied.extend(("f0",[f,b"\xa5"*64,b""]) for f in bad)
        expected.extend([(100,b"")]*len(bad))
        supplied.extend([("f0",[frames[0],b"\xa5"*15,b""]),("f0",[seed,b"\xa5"*527,b""]),
                         ("f0",[bad[-1],b"",b""]),
                         ("f0",[encode((0,MAX,MIN)),b"\xa5"*48,b""])])
        expected.extend([(102,b""),(102,b""),(100,b""),(0,struct.pack("<2Q",1,MIN)+packet_id(2))])
        hashes={}
        for backend in ("direct","selfhost"):
            with NativeModule(SRC,backend=backend,byte_exports=("f0",)) as m:
                hashes[backend]=dict(artifact_sha256=m.artifact_sha256,closure=m.receipt["chain_migration"])
                for i in range(0,len(supplied),24):
                    ask=supplied[i:i+24]
                    for call,obs,(code,val) in zip(ask,m.call_many(ask,timeout=20),expected[i:i+24],strict=True):
                        obs.require_returned()
                        frame,out,arena=call[1]
                        self.assertEqual((obs.value,obs.arguments),(code,[frame,val+out[len(val):],arena]))
        if proof:=os.environ.get("HIA_HISTORY_CUTOFF_PROOF"):
            Path(proof).write_text(json.dumps(dict(original_source_sha256=SHA,original_loop_sha256=loop,original_domain_pins=DOMAIN_PINS,
                original_executable_sha256=binary,original_stdout_sha256=sha(run.stdout),original_windows=len(vectors),
                native_cases_each=len(expected),native=hashes,owner_invoked=False),indent=2,sort_keys=True)+"\n")
