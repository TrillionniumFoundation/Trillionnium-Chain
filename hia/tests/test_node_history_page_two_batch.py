"""Atomic private two-batch HPF and cutoff versus the two actual frozen loops."""
from pathlib import Path
from hashlib import sha256
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import history_page_fold_original as frozen
from hia.tests.native_support import NativeModule
from hia.tests.test_history_page_cutoff import RUST, SHA
from hia.tests.test_node_history_page_fold import O, W

SOURCE=Path(__file__).resolve().parents[1]/"src/node/history_page_two_batch.hepta"
DRIVER=Path(__file__).with_name("rust_history_page_two_batch_reference.rs")


def composed_original(extract):
    files,pins=extract()
    rust=RUST.read_bytes()
    if sha256(rust).hexdigest()!=SHA:
        raise ValueError("Unexpected frozen history source")
    body=rust[rust.index(b"    fn history_with_decoders("):]
    start=body.index(b"        let mut packets = Vec::new();")
    cutoff=body[start:body.index(b"        progress(count)?;",start)]
    driver=files["main.rs"]
    if driver.count(b"fn main() {")!=1:
        raise ValueError("Unexpected earlier synthetic fixture")
    driver=driver[:driver.index(b"fn main() {")]
    extension=DRIVER.read_bytes()
    marker=b"        // EXACT_ORIGINAL_CUTOFF_LOOP"
    if extension.count(marker)!=1 or cutoff.count(b"800_000")!=1:
        raise ValueError("Unexpected original loop witness seam")
    return {**files,"main.rs":driver+b"\n"+extension.replace(marker,cutoff)},pins


def actual():
    extract=frozen.extract
    with tempfile.TemporaryDirectory(prefix="trnm-held-history-two-batch-") as temp:
        with patch.object(frozen,"extract",lambda:composed_original(extract)):
            raw,pins=frozen.original(Path(temp))
    cases=[]
    at=0
    while at<len(raw):
        n,status,out=struct.unpack_from("<3Q",raw,at)
        at+=24
        cases.append((raw[at:at+n],status,raw[at+n:at+n+out]))
        at+=n+out
    if at!=len(raw):
        raise ValueError("Unconsumed exact original observation")
    return cases, dict(pins=pins, observation_sha256=sha256(raw).hexdigest(),
                       observation_bytes=len(raw))


class HistoryPageTwoBatch(unittest.TestCase):
    def test_atomic_two_batch_and_cutoff_against_frozen_original_both_emitters(self):
        vectors,proof=actual()
        artifacts={}
        self.assertEqual([code for _,code,_ in vectors],[0,0,0,0,42])
        self.assertEqual([struct.unpack_from("<3Q",o) for _,code,o in vectors if code==0],
                         [(65,16,16*49_508),(84,2,800_000),(128,1,1_048_576),(70,1,400_001)])
        for backend in ("direct","selfhost"):
            with NativeModule(SOURCE,backend=backend,byte_exports=("f0",)) as module:
                self.assertEqual(len(module.artifact_sha256),64)
                artifacts[backend]=dict(artifact_sha256=module.artifact_sha256,
                                        closure=module.receipt["chain_migration"])
                def check(f,code,out=b"",cap=541,scratch=521):
                    got=module.call("f0",[f,O*cap,W*scratch]).require_returned()
                    self.assertEqual((got.abi_status,got.value,got.arguments[:2]),
                                     (0,code,[f,out+O*(cap-len(out))]))
                    self.assertEqual(got.arguments[2][512:],W*max(0,scratch-512))

                for i,(f,code,out) in enumerate(vectors):
                    with self.subTest(backend=backend,case=i):
                        check(f,code,out)
                        if not code:
                            check(f,0,out,cap=len(out),scratch=512)
                f,_,output=vectors[1]
                batch2=struct.unpack_from("<Q",f,128)[0]
                table=struct.unpack_from("<Q",f,136)[0]
                def patch_u64(raw,at,value):
                    return raw[:at]+struct.pack("<Q",value)+raw[at+8:]
                check(patch_u64(f,batch2+64,94),42) # same actual handoff, changed second ID
                check(patch_u64(f,batch2+96,1),42) # ordinal must restart at zero
                check(patch_u64(f,len(f)-40,99),100) # visited ID does not join
                check(patch_u64(f,len(f)-8,49_507),100) # visited length outside profile
                check(patch_u64(f,table,99),0,output) # unvisited ID not read
                check(patch_u64(f,table+32,0),0,output) # unvisited length not read
                check(f+b"!",100)
                check(f[:-1],100)
                check(f,102,cap=len(output)-1)
                check(f,102,scratch=511)
        self.assertNotEqual(artifacts["direct"]["artifact_sha256"],
                            artifacts["selfhost"]["artifact_sha256"])
        if target:=os.environ.get("HIA_HPT_TWO_BATCH_PROOF"):
            Path(target).write_text(json.dumps(dict(
                original=proof, native=artifacts, original_cases=len(vectors), native_calls_each=19,
                cases=[(len(f),sha256(f).hexdigest(),status,len(out),sha256(out).hexdigest())
                       for f,status,out in vectors]
            ),indent=2,sort_keys=True)+"\n")
