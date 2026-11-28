"""Exact original TCM2 observation with a detached context and no payload reader."""
from pathlib import Path
import unittest

from hia.tests.test_da_cell_content_closure_observe import (
    ROOT, alter, context_from_manifest, frame, put, qualify_observation, tcm2,
)
from hia.tests.test_da_cell_content_manifest_value import CAP

SOURCE = ROOT / "hia/src/data_availability/cell_content_manifest_observe.hepta"
WITNESS = Path(__file__).with_name("rust_da_cell_content_manifest_observe_reference.rs")


def matrix():
    m = tcm2()
    c = context_from_manifest(m)
    z = bytes(64)
    max_u64 = (1 << 64) - 1
    yield frame(m,c,1,len(m)+1),0
    yield frame(m,c,max_u64,max_u64),0
    yield frame(m,c,1,len(m)),35
    yield frame(m,c,7,1),35
    yield frame(m,c,0,max_u64),30
    yield frame(m,c,max_u64,0),30
    yield frame(m,put(c,0,b"XXXX"),1,1),31
    yield frame(m,alter(c,68,255),1,1),31
    yield frame(m,put(c,4,z),1,1),32
    yield frame(m,put(c,69,z),1,1),32
    for k in (1,2,4,5):
        yield frame(m,alter(c,68,k),1,1),33
    for location in (4,67,69,132,133,140):
        yield frame(m,alter(c,location,c[location]^128),1,1),34
    yield frame(m,alter(alter(c,68,4),140,1),1,1),33
    yield frame(m,alter(c,68,4),0,1),30
    yield frame(m,alter(c,68,255),0,0),31
    yield frame(m,put(put(c,69,z),0,b"ZZZZ"),1,1),31
    for n in (0,1,140,156):
        yield bytes(n),100

    large = tcm2(b"A"*64)
    # Whole TCM2 (including its complete payload declaration) precedes all
    # context and budget decisions. These are ordinary inert declared bytes.
    for raw,status in [
        (b"",1),(m[:-1],1),(large+b"z",1),
        (alter(m,0,0),2),(alter(large,3,49),2),(alter(m,4,0),3),
        (alter(large,4,65),3),(alter(m,4,2),4),(large[:-1],4),
        (tcm2(b"\xc3"),5),(tcm2(b"\xed\xa0\x80"),5),
        (tcm2(kind=0),6),(tcm2(claim_magic=b"ZZZZ"),6),
        (tcm2(profile=z),7),(tcm2(instance=z),7),
        (tcm2(b"/"),8),(tcm2("é".encode()),8),
        (tcm2(kind=3),9),(tcm2(kind=2),9),
        (tcm2(size=0),10),(tcm2(size=CAP+1),10),
    ]:
        yield frame(raw,put(c,69,z),0,0),status
    for n in range(1,65):
        m = tcm2(b"N"*(n-1)+b"0", size=(CAP if n%2 else 1),
                 generation=n<<55, instance=bytes([n])*64, aliases=bytes([65-n])*160,
                 digest=bytes([n])*64)
        c = context_from_manifest(m)
        yield frame(m,c,1,len(m)+1),0
        if n in (1,2,3,15,16,17,31,32,33,47,48,49,62,63,64):
            yield frame(m,c,9,len(m)),35
            yield frame(m,c,9,len(m)+2),0


class DaCellContentManifestObserve(unittest.TestCase):
    def test_actual_declared_tcm2_observation_and_fresh_budget_both_stock(self):
        cases = list(matrix())
        self.assertEqual({s for _,s in cases},{0,*range(1,11),*range(30,36),100})
        qualify_observation(self,cases,SOURCE,WITNESS)
