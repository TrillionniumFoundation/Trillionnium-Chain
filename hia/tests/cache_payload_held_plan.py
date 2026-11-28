"""Mechanical private plan composition from the published cursor arithmetic only."""
import hashlib

from hia.tests.test_da_cell_cache_payload_cursor import SOURCE as PRIOR
from hia.tests.tensor_readback_three_derivation import replace

SOURCE=PRIOR.with_name("cell_cache_payload_held_read.hepta")
PIN="85511ef642f55d26c9e5a6aa3443f32e0a891c18a75f9dd3a066612497c7701f"
ENTRY="block entry(ci:readbuf,cpos:u64,creq:u64,crows:u64,ccount:u64)"


def plan():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published cursor plan is not the frozen source")
    code=raw.decode()
    a=code.index("block chunk(")
    b=code.index("block read_out(",a)
    code=code[a:b]
    for old,new in (
        ("block chunk(ci:readbuf,co:mutbuf,cpos:u64,creq:u64,crows:u64,ccount:u64)",ENTRY),
        ("read_count(ci,co,cpos,creq,crows,index,off_in_chunk)","read_count(ci,creq,crows,index,off_in_chunk)"),
        ("block read_count(ki:readbuf,ko:mutbuf,kp:u64,kreq:u64,kr:u64,kindex:u64,koff:u64)",
         "block read_count(ki:readbuf,kreq:u64,kr:u64,kindex:u64,koff:u64)"),
        ("  next:u64 = int.add.wrap(kp,count_bytes)\n",""),
        ("  branch valid_off read_out(ko,kindex,koff,count_bytes,next) internal()",
         "  branch valid_off found(row,koff,count_bytes) internal()"),
    ):
        code=replace(code,old,new)
    return ('''
fn ch_plan(ci:readbuf,cpos:u64,creq:u64,crows:u64,ccount:u64) -> (u64,u64,u64) effects(read,write,trap) entry(entry)
'''+code+'''block found(row_at:u64,offset:u64,count:u64)
  ret(row_at,offset,count)
block internal()
  z:u64 = const() {"value":0}
  ret(z,z,z)
end
''').encode()
