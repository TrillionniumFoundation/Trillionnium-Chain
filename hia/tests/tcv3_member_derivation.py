"""Derive the exact previously published TCV2 structural body for a subspan."""
import hashlib
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1]/"src/data_availability"
SOURCE = DATA/"cell_complete_version_content.hepta"
PIN = "f2e55789919fb75ba16d25d95679339c16da4a51f5df5527937c6f282a9ee566"


def derive(raw):
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("published TCV2 source changed")
    old=raw.decode("ascii")
    s=old[old.index("block have_tag("):old.index("block capacity(")]
    # The old body already threads absolute N (end) and does not dereference
    # output until the removed publisher. New base enters only until tc_frame.
    s=re.sub(r",o\d(?::mutbuf)?", "", s)
    s=s.replace("four1:u64)","four1:u64,base1:u64)").replace(
        "  fits:bool = compare.le(four1,n1)",
        "  extent1:u64 = int.sub.wrap(n1,base1)\n  fits:bool = compare.le(four1,extent1)")
    s=s.replace("n1,four1)","n1,four1,base1)").replace(
        "four2:u64)","four2:u64,base2:u64)")
    s=s.replace('  z2:u64 = const() {"value":0}\n','').replace(
        "call(i2,z2,four2)","call(i2,base2,four2)")
    s=s.replace("  branch equal version_frame(i2,w2,n2,four2)",
        "  offset2:u64 = int.add.wrap(base2,four2)\n  branch equal version_frame(i2,w2,n2,offset2)")
    s=s.replace("capacity(i8,w8,n8,c8)","validated()")
    if "validated()" not in s or "call(i2,base2,four2)" not in s:
        raise ValueError("unexpected TCV2 boundary")
    errs=old[old.index("block truncated()"):old.index("block no_room()")]
    return (
        'fn c3_tcv_content(c3_di:readbuf,c3_dw:mutbuf,c3_db:u64,c3_de:u64) -> (u32) effects(read,write,trap) entry(entry)\n'
        'block entry(c3_di:readbuf,c3_dw:mutbuf,c3_db:u64,c3_de:u64)\n'
        '  four:u64 = const() {"value":4}\n'
        '  jump have_tag(c3_di,c3_dw,c3_de,four,c3_db)\n'
        +s+'block validated()\n  accept:u32 = const() {"value":0}\n  ret(accept)\n'+errs+"end\n"
    )
