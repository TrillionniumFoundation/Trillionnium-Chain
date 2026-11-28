"""Bind the exact immutable range observer to the published 4 MiB reader."""
import hashlib

from hia.tests.tensor_readback_four_derivation import SOURCE as PRIOR, WORK
from hia.tests.tensor_readback_three_derivation import replace

SOURCE=PRIOR.with_name("cell_tensor_reader_readback_layout.hepta")
PIN="c851d7f66b900d958d9913740885de4ab45087f345b177dccd8bc01cc47dccb2"
BASE_SLOT=159472
CANONICAL=709120
WIDTH=16
READBACK=114


def derive():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published 4 MiB reader drifted")
    assert BASE_SLOT+8==159480 and CANONICAL+(16384*8)==WORK
    doc=raw.decode()
    for a,b in (
        ("trnm_cell_tensor_reader_four_v1","trnm_cell_tensor_reader_layout_v1"),
        ('  begin_eight:u64 = const() {"value":8}\n',
         '  begin_eight:u64 = const() {"value":8}\n'
         '  base_slot:u64 = const() {"value":159472}\n'
         '  raw_base:u64 = int.add.wrap(begin_h,begin_eight)\n'
         '  keep_base:u64 = call(begin_w,base_slot,raw_base) {"function":"cp_put"}\n'),
        ('  saved:u64 = call(w,pos,pair) {"function":"cp_put"}',
         '  saved:u64 = call(w,pos,pair) {"function":"cp_put"}\n'
         '  cpbase:u64 = const() {"value":709120}\n'
         '  cpstep:u64 = const() {"value":8}\n'
         '  cpoff:u64 = int.mul.wrap(n,cpstep)\n'
         '  cpat:u64 = int.add.wrap(cpbase,cpoff)\n'
         '  cpsave:u64 = call(w,cpat,pair) {"function":"cp_put"}'),
        ('  room_okay:bool = compare.le(room_c114,room_n)',
         '  room_c16:u64 = const() {"value":16}\n'
         '  room_rangebytes:u64 = int.mul.wrap(room_c16,room_count)\n'
         '  room_need:u64 = int.add.wrap(room_c114,room_rangebytes)\n'
         '  room_okay:bool = compare.le(room_need,room_n)'),
        ('  publish_ok:u32 = const() {"value":0}',
         '  publish_layout:u64 = call(publish_w,publish_o,publish_count) {"function":"lt_ranges"}\n'
         '  publish_ok:u32 = const() {"value":0}'),
    ):
        doc=replace(doc,a,b)
    return doc.encode()
