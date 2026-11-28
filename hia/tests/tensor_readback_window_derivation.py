"""Exact previous selected reader plus a bounded tensor-relative copy window."""
import hashlib

from hia.tests.tensor_readback_selected_derivation import SOURCE as PRIOR
from hia.tests.tensor_readback_three_derivation import replace

SOURCE=PRIOR.with_name("cell_tensor_reader_readback_window.hepta")
PIN="56f176395327f4ec356da8a80855aeb6a160ea4cb450e7f8939634f42fe30300"
WORK=840472
MAX_FRAME_SUFFIX=273


def derive():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published immutable selected reader changed")
    d=raw.decode()
    for a,b in (
        ("trnm_cell_tensor_reader_selected_v1","trnm_cell_tensor_reader_window_v1"),
        ('  fullmax:u64 = const() {"value":4194561}',
         '  fullmax:u64 = const() {"value":4194577}'),
        ('  need:u64 = const() {"value":840456}',
         '  need:u64 = const() {"value":840472}'),
        ('  maxq:u64 = const() {"value":255}', '  maxq:u64 = const() {"value":271}'),
        ('  lower:bool = compare.lt(z,n1)',
         '  params:u64 = const() {"value":16}\n  lower:bool = compare.lt(params,n1)'),
        ('  utf:u64 = call(q2,a2,n2) {"function":"value_utf8"}',
         '  req:u64 = const() {"value":16}\n'
         '  name:u64 = int.add.wrap(a2,req)\n'
         '  name_n:u64 = int.sub.wrap(n2,req)\n'
         '  utf:u64 = call(q2,name,name_n) {"function":"value_utf8"}'),
        ('  jump length(w3,n3)',
         '  fixed:u64 = const() {"value":16}\n'
         '  name_bytes:u64 = int.sub.wrap(n3,fixed)\n'
         '  jump length(w3,name_bytes)'),
        ('  query_pos:u64 = const() {"value":840200}',
         '  query_pos:u64 = const() {"value":840216}'),
        ('  branch sane capacity(i4,o4,e4,b4,s4,x4,y4,z4,base,from,till,eight) internal()',
         '''  branch sane window(i4,o4,w4,e4,b4,s4,x4,y4,z4,base,from,till,eight) internal()
block window(wi:readbuf,wo:mutbuf,ww:mutbuf,we:u64,wb:readbuf,ws:bool,wx:readbuf,wy:readbuf,wz:u64,wbase:u64,wfrom:u64,wtill:u64,w8:u64)
  relative_slot:u64 = const() {"value":840200}
  want_slot:u64 = const() {"value":840208}
  relative:u64 = call(ww,relative_slot) {"function":"cp_get"}
  want:u64 = call(ww,want_slot) {"function":"cp_get"}
  tensor_bytes:u64 = int.sub.wrap(wtill,wfrom)
  lower_ok:bool = compare.le(relative,tensor_bytes)
  left:u64 = int.sub.wrap(tensor_bytes,relative)
  want_ok:bool = compare.le(want,left)
  inside_window:bool = bool.and(lower_ok,want_ok)
  first:u64 = int.add.wrap(wfrom,relative)
  last:u64 = int.add.wrap(first,want)
  branch inside_window capacity(wi,wo,we,wb,ws,wx,wy,wz,wbase,first,last,w8) invalid_window()'''),
        ('block short()\n  no_room:u32',
         'block invalid_window()\n  bad_range:u32 = const() {"value":243}\n  ret(bad_range)\nblock short()\n  no_room:u32'),
    ):
        if a=='  need:u64 = const() {"value":840456}':
            assert d.count(a)==2
            d=d.replace(a,b)
        else:
            d=replace(d,a,b)
    return d.encode()
