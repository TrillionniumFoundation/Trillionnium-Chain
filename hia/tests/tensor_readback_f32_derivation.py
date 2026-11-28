"""Mechanically reuse the immutable window owner for the original typed F32 read."""
import hashlib

from hia.tests.tensor_readback_window_derivation import SOURCE as PRIOR
from hia.tests.tensor_readback_three_derivation import replace

SOURCE=PRIOR.with_name("cell_tensor_reader_readback_f32.hepta")
PIN="8e9f7d75a3dff78e69686efeda3b3434b1f77b2667b6687220ccdd8c1b803c72"
WORK=840464
MAX_FRAME_SUFFIX=265


def derive():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published immutable window reader changed")
    d=raw.decode()
    for a,b in (
        ("trnm_cell_tensor_reader_window_v1","trnm_cell_tensor_reader_f32_v1"),
        ('  fullmax:u64 = const() {"value":4194577}','  fullmax:u64 = const() {"value":4194569}'),
        ('  need:u64 = const() {"value":840472}', '  need:u64 = const() {"value":840464}'),
        ('  maxq:u64 = const() {"value":271}','  maxq:u64 = const() {"value":263}'),
        ('  params:u64 = const() {"value":16}','  params:u64 = const() {"value":8}'),
        ('  req:u64 = const() {"value":16}','  req:u64 = const() {"value":8}'),
        ('  fixed:u64 = const() {"value":16}','  fixed:u64 = const() {"value":8}'),
        ('  query_pos:u64 = const() {"value":840216}','  query_pos:u64 = const() {"value":840208}'),
        ('  ord:u64 = call(i3,end3,c3,pos3,w3,qn3,z3)', '  ord:u64,dt:u64 = call(i3,end3,c3,pos3,w3,qn3,z3)'),
        ('  branch found range(i3,o3,w3,e3,l3,b3,s3,x3,y3,z3,ord) absent()',
         '''  branch found dtype(i3,o3,w3,e3,l3,b3,s3,x3,y3,z3,ord,dt) absent()
block dtype(ti:readbuf,to:mutbuf,tw:mutbuf,te:u64,tl:u64,tb:readbuf,ts:bool,tx:readbuf,ty:readbuf,tz:u64,tord:u64,tdt:u64)
  dtpos:usize = int.cast(tdt) {"mode":"wrap"}
  dtbyte:u8 = buffer.load(ti,dtpos)
  f32_code:u8 = const() {"value":1}
  isf32:bool = compare.eq(dtbyte,f32_code)
  branch isf32 range(ti,to,tw,te,tl,tb,ts,tx,ty,tz,tord) wrong_dtype()'''),
        ('  branch sane window(i4,o4,w4,e4,b4,s4,x4,y4,z4,base,from,till,eight) internal()',
         '  branch sane index(i4,o4,w4,e4,b4,s4,x4,y4,z4,base,from,till) internal()'),
        ('block invalid_window()\n  bad_range:u32',
         '''block wrong_dtype()
  no_f32:u32 = const() {"value":244}
  ret(no_f32)
block index_overflow()
  overflow:u32 = const() {"value":245}
  ret(overflow)
block invalid_window()
  bad_range:u32'''),
        ('fn lt_find(i:readbuf,end:u64,c:u64,p:u64,q:mutbuf,qn:u64,j:u64) -> (u64)',
         'fn lt_find(i:readbuf,end:u64,c:u64,p:u64,q:mutbuf,qn:u64,j:u64) -> (u64,u64)'),
        ('branch done answer(lc) row(', 'branch done miss(lc) row('),
        ('dt,next) answer(c1)', 'dt,next) miss(c1)'),
        ('  branch same answer(j3) advance(i3,e3,c3,q3,n3,j3,next3)',
         '  dt3:u64 = int.add.wrap(view3,n3)\n  branch same answer(j3,dt3) advance(i3,e3,c3,q3,n3,j3,next3)'),
        ('block answer(ordinal:u64)\n  ret(ordinal)',
         'block miss(missed:u64)\n  miss_dt:u64 = const() {"value":0}\n  ret(missed,miss_dt)\n'
         'block answer(ordinal:u64,dt_at:u64)\n  ret(ordinal,dt_at)'),
    ):
        if a=='  need:u64 = const() {"value":840472}':
            assert d.count(a)==2
            d=d.replace(a,b)
        else:
            d=replace(d,a,b)
    a=d.index("block window(")
    b=d.index("block contiguous(",a)
    return (d[:a]+'''block index(wi:readbuf,wo:mutbuf,ww:mutbuf,we:u64,wb:readbuf,ws:bool,wx:readbuf,wy:readbuf,wz:u64,wbase:u64,wfrom:u64,wtill:u64)
  index_slot:u64 = const() {"value":840200}
  ix:u64 = call(ww,index_slot) {"function":"cp_get"}
  max_index:u64 = const() {"value":4611686018427387903}
  index_fits:bool = compare.le(ix,max_index)
  branch index_fits element(wi,wo,we,wb,ws,wx,wy,wz,wbase,wfrom,wtill,ix) index_overflow()
block element(ei:readbuf,eo:mutbuf,ee:u64,eb:readbuf,es:bool,ex:readbuf,ey:readbuf,ez:u64,ebase:u64,efrom:u64,etill:u64,eidx:u64)
  k4:u64 = const() {"value":4}
  relative:u64 = int.mul.wrap(eidx,k4)
  tensor_bytes:u64 = int.sub.wrap(etill,efrom)
  lower_ok:bool = compare.le(relative,tensor_bytes)
  left:u64 = int.sub.wrap(tensor_bytes,relative)
  want_ok:bool = compare.le(k4,left)
  inside_element:bool = bool.and(lower_ok,want_ok)
  first:u64 = int.add.wrap(efrom,relative)
  branch inside_element capacity(ei,eo,ee,eb,es,ex,ey,ez,ebase,first,k4) invalid_window()
block capacity(i5:readbuf,o5:mutbuf,e5:u64,b5:readbuf,s5:bool,x5:readbuf,y5:readbuf,z5:u64,base5:u64,from5:u64,n5:u64)
  o0:usize = buffer.len(o5)
  o_room:u64 = int.cast(o0) {"mode":"wrap"}
  enough:bool = compare.le(n5,o_room)
  branch enough publish(i5,o5,e5,b5,s5,x5,y5,z5,base5,from5,n5) short()
block publish(i6:readbuf,o6:mutbuf,e6:u64,b6:readbuf,s6:bool,x6:readbuf,y6:readbuf,z6:u64,base6:u64,from6:u64,n6:u64)
  branch s6 split(o6,b6,x6,y6,from6,n6,z6) contiguous(i6,o6,e6,base6,from6,n6,z6)
'''+d[b:]).encode()
