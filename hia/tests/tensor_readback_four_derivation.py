"""Bind the wider-body reader to the exact published full-count reader."""
import hashlib

from hia.tests.tensor_header_spans_derivation import transmit
from hia.tests.tensor_readback_spans_derivation import SOURCE as PRIOR, WORK
from hia.tests.tensor_readback_three_derivation import parts, replace

SOURCE=PRIOR.with_name("cell_tensor_reader_readback_four.hepta")
PIN="c031617e6f87448934785aefbc5dde2b697b85e6cb1bb213d6f98fbd07e1d1d0"
CAP=1<<20
LOGICAL=4*CAP
BODY=3*CAP


def derive():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published full-count reader drifted")
    fs=parts(raw)
    f0=replace(fs["f0"],"call(i,o,w,i,i,s)","call(i,o,w,i,i,s,i,i)")
    f1=fs["f1"]
    signature="b:readbuf,o:mutbuf"
    if f1.count(signature)!=2:
        raise ValueError("Published ABI parameter shape drifted")
    f1=f1.replace(signature,"b:readbuf,x:readbuf,y:readbuf,o:mutbuf")
    f1=replace(f1,"call(i,o,w,j,b,s)","call(i,o,w,j,b,s,x,y)")
    for fn,terminal in (("sm_frame","envelope"),("sm_extent","header_length"),
                        ("sm_layout","hash_fail"),("sm_hash","finish")):
        fs[fn]=transmit(fs[fn],fn,fn,("ex","ey"),("readbuf","readbuf"),terminal)
    f=fs["sm_frame"]
    for wanted,new in (
      ('  twoM:u64 = const() {"value":2097152}','  fourM:u64 = const() {"value":4194304}'),
      ('select(s_entry,oneM,twoM)','select(s_entry,oneM,fourM)'),
      ('  aggregate:u64 = int.add.wrap(n,sum_ab)',
       '  ex0:usize = buffer.len(ex_entry)\n'
       '  ey0:usize = buffer.len(ey_entry)\n'
       '  exn:u64 = int.cast(ex0) {"mode":"wrap"}\n'
       '  eyn:u64 = int.cast(ey0) {"mode":"wrap"}\n'
       '  ex_ok:bool = compare.le(exn,oneM)\n'
       '  ey_ok:bool = compare.le(eyn,oneM)\n'
       '  tail_ok:bool = bool.and(ex_ok,ey_ok)\n'
       '  ext:u64 = int.add.wrap(exn,eyn)\n'
       '  across:u64 = int.add.wrap(sum_ab,ext)\n'
       '  aggregate:u64 = int.add.wrap(n,across)'),
      ('compare.le(aggregate,twoM)','compare.le(aggregate,fourM)'),
      ('  all_spans:bool = bool.and(two_spans,extent_ok)',
       '  each:bool = bool.and(two_spans,tail_ok)\n'
       '  all_spans:bool = bool.and(each,extent_ok)'),
      ('  other_two:u64 = int.add.wrap(ln_j,ln_b)',
       '  lx0:usize = buffer.len(ex_length)\n'
       '  ly0:usize = buffer.len(ey_length)\n'
       '  lx_count:u64 = int.cast(lx0) {"mode":"wrap"}\n'
       '  ly_count:u64 = int.cast(ly0) {"mode":"wrap"}\n'
       '  more_len:u64 = int.add.wrap(lx_count,ly_count)\n'
       '  core_len:u64 = int.add.wrap(ln_j,ln_b)\n'
       '  other_two:u64 = int.add.wrap(core_len,more_len)'),
      ('call(adv_i,adv_o,adv_w,adv_e,adv_l,adv_j,adv_b,adv_s)',
       'call(adv_i,adv_o,adv_w,adv_e,adv_l,adv_j,adv_b,adv_s,ex_advance,ey_advance)'),
    ):
        f=replace(f,wanted,new)
    fs["sm_frame"]=f
    x=fs["sm_extent"]
    for wanted,new in (
      ('  branch entry_okay parse(', '  entry_one_m:u64 = const() {"value":1048576}\n'
        '  entry_first_fit:bool = compare.le(entry_first_end,entry_one_m)\n'
        '  entry_profile:bool = bool.and(entry_okay,entry_first_fit)\n'
        '  branch entry_profile parse('),
      ('  position_shape:bool = bool.or(position_whole,position_split_fit)',
       '  position_match:bool = bool.or(position_whole,position_split_fit)\n'
       '  position_prefix:u64 = const() {"value":8}\n'
       '  position_used:u64 = int.add.wrap(position_prefix,position_hlen)\n'
       '  position_body:u64 = int.sub.wrap(position_l,position_used)\n'
       '  position_bodymax:u64 = const() {"value":3145728}\n'
       '  position_bodyfit:bool = compare.le(position_body,position_bodymax)\n'
       '  position_shape:bool = bool.and(position_match,position_bodyfit)'),
      ('call(layout_i,layout_o,layout_w,layout_e,layout_l,layout_hlen,layout_j,layout_b,layout_s)',
       'call(layout_i,layout_o,layout_w,layout_e,layout_l,layout_hlen,layout_j,layout_b,layout_s,ex_layout,ey_layout)'),
    ):
        x=replace(x,wanted,new)
    fs["sm_extent"]=x
    fs["sm_layout"]=replace(fs["sm_layout"],
      'call(compute_i,compute_w,compute_e,compute_l,j_compute,b_compute,s_compute)',
      'call(compute_i,compute_w,compute_e,compute_l,j_compute,b_compute,s_compute,ex_compute,ey_compute)')
    h=fs["sm_hash"]
    for block,expr in (
        ("first", "first_i,first_e,first_n,first_w"),
        ("header", "header_j,header_zero,header_n,header_w"),
        ("body", "body_b,body_zero,body_n,body_w"),
    ):
        h=replace(h,'call('+expr+') {"function":"tr_sha_update"}',
                  'call('+expr+', '+block+'_limit) {"function":"tr_sha_update_limit"}')
        h=replace(h,'  '+block+'_'+('r' if block=="first" else 'rc')+':u64 = call(',
                  '  '+block+'_limit:u64 = const() {"value":4194304}\n  '+block+'_'+('r' if block=="first" else 'rc')+':u64 = call(')
    h=replace(h,'  branch body_okay finish(body_i,body_w) bad()',
        '  branch body_okay extra_one(body_i,body_w,ex_body,ey_body) bad()\n'
        'block extra_one(xi:readbuf,xw:mutbuf,xb:readbuf,xc:readbuf)\n'
        '  xn0:usize = buffer.len(xb)\n'
        '  xn:u64 = int.cast(xn0) {"mode":"wrap"}\n'
        '  xz:u64 = const() {"value":0}\n'
        '  xcap:u64 = const() {"value":4194304}\n'
        '  xr:u64 = call(xb,xz,xn,xw,xcap) {"function":"tr_sha_update_limit"}\n'
        '  xok:bool = compare.eq(xr,xz)\n'
        '  branch xok extra_two(xi,xw,xc) bad()\n'
        'block extra_two(yi:readbuf,yw:mutbuf,yb:readbuf)\n'
        '  yn0:usize = buffer.len(yb)\n'
        '  yn:u64 = int.cast(yn0) {"mode":"wrap"}\n'
        '  yz:u64 = const() {"value":0}\n'
        '  ycap:u64 = const() {"value":4194304}\n'
        '  yr:u64 = call(yb,yz,yn,yw,ycap) {"function":"tr_sha_update_limit"}\n'
        '  yok:bool = compare.eq(yr,yz)\n'
        '  branch yok finish(yi,yw) bad()')
    h=replace(h,'  finish_rc:u64 = call(finish_w) {"function":"tr_sha_final"}',
        '  finish_limit:u64 = const() {"value":4194304}\n'
        '  finish_rc:u64 = call(finish_w,finish_limit) {"function":"tr_sha_final_limit"}')
    fs["sm_hash"]=h
    fs["f0"],fs["f1"]=f0,f1
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_cell_tensor_reader_four_v1\n"+"".join(fs.values())).encode()
