"""Compose the exact immutable readback order with a physically separate full header."""
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
ONE = ROOT / "hia/src/data_availability/cell_tensor_reader_readback.hepta"
HEADER = ONE.with_name("cell_tensor_header_json_wide.hepta")
SOURCE = ONE.with_name("cell_tensor_reader_readback_three.hepta")
PIN_ONE = "dd73d8795fc857608f6cc1ec3f3183c59982b8158279e3c17e0798ab19626fc8"
PIN_HEADER = "c04a95b2cf93262414277c6108b0e516d676271136d44ba9c39e689abaa02e45"


def replace(s,a,b):
    if s.count(a)!=1:
        raise ValueError("Published assembly anchor moved: "+a)
    return s.replace(a,b)


def parts(raw):
    _,*parts=re.split(r"(?=^fn )",raw.decode(),flags=re.M)
    return {p.split("(",1)[0].removeprefix("fn "):p for p in parts}


def transmit(src,name,new,extra,types,keep):
    """Carry additional read loans to old branches without changing their decisions."""
    before,rest=src.split("\nblock "+keep+"(",1)
    names=re.findall(r"^block ([a-z][a-z0-9_]*)\(",before,re.M)
    if not names or names[0]!="entry":
        raise ValueError("Unexpected source boundaries")
    suffix=lambda block:[a+"_"+block for a in extra]
    typed=lambda block:",".join(k+":"+t for k,t in zip(suffix(block),types,strict=True))
    before=replace(before,"fn "+name+"(","fn "+new+"(")
    before,n=re.subn(r"\(([^\n()]+)\) -> \((u32|bool)\)",
                  lambda m:"("+m[1]+","+typed("entry")+") -> ("+m[2]+")",before,count=1)
    if n!=1: raise ValueError("No expected source signature")
    out=[]; local=None
    for line in before.splitlines():
        if line.startswith("block "):
            local=line.split("(",1)[0][6:]
            if local not in names or not line.endswith(")"):
                raise ValueError("Unknown source block")
            line=line[:-1]+","+typed(local)+")"
        if line.startswith(("  branch ","  jump ")):
            line=re.sub(r"\b("+"|".join(names)+r")\(([^()]*)\)",
                lambda m:m[1]+"("+m[2]+","+ ",".join(suffix(local))+")",line)
        out.append(line)
    return "\n".join(out)+"\nblock "+keep+"("+rest


def derive():
    old,header=ONE.read_bytes(),HEADER.read_bytes()
    if (hashlib.sha256(old).hexdigest(),hashlib.sha256(header).hexdigest())!=(PIN_ONE,PIN_HEADER):
        raise ValueError("Published one-loan framing or full-header operand changed")
    p=parts(old)
    frame=p["f0"]
    a=frame.index("block extent(")
    b=frame.index("block envelope()",a)
    frame=frame[:a]+"block envelope()"+frame[b+len("block envelope()"):]
    for obsolete in ("header_length", "bad_prefix", "bad_padding"):
        frame,n = re.subn(r"(?m)^block "+obsolete+r"\(\)\n[^\n]+\n[^\n]+\n","",frame)
        if n != 1:
            raise ValueError("Released framing refusal block changed")
    frame=transmit(frame,"f0","sm_frame",("j","b","s"),("readbuf","readbuf","bool"),"envelope")
    frame=replace(frame,'  cap:u64 = const() {"value":1048576}',
        '  oneM:u64 = const() {"value":1048576}\n'
        '  twoM:u64 = const() {"value":2097152}\n'
        '  cap:u64 = select(s_entry,oneM,twoM)\n'
        '  jj0:usize = buffer.len(j_entry)\n'
        '  bb0:usize = buffer.len(b_entry)\n'
        '  jj:u64 = int.cast(jj0) {"mode":"wrap"}\n'
        '  bb:u64 = int.cast(bb0) {"mode":"wrap"}\n'
        '  ja:bool = compare.le(jj,oneM)\n'
        '  ba:bool = compare.le(bb,oneM)\n'
        '  sum_ab:u64 = int.add.wrap(jj,bb)\n'
        '  aggregate:u64 = int.add.wrap(n,sum_ab)\n'
        '  extent_ok:bool = compare.le(aggregate,twoM)\n'
        '  two_spans:bool = bool.and(ja,ba)\n'
        '  all_spans:bool = bool.and(two_spans,extent_ok)\n'
        '  contiguous:bool = bool.not(s_entry)\n'
        '  shape:bool = bool.or(all_spans,contiguous)')
    frame=replace(frame,'  good:bool = bool.and(lo,hi)',
        '  extent_guard:bool = bool.and(lo,hi)\n'
        '  good:bool = bool.and(extent_guard,shape)')
    frame=replace(frame,'  actual:u64 = int.sub.wrap(ln,le)',
        '  first_part:u64 = int.sub.wrap(ln,le)\n'
        '  ln_j0:usize = buffer.len(j_length)\n'
        '  ln_b0:usize = buffer.len(b_length)\n'
        '  ln_j:u64 = int.cast(ln_j0) {"mode":"wrap"}\n'
        '  ln_b:u64 = int.cast(ln_b0) {"mode":"wrap"}\n'
        '  other_two:u64 = int.add.wrap(ln_j,ln_b)\n'
        '  length_zero:u64 = const() {"value":0}\n'
        '  addition:u64 = select(s_length,other_two,length_zero)\n'
        '  actual:u64 = int.add.wrap(first_part,addition)')
    frame=replace(frame,'  branch equal_size extent(li,lo_,lw,le,actual) actual_length()',
        '  branch equal_size advance(lo_,li,lw,le,actual,j_length,b_length,s_length) actual_length()\n'
        'block advance(adv_o:mutbuf,adv_i:readbuf,adv_w:mutbuf,adv_e:u64,adv_l:u64,adv_j:readbuf,adv_b:readbuf,adv_s:bool)\n'
        '  adv_code:u32 = call(adv_i,adv_o,adv_w,adv_e,adv_l,adv_j,adv_b,adv_s) {"function":"sm_extent"}\n'
        '  ret(adv_code)')
    l=transmit(p["sl_layout"],"sl_layout","sm_layout",("j","b","s"),("readbuf","readbuf","bool"),"hash_fail")
    l=replace(l,'{"value":131072}','{"value":1048576}')
    l=replace(l,'  begin_body:u64 = int.add.wrap(begin_e,begin_eight)\n',
        '  begin_offset:u64 = int.add.wrap(begin_e,begin_eight)\n'
        '  begin_body:u64 = select(s_begin,begin_z,begin_offset)\n')
    l=replace(l,'call(begin_i,begin_tail,begin_start,begin_w) {"function":"hj_object"}',
        'call(j_begin,begin_tail,begin_start,begin_w) {"function":"hj_object"}')
    l=replace(l,'call(finish_json_i,finish_json_p,finish_json_t) {"function":"oj_ws"}',
        'call(j_finish_json,finish_json_p,finish_json_t) {"function":"oj_ws"}')
    l=replace(l,'  declared_data_len:u64 = int.sub.wrap(declared_total_end,declared_t)',
        '  declared_prefix:u64 = const() {"value":8}\n'
        '  declared_inner:u64 = int.sub.wrap(declared_l,declared_prefix)\n'
        '  declared_body_end:u64 = select(s_declared,declared_inner,declared_total_end)\n'
        '  declared_data_len:u64 = int.sub.wrap(declared_body_end,declared_t)')
    # Pass the validated logical end of the header span, not its full
    # physical loan size, through the roster match and second-pass dtype.
    l=replace(l,'verify(declared_i,declared_o,declared_w,declared_e,declared_l,declared_end,declared_at,declared_count,declared_data_len,declared_idx,j_declared,b_declared,s_declared)',
        'verify(declared_i,declared_o,declared_w,declared_e,declared_l,declared_end,declared_at,declared_count,declared_data_len,declared_idx,j_declared,b_declared,s_declared,declared_t)')
    l=replace(l,'j_verify:readbuf,b_verify:readbuf,s_verify:bool)',
        'j_verify:readbuf,b_verify:readbuf,s_verify:bool,header_limit:u64)')
    l=replace(l,'call(verify_i,verify_w,verify_n,verify_at,verify_count,verify_len,verify_z) {"function":"sl_match"}',
        'call(verify_i,verify_w,verify_n,verify_at,verify_count,verify_len,verify_z,j_verify,header_limit) {"function":"sm_match"}')
    l=replace(l,'call(compute_i,compute_w,compute_e,compute_l) {"function":"sl_hash"}',
        'call(compute_i,compute_w,compute_e,compute_l,j_compute,b_compute,s_compute) {"function":"sm_hash"}')
    match=transmit(p["sl_match"],"sl_match","sm_match",("j","jl"),("readbuf","u64"),"success")
    match=replace(match,'call(same_i,same_w,same_p,same_dtype,same_after,same_row) {"function":"sl_same"}',
        'call(same_i,same_w,same_p,same_dtype,same_after,same_row,j_same,jl_same) {"function":"sm_same"}')
    same=transmit(p["sl_same"],"sl_same","sm_same",("j","jl"),("readbuf","u64"),"bad")
    same=replace(same,'call(type_match_w,type_match_row,type_match_dt) {"function":"sl_dtype"}',
        'call(type_match_w,type_match_row,type_match_dt,j_type_match,jl_type_match) {"function":"sm_dtype"}')
    return (ENTRY+frame+l+match+same).encode()


ENTRY="""hia-asm.v1 hepta.hia.program.v8 trnm_cell_tensor_reader_full_header_v1
fn f0(i:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(i:readbuf,o:mutbuf,w:mutbuf)
  s:bool = const() {"value":false}
  r:u32 = call(i,o,w,i,i,s) {"function":"sm_frame"}
  ret(r)
end
fn f1(i:readbuf,j:readbuf,b:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(i:readbuf,j:readbuf,b:readbuf,o:mutbuf,w:mutbuf)
  s:bool = const() {"value":true}
  r:u32 = call(i,o,w,j,b,s) {"function":"sm_frame"}
  ret(r)
end
"""
