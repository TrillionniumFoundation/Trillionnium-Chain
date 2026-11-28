"""Mechanically reuse the released one-loan parser/decision blocks for a wide immutable borrow."""
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
ONE = ROOT / "hia/src/data_availability/cell_tensor_reader_readback.hepta"
WIDE = ONE.with_name("cell_tensor_reader_readback_wide.hepta")
ONE_SHA = "dd73d8795fc857608f6cc1ec3f3183c59982b8158279e3c17e0798ab19626fc8"
MAX_SPAN = 1 << 20
MAX_LOGICAL = 2 * MAX_SPAN


def replace_once(src, old, new):
    if src.count(old) != 1:
        raise ValueError("Unrecognized one-loan CFG anchor")
    return src.replace(old, new)


def transmit_two_read_inputs(src, name, first, end):
    """Thread the new immutable pointer plus mode only through selected old blocks."""
    before, tail = src.split("\nblock " + end + "(", 1)
    names = re.findall(r"^block ([a-z][a-z0-9_]*)\(", before, re.M)
    if not names or names[0] != first:
        raise ValueError("Unexpected source CFG boundary")
    before = replace_once(before, "fn " + name + "(", "fn " + {
        "f0": "sw_frame", "sl_layout": "sw_layout"}[name] + "(")
    pat = r"(\((?:[^\n()]+)?)\) -> \(u32\)"
    before,n = re.subn(pat,r"\1,extra:readbuf,split:bool) -> (u32)",before,count=1)
    if n != 1:
        raise ValueError("No exact function signature")
    result = []
    current = None
    for line in before.splitlines():
        if line.startswith("block "):
            current = line.split("(",1)[0][6:]
            if not line.endswith(")") or current not in names:
                raise ValueError("Unexpected block")
            line = line[:-1] + ",ex_"+current+":readbuf,sp_"+current+":bool)"
        elif line.startswith(("  jump ", "  branch ")):
            line = re.sub(r"\b(" + "|".join(names) + r")\(([^)]*)\)",
                          lambda m: m.group(1)+"("+m.group(2)+",ex_"+current+",sp_"+current+")",
                          line)
        result.append(line)
    result[0] = result[0].replace(",extra:readbuf,split:bool)",",ex_entry:readbuf,sp_entry:bool)")
    return "\n".join(result)+"\nblock "+end+"("+tail


def derive():
    raw = ONE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ONE_SHA:
        raise ValueError("Published immutable reader source changed")
    _,frame,layout,*_ = re.split(r"(?=^fn )",raw.decode(),flags=re.M)
    frame = transmit_two_read_inputs(frame,"f0","entry","envelope")
    frame = replace_once(frame,'  cap:u64 = const() {"value":1048576}',
        '  perloan:u64 = const() {"value":1048576}\n'
        '  logicalcap:u64 = const() {"value":2097152}\n'
        '  cap:u64 = select(sp_entry,perloan,logicalcap)\n'
        '  extra_len0:usize = buffer.len(ex_entry)\n'
        '  extra_len:u64 = int.cast(extra_len0) {"mode":"wrap"}\n'
        '  extra_ok:bool = compare.le(extra_len,perloan)\n'
        '  whole:bool = bool.not(sp_entry)\n'
        '  both_cap:bool = bool.or(whole,extra_ok)')
    frame = replace_once(frame,'  good:bool = bool.and(lo,hi)',
        '  first_fit:bool = bool.and(lo,hi)\n'
        '  good:bool = bool.and(first_fit,both_cap)')
    frame = replace_once(frame,'  actual:u64 = int.sub.wrap(ln,le)',
        '  physical:u64 = int.sub.wrap(ln,le)\n'
        '  tail_size0:usize = buffer.len(ex_length)\n'
        '  tail_size:u64 = int.cast(tail_size0) {"mode":"wrap"}\n'
        '  no_tail:u64 = const() {"value":0}\n'
        '  actual_tail:u64 = select(sp_length,tail_size,no_tail)\n'
        '  actual:u64 = int.add.wrap(physical,actual_tail)')
    frame = replace_once(frame,
        '  header:u64 = call(fi,fe,f8) {"function":"rac_read_le"}',
        '  froom0:usize = buffer.len(fi)\n'
        '  froom:u64 = int.cast(froom0) {"mode":"wrap"}\n'
        '  fprefix:u64 = int.add.wrap(fe,f8)\n'
        '  fprefix_ok:bool = compare.le(fprefix,froom)\n'
        '  branch fprefix_ok read_prefix(fi,fo,fw,fe,fl,f2,f8,fcap,fprefix,froom,ex_extent,sp_extent) divided()\n'
        'block read_prefix(fp_i:readbuf,fp_o:mutbuf,fp_w:mutbuf,fp_e:u64,fp_l:u64,fp_two:u64,fp_eight:u64,fp_cap:u64,fp_at:u64,fp_physical:u64,ex_rp:readbuf,sp_rp:bool)\n'
        '  header:u64 = call(fp_i,fp_e,fp_eight) {"function":"rac_read_le"}')
    frame = replace_once(frame,
        '  after_prefix:u64 = int.sub.wrap(fl,f8)\n'
        '  not_tiny:bool = compare.le(f2,header)\n'
        '  not_large:bool = compare.le(header,fcap)',
        '  after_prefix:u64 = int.sub.wrap(fp_l,fp_eight)\n'
        '  not_tiny:bool = compare.le(fp_two,header)\n'
        '  not_large:bool = compare.le(header,fp_cap)')
    frame = replace_once(frame,
        '  branch present_header prefix(fi,fo,fw,fe,fl,header,ex_extent,sp_extent) header_length()',
        '  actual_header_end:u64 = int.add.wrap(fp_at,header)\n'
        '  whole_header:bool = compare.le(actual_header_end,fp_physical)\n'
        '  branch present_header physical_header(fp_i,fp_o,fp_w,fp_e,fp_l,header,whole_header,ex_rp,sp_rp) header_length()\n'
        'block physical_header(ph_i:readbuf,ph_o:mutbuf,ph_w:mutbuf,ph_e:u64,ph_l:u64,ph_h:u64,ph_ok:bool,ph_tail:readbuf,ph_split:bool)\n'
        '  branch ph_ok prefix(ph_i,ph_o,ph_w,ph_e,ph_l,ph_h,ph_tail,ph_split) divided()')
    frame = replace_once(frame,
        'call(xs_i,xs_o,xs_w,xs_e,xs_l,xs_h) {"function":"sl_layout"}',
        'call(xs_i,xs_o,xs_w,xs_e,xs_l,xs_h,ex_check_layout,sp_check_layout) {"function":"sw_layout"}')
    frame = replace_once(frame, 'block envelope()',
        'block divided()\n  split_err:u32 = const() {"value":225}\n  ret(split_err)\nblock envelope()')
    layout = transmit_two_read_inputs(layout,"sl_layout","entry","hash_fail")
    layout = replace_once(layout,
        'call(compute_i,compute_w,compute_e,compute_l) {"function":"sl_hash"}',
        'call(compute_i,compute_w,compute_e,compute_l,ex_compute,sp_compute) {"function":"sw_hash"}')
    return (ENTRY+frame+layout+HASH).encode()


# f0 is the standard Selfhost loan shape. Only a read-only pointer is passed
# redundantly to the same function and its inactive alias is never read as data.
ENTRY = '''hia-asm.v1 hepta.hia.program.v8 trnm_cell_tensor_reader_readback_wide_v1
fn f0(i:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(i:readbuf,o:mutbuf,w:mutbuf)
  split:bool = const() {"value":false}
  code:u32 = call(i,o,w,i,split) {"function":"sw_frame"}
  ret(code)
end
fn f1(h:readbuf,p:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(h:readbuf,p:readbuf,o:mutbuf,w:mutbuf)
  split:bool = const() {"value":true}
  code:u32 = call(h,o,w,p,split) {"function":"sw_frame"}
  ret(code)
end
'''

HASH = '''fn sw_hash(i:readbuf,w:mutbuf,e:u64,l:u64,t:readbuf,s:bool) -> (u64) effects(read,write,trap) entry(entry)
block entry(i:readbuf,w:mutbuf,e:u64,l:u64,t:readbuf,s:bool)
  init:u64 = call(w) {"function":"tr_sha_init"}
  z:u64 = const() {"value":0}
  good:bool = compare.eq(init,z)
  branch good first(i,w,e,l,t,s) internal()
block first(ai:readbuf,aw:mutbuf,ae:u64,al:u64,at:readbuf,as_:bool)
  actual0:usize = buffer.len(ai)
  actual:u64 = int.cast(actual0) {"mode":"wrap"}
  first_n:u64 = int.sub.wrap(actual,ae)
  length:u64 = select(as_,first_n,al)
  wrote:u64 = call(ai,ae,length,aw) {"function":"tr_sha_update"}
  zero:u64 = const() {"value":0}
  okay:bool = compare.eq(wrote,zero)
  branch okay maybe_tail(ai,aw,at,as_) internal()
block maybe_tail(bi:readbuf,bw:mutbuf,bt:readbuf,bs:bool)
  branch bs tail(bi,bw,bt) finish(bi,bw)
block tail(ci:readbuf,cw:mutbuf,ct:readbuf)
  raw:usize = buffer.len(ct)
  tlen:u64 = int.cast(raw) {"mode":"wrap"}
  c0:u64 = const() {"value":0}
  cstat:u64 = call(ct,c0,tlen,cw) {"function":"tr_sha_update"}
  cok:bool = compare.eq(cstat,c0)
  branch cok finish(ci,cw) internal()
block finish(di:readbuf,dw:mutbuf)
  ds:u64 = call(dw) {"function":"tr_sha_final"}
  dz:u64 = const() {"value":0}
  dok:bool = compare.eq(ds,dz)
  branch dok compare(di,dw) internal()
block compare(gi:readbuf,gw:mutbuf)
  gpos:u64 = const() {"value":291072}
  gdst:u64 = const() {"value":1168}
  gn:u64 = const() {"value":32}
  ptr:u64 = call(gw,gpos) {"function":"cp_get"}
  equal:u64 = call(gi,ptr,gw,gdst,gn) {"function":"ca_equal"}
  ret(equal)
block internal()
  err:u64 = const() {"value":2}
  ret(err)
end
'''
