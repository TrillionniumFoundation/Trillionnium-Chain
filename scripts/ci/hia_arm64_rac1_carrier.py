"""Test-private scalar carrier for unchanged RAC1. No foreign buffer ABI."""
import hashlib
import re

PIN = "b0632a1cd5acdf14f22afb2fbfefbf7c2f1a7ca9ba7faa4a679f0d75ececdbe9"
ENTRY = "rac1_test_window"
MAX_INPUT = 192
MAX_CAPACITY = 216
WORDS = MAX_INPUT // 8

# Pack unsigned little-endian words into an owned buffer; reads/writes
# stop at its actual logical extent, not the padded scalar packet length.
HELPERS = """fn rac_test_put(dst:mutbuf,base:usize,word:u64) -> (u64) effects(write,trap) entry(start)
block start(dst:mutbuf,base:usize,word:u64)
  len:usize = buffer.len(dst)
  zero:usize = const() {"value":0}
  jump loop(dst,base,word,len,zero)
block loop(d:mutbuf,p:usize,w:u64,n:usize,i:usize)
  eight:usize = const() {"value":8}
  in_word:bool = compare.lt(i,eight)
  in_buf:bool = compare.lt(p,n)
  inside:bool = bool.and(in_word,in_buf)
  branch inside write(d,p,w,n,i) done()
block write(b:mutbuf,q:usize,bits:u64,k:usize,j:usize)
  byte:u8 = int.cast(bits) {"mode":"wrap"}
  _ = buffer.store(b,q,byte)
  one:usize = const() {"value":1}
  shift:u64 = const() {"value":8}
  q1:usize = int.add.checked(q,one)
  j1:usize = int.add.checked(j,one)
  bits1:u64 = int.shr.checked(bits,shift)
  jump loop(b,q1,bits1,k,j1)
block done()
  res:u64 = const() {"value":0}
  ret(res)
end
fn rac_test_expect(src:readbuf,base:usize,word:u64) -> (bool) effects(read,trap) entry(start)
block start(src:readbuf,base:usize,word:u64)
  len:usize = buffer.len(src)
  zero:usize = const() {"value":0}
  jump loop(src,base,word,len,zero)
block loop(s:readbuf,p:usize,w:u64,n:usize,i:usize)
  eight:usize = const() {"value":8}
  in_word:bool = compare.lt(i,eight)
  in_buf:bool = compare.lt(p,n)
  inside:bool = bool.and(in_word,in_buf)
  branch inside read(s,p,w,n,i) done()
block read(s1:readbuf,q:usize,bits:u64,k:usize,j:usize)
  a:u8 = buffer.load(s1,q)
  b:u8 = int.cast(bits) {"mode":"wrap"}
  same:bool = compare.eq(a,b)
  branch same next(s1,q,bits,k,j) bad()
block next(s2:readbuf,r:usize,more:u64,m:usize,l:usize)
  one:usize = const() {"value":1}
  shift:u64 = const() {"value":8}
  r1:usize = int.add.checked(r,one)
  l1:usize = int.add.checked(l,one)
  more1:u64 = int.shr.checked(more,shift)
  jump loop(s2,r1,more1,m,l1)
block done()
  good:bool = const() {"value":true}
  ret(good)
block bad()
  falseval:bool = const() {"value":false}
  ret(falseval)
end
fn rac_test_fill(dst:mutbuf,byte:u8) -> (u64) effects(write,trap) entry(start)
block start(dst:mutbuf,byte:u8)
  n:usize = buffer.len(dst)
  z:usize = const() {"value":0}
  jump loop(dst,byte,n,z)
block loop(d:mutbuf,b:u8,len:usize,i:usize)
  inside:bool = compare.lt(i,len)
  branch inside write(d,b,len,i) done()
block write(s:mutbuf,c:u8,n2:usize,j:usize)
  _ = buffer.store(s,j,c)
  one:usize = const() {"value":1}
  j1:usize = int.add.checked(j,one)
  jump loop(s,c,n2,j1)
block done()
  z2:u64 = const() {"value":0}
  ret(z2)
end
fn rac_test_tail(s:readbuf,start:usize,want:u8) -> (bool) effects(read,trap) entry(entry)
block entry(s:readbuf,start:usize,want:u8)
  len:usize = buffer.len(s)
  start_ok:bool = compare.le(start,len)
  branch start_ok loop(s,start,len,want) bad()
block loop(s1:readbuf,i:usize,n:usize,b:u8)
  inside:bool = compare.lt(i,n)
  branch inside get(s1,i,n,b) good()
block get(s2:readbuf,j:usize,m:usize,c:u8)
  byte:u8 = buffer.load(s2,j)
  same:bool = compare.eq(byte,c)
  one:usize = const() {"value":1}
  j1:usize = int.add.checked(j,one)
  branch same loop(s2,j1,m,c) bad()
block good()
  yes:bool = const() {"value":true}
  ret(yes)
block bad()
  no:bool = const() {"value":false}
  ret(no)
end
fn rac_test_get(s:readbuf,start:usize) -> (u64) effects(read,trap) entry(entry)
block entry(s:readbuf,start:usize)
  len:usize = buffer.len(s)
  z:usize = const() {"value":0}
  out:u64 = const() {"value":0}
  jump loop(s,len,start,z,out)
block loop(x:readbuf,n:usize,p:usize,i:usize,a:u64)
  eight:usize = const() {"value":8}
  in_word:bool = compare.lt(i,eight)
  in_buf:bool = compare.lt(p,n)
  inside:bool = bool.and(in_word,in_buf)
  branch inside get(x,n,p,i,a) done(a)
block get(y:readbuf,m:usize,q:usize,j:usize,b:u64)
  octet:u8 = buffer.load(y,q)
  wide:u64 = int.cast(octet) {"mode":"wrap"}
  j64:u64 = int.cast(j) {"mode":"wrap"}
  scale:u64 = const() {"value":8}
  shift:u64 = int.mul.checked(j64,scale)
  placed:u64 = int.shl.checked(wide,shift)
  merged:u64 = bit.or(b,placed)
  one:usize = const() {"value":1}
  q1:usize = int.add.checked(q,one)
  j1:usize = int.add.checked(j,one)
  jump loop(y,m,q1,j1,merged)
block done(result:u64)
  ret(result)
end
"""


def compose(original: bytes) -> bytes:
    if hashlib.sha256(original).hexdigest() != PIN:
        raise ValueError("RAC1 source digest mismatch")
    head, body = original.split(b"\n", 1)
    if head != b"hia-asm.v1 hepta.hia.program.v8 trnm_release_rac1_header":
        raise ValueError("RAC1 header mismatch")
    params = ["ulen:u64", "ucap:u64", "selector:u64"] + [f"w{i}:u64" for i in range(WORDS)]
    formals = ",".join(params)
    names = ",".join(v.split(":")[0] for v in params)
    lines = [f"fn {ENTRY}({formals}) -> (u64) effects(read,write,alloc,trap) entry(entry)",
             f"block entry({formals})",
             f'  in_limit:u64 = const() {{"value":{MAX_INPUT}}}',
             f'  out_limit:u64 = const() {{"value":{MAX_CAPACITY}}}',
             '  selectors:u64 = const() {"value":27}',
             "  inside_len:bool = compare.le(ulen,in_limit)",
             "  inside_cap:bool = compare.le(ucap,out_limit)",
             "  inside_sel:bool = compare.le(selector,selectors)",
             "  extents:bool = bool.and(inside_len,inside_cap)",
             "  guards:bool = bool.and(extents,inside_sel)",
             f"  branch guards work({names}) oob()",
             "block oob()",
             '  bad:u64 = const() {"value":18446744073709551615}',
             "  ret(bad)",
             f"block work({formals})",
             '  input_len:usize = int.cast(ulen) {"mode":"wrap"}',
             '  output_len:usize = int.cast(ucap) {"mode":"wrap"}',
             '  scr_len:usize = const() {"value":11}',
             '  inp:buffer = buffer.new(input_len)',
             '  out:buffer = buffer.new(output_len)',
             '  scr:buffer = buffer.new(scr_len)',
             '  input_w:mutbuf = borrow.mut(inp)',
             '  output_w:mutbuf = borrow.mut(out)',
             '  scratch_w:mutbuf = borrow.mut(scr)',
             '  output_pattern:u8 = const() {"value":205}',
             '  scratch_pattern:u8 = const() {"value":146}',
             '  filled_o:u64 = call(output_w,output_pattern) {"function":"rac_test_fill"}',
             '  filled_s:u64 = call(scratch_w,scratch_pattern) {"function":"rac_test_fill"}']
    for i in range(WORDS):
        lines.extend((f'  at{i}:usize = const() {{"value":{8*i}}}',
                      f'  put{i}:u64 = call(input_w,at{i},w{i}) {{"function":"rac_test_put"}}'))
    lines.extend(('  _ = loan.end(input_w)',
                  '  input_r:readbuf = borrow.read(inp)',
                  '  rc32:u32 = call(input_r,output_w,scratch_w) {"function":"f0"}',
                  '  _ = loan.end(output_w)', '  _ = loan.end(scratch_w)',
                  '  input_ok0:bool = const() {"value":true}'))
    for i in range(WORDS):
        lines.extend((f'  check{i}:bool = call(input_r,at{i},w{i}) {{"function":"rac_test_expect"}}',
                      f'  input_ok{i+1}:bool = bool.and(input_ok{i},check{i})'))
    lines.extend(('  _ = loan.end(input_r)', '  scr_r:readbuf = borrow.read(scr)',
                  '  out_r:readbuf = borrow.read(out)', '  z:usize = const() {"value":0}',
                  '  scr_ok:bool = call(scr_r,z,scratch_pattern) {"function":"rac_test_tail"}',
                  '  _ = loan.end(scr_r)', '  max_result:u32 = const() {"value":208}',
                  '  success:bool = compare.le(rc32,max_result)',
                  '  rc_len:usize = int.cast(rc32) {"mode":"wrap"}',
                  '  tail_at:usize = select(success,rc_len,z)',
                  '  tail_ok:bool = call(out_r,tail_at,output_pattern) {"function":"rac_test_tail"}',
                  f'  input_scr_ok:bool = bool.and(input_ok{WORDS},scr_ok)',
                  '  all_ok:bool = bool.and(input_scr_ok,tail_ok)',
                  '  zero_sel:u64 = const() {"value":0}', '  seven:u64 = const() {"value":7}',
                  '  eight:u64 = const() {"value":8}', '  is_status:bool = compare.eq(selector,zero_sel)',
                  '  window_offset0:u64 = int.mul.checked(selector,eight)',
                  '  window_offset1:u64 = int.sub.wrap(window_offset0,seven)',
                  '  one64:u64 = const() {"value":1}',
                  '  window_offset:u64 = int.sub.wrap(window_offset1,one64)',
                  '  window_idx:usize = int.cast(window_offset) {"mode":"wrap"}',
                  '  segment:u64 = call(out_r,window_idx) {"function":"rac_test_get"}',
                  '  _ = loan.end(out_r)',
                  '  _ = owner.drop(scr)', '  _ = owner.drop(out)', '  _ = owner.drop(inp)',
                  '  status64:u64 = int.cast(rc32) {"mode":"wrap"}',
                  '  chosen:u64 = select(is_status,status64,segment)',
                  '  invariant_error:u64 = const() {"value":18446744073709551614}',
                  '  result:u64 = select(all_ok,chosen,invariant_error)',
                  '  ret(result)', 'end'))
    work_pos = lines.index(f"block work({formals})")
    old_names = set(names.split(","))
    renamer = re.compile(r"\b(?:" + "|".join(sorted(old_names)) + r")\b")
    lines[work_pos:] = [renamer.sub(lambda m: "arg_" + m.group(), line) for line in lines[work_pos:]]
    prefix = ("hia-asm.v1 hepta.hia.program.v8 trnm_rac1_arm_test_only\n"
              f"exports({ENTRY})\n")
    return prefix.encode() + body + b"\n" + HELPERS.encode() + ("\n".join(lines) + "\n").encode()
