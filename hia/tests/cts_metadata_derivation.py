"""Exact mechanical nonzero-span derivations for the offline CTS1 diagnostic."""
import hashlib
from pathlib import Path
import re

DATA = Path(__file__).resolve().parents[1]/"src/data_availability"
PINS = {
    "cell_version_commitment.hepta":"b95c5161f3687fdb989fcbaae8754406d8e1567101622e9e1cec2695cd5cf4bc",
    "cell_complete_version.hepta":"5b723faa5ad09f288981bbb5330ec7a27d65f2221b3306d321ba359245f498d6",
    "cell_tensor_model_manifest.hepta":"724c42e6377d28bf633f22849d3a3ccf8667f983a891919d6618359e0bb13432",
}
BEGIN = "fn cs_tcv_span("


def checked(name, data):
    if hashlib.sha256(data).hexdigest()!=PINS[name]:
        raise ValueError(f"published CTS1 dependency differs: {name}")
    return data.decode("ascii")


def only(raw, fn):
    start=raw.index(f"fn {fn}(")
    limit=raw.index("\nend\n",start)
    return raw[start:limit+len("\nend\n")]


def change(raw, before, after):
    if raw.count(before)!=1:
        raise ValueError(f"ambiguous original instruction: {before}")
    return raw.replace(before,after,1)


def thread_base(raw, extra_entry=()):
    """Thread one proven origin only through original read-loan CFG edges."""
    blocks={}
    for m in re.finditer(r"(?m)^block (\w+)\((b\d+)_i:readbuf",raw):
        blocks[m[1]]=m[2]
    rows=[]
    current=None
    for line in raw.splitlines():
        if line.startswith("block "):
            name=line.split("(",1)[0][6:]
            current=blocks.get(name)
            if current:
                tail=[f"{current}_base:u64"]
                if name=="entry": tail+=list(extra_entry)
                line=line[:-1]+","+','.join(tail)+")"
        elif line.startswith(("  branch ","  jump ")):
            for name in blocks:
                pattern=rf"\b{name}\(([^()]*)\)"
                if re.search(pattern,line):
                    if current is None:
                        raise ValueError("missing original read loan")
                    line=re.sub(pattern,lambda m:f"{name}({m[1]},{current}_base)",line)
        rows.append(line)
    declaration=re.search(r"(?m)^block entry\(([^()]*)\)",'\n'.join(rows))[1]
    rows[0]=re.sub(r"^fn (\w+)\([^()]*\)",rf"fn \1({declaration})",rows[0],count=1)
    return "\n".join(rows)+"\n"


def derive(sources=None):
    names=tuple(PINS)
    sources=sources or {n:(DATA/n).read_bytes() for n in names}
    vc,tc,ma=[checked(n,sources[n]) for n in names]
    cv=only(vc,"tcv_validate_for_commitment").replace("fn tcv_validate_for_commitment(","fn cs_tcv_span(",1)
    cv=thread_base(cv,("b1_end:u64",))
    cv=change(cv,'''  b1_n_size:usize = buffer.len(b1_i)
  b1_n:u64 = int.cast(b1_n_size) {"mode":"wrap"}''','''  b1_len:u64 = int.sub.wrap(b1_end,b1_base)
  b1_n:u64 = int.add.wrap(b1_base,b1_len)''')
    cv=change(cv,"compare.le(b1_n,b1_cmax)","compare.le(b1_len,b1_cmax)")
    cv=change(cv,"compare.le(b2_c4,b2_n)",
              "compare.le(b2_first4,b2_n)")
    cv=change(cv,"  b2_okay:bool",'''  b2_first4:u64 = int.add.wrap(b2_base,b2_c4)
  b2_okay:bool''')
    cv=change(cv,"call(b3_i,b3_z,b3_c4)","call(b3_i,b3_base,b3_c4)")
    cv=change(cv,"  b5_mp:u64",'''  b5_origin:u64 = int.add.wrap(b5_base,b5_c4)
  b5_mp:u64''')
    cv=change(cv,"call(b5_i,b5_c4,b5_n)","call(b5_i,b5_origin,b5_n)")
    cv=change(cv,'call(b16_i,b16_w,b16_ep,b16_el,b16_ef) {"function":"tc_declared"}',
                 'call(b16_i,b16_w,b16_ep,b16_el,b16_ef,b16_base) {"function":"cs_tc_declared"}')
    cv=change(cv,"  b17_mp:u64",'''  b17_mctx:u64 = int.add.wrap(b17_base,b17_c68)
  b17_mp:u64''')
    cv=change(cv,"call(b17_i,b17_c68)","call(b17_i,b17_mctx)")
    cv=change(cv,'call(b20_i,b20_w,b20_cp,b20_ec,b20_mf,b20_ef,b20_which) {"function":"tc_links"}',
                 'call(b20_i,b20_w,b20_cp,b20_ec,b20_mf,b20_ef,b20_which,b20_base) {"function":"cs_tc_links"}')
    cv=change(cv,"validated(b21_cnt)","validated(b21_mf)")

    declared=thread_base(only(tc,"tc_declared").replace("fn tc_declared(","fn cs_tc_declared(",1))
    declared=change(declared,"  b2_ml:u64",'''  b2_ctx:u64 = int.add.wrap(b2_base,b2_c68)
  b2_ml:u64''')
    declared=change(declared,"call(b2_i,b2_c68,b2_c1)","call(b2_i,b2_ctx,b2_c1)")
    declared=change(declared,"int.add.wrap(b2_c68,b2_c1)","int.add.wrap(b2_ctx,b2_c1)")
    links=thread_base(only(tc,"tc_links").replace("fn tc_links(","fn cs_tc_links(",1))
    links=change(links,"  b2_m:u32",'''  b2_ctx:u64 = int.add.wrap(b2_base,b2_mctx)
  b2_m:u32''')
    links=change(links,"call(b2_i,b2_w,b2_cp,b2_mctx,b2_mf,b2_start,b2_stride)",
                       "call(b2_i,b2_w,b2_cp,b2_ctx,b2_mf,b2_start,b2_stride)")

    av=only(ma,"f0")
    front,tail=av.split("\nblock room(",1)
    _,errors=tail.split("\nblock failure(",1)
    front=change(front,"room(b12_i,b12_o,b12_w,b12_n,b12_start,b12_bytes)","tma_ok()")
    front=re.sub(r"\bb\d+_o(?::mutbuf)?,","",front)
    if re.search(r"\bb\d+_o\b",front):
        raise ValueError("TMA partial output remains")
    av=front+'''
block tma_ok()
  accepted:u32 = const() {"value":0}
  ret(accepted)
block failure('''+errors
    av=thread_base(av.replace("fn f0(","fn cs_tma_span(",1),("b1_end:u64",))
    av=change(av,'''  b1_extent:usize = buffer.len(b1_i)
  b1_n:u64 = int.cast(b1_extent) {"mode":"wrap"}''','''  b1_len:u64 = int.sub.wrap(b1_end,b1_base)
  b1_n:u64 = int.add.wrap(b1_base,b1_len)''')
    av=change(av,"compare.le(b1_c12,b1_n)","compare.le(b1_c12,b1_len)")
    av=change(av,"compare.le(b1_n,b1_c2097717)","compare.le(b1_len,b1_c2097717)")
    av=change(av,"call(b2_i,b2_c0,b2_c4)","call(b2_i,b2_base,b2_c4)")
    av=change(av,"  b3_ln:u64",'''  b3_field:u64 = int.add.wrap(b3_base,b3_c4)
  b3_ln:u64''')
    av=change(av,"call(b3_i,b3_c4,b3_c4)","call(b3_i,b3_field,b3_c4)")
    av=change(av,"  b3_after:u64 = int.add.wrap(b3_ln,b3_c8)",'''  b3_start:u64 = int.add.wrap(b3_base,b3_c8)
  b3_after:u64 = int.add.wrap(b3_ln,b3_start)''')
    av=change(av,"  b4_s:u32,b4_files:u64",'''  b4_inside:u64 = int.add.wrap(b4_base,b4_c8)
  b4_s:u32,b4_files:u64''')
    av=change(av,"call(b4_i,b4_w,b4_ln,b4_c8)","call(b4_i,b4_w,b4_ln,b4_inside)")
    av=change(av,"  b10_s:u64",'''  b10_inside:u64 = int.add.wrap(b10_base,b10_c8)
  b10_s:u64''')
    av=change(av,"call(b10_i,b10_c8,b10_ln,b10_w)","call(b10_i,b10_inside,b10_ln,b10_w)")
    # No branch reaches the old standalone output capacity control.
    av=re.sub(r'(?ms)^block capacity\(\)\n.*?(?=^block internal\(\))','',av,count=1)
    return "\n".join((cv,declared,links,av))
