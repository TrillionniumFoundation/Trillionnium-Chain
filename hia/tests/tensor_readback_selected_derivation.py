"""Mechanically chain the published exact immutable reader to a private byte projection."""
import hashlib
from pathlib import Path

from hia.tests.tensor_readback_layout_derivation import SOURCE as PRIOR
from hia.tests.tensor_readback_three_derivation import replace

SOURCE=PRIOR.with_name("cell_tensor_reader_readback_selected.hepta")
PIN="738fac64422f57046b7de49778ccf62d0a8b0fe32b343bd500b4ac5d4957d5f4"
TAIL=Path(__file__).with_name("tensor_readback_selected_tail.txt")
ENTRY=Path(__file__).with_name("tensor_readback_selected_entry.txt")


def derive():
    raw=PRIOR.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published immutable layout source changed")
    d=replace(raw.decode(),"trnm_cell_tensor_reader_layout_v1","trnm_cell_tensor_reader_selected_v1")
    end=d.index("fn sm_frame(")
    d=ENTRY.read_text()+d[end:]
    d=replace(d,"fn sm_frame(i:readbuf,o:mutbuf,w:mutbuf,j_entry:readbuf,b_entry:readbuf,s_entry:bool,ex_entry:readbuf,ey_entry:readbuf)",
              "fn sm_frame(i:readbuf,o:mutbuf,w:mutbuf,j_entry:readbuf,b_entry:readbuf,s_entry:bool,ex_entry:readbuf,ey_entry:readbuf,n:u64)")
    d=d[:len(ENTRY.read_text())]+replace(d[len(ENTRY.read_text()):],'  n0:usize = buffer.len(i)\n  n:u64 = int.cast(n0) {"mode":"wrap"}\n','')
    d=replace(d,"block entry(i:readbuf,o:mutbuf,w:mutbuf,j_entry:readbuf,b_entry:readbuf,s_entry:bool,ex_entry:readbuf,ey_entry:readbuf)",
              "block entry(i:readbuf,o:mutbuf,w:mutbuf,j_entry:readbuf,b_entry:readbuf,s_entry:bool,ex_entry:readbuf,ey_entry:readbuf,n:u64)")
    d=replace(d,'  need:u64 = const() {"value":840192}', '  need:u64 = const() {"value":840456}')
    d=replace(d,"room(compute_i,compute_o,compute_w,compute_l,compute_count,compute_idx)",
              "room(compute_i,compute_o,compute_w,compute_e,compute_l,compute_count,compute_idx,b_compute,s_compute,ex_compute,ey_compute)")
    lo=d.index("block room(")
    hi=d.index("block outside()",lo)
    d=d[:lo]+"""block room(ri:readbuf,ro:mutbuf,rw:mutbuf,re:u64,rl:u64,rc:u64,rx:u64,rb:readbuf,rs:bool,ex:readbuf,ey:readbuf)
  r:u32 = call(ri,ro,rw,re,rl,rc,rx,rb,rs,ex,ey) {"function":"lt_observe"}
  ret(r)
"""+d[hi:]
    d=replace(d,'block capacity()\n  capacity_s:u32 = const() {"value":102}\n  ret(capacity_s)\n','')
    # Superseded publishing helper cannot become a second endpoint in this module.
    d=d[:d.index("fn lt_ranges(")]
    return d.encode()+TAIL.read_bytes()
