"""Reuse the exact published grammar and bounded merge schedules for raw spans."""
import hashlib
import re

from hia.tests.tensor_header_metadata_derivation import SOURCE as METADATA
from hia.tests.tensor_readback_three_derivation import parts,replace

SOURCE = METADATA.with_name("cell_tensor_header_spans.hepta")
PIN = "943ad993247294bd73ddbe6a9b49f694aaf0e64448352bdc6abc0ebd15b47a41"
MAX_TENSORS = 16384
CAP = 1 << 20
RECORDS = 446976
SLOTS = RECORDS + 8*MAX_TENSORS
MERGE = SLOTS + 8*MAX_TENSORS
WORK = MERGE + 8*MAX_TENSORS


def transmit(src,name,new,extra,types,keep):
    """Carry additional read loans to old branches without changing their decisions."""
    before,rest=src.split("\nblock "+keep+"(",1)
    names=re.findall(r"^block ([a-z][a-z0-9_]*)\(",before,re.M)
    if not names or names[0]!="entry":
        raise ValueError("Unexpected source boundaries")
    suffix=lambda block:[a+"_"+block for a in extra]
    typed=lambda block:",".join(k+":"+t for k,t in zip(suffix(block),types,strict=True))
    before=replace(before,"fn "+name+"(","fn "+new+"(")
    before,n=re.subn(r"\(([^\n()]+)\) -> \((u32|u64|bool)\)",
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
    raw=METADATA.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("Published metadata visitor drifted")
    p=parts(raw)
    entry=p["f0"]
    for a,b in (
        ('f0_size_need:u64 = const() {"value":446976}',f'f0_size_need:u64 = const() {{"value":{WORK}}}'),
        ('  f0_estimate_cap:u64 = call(f0_estimate_w,f0_estimate_count,f0_estimate_z,f0_estimate_tc) {"function":"hj_measure"}',
         '  f0_estimate_bytes:u64 = int.mul.wrap(f0_estimate_count,f0_estimate_tc)\n'
         '  f0_estimate_cap:u64 = int.add.wrap(f0_estimate_bytes,f0_estimate_tc)'),
        ('  f0_estimate_z:u64 = const() {"value":0}\n',''),
        ('call(f0_publish_i,f0_publish_raw,f0_publish_w,f0_publish_o,f0_publish_count,f0_publish_z,f0_publish_c8) {"function":"hj_emit"}',
         'call(f0_publish_i,f0_publish_raw,f0_publish_w,f0_publish_o,f0_publish_count) {"function":"ht_publish"}'),
        ('  f0_publish_c8:u64 = const() {"value":8}\n',''),
    ):
        entry=replace(entry,a,b)
    obj=p["hj_object"]
    for a,b in (
        ('  pair_q:u64 = call(pair_i,pair_p,pair_n,pair_w,pair_temp)', '  pair_name:u64 = call(pair_i,pair_p,pair_n) {"function":"oj_ws"}\n'
         '  pair_q:u64 = call(pair_i,pair_name,pair_n,pair_w,pair_temp)'),
        ('colon(pair_i,pair_n,pair_q,pair_w) bad()', 'colon(pair_i,pair_n,pair_q,pair_w,pair_name) bad()'),
        ('colon_p:u64,colon_w:mutbuf)', 'colon_p:u64,colon_w:mutbuf,colon_name:u64)'),
        ('key(colon_i,colon_n,colon_q,colon_w) bad()', 'key(colon_i,colon_n,colon_q,colon_w,colon_name) bad()'),
        ('key_p:u64,key_w:mutbuf)', 'key_p:u64,key_w:mutbuf,key_name:u64)'),
        ('tensor(key_i,key_n,key_p,key_w,key_nl)', 'tensor(key_i,key_n,key_p,key_w,key_nl,key_name)'),
        ('tensor_w:mutbuf,tensor_nl:u64)', 'tensor_w:mutbuf,tensor_nl:u64,tensor_name:u64)'),
        ('call(tensor_i,tensor_n,tensor_p,tensor_w,tensor_nl) {"function":"hj_tensor"}',
         'call(tensor_i,tensor_n,tensor_p,tensor_w,tensor_nl,tensor_name) {"function":"ht_tensor"}'),
    ):
        obj=replace(obj,a,b)
    seen=transmit(p["hm_seen"],"hm_seen","ht_seen",("ri","rn"),("readbuf","u64"),"yes")
    seen=replace(seen,'{"function":"hm_slot"}','{"function":"ht_slot"}')
    seen=replace(seen,'call(iw,temp,in_,index) {"function":"hm_for_key"}',
                 'call(ri_inspect,rn_inspect,iw,temp,in_,index) {"function":"ht_against"}')
    merge=p["hm_merge"].replace("hm_slot","ht_slot").replace('{"value":438784}',f'{{"value":{MERGE}}}')
    # Carry the source loan across the old schedule, including branch joins.
    merge=transmit(merge,"hm_merge","ht_merge",("ri","rn"),("readbuf","u64"),"finish")
    start=merge.index("  left_pos:u64 = call(ci)")
    end=merge.index("  c1:u64 = const()",start)
    merge=merge[:start]+'  order:u64 = call(ri_compare_keys,rn_compare_keys,cw,ci,right_idx) {"function":"ht_order"}\n'+merge[end:]
    ins=p["hm_insert"]
    start=ins.index("  e8:u64")
    end=ins.index("  put_idx:u64")
    ins=ins[:start]+'''  e1:u64 = const() {"value":1}
  end_:u64 = int.add.wrap(count,e1)
  stored:u64 = call(w,pos,n) {"function":"cp_put"}
'''+ins[end:]
    ins=ins.replace("hm_record","ht_record").replace("hm_slot","ht_slot")
    ins=transmit(ins,"hm_insert","ht_insert",("ri","rn"),("readbuf","u64"),"done")
    ins=replace(ins,'call(mw,start,mb,me) {"function":"hm_merge"}',
                'call(mw,start,mb,me,ri_merge,rn_merge) {"function":"ht_merge"}')
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_cell_tensor_header_spans_v1\n"+entry+obj+seen+merge+ins).encode()
