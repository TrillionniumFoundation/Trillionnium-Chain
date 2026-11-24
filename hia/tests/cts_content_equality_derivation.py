"""Source-pinned relocation and reorder for the offline supplied-digest envelope."""
import hashlib
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]/"src/data_availability/cell_release_snapshot_metadata.hepta"
PIN = "d1e056ef7213db3fa8fc54d2278b2f4c8b308d751c604b3adab042c82604a5e4"
BEGIN = "block init("


def replace_once(src, before, after):
    if src.count(before)!=1:
        raise ValueError(f"unexpected original boundary: {before}")
    return src.replace(before,after,1)


def derive(verified: bytes) -> str:
    if hashlib.sha256(verified).hexdigest()!=PIN:
        raise ValueError("published CTS1 post-pin source changed")
    raw=verified.decode("ascii")
    f0=raw[raw.index("fn f0("):raw.index("\nend\n")]
    start=f0.index("block magic(")
    finish=f0.index("block publish(")
    validation, digest=f0[start:finish].split("block init(",1)
    digest="block init("+digest
    digest=replace_once(digest,'  uz:u64 = const() {"value":0}\n',
                         '''  uz:u64 = const() {"value":0}
  ubase:u64 = const() {"value":64}
  ul:u64 = int.sub.wrap(un,ubase)
''')
    digest=replace_once(digest,"call(ui,uz,un,uw)","call(ui,ubase,ul,uw)")
    digest=replace_once(digest,"publish(zi,zo,zw,ze)","digest_match(zi,zo,zw,ze)")
    equality='''block digest_match(pke_ei:readbuf,pke_eo:mutbuf,pke_ew:mutbuf,pke_en:u64)
  pke_a0:u64 = const() {"value":0}
  pke_a32:u64 = const() {"value":32}
  pke_a1:u64 = const() {"value":1}
  pke_h0:u64 = const() {"value":131168}
  pke_h1:u64 = const() {"value":131200}
  pke_c0:u64 = call(pke_ei,pke_a0,pke_ew,pke_h0,pke_a32) {"function":"ca_equal"}
  pke_c1:u64 = call(pke_ei,pke_a32,pke_ew,pke_h1,pke_a32) {"function":"ca_equal"}
  pke_left:bool = compare.eq(pke_c0,pke_a1)
  pke_right:bool = compare.eq(pke_c1,pke_a1)
  pke_exact:bool = bool.and(pke_left,pke_right)
  branch pke_exact magic(pke_ei,pke_eo,pke_ew,pke_en) mismatched()
block mismatched()
  pke_pin_code:u32 = const() {"value":208}
  ret(pke_pin_code)
'''
    validation=replace_once(validation,'  m0:u64 = const() {"value":0}', '  m0:u64 = const() {"value":64}')
    validation=replace_once(validation,'  m4:u64 = const() {"value":4}',
                            '''  m4:u64 = const() {"value":4}
  m68:u64 = const() {"value":68}''')
    validation=replace_once(validation,"tcv_frame(mi,mo,mw,mn,m4)","tcv_frame(mi,mo,mw,mn,m68)")
    validation=replace_once(validation,"init(oi,oo,ow,on,oe)","publish(oi,oo,ow,oe)")
    return digest+equality+validation+f0[finish:]+"\nend\n"
