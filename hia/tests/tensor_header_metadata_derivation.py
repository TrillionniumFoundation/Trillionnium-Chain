"""Bind the expanded metadata visitor to the exact published wide parser."""
import hashlib
from pathlib import Path

WIDE = Path(__file__).resolve().parents[1]/"src/data_availability/cell_tensor_header_json_wide.hepta"
SOURCE = WIDE.with_name("cell_tensor_header_metadata.hepta")
PIN = "c04a95b2cf93262414277c6108b0e516d676271136d44ba9c39e689abaa02e45"
WORK = 446976
MAX_KEYS = 1024


def derive():
    raw = WIDE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError("Published wide TensorHeader source drifted")
    raw = raw.decode()
    raw = raw.replace("trnm_cell_tensor_header_json_wide_v1", "trnm_cell_tensor_header_metadata_v1", 1)
    old = 'f0_size_need:u64 = const() {"value":160256}'
    if raw.count(old) != 1:
        raise ValueError("Published scratch guard changed")
    raw = raw.replace(old, 'f0_size_need:u64 = const() {"value":'+str(WORK)+'}')
    start = raw.index("\nblock key(", raw.index("fn hj_metadata("))
    end = raw.index("\nblock value(", start)
    replacement = '''
block key(key_i:readbuf,key_n:u64,key_p:u64,key_w:mutbuf)
  key_l16:u64 = const() {"value":16}
  key_l24:u64 = const() {"value":24}
  key_l255:u64 = const() {"value":255}
  key_max:u64 = const() {"value":1024}
  key_len:u64 = call(key_w,key_l16) {"function":"cp_get"}
  key_count:u64 = call(key_w,key_l24) {"function":"cp_get"}
  key_fits:bool = compare.le(key_len,key_l255)
  key_room:bool = compare.lt(key_count,key_max)
  key_valid:bool = bool.and(key_fits,key_room)
  branch key_valid unique(key_i,key_n,key_p,key_w,key_len,key_count) bad()
block unique(unique_i:readbuf,unique_n:u64,unique_p:u64,unique_w:mutbuf,unique_len:u64,unique_count:u64)
  unique_seen:bool = call(unique_w,unique_len,unique_count) {"function":"hm_seen"}
  branch unique_seen bad() remember(unique_i,unique_n,unique_p,unique_w,unique_len,unique_count)
block remember(remember_i:readbuf,remember_n:u64,remember_p:u64,remember_w:mutbuf,remember_len:u64,remember_count:u64)
  remember_k:u64 = call(remember_w,remember_len,remember_count) {"function":"hm_insert"}
  remember_c24:u64 = const() {"value":24}
  remember_t:u64 = call(remember_w,remember_c24,remember_k) {"function":"cp_put"}
  remember_colon:u64 = const() {"value":58}
  remember_q:u64 = call(remember_i,remember_n,remember_p,remember_colon) {"function":"hj_take"}
  remember_badval:u64 = const() {"value":18446744073709551615}
  remember_ok:bool = compare.ne(remember_q,remember_badval)
  branch remember_ok value(remember_i,remember_n,remember_q,remember_w) bad()'''
    stop = raw.index("\nend\n", end)
    unused = '\nblock outside()\n  outside_r:u64 = const() {"value":18446744073709551614}\n  ret(outside_r)'
    tail = raw[end:stop]
    if tail.count(unused) != 1:
        raise ValueError("Published metadata cap exit changed")
    return (raw[:start]+replacement+tail.replace(unused, "")+raw[stop:]).encode()
