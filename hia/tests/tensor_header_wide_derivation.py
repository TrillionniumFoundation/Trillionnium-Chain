"""Source-bind the wide visitor's reused bounded parser to the published JSON HIA."""
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / "hia/src/data_availability/cell_tensor_header_json.hepta"
WIDE = OLD.with_name("cell_tensor_header_json_wide.hepta")
OLD_SHA = "68dd05093634f59aac8aaf6db26fe49e54f51572a604055bed47c744b0bf27f5"
CAP = 1 << 20
WORK = 160256


def replace_once(s, a, b):
    if s.count(a) != 1:
        raise ValueError("Unrecognized published parser anchor")
    return s.replace(a, b)


def derive_core():
    raw = OLD.read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_SHA:
        raise ValueError("Published JSON visitor changed")
    _,*parts = re.split(r"(?=^fn )",raw.decode(),flags=re.M)
    f = {p.split("(",1)[0].removeprefix("fn "):p for p in parts}
    start = f["f0"]
    for a,b in (
        ('{"value":131072}', '{"value":' + str(CAP) + '}'),
        ('{"value":291072}', '{"value":' + str(WORK) + '}'),
        ('estimate(f0_suff_o,f0_suff_w)', 'estimate(f0_suff_o,f0_suff_w,f0_suff_i,f0_suff_n)'),
        ('block estimate(f0_estimate_o:mutbuf,f0_estimate_w:mutbuf)',
         'block estimate(f0_estimate_o:mutbuf,f0_estimate_w:mutbuf,f0_estimate_i:readbuf,f0_estimate_raw:u64)'),
        ('publish(f0_estimate_o,f0_estimate_w,f0_estimate_count)',
         'publish(f0_estimate_o,f0_estimate_w,f0_estimate_count,f0_estimate_i,f0_estimate_raw)'),
        ('block publish(f0_publish_o:mutbuf,f0_publish_w:mutbuf,f0_publish_count:u64)',
         'block publish(f0_publish_o:mutbuf,f0_publish_w:mutbuf,f0_publish_count:u64,f0_publish_i:readbuf,f0_publish_raw:u64)'),
        ('call(f0_publish_w,f0_publish_o,f0_publish_count,f0_publish_z,f0_publish_c8) {"function":"hj_emit"}',
         'call(f0_publish_i,f0_publish_raw,f0_publish_w,f0_publish_o,f0_publish_count,f0_publish_z,f0_publish_c8) {"function":"hj_emit"}'),
    ):
        start = replace_once(start,a,b)
    obj = replace_once(f["hj_object"],'{"function":"oj_string"}','{"function":"hv_key"}')
    meta = f["hj_metadata"]
    for prefix,name in (("pair","hv_key"),("value","hv_value")):
        old = f'call({prefix}_i,{prefix}_p,{prefix}_n,{prefix}_w,{prefix}_temp) {{"function":"oj_string"}}'
        meta = replace_once(meta,old,old.replace('"oj_string"',f'"{name}"'))
    entry = f["hj_entry"]
    for prefix,name in (("field","hv_field"),("string","hv_dtype")):
        old = f'call({prefix}_i,{prefix}_p,{prefix}_n,{prefix}_w,{prefix}_temp) {{"function":"oj_string"}}'
        entry = replace_once(entry,old,old.replace('"oj_string"',f'"{name}"'))
    entry = replace_once(entry,'save(string_i,string_n,string_q,string_w,string_row,string_flags)',
                         'save(string_i,string_n,string_q,string_w,string_row,string_flags,string_p)')
    entry = replace_once(entry,
        'block save(save_i:readbuf,save_n:u64,save_p:u64,save_w:mutbuf,save_row:u64,save_flags:u64)',
        'block save(save_i:readbuf,save_n:u64,save_p:u64,save_w:mutbuf,save_row:u64,save_flags:u64,save_raw:u64)')
    entry = replace_once(entry,'  save_ptr:u64 = call(save_w,save_len) {"function":"hj_keep"}\n','')
    entry = replace_once(entry,'call(save_w,save_at,save_ptr)','call(save_w,save_at,save_raw)')
    emit=f["hj_emit"]
    for a,b in (
        ('fn hj_emit(', 'fn hj_emit(entry_i:readbuf,entry_raw:u64,'),
        ('block entry(', 'block entry(entry_i:readbuf,entry_raw:u64,'),
        ('block loop(', 'block loop(loop_i:readbuf,loop_raw:u64,'),
        ('block row(', 'block row(row_i:readbuf,row_raw:u64,'),
        ('loop(entry_w', 'loop(entry_i,entry_raw,entry_w'),
        ('row(loop_w', 'row(loop_i,loop_raw,loop_w'),
        ('loop(row_w', 'loop(row_i,row_raw,row_w'),
        ('call(row_w,row_o,row_dtype_at,row_n13) {"function":"hj_emit_string"}',
         'call(row_i,row_raw,row_w,row_o,row_dtype_at,row_n13) {"function":"hv_emit_dtype"}'),
    ):
        emit = replace_once(emit,a,b)
    return ("hia-asm.v1 hepta.hia.program.v8 trnm_cell_tensor_header_json_wide_v1\n"
            +start+obj+meta+entry+emit).encode()
