"""Use exact published framing, grammar and name index for full immutable readback."""
import hashlib

from hia.tests.tensor_header_metadata_derivation import SOURCE as META
from hia.tests.tensor_header_spans_derivation import SOURCE as SPANS, WORK
from hia.tests.tensor_readback_metadata_derivation import SOURCE as READER
from hia.tests.tensor_readback_three_derivation import parts, replace

SOURCE=READER.with_name("cell_tensor_reader_readback_spans.hepta")
PIN=(
 "31ddf81a1917923d17643cdd34c56f53f7513f1b031344d0fc496a9983398c26",
 "e855b603237b450887904eac8e7b8cd32d7ae3d1e6fbe03098ab671e5e91a86a",
 "943ad993247294bd73ddbe6a9b49f694aaf0e64448352bdc6abc0ebd15b47a41",
)
DIGEST_SLOT=159480
RANGE_BASE=160256
RANGE_MERGE=291328
RANGE_MASK=(1<<22)-1


def derive():
    data=tuple(p.read_bytes() for p in (READER,SPANS,META))
    if tuple(hashlib.sha256(x).hexdigest() for x in data)!=PIN:
        raise ValueError("Published composed reader, span index or metadata grammar drifted")
    assert DIGEST_SLOT+8==159488 < 159744 < 160000 < RANGE_BASE < RANGE_MERGE < 422400 < 446976 < WORK
    old=data[0].decode()
    for a,b in (
      ('trnm_cell_tensor_reader_metadata_v1','trnm_cell_tensor_reader_spans_v1'),
      ('need:u64 = const() {"value":446976}',f'need:u64 = const() {{"value":{WORK}}}'),
      ('all_slot:u64 = const() {"value":159992}',f'all_slot:u64 = const() {{"value":{DIGEST_SLOT}}}'),
      ('compare_slot:u64 = const() {"value":159992}',f'compare_slot:u64 = const() {{"value":{DIGEST_SLOT}}}'),
      ('  verify_status:u32 = call(verify_i,verify_w,verify_n,verify_at,verify_count,verify_len,verify_z,j_verify,header_limit)',
       '  sorted:u64 = call(j_verify,header_limit,verify_w,verify_count) {"function":"ht_sort"}\n'
       '  verify_status:u32 = call(verify_i,verify_w,verify_n,verify_at,verify_count,verify_len,verify_z,j_verify,header_limit)'),
      ('call(coverage_w,coverage_count,coverage_len,coverage_z,coverage_z) {"function":"sl_cover"}',
       'call(coverage_w,coverage_count,coverage_len,coverage_z,coverage_z) {"function":"ir_cover"}'),
      ('  same_row:u64 = call(same_w,same_j) {"function":"hj_row"}\n',
       '  restored:bool = call(j_same,jl_same,same_w,same_j) {"function":"ht_restore"}\n'
       '  branch restored compare_row(same_i,same_w,same_n,same_p,same_count,same_len,same_j,same_dtype,same_after,j_same,jl_same) internal()\n'
       'block compare_row(ci:readbuf,cw:mutbuf,cn:u64,cp:u64,cc:u64,cl:u64,cj:u64,cd:u64,ca:u64,rj:readbuf,jn:u64)\n'
       '  same_row:u64 = const() {"value":4096}\n'),
      ('call(same_i,same_w,same_p,same_dtype,same_after,same_row,j_same,jl_same)',
       'call(ci,cw,cp,cd,ca,same_row,rj,jn)'),
      ('extent(same_i,same_w,same_n,same_count,same_len,same_j,same_dtype,same_after,same_row,j_same,jl_same)',
       'extent(ci,cw,cn,cc,cl,cj,cd,ca,same_row,rj,jn)'),
      ('call(remember_w,remember_j,remember_start,remember_end) {"function":"sl_place"}',
       'call(remember_w,remember_j,remember_start,remember_end) {"function":"ir_add"}'),
    ):
        old=replace(old,a,b)
    # Published boundaries live in [0,2MiB]. Exclusive end may equal 2MiB
    # in the contiguous frame; storing last-byte offset avoids 21-bit overflow.
    tensor=parts(data[1])["ht_tensor"]
    tensor=replace(tensor,"  p2:u64 = int.shl.checked(se,b)",
        '  single:u64 = const() {"value":1}\n  last:u64 = int.sub.wrap(se,single)\n  p2:u64 = int.shl.checked(last,b)')
    merge=parts(data[2])["hm_merge"].replace("hm_merge","ir_merge").replace("hm_slot","ir_slot").replace('{"value":438784}',f'{{"value":{RANGE_MERGE}}}')
    a=merge.index("  left_pos:u64 = call(ci)")
    b=merge.index("  branch first",a)
    merge=merge[:a]+"  first:bool = compare.le(ci,right_idx)\n"+merge[b:]
    return (old+tensor+merge).encode()
