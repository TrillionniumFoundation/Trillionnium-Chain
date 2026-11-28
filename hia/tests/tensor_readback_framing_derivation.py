"""Anchor the new immutable readback's pre-JSON blocks to the published framing."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRAMING = ROOT / "hia/src/data_availability/cell_tensor_reader_framing.hepta"
SOURCE = ROOT / "hia/src/data_availability/cell_tensor_reader_readback.hepta"
FRAMING_SHA = "017bb72c48d7b3158c1860cb8d2c7ed5b4d7c4f15248cd46673eef2a4f4639dc"
HEADER_SHA = "68dd05093634f59aac8aaf6db26fe49e54f51572a604055bed47c744b0bf27f5"
WORK = 293256


def derive_prefix():
    framing = FRAMING.read_bytes()
    if hashlib.sha256(framing).hexdigest() != FRAMING_SHA:
        raise ValueError("Published reader framing source changed")
    if hashlib.sha256(FRAMING.with_name("cell_tensor_header_json.hepta").read_bytes()).hexdigest() != HEADER_SHA:
        raise ValueError("Published JSON operand source changed")
    head = framing.decode()
    remove_begin = head.index("block output_room(")
    remove_end = head.index("block envelope()", remove_begin)
    head = head[:remove_begin] + head[remove_end:]
    replacements = {
        "trnm_cell_tensor_reader_framing_v1": "trnm_cell_tensor_reader_readback_v1",
        '{"value":13944}': '{"value":'+str(WORK)+'}',
        "  actual:u64 = int.sub.wrap(ln,le)\n":
            '  all_slot:u64 = const() {"value":291072}\n'
            '  digest_start:u64 = const() {"value":33}\n'
            '  kept_digest_at:u64 = int.add.wrap(file_at,digest_start)\n'
            '  saved_digest:u64 = call(lw,all_slot,kept_digest_at) {"function":"tr_put"}\n'
            '  actual:u64 = int.sub.wrap(ln,le)\n',
        "  branch qc output_room(qi,qo,qw,qe,ql,qh) bad_padding()":
            "  branch qc check_layout(qi,qo,qw,qe,ql,qh) bad_padding()\n"
            "block check_layout(xs_i:readbuf,xs_o:mutbuf,xs_w:mutbuf,xs_e:u64,xs_l:u64,xs_h:u64)\n"
            '  readback_status:u32 = call(xs_i,xs_o,xs_w,xs_e,xs_l,xs_h) {"function":"sl_layout"}\n'
            "  ret(readback_status)",
    }
    for old,new in replacements.items():
        if head.count(old) != 1:
            raise ValueError("Unrecognized published CFG anchor")
        head = head.replace(old,new)
    return head.encode()


def assert_bound():
    if not SOURCE.read_bytes().startswith(derive_prefix()):
        raise ValueError("Immutable reader prefix drifted from the published framing CFG")
