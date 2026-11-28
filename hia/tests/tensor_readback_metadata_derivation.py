"""Bind the composed 1024-key reader to both published HIA operands."""
import hashlib
from pathlib import Path

from hia.tests.tensor_header_metadata_derivation import SOURCE as METADATA, WORK
from hia.tests.tensor_readback_three_derivation import SOURCE as THREE, replace

SOURCE = THREE.with_name("cell_tensor_reader_readback_metadata.hepta")
PIN_THREE = "edaeb6de50c58642610228205505ac6a700cbf8e056cef9d1f63406e6a15e586"
PIN_METADATA = "943ad993247294bd73ddbe6a9b49f694aaf0e64448352bdc6abc0ebd15b47a41"
DIGEST_SLOT = 159992
TEMP = 160000
NAMES_END = 20000 + 128 * 255
META_ARENA = 160256
INTERVAL_BEGIN = 291080
INTERVAL_END = INTERVAL_BEGIN + 128 * 16


def derive():
    old,metadata=THREE.read_bytes(),METADATA.read_bytes()
    if (hashlib.sha256(old).hexdigest(),hashlib.sha256(metadata).hexdigest())!=(PIN_THREE,PIN_METADATA):
        raise ValueError("Published reader or metadata operand changed")
    # The digest locator survives header parsing; intervals start only once
    # metadata lookup is finished. Output is a separate mutbuf, never scratch.
    assert NAMES_END < DIGEST_SLOT and DIGEST_SLOT + 8 == TEMP < META_ARENA
    assert META_ARENA <= INTERVAL_BEGIN < INTERVAL_END <= WORK
    code=old.decode()
    for anchor,new in (
        ("trnm_cell_tensor_reader_full_header_v1","trnm_cell_tensor_reader_metadata_v1"),
        ('need:u64 = const() {"value":293256}', 'need:u64 = const() {"value":'+str(WORK)+'}'),
        ('all_slot:u64 = const() {"value":291072}', 'all_slot:u64 = const() {"value":'+str(DIGEST_SLOT)+'}'),
        ('compare_slot:u64 = const() {"value":291072}', 'compare_slot:u64 = const() {"value":'+str(DIGEST_SLOT)+'}'),
    ):
        code=replace(code,anchor,new)
    return code.encode()
