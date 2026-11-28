"""Observe original held-data primitives without opening a cache or reader."""
import hashlib
from pathlib import Path

from hia.tests.cache_payload_cursor_original import CELL, frozen
from hia.tests.test_da_protocol_context import locked_reference

STORE=CELL/"store.rs"
PIN="70889e05e7df573c06d6d5387e31cace34220180e091c6a809e4b03589bce95a"
HARNESS=Path(__file__).with_name("rust_cell_cache_payload_held_reference.rs")


def extract():
    src=frozen()
    store=STORE.read_bytes()
    if hashlib.sha256(store).hexdigest()!=PIN:
        raise ValueError("Frozen cache digest source changed")
    def span(raw,start,end,after=0):
        a=raw.index(start,after)
        return raw[a:raw.index(end,a)]
    first=span(src,b"        if output.is_empty()",b"        if self.cached_index")
    first=first.replace(b"return Ok(0);",b"return Ok(Some(Vec::new()));",1)
    anchor=store.index(b"    pub(super) fn chunk_with_deadline(")
    sha=span(store,b"            let actual = <[u8; 32]>::from(Sha256::digest(&bytes));",
              b"            check_data_deadline",anchor)
    # The store compares its lookup hash, which the frozen reader supplies
    # as expected.sha256. This comparison does not perform the actual lookup.
    check=span(store,b"            if actual == hash {",b"\n        }",anchor)
    assert b"return Ok(Some(bytes));" in check
    sha+=check.replace(b"return Ok(Some(bytes));",b"return true;")+b"\n"
    size=span(src,b"            if bytes.len() != expected.size as usize {",b"            self.cached_bytes =")
    copy=span(src,b"        let offset = (self.position % width)",b"        Ok(count)")
    # After the real reader's length/digest conditions, the exact held bytes are
    # what would become cached_bytes. No simulated store or clock is constructed.
    copy=copy.replace(b"self.cached_bytes",b"bytes")
    copy=copy.replace(b"        output[..count].copy_from_slice",
                      b"        let mut output = vec![0u8; count];\n        output[..count].copy_from_slice")
    d=HARNESS.read_bytes()
    for marker,fragment in ((b"// EXACT_READ_FIRST",first),(b"// EXACT_HASH",sha),
                            (b"// EXACT_LENGTH",size),(b"// EXACT_COPY",copy)):
        if d.count(marker)!=1:
            raise ValueError("Original held reader observation marker moved")
        d=d.replace(marker,fragment)
    return d


def original(directory,stream):
    src=extract()
    p=directory/"original_cache_payload_held.rs"
    with p.open("xb") as out:
        out.write(src)
    result=locked_reference(directory,stream,caller=p,extra_externs=("sha2",))
    if extract()!=src or p.read_bytes()!=src:
        raise ValueError("Original or its isolated exact source changed")
    return result,hashlib.sha256(src).hexdigest()
