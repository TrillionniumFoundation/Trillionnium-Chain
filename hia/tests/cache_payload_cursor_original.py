"""Exact extract of CachePayloadReader arithmetic, never a live reader."""
import hashlib
from pathlib import Path

from hia.tests.test_da_protocol_context import ROOT, locked_reference

CELL=ROOT/"trillionnium/crates/trnm-data-availability/src/cell"
READER=CELL/"tensor_reader.rs"
PINS={
    READER: "da6a97dfcaaec98ae3cac0afec3e33c86f48d6bc36b0249070a1505fac817ca3",
    CELL/"manifest.rs": "cf945af731b8172d6b093bded63d546ac3f3a15756524e739a50187dcdaebdc5",
}
HARNESS=Path(__file__).with_name("rust_cell_cache_payload_cursor_reference.rs")


def frozen():
    blobs={p:p.read_bytes() for p in PINS}
    if {p:hashlib.sha256(raw).hexdigest() for p,raw in blobs.items()}!=PINS:
        raise ValueError("Frozen original cursor or manifest changed")
    return blobs[READER]


def extract(source):
    def span(start,end):
        a=source.index(start)
        return source[a:source.index(end,a)]
    seek=span(b"        let next = match from {",b"\n    }")
    read_first=span(b"        if output.is_empty()",b"        if self.cached_index")
    read_last=span(b"        let offset = (self.position % width)",b"        output[..count]")
    advance=span(b"        self.position += count as u64;",b"\n    }")
    # Reify only the extent of the row after original cached_bytes.len()==expected.size;
    # no successful read, clock pass, or cache contents are returned or constructed.
    occurrence=b"self.cached_bytes.len()"
    if read_last.count(occurrence)!=1:
        raise ValueError("Original cache row extent anchor changed")
    read_last=read_last.replace(occurrence,b"expected.size as usize")
    fragments={b"// EXACT_SEEK":seek,b"// EXACT_READ_FIRST":read_first,
               b"// EXACT_READ_LAST":read_last,b"// EXACT_ADVANCE":advance}
    d=HARNESS.read_bytes()
    for marker,fragment in fragments.items():
        if d.count(marker)!=1:
            raise ValueError("Missing exact original arithmetic slot")
        d=d.replace(marker,fragment)
    return d


def original(directory,stream):
    original=frozen()
    generated=extract(original)
    p=directory/"original_cache_payload_cursor.rs"
    with p.open("xb") as file:
        file.write(generated)
    raw=locked_reference(directory,stream,caller=p)
    if frozen()!=original or extract(original)!=generated or p.read_bytes()!=generated:
        raise ValueError("Original or generated arithmetic changed")
    return raw,hashlib.sha256(generated).hexdigest()
