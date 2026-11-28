"""Source-bound CachePayloadReader arithmetic/slot witness, without its store or clock."""
import hashlib

from hia.tests.cache_payload_cursor_original import frozen
from hia.tests.cache_payload_held_original import extract as held_extract
from hia.tests.test_da_protocol_context import locked_reference

from pathlib import Path

HARNESS=Path(__file__).with_name("rust_cell_cache_payload_transcript_reference.rs")


def extract():
    reader=frozen()
    held=held_extract()

    def cut(src,start,end,offset=0):
        first=src.index(start,offset)
        return src[first:src.index(end,first)]

    digest=cut(held,b"fn digest_equal(",b"\nimpl CursorArithmetic")
    read=cut(reader,b"        if output.is_empty()",b"\n    }",reader.index(b"impl Read"))
    pre=cut(read,b"            let bytes = self",b"            if bytes.len()")
    replacement=(b"            let held = self.held[index];\n"
                 b"            let bytes = (!held.is_empty() && digest_equal(held, expected.sha256))\n"
                 b"                .then(|| held.to_vec())\n"
                 b"                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, \"tensor chunk absent\"))?;\n")
    assert read.count(pre)==1 and read.count(b"        self.check_deadline()?;\n")==1
    read=read.replace(pre,replacement).replace(b"        self.check_deadline()?;\n",b"")
    seek=cut(reader,b"        let next = match from {",b"\n    }")
    data=HARNESS.read_bytes()
    for key, value in ((b"// EXACT_DIGEST",digest),(b"// EXACT_READ",read),(b"// EXACT_SEEK",seek)):
        assert data.count(key)==1
        data=data.replace(key,value)
    return data


def original(directory,stream):
    data=extract()
    p=directory/"original_cache_payload_transcript.rs"
    with p.open("xb") as f:
        f.write(data)
    actual=locked_reference(directory,stream,caller=p,extra_externs=("sha2",))
    if p.read_bytes()!=data or extract()!=data:
        raise ValueError("Frozen transcript source changed")
    return actual,hashlib.sha256(data).hexdigest()
