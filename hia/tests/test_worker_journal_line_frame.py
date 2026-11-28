"""Native borrowed journal geometry vs exact Rust framing and private CLI files."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import ROOT
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INSUFFICIENT, INVALID, ingress_rows, observed_call, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/journal_line_frame.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-worker-agent/src/worker_journal.rs"
HEADER = struct.Struct("<4sI")
SPAN = struct.Struct("<III")
READER_MAX = 65536
MAX_SPANS = 64
ARTIFACTS = ("jsonl", "md", "md.index.json")
SPACES = tuple(range(9,14))+(32,133,160,5760,*range(8192,8203),8232,8233,8239,8287,12288)


def unpack_bytes(packet):
    marker, n = HEADER.unpack_from(packet)
    body = packet[HEADER.size:]
    if marker != b"WJF1" or n > MAX_SPANS or len(body) != n*SPAN.size:
        raise AssertionError("Incorrect native framing packet")
    result = list(SPAN.iter_unpack(body))
    if any(ordinal != i or length == 0 for i,(ordinal,_,length) in enumerate(result)):
        raise AssertionError("Logical ordinal or span length is malformed")
    return result


def reassemble(snapshot, spans):
    # Always add a fresh CR before LF. Rust lines strips exactly that CR,
    # so a CR present in the proven span (from original CR+CR+LF) survives.
    end=0
    pieces=[]
    for _,at,length in spans:
        if at < end or at+length > len(snapshot):
            raise AssertionError("Span outside proven borrowed source extent")
        body=snapshot[at:at+length]
        if b"\n" in body:
            raise AssertionError("Returned record span includes a line delimiter")
        pieces.append(body+b"\r\n")
        end=at+length
    return b"".join(pieces)


class WorkerJournalLineFrame(unittest.TestCase):
    def test_exact_one_cr_and_blank_only_trim_retains_other_bytes(self):
        first=b" \talpha\r"
        first_physical=b"\n\t\r\n"+first+b"\r\n"
        blank="\u0085\u2028\u2029\u3000\r\n".encode()
        second="\ufeff β\u2028 γ\u00a0".encode()
        tail=b"\r\n"
        original=first_physical+blank+second+tail
        want=[(0,4,len(first)),(1,len(first_physical+blank),len(second))]
        required=HEADER.size+len(want)*SPAN.size
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as native:
                n, out=observed_call(native,original,required+7)
                self.assertEqual(n,required)
                self.assertEqual(unpack_bytes(out[:n]),want)
                self.assertEqual(out[n:],FILL*7)
                self.assertEqual(reassemble(original,want),first+b"\r\n"+second+b"\r\n")
                self.assertEqual(observed_call(native,original,required-1),(INSUFFICIENT,FILL*(required-1)))
                self.assertEqual(observed_call(native,b"",8),(8,b"WJF1"+b"\0"*4))
                self.assertEqual(observed_call(native,b"\r\n",8),(8,b"WJF1"+b"\0"*4))

    def test_complete_utf8_termination_and_exact_private_caps(self):
        body=(b"x\n")*64
        long=(b"\n"*(READER_MAX-2))+b"x\n"
        spaces="".join(chr(c)+"\n" for c in SPACES).encode()
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE,backend=backend,byte_exports=("f0",)) as native:
                n,got=observed_call(native,body,776)
                self.assertEqual(n,776)
                self.assertEqual(unpack_bytes(got),[(i,i*2,1) for i in range(64)])
                n, got=observed_call(native,long,20)
                self.assertEqual((n,unpack_bytes(got)),(20,[(0,READER_MAX-2,1)]))
                self.assertEqual(observed_call(native,spaces,8),(8,b"WJF1"+b"\0"*4))
                for invalid in (b"x",b"x\r",b"\n\xc3\n",b"ok\n\xff\n"):
                    self.assertEqual(observed_call(native,invalid,32),(INVALID,FILL*32))
                for larger in (body+b"x\n",long+b"\n"):
                    self.assertEqual(observed_call(native,larger,800),(INSUFFICIENT,FILL*800))


def pinned_rust_projection(d):
    original=ORIGINAL.read_bytes()
    typed_tail=b'.map(|line| serde_json::from_str(line).context("invalid worker journal record"))'
    after=original.split(b"pub(crate) fn decode<T: DeserializeOwned>",1)[1]
    before=after.split(b"\n}\n",1)[0]
    exact_lines, rest=before.split(b" {\n    ",1)[1].split(typed_tail,1)
    if rest.strip()!=b".collect()" or exact_lines.strip()!=(
            b"std::str::from_utf8(bytes)?\n        .lines()\n        .filter(|line| !line.trim().is_empty())"):
        raise AssertionError("Exact original framing expression changed")
    guard=b'bytes.is_empty() || bytes.ends_with(b"\\n")'
    read_locked=original.split(b"fn read_locked(",1)[1].split(b"\n}\n",1)[0]
    if read_locked.count(guard)!=1 or b'"incomplete worker journal record"' not in read_locked:
        raise AssertionError("Original live-reader EOF contract changed")
    program=b'''
use std::io::{self, Read, Write};
fn run(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !(EOF_GUARD) { return Err("incomplete worker journal record".into()); }
    let retained: Vec<&str> = EXACT_LINES.collect();
    let mut out = Vec::new();
    out.extend(b"WJF1");
    out.extend((retained.len() as u32).to_le_bytes());
    for (n, line) in retained.into_iter().enumerate() {
        let start = (line.as_ptr() as usize) - (bytes.as_ptr() as usize);
        out.extend((n as u32).to_le_bytes());
        out.extend((start as u32).to_le_bytes());
        out.extend((line.len() as u32).to_le_bytes());
    }
    Ok(out)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    io::stdout().write_all(&run(input.as_slice())?)?;
    Ok(())
}
'''.replace(b"EOF_GUARD",guard).replace(b"EXACT_LINES",exact_lines.strip())
    source=d/"original_span_projection.rs"
    executable=d/"original_span_projection"
    source.write_bytes(program)
    rustc=os.environ.get("RUSTC","rustc")
    version=subprocess.check_output([rustc,"--version"],timeout=15).decode().strip()
    if version.split()[:2] != ["rustc","1.95.0"]:
        raise AssertionError("Exact pinned rustc 1.95.0 is required")
    command=[rustc,"--edition=2024","-C","debuginfo=0","-C","strip=symbols",
             str(source),"-o",str(executable)]
    comp=subprocess.run(command,capture_output=True,timeout=30)
    (d/"rustc.stdout.raw").write_bytes(comp.stdout)
    (d/"rustc.stderr.raw").write_bytes(comp.stderr)
    if comp.returncode:
        raise AssertionError("Pinned source-bound span projection did not compile")
    return executable,{
        "rustc":version,"source_sha256":sha256(program).hexdigest(),
        "rust_reader_source_sha256":sha256(original).hexdigest(),
        "qualified_projection_sha256":sha256(executable.read_bytes()).hexdigest(),
        "exact_original_iterator_sha256":sha256(exact_lines.strip()).hexdigest(),
        "original_disk_guard_reused":True,"cargo_ran":False,
    }


def scenarios():
    rows=ingress_rows(["rejected","pending","failed_adapter","reveal_submitted",
                       "Rejected","failed_submission","rejected"])
    for i, row in enumerate(rows):
        row["request_id"]=f"framing|{i} 🧾"
        row["text"]="JSON string retains \u0085 and \u2028; escaped LF \n"
    payloads=[json.dumps(x,ensure_ascii=False).encode() for x in rows]
    full_space_roster="".join(chr(c)+"\n" for c in SPACES).encode()
    mixed=(full_space_roster+b" \t"+payloads[0]+b"\t\r\r\n"+payloads[1]+b"\n"
           +"\u2003\u0085\r\n".encode()+payloads[2]+b"\r\n"
           +payloads[3]+b"\n"+payloads[4]+b"\r\n"+payloads[5]+b"\n"+payloads[6]+b"\r\n")
    retained_not_json=b"\xc2\xa0"+payloads[0]+b"\n"
    return {"mixed":(mixed,7,5,None),"blank":(full_space_roster,0,0,None),"empty":(b"",0,0,None),
            "incomplete":(payloads[0]+b"\n"+payloads[1],None,None,b"incomplete worker journal record"),
            "utf8":(payloads[0]+b"\n\xc3\n",None,None,b"utf-8"),
            "untrimmed_nonblank":(retained_not_json,1,None,b"invalid worker journal record")}


def cli_artifacts(binary, path, stem, accepted, error):
    before=sha256(path.read_bytes()).hexdigest()
    for ext in ("jsonl","md"):
        output=path.parent/(stem+"."+ext)
        found=subprocess.run([str(binary),"export-audit","--ingress-file",str(path),
                              "--output-file",str(output)],cwd=path.parent,
                             capture_output=True,timeout=25)
        output.with_name(output.name+".stdout.raw").write_bytes(found.stdout)
        output.with_name(output.name+".stderr.raw").write_bytes(found.stderr)
        if accepted:
            if found.returncode or found.stderr or not output.is_file():
                raise AssertionError("Original Worker refused an admitted private snapshot")
        elif found.returncode==0 or error not in found.stderr.lower() or output.exists():
            raise AssertionError("Original Worker did not preserve its refusal boundary")
    if sha256(path.read_bytes()).hexdigest()!=before:
        raise AssertionError("Observation changed immutable journal bytes")
    return tuple((path.parent/(stem+"."+ext)).read_bytes() for ext in ARTIFACTS) if accepted else None


def observe_original(binary, build, directory):
    def bound():
        return (build["repository_inputs"]==original_inputs()
                and sha256(binary.read_bytes()).hexdigest()==build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker source/lock/binary identity differs")
    projection, reference = pinned_rust_projection(directory)
    proof={}
    with ExitStack() as stack:
        modules={b:stack.enter_context(NativeModule(
            NATIVE,backend=b,byte_exports=("f0",))) for b in BACKENDS}
        for name,(snapshot,count,selected,reason) in scenarios().items():
            d=directory/name
            d.mkdir(mode=0o700)
            raw=d/"original-ingress.jsonl"
            raw.write_bytes(snapshot)
            raw.chmod(0o600)
            if name=="mixed":
                (d/"extra-terminal-cr-retained.txt").write_bytes(b"original contains CR+CR+LF on one row\n")
            want=cli_artifacts(binary,raw,"original",reason is None,reason)
            rust=subprocess.run([str(projection)],input=snapshot,capture_output=True,timeout=10)
            (d/"original-span-projection.bin").write_bytes(rust.stdout)
            (d/"original-span-projection.stderr.raw").write_bytes(rust.stderr)
            if count is None:
                if rust.returncode==0 or rust.stdout:
                    raise AssertionError("Geometry reference did not refuse invalid source")
            elif rust.returncode or rust.stderr or len(unpack_bytes(rust.stdout))!=count:
                raise AssertionError("Exact Rust iterator did not observe expected spans")
            for backend,native in modules.items():
                result,out=observed_call(native,snapshot,783)
                if count is None:
                    if (result,out)!=(INVALID,FILL*783):
                        raise AssertionError("Native refusal wrote bytes or disagreed")
                    continue
                if out[:result]!=rust.stdout or out[result:]!=FILL*(783-result):
                    raise AssertionError("Native framing offsets/lengths differ from exact Rust")
                spans=unpack_bytes(out[:result])
                (d/(backend+".span-packet.bin")).write_bytes(out[:result])
                reconstructed=d/(backend+"-reassembled.jsonl")
                reconstruction=reassemble(snapshot,spans)
                if name=="mixed" and b"\t\r\r\n" not in reconstruction:
                    raise AssertionError("Additional raw CR did not survive reconstruction")
                reconstructed.write_bytes(reconstruction)
                reconstructed.chmod(0o600)
                got=cli_artifacts(binary,reconstructed,backend,reason is None,reason)
                if got!=want:
                    raise AssertionError("Reconstruction from native spans changed original CLI bytes")
            row={"span_count":count,"original_export_count":selected,
                 "source_sha256":sha256(snapshot).hexdigest(),"original_cli_status":"accepted" if want else "rejected"}
            if want:
                if json.loads(want[2])["total_records"]!=selected:
                    raise AssertionError("Actual original export attendance changed")
                row["artifact_sha256"]=dict(zip(ARTIFACTS,(sha256(p).hexdigest() for p in want),strict=True))
            proof[name]=row
    if not bound():
        raise AssertionError("Original Worker binding changed during observation")
    result={"original_inputs":original_inputs(),"original_binary_sha256":build["executable_sha256"],
            "rust_span_reference":reference,"independent_cli_raw_and_native_span_replay":True,
            "native_status_json_serde_admission_or_path_authority":False,
            "backends":{b:{"artifact_sha256":m.artifact_sha256,"receipt":m.receipt} for b,m in modules.items()},
            "scenarios":proof}
    (directory/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--original-binary",type=Path,required=True)
    p.add_argument("--original-build-receipt",type=Path,required=True)
    args=p.parse_args()
    target=args.output.resolve()
    if target.is_relative_to(ROOT):
        p.error("Store private proof outside the checkout")
    target.mkdir(mode=0o700)
    print(json.dumps(observe_original(args.original_binary.resolve(strict=True),
          json.loads(args.original_build_receipt.read_bytes()),target)["scenarios"],sort_keys=True))


if __name__=="__main__":
    main()
