"""Physical sealed anonymous Worker read/query/stdout, no host JSON handoff."""
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.platform.bench.main_build import exact_native_text
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query.build import (
    ADAPTER_END, IMAGE_N, PROGRAMS, RAW_MAX, THUNK_END, build, guard_space,
)
from hia.tests.test_worker_audit_export_row_decode import fixture_cases
from hia.tests.test_worker_audit_select import original_inputs
from hia.tests.test_worker_audit_task_query import MAX_TASK, query_original
from hia.tests.test_worker_audit_task_query_pretty import EMPTY_STDOUT
from hia.tests.test_worker_journal_audit_dto import raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_audit_stdin import (
    ADD_SEALS, ALL_SEALS, GET_SEALS, SEAL_WRITE, _sealed_image, checked_adapter_readback, physical_fixture,
)
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import HIA_ROOT, build_native

HEADER = struct.Struct("<4sIIIQ")
BASE = 0x400000
ROLE_ORDER = ("wid", "wer", "wtq")
ELF_NAME = "sealed-worker-task-query.elf"

# Independently generated in the CLI proof; this literal only drives unit controls.
EMPTY_INDEX = (b'{\n  "version": 1,\n  "total_records": 0,\n  "by_task_id": {},\n'
               b'  "by_status": {},\n  "by_status_phase": {},\n  "by_provider": {},\n'
               b'  "by_model": {},\n  "by_agent_protocol": {},\n  "by_compliance_profile": {},\n'
               b'  "by_provenance_fingerprint": {}\n}')


def digest(data):
    return sha256(data).hexdigest()


def transport(sidecar, rows, task):
    return HEADER.pack(b"WQS1", len(sidecar), len(rows), 0, task) + sidecar + rows


def checked_layout(path, directory, record):
    old_sites = checked_adapter_readback(path, directory/"prior-adapter.txt")
    # Retain independent decoded instructions of only the new fixed thunk.
    listing = subprocess.run(
        ["/usr/bin/objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", "--insn-width=15",
         "--adjust-vma=0x400000", f"--start-address={BASE+ADAPTER_END:#x}",
         f"--stop-address={BASE+THUNK_END:#x}", str(path)],
        check=True, capture_output=True, timeout=10,
    ).stdout
    (directory/"query-thunk.txt").write_bytes(listing)
    instructions = [l.split("\t")[-1].strip() for l in listing.decode("ascii").splitlines() if "\t" in l]
    calls = tuple(int(i.split()[-1], 16) for i in instructions if i.startswith("call "))
    expected = tuple(BASE+record["kernel_text"][r]["at"] for r in ROLE_ORDER)
    if calls != expected or any(i.split()[0] in {"syscall","sysenter","int"} for i in instructions):
        raise AssertionError("Fixed syscall-free thunk does not sequence exact native kernel entries")
    # The pinned thunk digest separately covers every instruction; this check
    # exposes both cap checks and forward-copy/live-region proof in the receipt.
    geometry = (
        "cmp    rsi,0x18", "cmp    rsi,0x10000", "cmp    r15,rax",
        "lea    rdx,[r13+0x10000]", "mov    ecx,0x7428",
        "mov    ecx,0x10000", "cmp    rax,0x10000", "mov    ecx,0x100000",
        "cmp    r9,0x19000", "mov    r9d,0x19000",
    )
    if any(g not in instructions for g in geometry):
        raise AssertionError("Physical/typed cap or pointer domain changed in x86 readback")
    return {"existing_adapter_syscall_sites":old_sites,
            "native_calls":dict(zip(ROLE_ORDER, (hex(i) for i in calls), strict=True)),
            "scratch_reused_only_after_return":True, "thunk_has_no_syscalls":True}


def check_nonpipe_sink(image, data):
    source = os.memfd_create("private-query-proof-input", os.MFD_ALLOW_SEALING)
    destination = os.memfd_create("private-query-proof-unsupported-sink", os.MFD_ALLOW_SEALING)
    sentinel = b"local unchanged sink"
    try:
        for fd, payload in ((source,data),(destination,sentinel)):
            if os.write(fd,payload)!=len(payload):
                raise OSError("Short private input setup")
            fcntl.fcntl(fd,ADD_SEALS,ALL_SEALS)
            if fcntl.fcntl(fd,GET_SEALS)!=ALL_SEALS or os.lseek(fd,0,os.SEEK_SET)!=0:
                raise AssertionError("Cannot stage private sealed control")
        with _sealed_image(image) as executable:
            found = subprocess.run([f"/proc/self/fd/{executable}"], stdin=source, stdout=destination,
                                   stderr=subprocess.PIPE, pass_fds=(executable,), close_fds=True,
                                   env={}, timeout=15)
        if (found.returncode != 75 or found.stderr or os.lseek(source,0,os.SEEK_CUR) != 0
                or os.lseek(destination,0,os.SEEK_CUR) != 0
                or os.pread(destination,len(sentinel)+1,0)!=sentinel):
            raise AssertionError("An unsupported known local sink was not refused before any reading/output")
        return {"status":75, "stdin_cursor":0, "sink_cursor":0, "sink_bytes_unchanged":True}
    finally:
        os.close(source)
        os.close(destination)


def refusals(image, good_index, examples=(), directory=None):
    good = transport(good_index,b"",0)
    row_bytes = RAW_MAX-HEADER.size-len(good_index)
    if row_bytes<=0:
        raise AssertionError("Unexpected empty-sidecar extent")
    left = transport(good_index,b"!"*row_bytes,0)
    right = transport(good_index+b"!"*row_bytes,b"",0)
    if len(left)!=RAW_MAX or len(right)!=RAW_MAX:
        raise AssertionError("Exact physical split controls changed")
    mixed = (
        ("empty-physical-input",b"",0,ALL_SEALS,74,0),
        ("short-pair",good[:23],0,ALL_SEALS,74,23),
        ("wrong-pair-marker",b"WQS2"+good[4:],0,ALL_SEALS,74,len(good)),
        ("reserved-word",good[:12]+b"\1"+good[13:],0,ALL_SEALS,74,len(good)),
        ("pair-length-sum",good[:-1],0,ALL_SEALS,74,len(good)-1),
        ("different-index-split",(good[:4]+struct.pack("<II",len(good_index)-1,1)+good[12:]),0,ALL_SEALS,74,len(good)),
        ("two-u32-lengths-do-not-wrap",good[:4]+struct.pack("<II",0xffffffff,0xffffffff)+good[12:],
         0,ALL_SEALS,74,len(good)),
        ("exact-64k-index-empty-rows",right,0,ALL_SEALS,74,RAW_MAX),
        ("exact-64k-small-index-large-rows",left,0,ALL_SEALS,74,RAW_MAX),
        ("one-byte-over-physical",left+b"x",0,ALL_SEALS,71,0),
        ("nonzero-shared-cursor",good,1,ALL_SEALS,72,1),
        ("missing-seals",good,0,0,70,0),
        ("missing-write-seal",good,0,ALL_SEALS & ~SEAL_WRITE,70,0),
        *((name,blob,0,ALL_SEALS,74,len(blob)) for name,blob in examples),
    )
    found = {}
    for name,payload,initial,seals,status,after in mixed:
        result, observation = physical_fixture(image,payload,initial=initial,seals=seals)
        if (result.returncode,result.stdout,observation["offset_after"]) != (status,b"",after):
            raise AssertionError(f"{name} modified output or read the wrong extent: {observation!r}")
        if directory:
            target=fresh_directory(directory/name)
            (target/"sealed-frame.raw").write_bytes(payload)
            (target/"stdout.raw").write_bytes(result.stdout)
            (target/"stderr.raw").write_bytes(result.stderr)
        found[name]=observation
    found["unsupported-owned-nonpipe-stdout"] = check_nonpipe_sink(image,good)
    return found


def direct_object_limits(output):
    """The first-party direct kernels are tested elsewhere as shared callables."""
    from hepta.object_symbols import inspect_object_symbols

    result = {}
    expected = {"wer":{"abort","memset"}, "wid":{"abort"}, "wtq":{"abort"}}
    for role, (name, _, _) in PROGRAMS.items():
        guard_space(output)
        raw = output/(role+".direct.o")
        receipt,_=build_native(HIA_ROOT/f"src/worker_agent/{name}.hepta",raw,
                               kind="object",backend="direct",byte_exports=("f0",))
        observed=inspect_object_symbols(raw.read_bytes(),"ELF64",62)
        if set(observed["undefined"])!=expected[role] or observed["defined"]=={"f0"}:
            raise AssertionError("Unexpected direct eligibility identity")
        try:
            exact_native_text(raw.read_bytes())
        except ValueError as exc:
            result[role]={"exports":sorted(observed["defined"]), "imports":sorted(observed["undefined"]),
                          "strict_rejection":str(exc), "receipt":receipt}
        else:
            raise AssertionError("Unapproved direct raw object admitted")
    return result


class WorkerAuditSealedQuery(unittest.TestCase):
    def test_static_seal_extent_and_stdout_refusal_controls(self):
        with tempfile.TemporaryDirectory(prefix="trnm-query-sealed-") as tmp:
            root=Path(tmp)
            image, report=build(root/"build")
            checked_layout(root/"build"/ELF_NAME,root,report)
            head=transport(EMPTY_INDEX,b"",MAX_TASK)
            found, outcome=physical_fixture(image,head)
            self.assertEqual((found.returncode, found.stdout, outcome["offset_after"]), (0,EMPTY_STDOUT,len(head)))
            self.assertEqual(len(refusals(image,EMPTY_INDEX)),14)


def original_case(binary, directory, journal):
    src=directory/"original-ingress.jsonl"
    src.write_bytes(journal)
    src.chmod(0o600)
    rows, _, ix=cli_artifacts(binary,src,"original",True,None)
    raw_index=(directory/"original.jsonl.index.json").read_bytes()
    if raw_index!=ix:
        raise AssertionError("Original export formats produced different index bytes")
    return raw_index,rows


def observe_queries(image, binary, directory, pair, tasks):
    out={}
    for task in tasks:
        request=transport(*pair,task)
        if len(request)>RAW_MAX:
            raise AssertionError("Positive original fixture exceeds the already-locked physical cap")
        original, stdout_sha=query_original(binary,directory/"original.jsonl",task,directory)
        wanted=(directory/f"query-{task}.stdout.raw").read_bytes()
        found, trace=physical_fixture(image,request)
        if (found.returncode or found.stdout!=wanted or trace["offset_after"]!=len(request)
                or trace["offset_before"] or trace["seals"]!=ALL_SEALS or not wanted.endswith(b"\n")
                or digest(wanted)!=stdout_sha):
            raise AssertionError("Named physical query differs from independent actual Rust stdout")
        (directory/f"task-{task}.sealed-frame.raw").write_bytes(request)
        (directory/f"task-{task}.native-stdout.raw").write_bytes(found.stdout)
        (directory/f"task-{task}.native-stderr.raw").write_bytes(found.stderr)
        out[str(task)]={**trace,"hit_count":len(original["hit_indexes"]),"original_sha256":stdout_sha}
        if task==MAX_TASK and "maximum-ordered" in directory.name and original["hit_indexes"]!=list(range(64)):
            raise AssertionError("Boundary fixture lost the 64th compact ordinal")
    return out


def qualify(binary, original, output):
    def bound():
        return (original["repository_inputs"]==original_inputs()
                and original["executable_sha256"]==digest(binary.read_bytes()))
    if not bound():
        raise AssertionError("Use the exact locked original executable and source")
    image, report=build(output/"build")
    layout=checked_layout(output/"build"/ELF_NAME,output,report)
    incompatible=direct_object_limits(output)
    cases={}
    raw_items={}
    for name,(journal,tasks) in fixture_cases().items():
        guard_space(output)
        directory=fresh_directory(output/name)
        pair=original_case(binary,directory,journal)
        raw_items[name]=pair
        cases[name]=observe_queries(image,binary,directory,pair,tasks)

    # Size the private payload from genuine first execution, not a host JSON
    # reserializer. Padding the ordinary synthetic ASCII request leaves the
    # genuine sidecar unchanged and reaches the exact old physical cap.
    def limit_record(padding):
        record=row(-3,"rejected",ordinal=7,request="owned-limit-"+("z"*padding))
        record["task_id"]=MAX_TASK
        return snapshot(raw(record))
    before=fresh_directory(output/"limit-length-calibration")
    baseline=original_case(binary,before,limit_record(0))
    pad=RAW_MAX-len(transport(*baseline,MAX_TASK))
    if not 0 < pad < RAW_MAX:
        raise AssertionError("Cannot establish actual boundary witness")
    at_max=fresh_directory(output/"exact-65536")
    exact=original_case(binary,at_max,limit_record(pad))
    if exact[0]!=baseline[0] or len(transport(*exact,MAX_TASK))!=RAW_MAX:
        raise AssertionError("Actual untouched export did not produce exact physical cap")
    cases["exact-65536"]=observe_queries(image,binary,at_max,exact,(MAX_TASK,))
    other=raw_items["original-control-escapes"]
    negatives=refusals(image,raw_items["empty"][0], (
        ("valid-raws-with-different-task",transport(other[0],exact[1],MAX_TASK)),
        ("valid-raws-with-different-count",transport(raw_items["empty"][0],other[1],0)),
    ), fresh_directory(output/"controls"))
    if not bound() or digest(image)!=report["elf"]["sha256"]:
        raise AssertionError("Observed original or target changed")
    qualification={"schema":"trnm.hia.worker-sealed-task-query.observation.v1", "status":"PASS",
         "build":report,"decoded_static_layout":layout,"cases":cases,"refusals":negatives,
         "original_sources":original_inputs(),"original_executable":original["executable_sha256"],
         "strict_direct_rejections":incompatible,
         "host_row_or_map_parsing":False,"native_opens_named_data_paths":False,
         "host_supplies_original_raw_file_bytes":True,
         "physical_input_sealed_fd0_only":True,"physical_output_parent_anon_pipe_only":True,
         "runtime_eintr_observed":False,"independent_syscall_trace":False,
         "typed_guard_live_in_checked_thunk":True,"overcombined_typed_after_valid_raw_observed":False,
         "production_dispatch":False,"installed":False}
    (output/"report.json").write_text(json.dumps(qualification,indent=2,sort_keys=True)+"\n")
    return qualification


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("output","original-binary","original-build-receipt"):
        p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args()
    r=qualify(a.original_binary.resolve(strict=True),json.loads(a.original_build_receipt.read_bytes()),fresh_directory(a.output))
    print(json.dumps({k:r[k] for k in ("status","cases","refusals")},sort_keys=True))


if __name__=="__main__":
    main()
