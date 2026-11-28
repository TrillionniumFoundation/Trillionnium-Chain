"""Physically read a private sealed Linux stdin fixture with the HIA-owned ELF."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from hia.platform.build import sealed_executable, sha256
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_journal_audit_stdin.build import PREFIX, RAW_MAX, WAO_MAX, build
from hia.tests.test_worker_audit_export_transaction import NAMES, artifacts
from hia.tests.test_worker_audit_select import original_inputs
from hia.tests.test_worker_journal_audit_dto import declared_input, raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row, scenarios
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_audit_export_v3 import near_raw_cap
from hia.tests.test_worker_journal_line_frame import cli_artifacts

ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)
ALL_SEALS = 15  # Linux F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE


def physical_fixture(image, data, *, initial=0, seals=ALL_SEALS):
    """Create the only admitted input here, not from an external FD or path."""
    in_fd = os.memfd_create("worker-owned-fixture-source", os.MFD_ALLOW_SEALING)
    try:
        position = 0
        while position < len(data):
            count = os.write(in_fd, data[position:])
            if count <= 0:
                raise OSError("Short setup write")
            position += count
        if seals:
            fcntl.fcntl(in_fd, ADD_SEALS, seals)
        before = os.fstat(in_fd)
        observed_seals = fcntl.fcntl(in_fd, GET_SEALS)
        if (not stat.S_ISREG(before.st_mode) or observed_seals != seals
                or before.st_size != len(data) or os.lseek(in_fd, initial, os.SEEK_SET) != initial):
            raise AssertionError("Private test capture seal/extent/offset differs")
        with _sealed_image(image) as exe_fd:
            found = subprocess.run([f"/proc/self/fd/{exe_fd}"], stdin=in_fd,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(exe_fd,),
                                   close_fds=True, check=False, env={}, timeout=15)
        cursor = os.lseek(in_fd, 0, os.SEEK_CUR)
        after = os.fstat(in_fd)
        # pread does not modify the independently observed shared cursor.
        unchanged = os.pread(in_fd, len(data) + 1, 0) == data
        if ((before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size)
                or fcntl.fcntl(in_fd, GET_SEALS) != observed_seals or not unchanged
                or len(found.stdout) > WAO_MAX or found.stderr):
            raise AssertionError("Native observation changed fixture or overflowed output envelope")
        return found, {"input_bytes": len(data), "input_sha256": sha256(data),
                       "seals": observed_seals, "offset_before": initial, "offset_after": cursor,
                       "input_bytes_unchanged": unchanged, "status": found.returncode,
                       "stdout_bytes": len(found.stdout), "stdout_sha256": sha256(found.stdout)}
    finally:
        os.close(in_fd)


@contextmanager
def _sealed_image(image):
    exe_fd = sealed_executable(image, "worker-owned-sealed-stdin-image")
    try:
        if (fcntl.fcntl(exe_fd, GET_SEALS) != ALL_SEALS
                or os.pread(exe_fd, len(image) + 1, 0) != image):
            raise AssertionError("Exact static image capture changed")
        yield exe_fd
    finally:
        os.close(exe_fd)


def checked_adapter_readback(path, destination):
    args = ["/usr/bin/objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
            "--insn-width=15", "--adjust-vma=0x400000"]
    listing = subprocess.run([*args, "--start-address=0x4000b0", f"--stop-address={0x400000+PREFIX:#x}",
                              str(path)], check=True, capture_output=True, timeout=10).stdout
    destination.write_bytes(listing)
    # Exact reviewed byte hash is checked at build time. Disassembly independently
    # checks the syscall instruction locations and single linked-in call target.
    rows = {}
    for line in listing.decode("ascii").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].strip().endswith(":"):
            rows[int(parts[0].strip()[:-1], 16)] = parts[2].strip()
    actual = tuple(i - 0x400000 for i, text in rows.items() if text == "syscall")
    expected = (0xc1, 0xee, 0x10f, 0x13a, 0x152, 0x191, 0x1cf, 0x219, 0x23c, 0x24e, 0x2be, 0x34f)
    calls = tuple((i, op) for i, op in rows.items() if op.startswith("call"))
    if actual != expected or len(calls) != 1 or not calls[0][1].endswith("0x400358"):
        raise AssertionError("Static native syscall or WQX dispatch inventory changed")
    kernel = subprocess.run([*args, f"--start-address={0x400000+PREFIX:#x}", str(path)],
                            check=True, capture_output=True, timeout=10).stdout
    if any(line.split(b"\t")[-1].strip().split(b" ", 1)[0] in (b"syscall", b"sysenter", b"int")
           for line in kernel.splitlines() if b"\t" in line):
        raise AssertionError("Pure pinned Worker body contains a system-call instruction")
    return dict(zip((hex(i) for i in actual), ("fstat(0)", "fcntl(0,F_GET_SEALS)", "fstat(0)", "lseek(0,CUR)",
        "fstat(1)", "mmap(anonymous)", "read(0,data)", "read(0,EOF)", "lseek(0,CUR)", "close(0)",
        "write(1,WAO1)", "exit"), strict=True))


def refusal_controls(image, data, directory=None):
    late = snapshot(raw(row(-1)), raw({**row(3), "reputation_delta": "3"}))
    observed = {}
    for name, payload, seals, initial, exit_code, final in (
        ("no-seals", data, 0, 0, 70, 0),
        ("incomplete-seals", data, ALL_SEALS & ~SEAL_WRITE, 0, 70, 0),
        ("offset-is-not-rewound", data, ALL_SEALS, 1, 72, 1),
        ("one-byte-over-cap", b"\n" * (RAW_MAX + 1), ALL_SEALS, 0, 71, 0),
        ("late-parse-refusal-without-output", late, ALL_SEALS, 0, 74, len(late)),
    ):
        found, proof = physical_fixture(image, payload, initial=initial, seals=seals)
        if directory:
            case = fresh_directory(directory / name)
            (case / "input.raw").write_bytes(payload)
            (case / "stdout.raw").write_bytes(found.stdout)
            (case / "stderr.raw").write_bytes(found.stderr)
        if (found.returncode, found.stdout, proof["offset_after"]) != (exit_code, b"", final):
            raise AssertionError(f"Native refusal or read ownership differed: {name} {proof!r}")
        observed[name] = proof
    return observed


class WorkerJournalAuditStdin(unittest.TestCase):
    def test_exact_native_capability_and_seal_refusals(self):
        with tempfile.TemporaryDirectory(prefix="trnm-worker-sealed-stdin-") as temp:
            top = Path(temp)
            image, _ = build(top / "build")
            checked_adapter_readback(top / "build/fixture.elf", top / "adapter.txt")
            raw_data = snapshot(raw(row(-3)))
            success, proof = physical_fixture(image, raw_data)
            self.assertEqual((success.returncode, proof["offset_after"]), (0, len(raw_data)))
            jl, md, idx = artifacts(success.stdout)
            self.assertEqual(json.loads(jl)["reputation_delta"], -3)
            self.assertIn(b"| -3 |", md)
            self.assertEqual(json.loads(idx)["total_records"], 1)
            self.assertEqual(len(refusal_controls(image, raw_data)), 5)


def qualify(binary, original, output):
    def bound():
        return (original["repository_inputs"] == original_inputs()
                and original["executable_sha256"] == sha256(binary.read_bytes()))

    if not bound():
        raise AssertionError("Original Worker binary/source identity differs")
    declaration = declared_input()
    image, receipt = build(output / "build")
    syscall_sites = checked_adapter_readback(output / "build/fixture.elf", output / "adapter.txt")
    cases = {}
    for name, (data, records, chosen) in {**scenarios(), "exact_raw_cap": (near_raw_cap(), 2, 2)}.items():
        directory = fresh_directory(output / name)
        path = directory / "private-original.jsonl"
        path.write_bytes(data)
        path.chmod(0o600)
        expected = cli_artifacts(binary, path, "original", True, None)
        found, proof = physical_fixture(image, data)
        (directory / "stdout.raw").write_bytes(found.stdout)
        (directory / "stderr.raw").write_bytes(found.stderr)
        if ((found.returncode, proof["offset_after"]) != (0, len(data)) or artifacts(found.stdout) != expected
                or json.loads(expected[2])["total_records"] != chosen
                or (directory / "original.jsonl.index.json").read_bytes() != expected[2]):
            raise AssertionError(f"Physical native input / original artifact parity differs: {name}")
        cases[name] = {**proof, "input_records": records, "selected_records": chosen,
                       "artifacts": dict(zip(NAMES, map(sha256, expected), strict=True))}
    refusals = refusal_controls(image, snapshot(raw(row(-3))), output)
    if not bound() or declaration != declared_input():
        raise AssertionError("Original Worker source or executable changed during observation")
    report = {"schema": "trnm.worker-owned-sealed-stdin.qualification.v1", "status": "PASS",
              "cases": cases, "refusals": refusals, "build": receipt, "static_syscall_sites": syscall_sites,
              "original_struct_sha256": declaration, "original_executable_sha256": original["executable_sha256"],
              "original_sources": original_inputs(), "journal_path_opened_by_candidate": False,
              "output_authority": "held anonymous stdout pipe only",
              "full_syscall_trace_observed": False, "eintr_observed": False,
              "production_dispatch": False, "test_source_sha256": sha256(Path(__file__).read_bytes())}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-binary", type=Path, required=True)
    parser.add_argument("--original-build-receipt", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.original_binary.resolve(strict=True), json.loads(args.original_build_receipt.read_bytes()),
                     fresh_directory(args.output))
    print(json.dumps({key: report[key] for key in ("status", "cases", "refusals")}, sort_keys=True))


if __name__ == "__main__":
    main()
