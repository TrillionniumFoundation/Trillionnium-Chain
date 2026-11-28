"""Actual process interruption and explicit EIO controls at durable boundaries."""
import re
import struct

from .fixtures import record
from .cases_recovery import disk, expect
from .qualification_support import need
from .owned_process_trace import run as traced


def envelope(op, body=b""):
    return b"HCSAPI01" + struct.pack("<QQQ", op, len(body), 0) + body


def decode(raw):
    rows = []
    while raw:
        need(len(raw) >= 48 and raw[:8] == b"HCSAPO01", "Traced output has an incomplete envelope")
        header = struct.unpack("<5Q", raw[8:48])
        end = 48 + header[3]
        need(end <= len(raw), "Traced output has an incomplete payload")
        rows.append((header, raw[48:end]))
        raw = raw[end:]
    return rows


def snapshot(path):
    return {re.sub(r"\.tmp-\d+", ".tmp-PID", name): value for name, value in disk(path).items()}


def run(suite):
    cp0 = record()
    cp1 = record(1, predecessor=cp0[640:])
    cp2 = record(2, predecessor=cp1[640:])
    cp3 = record(3, predecessor=cp2[640:])
    # The expected crash-test pin is held separately BEFORE any traced run.
    # It comes from an independent successful original/native journal with the
    # same deterministic CAS input, never from the interrupted sibling head.
    golden = suite.pair("crash-external-custodian")
    golden.path(11, "j")
    empty_pin = golden.call(14)[1]
    golden.call(17, bytes(680) + cp0)
    full_pin = golden.call(14)[1]
    golden.call(19)
    golden.close()
    for ledger, boundaries in (
        (False, ("journal-write", "journal-fdatasync", "journal-directory-fdatasync",
                 "head-write", "head-fsync", "head-rename", "head-directory-fdatasync")),
        (True, ("ledger-record-write", "ledger-record-fsync", "ledger-record-rename",
                "ledger-record-directory-fsync", "ledger-head-write", "ledger-head-fsync",
                "ledger-head-rename", "ledger-head-directory-fsync")),
    ):
        fault_points = ({"journal-fdatasync", "journal-directory-fdatasync", "head-fsync", "head-rename"}
                        if not ledger else {"ledger-record-fsync", "ledger-record-directory-fsync",
                                            "ledger-head-fsync", "ledger-head-rename"})
        for inject in (False, True):
            for boundary in boundaries:
                if inject and boundary not in fault_points:
                    continue
                label = ("eio-" if inject else "crash-") + boundary
                p = suite.pair(label)
                paths = (p.na / "state", p.nb / "state") if ledger else (p.na, p.nb)
                traces, raw_outputs = [], []
                for kind, owner, path in zip(("native", "original"), (p.na, p.nb), paths):
                    if ledger:
                        payload = envelope(40, cp0 + bytes(path))
                        payload += envelope(43, cp0 + cp1) + envelope(42)
                        payload += envelope(44, cp0 + cp1) + envelope(45)
                    else:
                        payload = envelope(11, bytes(path / "j"))
                        payload += envelope(17, bytes(680) + cp0)
                        payload += envelope(16, cp0[16:48]) + envelope(14) + envelope(19)
                    executable = suite.native / "checkpoint-store-api" if kind == "native" else suite.original_api
                    evidence = suite.output / (label + "-" + kind)
                    trace = traced(executable, payload, evidence, storage=path, target=boundary, inject=inject)
                    traces.append(trace)
                    output = (evidence / "stdout.raw").read_bytes()
                    raw_outputs.append(output)
                    need(not (evidence / "stderr.raw").read_bytes(), "Traced API wrote an unexpected diagnostic")
                    decoded = decode(output)
                    if inject:
                        need(len(decoded) == 5 and decoded[0][0][0] == 0 and decoded[1][0][0] == 1,
                             "Injected syscall failure was acknowledged as success")
                        if ledger:
                            need(decoded[2][0][0] == 0 and decoded[2][1][8:680] == cp0
                                 and b"ledger owner is fenced" in decoded[3][1],
                                 "Ledger did not retain the original cached head/fenced owner behavior")
                        else:
                            need(all(b"authority unavailable" in row[1] for row in decoded[2:4]),
                                 "Failed authority mutation did not fence subsequent reads and exports")
                    else:
                        need(len(decoded) == 1 and decoded[0][0][0] == 0,
                             "Crash cut occurred after the mutation response")
                need(raw_outputs[0] == raw_outputs[1], "Traced native/original API errors or cached head differ")
                before = [snapshot(path) for path in paths]
                need(before[0] == before[1], ("Crash-stage native/original disk bytes differ", label, before))
                suite.emit({"kind": "durability-boundary", "case": label, "status": "PASS",
                            "fault_injected": inject, "power_failure_claimed": False,
                            "actions": [trace["actions"] for trace in traces],
                            "native_output": raw_outputs[0].hex(), "original_output": raw_outputs[1].hex(),
                            "disk_at_boundary": before})
                if ledger:
                    # A foreign operation context preserves every partial file.
                    expect(p.call(41, cp2 + cp3 + bytes(paths[0]), cp2 + cp3 + bytes(paths[1])),
                           1, "neither exact source nor exact target")
                    need([snapshot(path) for path in paths] == before, "ThirdState cleaned interrupted evidence")
                    p.call(41, cp0 + cp1 + bytes(paths[0]), cp0 + cp1 + bytes(paths[1]))
                    result = p.call(44, cp0 + cp1)
                    expected_target = boundary not in ("ledger-record-write", "ledger-record-fsync")
                    need(result[1] == struct.pack("<Q", expected_target), "Interrupted ledger resolved the wrong exact state")
                    p.call(45)
                else:
                    expect(p.call(12, empty_pin + bytes(paths[0] / "j"), empty_pin + bytes(paths[1] / "j")),
                           1, "external journal checkpoint mismatch")
                    need([snapshot(path) for path in paths] == before, "Wrong external pin repaired the sibling head")
                    p.call(12, full_pin + bytes(paths[0] / "j"), full_pin + bytes(paths[1] / "j"))
                    need(p.call(16, cp0[16:48])[1] == struct.pack("<Q", 1) + cp0,
                         "Matching separately retained pin did not recover the exact record")
                    need(p.call(14)[1] == full_pin, "Recovered journal pin differs")
                    p.call(19)
                need(snapshot(paths[0]) == snapshot(paths[1]), "Post-crash recovery disk bytes differ")
                p.close()
