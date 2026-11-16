"""Bind actual application results and preserve complete same-job CI evidence.

This hosted reader supplies no runtime result and never executes a native or
Rust algorithm. Successful binding requires the committed source, actual pipes,
all physical controls, public admission failures, and actual original tests.
Packaging preserves failures and never upgrades qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import traceback

from hia.tools import qualify_foundation_ci as base
from hia.tools import qualify_genesis_ci as transfer
from hia.tools import qualify_execution_ci as shared

ROOT = base.ROOT
SCHEMA = "trnm.hia.application-ci-binding.v1"
PACKAGE = "trnm.hia.application-ci-evidence.v1"
STAGE = "execution-application"
PREFIX = "hia-execution-application"
require, read, identity = base.require, base.read, base.identity
write_new, object_hash = base.write_new, base.object_hash
same, bytes_id = shared.equal, shared.bytes_id
STDIO = ("regular-stdin", "regular-stdout", "regular-stderr", "stdout-stderr-alias",
         "stdin-write-end", "stdout-read-end", "nonblocking-stdin",
         "nonblocking-stdout", "nonblocking-stderr")
BAD_FRAMES = (
    ("unknown-namespace", struct.pack("<Q", 8) + b"UNKNOWN1", 64),
    ("external-prepared-import", struct.pack("<Q", 16) + b"MPVALUE1" + bytes(8), 64),
    ("short-application", struct.pack("<Q", 8) + b"APPLY001", 64),
    ("application-length-disagreement",
     struct.pack("<Q", 40) + b"APPLY001" + struct.pack("<4Q", 1, 10, 1, 0), 73),
    ("invalid-callback-flag",
     struct.pack("<Q", 40) + b"APPLY001" + struct.pack("<4Q", 1, 10, 0, 2), 73))
BAD_ACKS = (
    ("bad-magic", b"NOTACK00" + struct.pack("<QQ", 1, 0)),
    ("stale-ordinal", b"APGO0001" + struct.pack("<QQ", 2, 0)),
    ("invalid-action", b"APGO0001" + struct.pack("<QQ", 1, 2)))
PRIVATE_NAMES = (
    "private-prepared-produced-by-actual-settings-wire-hash-and-signature-images",
    "short-prepared-refused-before-mutation", "short-private-work-refused-before-mutation",
    "private-fixture-not-ready-refused", "private-fixture-zero-generation-refused",
    "private-growth-reservation-before-application-or-state-mutation",
    "actual-prepared-private-initialization-keeps-generation-and-readonly-input",
    "private-generation-exhaustion-before-new-ready-or-mutation",
    "private-state-close-erases-owned-heap")


def observations(root):
    return root / (PREFIX + "-observations")


def actual_identity(value):
    require(transfer.file_id(value), "Malformed exact byte identity")
    return value


def positive_int(value, label, zero=False):
    require(type(value) is int and value >= (0 if zero else 1), label)
    return value


def hex_bytes(value):
    require(isinstance(value, str) and len(value) % 2 == 0
            and all(c in "0123456789abcdef" for c in value), "Noncanonical recorded bytes")
    return bytes.fromhex(value)


def u64(raw, offset):
    require(type(offset) is int and 0 <= offset <= len(raw) - 8, "Truncated private integer")
    return struct.unpack_from("<Q", raw, offset)[0]


def capture_file(source, target, expected):
    """Create or verify an independent evidence copy; never replace an old file."""
    if target.exists() or target.is_symlink():
        require(identity(source) == identity(target) == expected, "Existing capture differs")
    else:
        shared.captured_file(source, target, expected)


def file_tree(directory):
    require(directory.resolve(strict=True) == directory and directory.is_dir(),
            "Unaliased source directory required")
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "Symbolic source or evidence input")
        if path.is_dir():
            continue
        result[path.relative_to(directory).as_posix()] = identity(path)
    return result


def native_build(directory, repository, admitted):
    """Read all sixteen actual compiler/emitter streams, not only ELF claims."""
    from hia.platform.execution_application import source_graph as graph
    from hia.platform.execution_application import rust_oracle as oracle
    built = read(directory / "build.json")
    source, composed = oracle.validate_source_bindings(repository, {
        "schema": "trnm.execution-application-comparison.v1", "status": "PASS", "build": built})
    require(source == admitted["source_inputs"] and built["original_sources"] == admitted["original_sources"]
            and built["original_source_set_sha256"] == object_hash(admitted["original_sources"]),
            "Physical/compiler source closure differs from native semantics")
    require(file_tree(directory / "source-snapshot") == source, "Complete native source snapshot differs")
    expected = admitted["comparison"]["build"]
    for key in ("images", "elf_prefix", "executable", "composed_sources",
                "compiler_sha256", "compiler_qualification_binding", "toolchain"):
        require(same(built.get(key), expected.get(key)), "Actual compiled artifact differs: " + key)
    images = {}
    for name in (*graph.IMAGE_ORDER, "linux_emitter"):
        images[name] = base.regular(directory / (name + (".elf" if name == "linux_emitter" else ".flat"))).read_bytes()
        require(bytes_id(images[name]) == built["images"][name]
                and base.regular(directory / (name + "-composed.hepta")).read_bytes() == composed[name],
                "Exact compiled image/composition differs")
    prefix = base.regular(directory / "elf-prefix.raw").read_bytes()
    executable = base.regular(directory / "owner.elf").read_bytes()
    require(bytes_id(prefix) == built["elf_prefix"] and bytes_id(executable) == built["executable"]
            and executable == prefix + b"".join(images[name] for name in graph.IMAGE_ORDER),
            "Actual final ELF relationship differs")
    labels = ["compile-" + name for name in (*graph.IMAGE_ORDER, "linux_emitter")] + ["emit-prefix"]
    require([row.get("stage") for row in built["stages"]] == labels,
            "Actual native compiler stage inventory differs")
    for row, name in zip(built["stages"], (*graph.IMAGE_ORDER, "linux_emitter", "prefix"), strict=True):
        folder = directory / "pinned-native" / row["stage"]
        require(same(read(folder / "receipt.json"), row), "Native compiler independent receipt differs")
        raw_in = base.regular(folder / "stdin.raw").read_bytes()
        raw_out = base.regular(folder / "stdout.raw").read_bytes()
        raw_err = base.regular(folder / "stderr.raw").read_bytes()
        payload = struct.pack("<14Q", *(len(images[n]) for n in graph.IMAGE_ORDER)) if name == "prefix" else composed[name]
        emitted = prefix if name == "prefix" else images[name]
        expected_executable = bytes_id(images["linux_emitter"]) if name == "prefix" else {"sha256": base.COMPILER}
        positive_int(row.get("executable_bytes"), "Actual native executable extent absent")
        require(raw_in == payload and raw_out == emitted and raw_err == b""
                and {"bytes": row.get("input_bytes"), "sha256": row.get("input_sha256")} == bytes_id(raw_in)
                and {"bytes": row.get("output_bytes"), "sha256": row.get("output_sha256")} == bytes_id(raw_out)
                and row.get("stderr_sha256") == bytes_id(b"")["sha256"]
                and row.get("stderr_hex") == "" and row.get("executable_sha256") == expected_executable["sha256"],
                "Actual native compiler stream/pin differs")
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0
                and row.get("timed_out") is False and row.get("cleanup") is None
                and row.get("cleanup_limit_seconds") == 3 and row.get("wall_limit_seconds") == 30
                and row.get("environment") == {"PATH": ""}
                and len(row.get("argv", [])) == 1
                and re.fullmatch(r"/proc/self/fd/[0-9]+", row["argv"][0]) is not None
                and type(row.get("start_monotonic_ns")) is int
                and type(row.get("end_monotonic_ns")) is int
                and row["end_monotonic_ns"] > row["start_monotonic_ns"],
                "Native compiler process did not close")
    return built


def frame_journal(directory, stdin, stdout):
    """Every successful exchange must be an exact prefix of the actual pipes."""
    records = read(directory / "observed-frames.json")
    require(isinstance(records, list) and records, "Complete physical frame journal required")
    sent = bytearray()
    received = bytearray()
    commands = 0
    for row in records:
        require(set(row) == {"sent_hex", "received_hex", "elapsed_ns"}, "Unexpected frame observation")
        positive_int(row["elapsed_ns"], "Invalid physical frame duration", zero=True)
        incoming, outgoing = hex_bytes(row["sent_hex"]), hex_bytes(row["received_hex"])
        require(len(outgoing) >= 16, "Short native output frame")
        sent.extend(incoming)
        received.extend(struct.pack("<Q", len(outgoing)) + outgoing)
        if outgoing[:8] in (b"SVPRES01", b"APRESULT", b"MPRESULT"):
            commands += 1
    require(stdin.startswith(sent) and stdout == received,
            "Physical frame journal is not the full actual output or input prefix")
    return records, bytes(sent), commands


def physical_process(directory, declared, built, exit_code, *, trace=False, injected=False):
    receipt = read(directory / "receipt.json")
    require(same(receipt, declared) and receipt.get("schema") == "trnm.execution-state-native-process.v1"
            and receipt.get("executable") == built["executable"]
            and type(receipt.get("exit_code")) is int and receipt["exit_code"] == exit_code
            and receipt.get("cleanup") is None and receipt.get("cleanup_limit_seconds") == 3
            and receipt.get("wall_limit_seconds") == 240 and receipt.get("runtime_host_proxy") is False
            and receipt.get("instrumentation") == {"trace": trace, "mremap_errno_injected": injected}
            and receipt.get("unconsumed_stdout_hex") == "",
            "Physical actual process or lifetime differs")
    positive_int(receipt.get("pid"), "Actual process PID absent")
    positive_int(receipt.get("elapsed_ns"), "Actual physical duration absent")
    raw = {name: base.regular(directory / (name + ".raw")).read_bytes() for name in ("stdin", "stdout", "stderr")}
    require(receipt.get("files") == {name + ".raw": bytes_id(value) for name, value in raw.items()}
            and receipt.get("stdin_attempted_bytes") == receipt.get("stdin_actual_write_bytes") == len(raw["stdin"])
            and receipt.get("stdout_bytes") == len(raw["stdout"])
            and receipt.get("stderr_bytes") == len(raw["stderr"]),
            "Complete physical pipe identity/count differs")
    require(raw["stderr"] == (b"" if exit_code in (0, -9) else b"SVPFAIL1" + struct.pack("<Q", exit_code)),
            "Actual failure diagnostic differs")
    require(receipt.get("clean_close") is (exit_code == 0)
            and (exit_code != 0 or receipt.get("failure") is None), "Physical close classification differs")
    frames, sent, _ = frame_journal(directory, raw["stdin"], raw["stdout"])
    if trace:
        require(identity(directory / "syscalls.raw") == receipt.get("syscall_trace"),
                "Complete actual syscall trace differs")
    return receipt, raw, frames, sent


def private_journal(path, images, context, first_transaction):
    """Reparse paired direct native calls, exact buffers and fixture writes."""
    pending = None
    calls, writes, rows = [], [], 0
    with base.regular(path).open("rb") as stream:
        for line in stream:
            row = json.loads(line, object_pairs_hook=base.unique_object)
            rows += 1
            kind = row.get("kind")
            if kind == "private-adapter-fixture-write":
                require(pending is None and row.get("production_input") is False, "Fixture overlaps a native call")
                before, after, patch = (hex_bytes(row[key]) for key in ("before_hex", "after_hex", "bytes_hex"))
                offset = row["offset"]
                require(type(offset) is int and 0 <= offset <= len(before) - len(patch)
                        and after == before[:offset] + patch + before[offset + len(patch):],
                        "Private fixture write changed bytes outside its declared extent")
                writes.append(row)
                continue
            require(kind in ("native-call-start", "native-call-complete"), "Unknown private journal event")
            fields = {"kind", "index", "image", "image_identity", "capacities",
                      "input_hex", "output_before_hex", "private_before_hex"}
            if kind == "native-call-start":
                require(pending is None and set(row) == fields
                        and type(row.get("index")) is int and row["index"] == len(calls) + 1,
                        "Missing, duplicate or reordered native call")
                pending = row
                continue
            require(pending is not None and set(row) == fields | {
                "return", "input_after_hex", "output_after_hex", "private_after_hex"}
                and all(same(row[key], pending[key]) for key in fields - {"kind"}),
                "Native completion differs from its actual start")
            name, caps = row["image"], row["capacities"]
            require(name in images and row["image_identity"] == images[name]
                    and type(caps) is list and len(caps) == 3
                    and all(type(n) is int and n >= 0 for n in caps)
                    and type(row["return"]) is int and 0 <= row["return"] < 1 << 32,
                    "Invalid actual private image or three-capability shape")
            decoded = {key: hex_bytes(row[key]) for key in (
                "input_hex", "output_before_hex", "private_before_hex",
                "input_after_hex", "output_after_hex", "private_after_hex")}
            require([len(decoded[key]) for key in ("input_hex", "output_before_hex", "private_before_hex")] == caps
                    and [len(decoded[key]) for key in ("input_after_hex", "output_after_hex", "private_after_hex")] == caps
                    and decoded["input_hex"] == decoded["input_after_hex"],
                    "Native capability extent or readonly input changed")
            calls.append({**row, "decoded": decoded})
            pending = None
    require(pending is None and rows == 51 and len(calls) == 21 and len(writes) == 9,
            "Incomplete actual private-call journal")
    names = ["settings", "prepare_bridge", "prepare_bridge", "pnx", "prepare_bridge", "sha",
             "prepare_bridge", "ed", "prepare_bridge", "sha", "prepare_bridge", "prepare_bridge",
             "state", *["core"] * 6, "prepare_bridge", "state"]
    require([row["image"] for row in calls] == names, "Actual private operation order differs")
    def data(index, key):
        return calls[index - 1]["decoded"][key]
    def returned(index, expected):
        require(calls[index - 1]["return"] == expected, "Actual private return differs")
    from hia.platform.execution_application.native_io import parse_context
    from hia.platform.execution_state.native_io import command, decode
    extent = calls[0]["return"]
    require(calls[0]["capacities"] == [5, 16384, 1 << 20] and data(1, "input_hex") == b"SDV1\0"
            and 576 <= extent <= 16384, "Private actual Settings invocation differs")
    snapshot = data(1, "output_after_hex")[:extent]
    require(same(parse_context(b"APREADY1" + struct.pack("<Q", extent) + snapshot), context),
            "Private actual Settings differs from public native context")
    raw = bytes.fromhex(first_transaction["wire_hex"])
    initial = b"APPLY001" + struct.pack("<4Q", 1, first_transaction["height"], len(raw), 0) + raw
    require(data(2, "input_hex") == initial, "Private preparation does not use the real corpus wire")
    initial_private = bytearray(196608)
    initial_private[:extent] = snapshot
    struct.pack_into("<Q", initial_private, 50176, extent)
    require(data(2, "private_before_hex") == initial_private, "Prepared arena was not initialized from actual Settings")
    completion = bytearray(65536)
    previous = 2
    returned(2, 256)
    for index, crypto_index in ((3, None), (5, 4), (7, 6), (9, 8), (11, 10), (12, None)):
        if crypto_index is not None:
            nr, address, length = struct.unpack_from("<3Q", data(previous, "output_after_hex"))
            require({4097: "pnx", 4098: "sha", 4099: "ed"}.get(nr) == calls[crypto_index - 1]["image"]
                    and 131072 <= address <= 327680 and address - 131072 + length <= 196608
                    and data(crypto_index, "input_hex") ==
                        data(previous, "private_after_hex")[address - 131072:address - 131072 + length],
                    "Native crypto input is not the actual private continuation")
            struct.pack_into("<Q", completion, 0, calls[crypto_index - 1]["return"])
            completion[128:160] = data(crypto_index, "output_after_hex")
        struct.pack_into("<Q", completion, 8, u64(data(previous, "private_after_hex"), 50000))
        require(data(index, "input_hex") == completion
                and data(index, "private_before_hex") == data(previous, "private_after_hex")
                and data(index, "output_before_hex") == data(previous, "output_after_hex"),
                "Private preparation continuation lost real completion or arena continuity")
        previous = index
    for index, value in ((3, 0), (4, 0), (5, 0), (6, 32), (7, 0), (8, 0),
                         (9, 0), (10, 32), (11, 256), (12, 512)):
        returned(index, value)
    ready = data(12, "private_after_hex")[:65536]
    require(u64(ready, 50128) == 1 and u64(ready, 50136) > 0, "Actual private Prepared is not ready")
    returned(13, 1)
    require(data(13, "input_hex") == command(5)[8:], "Private State construction differs")
    base_handle = u64(data(13, "output_after_hex"), 32)
    require(base_handle > 0, "Private State result is not a live handle")
    expected_inputs = [ready[:50183], ready, ready, ready]
    for index, offset in ((16, 50128), (17, 50136)):
        damaged = bytearray(ready)
        struct.pack_into("<Q", damaged, offset, 0)
        expected_inputs[index - 14] = bytes(damaged)
    for index, expected in zip(range(14, 18), expected_inputs, strict=True):
        returned(index, 9)
        require(data(index, "input_hex") == expected
                and data(index, "private_before_hex") == data(index, "private_after_hex")
                and data(index, "output_before_hex") == data(index, "output_after_hex") == b"\x5b" * 4096,
                "Rejected private shape/Ready mutated output or work")
    require(calls[13]["capacities"] == [50183, 4096, 4096]
            and calls[14]["capacities"] == [65536, 4096, 4095],
            "Required three-capability truncation controls differ")
    returned(18, 3)
    before, after = data(18, "private_before_hex"), data(18, "private_after_hex")
    expected = bytearray(before)
    expected[32:40], expected[216:224] = after[32:40], after[216:224]
    require(data(18, "input_hex") == ready and after == expected and u64(after, 32) > len(before)
            and u64(after, 216) == 1 and data(18, "output_after_hex") == data(18, "output_before_hex"),
            "Private growth reservation mutated application state")
    returned(19, 7)
    require(data(19, "input_hex") == ready
            and u64(data(19, "private_after_hex"), 256) == u64(ready, 50136)
            and data(19, "output_after_hex") == data(19, "output_before_hex"),
            "Actual Prepared generation was not preserved")
    returned(20, 514)
    require(data(20, "input_hex") == initial
            and u64(data(20, "private_before_hex"), 51008) == (1 << 64) - 1
            and data(20, "private_after_hex") == data(20, "private_before_hex")
            and data(20, "output_after_hex") == data(20, "output_before_hex"),
            "Private generation exhaustion wrapped or mutated")
    returned(21, 4)
    require(data(21, "input_hex") == command(26)[8:]
            and data(21, "private_before_hex") == data(13, "private_after_hex")
            and data(21, "private_after_hex") == bytes(65536),
            "Actual private State close did not erase its owned heap")
    return {"records": rows, "actual_native_calls": len(calls),
            "full_three_buffer_bytes": True, "private_fixtures_are_production_inputs": False}


def physical(directory, repository, admitted):
    from hia.platform.execution_application import cases
    from hia.platform.execution_application.native_io import ReplaySession, command
    from hia.platform.execution_application.qualify import Observer
    from hia.platform.execution_state.cases import tape
    report = read(directory / "report.json")
    require(report.get("schema") == "trnm.execution-application-physical.v1"
            and report.get("status") == "PASS" and report.get("controls_total") == 32
            and report.get("actual_processes") == 23
            and report.get("trace_required") is True and report.get("trace_status") == "PASS"
            and report.get("verification") == {"primary_error": None, "cleanup_errors": [],
                "source_after": {"status": "PASS", "errors": []}}
            and report.get("original_rust") == "NOT_RUN",
            "Complete actual application physical qualification is required")
    for key in ("private_fixtures_are_production_inputs", "runtime_host_proxy", "complete_node"):
        require(report.get(key) is False, "Physical qualification scope changed")
    built = native_build(directory / "build", repository, admitted)
    require(same(report.get("build"), built), "Physical report build differs")
    names = ["actual-stdio-" + name for name in STDIO]
    names += ["actual-" + name + "-refused" for name, _, _ in BAD_FRAMES]
    names += ["actual-account-callback-" + name + "-refused" for name, _ in BAD_ACKS]
    names += ["actual-truncated-account-callback-refused", "actual-sigkill-at-live-account-callback",
              "actual-fresh-owner-after-abrupt-death", "actual-closed-output-is-epipe-not-sigpipe-or-success"]
    names += list(PRIVATE_NAMES) + ["actual-dynamic-unknown-value-through-application-and-full-state",
                                  "actual-kernel-enomem-without-partial-owned-result"]
    require([row.get("name") for row in report["controls"]] == names
            and all(row.get("status") == "PASS" for row in report["controls"]), "Physical control roster differs")
    controls = {row["name"]: row for row in report["controls"]}
    for name in STDIO:
        path = directory / ("stdio-" + name)
        receipt = read(path / "receipt.json")
        require(same(receipt, controls["actual-stdio-" + name]["receipt"])
                and receipt.get("kind") == name and receipt.get("exit_code") == 64
                and receipt.get("cleanup") is None and receipt.get("unchanged_file") is True
                and receipt.get("executable") == built["executable"]
                and base.regular(path / "stdout.raw").read_bytes() == b""
                and base.regular(path / "stderr.raw").read_bytes() == b"",
                "Actual stdio refusal emitted bytes or changed its file")
        meta = receipt["actual_descriptors"]
        require(len(meta) == 3 and all(type(row[key]) is int for row in meta for key in ("mode", "dev", "ino", "flags")),
                "Actual descriptor metadata is incomplete")
        if name.startswith("regular-"):
            index = {"stdin": 0, "stdout": 1, "stderr": 2}[name.split("-")[1]]
            require(stat.S_ISREG(meta[index]["mode"])
                    and base.regular(path / "unchanged-file").read_bytes() == b"unchanged descriptor refusal\0\xff",
                    "Regular stdio rejection did not preserve the actual target")
        elif name == "stdout-stderr-alias":
            require((meta[1]["dev"], meta[1]["ino"]) == (meta[2]["dev"], meta[2]["ino"]),
                    "Descriptor alias fixture did not use the same actual pipe")
        elif name.startswith("nonblocking-"):
            index = {"stdin": 0, "stdout": 1, "stderr": 2}[name.split("-")[1]]
            require(meta[index]["flags"] & os.O_NONBLOCK, "Actual nonblocking stdio fixture missing")
        elif name == "stdin-write-end":
            require(meta[0]["flags"] & os.O_ACCMODE == os.O_WRONLY, "Actual wrong stdin end missing")
        else:
            require(meta[1]["flags"] & os.O_ACCMODE == os.O_RDONLY, "Actual wrong stdout end missing")
    def process(name, control, code, **options):
        return physical_process(directory / name, controls[control]["process"], built, code, **options)
    for name, payload, code in BAD_FRAMES:
        _, raw, _, sent = process(name, "actual-" + name + "-refused", code)
        replay = ReplaySession(raw["stdin"], raw["stdout"])
        require(replay.context_fields == admitted["context"] and raw["stdin"] == payload and sent == b""
                and replay.output_at == len(raw["stdout"]), "Public malformed frame evidence differs")
    def at_callback(raw):
        replay = ReplaySession(raw["stdin"], raw["stdout"])
        observer = Observer(replay)
        handle = observer.state(5)["result"]
        for key, value in cases.base().items():
            observer.put(handle, key.encode(), tape(value))
        wire = cases.wire(1, cases.public(1) + cases.u64(10))
        frame = b"APPLY001" + struct.pack("<4Q", handle, 10, len(wire), 1) + wire
        reply = replay.exchange(struct.pack("<Q", len(frame)) + frame)
        require(reply[:8] == b"APCALL01" and u64(reply, 8) == 1
                and len(reply) == 24 + u64(reply, 16)
                and replay.output_at == len(raw["stdout"]), "Actual account callback was not reached")
        return replay, handle
    for name, ack in BAD_ACKS:
        _, raw, _, _ = process("callback-" + name, "actual-account-callback-" + name + "-refused", 64)
        replay, _ = at_callback(raw)
        require(raw["stdin"][replay.input_at:] == ack, "Actual malformed callback acknowledgement differs")
    _, raw, _, _ = process("callback-truncated", "actual-truncated-account-callback-refused", 74)
    replay, _ = at_callback(raw)
    require(raw["stdin"][replay.input_at:] == b"APGO0001" + struct.pack("<Q", 1),
            "Actual truncated acknowledgement differs")
    _, raw, _, _ = process("abrupt-callback", "actual-sigkill-at-live-account-callback", -9)
    replay, old_handle = at_callback(raw)
    require(replay.input_at == len(raw["stdin"])
            and controls["actual-sigkill-at-live-account-callback"]["clean_shutdown_claim"] is False,
            "Killed callback was relabelled as a clean close")
    _, raw, _, _ = process("fresh-after-kill", "actual-fresh-owner-after-abrupt-death", 0)
    replay = ReplaySession(raw["stdin"], raw["stdout"])
    stats, stale = replay.state(0), replay.state(9, old_handle, key=b"account:old")
    require(stats["live_objects"] == stats["live_blocks"] == 0 and stale["status"] == 65,
            "Fresh actual owner revived a dead process handle")
    replay.state(26); replay.finish()
    _, raw, _, sent = process("closed-output", "actual-closed-output-is-epipe-not-sigpipe-or-success", 74)
    require(raw["stdin"] == command(0) and sent == b"", "Closed output was not the actual failed State operation")
    journals = report["private_journals"]
    require(len(journals) == 1 and journals[0].get("path") == "private/private-calls.jsonl"
            and identity(directory / journals[0]["path"]) ==
                {key: journals[0][key] for key in ("bytes", "sha256")}, "Private journal bytes differ")
    checked = private_journal(directory / journals[0]["path"], built["images"], admitted["context"],
                              admitted["inputs"][0]["transactions"][0])
    require(all(same(journals[0].get(key), value) for key, value in checked.items())
            and controls[PRIVATE_NAMES[0]].get("native_continuations") == 6,
            "Private native call accounting differs")
    for name in (PRIVATE_NAMES[3], PRIVATE_NAMES[4], PRIVATE_NAMES[7]):
        require(controls[name].get("production_input") is False, "Private fixture became production authority")
    row = controls["actual-dynamic-unknown-value-through-application-and-full-state"]
    _, raw, _, _ = process("large-value", row["name"], 0, trace=True)
    actual_base = cases.base()
    actual_base[cases.account(0)]["unknown"] = {"ascii": "\0text", "large": "x" * ((1 << 20) + 1)}
    case = cases.history("physical-full-unknown-large-value", actual_base,
                         [cases.tx(1, cases.public(1) + cases.u64(10), root=True, expect="OK")])
    replay = ReplaySession(raw["stdin"], raw["stdout"])
    observed = Observer(replay).history(case)
    require(same(observed, row["complete_observation"])
            and observed["observations"][0]["root"]["error"] == "LIMIT"
            and row.get("new_value_or_state_limit") is False, "Actual dynamic Value/root error order differs")
    replay.state(26); replay.finish()
    trace = base.regular(directory / "large-value/syscalls.raw").read_text()
    moves = re.findall(r"mremap\((0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*MREMAP_MAYMOVE\)\s*=\s*(0x[0-9a-f]+)", trace)
    require(moves and any(old != new for old, _, _, new in moves)
            and [list(item) for item in moves] == row["actual_relocations"]
            and identity(directory / "large-value/syscalls.raw") == row["trace"]
            and "PROT_WRITE|PROT_EXEC" not in trace and "PROT_EXEC|PROT_WRITE" not in trace
            and re.search(r"mprotect\([^\n]*PROT_READ\)\s*=\s*0", trace)
            and re.search(r"munmap\([^\n]*\)\s*=\s*0", trace),
            "Actual relocation, readonly capture or teardown evidence is incomplete")
    row = controls["actual-kernel-enomem-without-partial-owned-result"]
    receipt, raw, _, sent = process("actual-enomem", row["name"], 72, trace=True, injected=True)
    require(raw["stdin"] == command(1, data=tape("x" * 5000)) and sent == b""
            and receipt["commands"] == 0 and row.get("explicit_errno_fixture") is True
            and row.get("physical_memory_exhaustion_claim") is False, "Actual ENOMEM fixture or scope differs")
    trace = base.regular(directory / "actual-enomem/syscalls.raw").read_text()
    require(re.search(r"mremap\([^\n]*\)\s*=\s*-1 ENOMEM[^\n]*INJECTED", trace),
            "Actual kernel ENOMEM injection is missing")
    return {"physical_report": identity(directory / "report.json"), "physical_controls": 32,
            "physical_processes": 23, "physical_trace": "PASS", "private_journals": journals}


def integrity_roster(sources):
    from hia.platform.execution_application.source_graph import REQUIRED
    roster = [("source-closure", "actual-complete-dynamic-source-fixture")]
    roster += [("every-source-omission", "omitted-" + name) for name in sorted(sources)]
    roster += [("physical-source-omission", "missing-owned-" + name) for name in sorted(REQUIRED)]
    roster += [("physical-source-omission", "missing-shared-" + name) for name in (
        "hia/platform/build.py", "hia/components.json", "hia/src/crypto/ed25519_verify.hepta", "config/pon/devnet-v1.json")]
    roster += [("forged-binding", "forged-" + name) for name in (
        "source_set_sha256", "compiler_sha256", "runtime_host_proxy", "original_rust_executed", "complete_node", "source_after")]
    roster += [("path-and-inventory", "escaping-" + repr(name)) for name in (
        "../escaped.py", "hia/../escaped.py", "/absolute.py", "hia\\escaped.py")]
    roster += [("path-and-inventory", name) for name in (
        "new-owned-source-cannot-be-omitted", "symbolic-owned-source", "stale-bytecode-directory")]
    roster += [("native-dependency-closure", name) for name in (
        "cycle", "missing-function", "escaping-include", "duplicate-json-key")]
    roster += [("canonical-corpus", name) for name in (
        "source-derived-328-histories", "single-bounded-xz-stream", "xz-truncated",
        "xz-trailing", "xz-concatenated", "xz-different")]
    roster += [("public-cli", "override-" + name.lower()) for name in (
        "RUSTC", "CARGO_BUILD_RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOC", "CARGO_PROFILE_DEV_OPT_LEVEL",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER")]
    roster += [("public-cli", "optimized-python"), ("actual-bundle", "actual-complete-native-bundle")]
    for name in ("source-omission", "semantic-observation", "history-omission", "process-omission"):
        roster += [("actual-bundle", "coherent-" + name), ("public-cli", "valid-bundle-" + name)]
    roster += [("actual-bundle", "coherent-actual-stdin-semantic-tamper"),
               ("public-cli", "valid-bundle-actual-stdin-tamper")]
    roster += [("actual-bundle", name) for name in (
        "missing-native-build/quota.flat", "missing-processes/008/observed-frames.json",
        "extra-artifact", "coherent-concatenated-corpus-stream", "all-mutants-restored-to-exact-valid-bundle")]
    roster += [("public-cli", "target-inside-repository")]
    return roster


def integrity(directory, repository, admitted, bundle):
    from hia.platform.execution_application import rust_oracle as oracle
    from hia.platform.execution_application import source_graph as graph
    report = read(directory / "report.json")
    expected = integrity_roster(admitted["source_inputs"])
    require(report.get("schema") == "trnm.execution-application-integrity.v1"
            and report.get("status") == "PASS" and report.get("primary_error") is None
            and report.get("source_after") == {"status": "PASS", "errors": []}
            and report.get("source_inputs") == admitted["source_inputs"]
            and report.get("source_set_sha256") == object_hash(admitted["source_inputs"])
            and report.get("actual_bundle_checked") is True
            and report.get("source_fixture_is_native_execution_claim") is False
            and report.get("original_rust_executed") is False,
            "Complete public application admission evidence is required")
    require([(row.get("group"), row.get("name")) for row in report["controls"]] == expected
            and all(row.get("status") == "PASS" for row in report["controls"])
            and type(report.get("groups")) is int and report["groups"] == 9
            and type(report.get("controls_total")) is int and report["controls_total"] == len(expected)
            and report.get("public_cli_controls") == 16,
            "Source, corpus or public-CLI negative control inventory differs")
    require(graph.complete_sources(directory / "source-fixture")[0] == admitted["source_inputs"],
            "Integrity fixture source restoration differs")
    oracle.utility.bounded_xz(directory / "xz-fixture.xz", admitted["corpus_raw"])
    restored = oracle.validate_bundle(repository, directory / "mutant-bundle")
    require(restored["bundle_artifacts"] == admitted["bundle_artifacts"],
            "Actual coherent negative controls did not restore the complete native bundle")
    by_name = {row["name"]: row for row in report["controls"]}
    require(by_name["actual-complete-dynamic-source-fixture"].get("native_execution_claim") is False
            and by_name["actual-complete-dynamic-source-fixture"].get("source_files") == len(admitted["source_inputs"])
            and by_name["source-derived-328-histories"].get("corpus") == bytes_id(admitted["corpus_raw"])
            and by_name["source-derived-328-histories"].get("histories") == 328
            and by_name["source-derived-328-histories"].get("transactions") == 335
            and by_name["actual-complete-native-bundle"].get("histories") == 328
            and by_name["actual-complete-native-bundle"].get("artifacts") == len(admitted["bundle_artifacts"]),
            "Source-only/native distinction or real bundle identity differs")
    for row in report["controls"]:
        group, name = row["group"], row["name"]
        if group != "public-cli":
            if "actual_rejection" in row:
                require(isinstance(row["actual_rejection"], str) and row["actual_rejection"],
                        "Negative control lost its actual refusal")
            continue
        folder = directory / ("cli-" + name)
        receipt = read(folder / "receipt.json")
        require(same(receipt, row["receipt"]) and type(receipt.get("exit_code")) is int
                and receipt["exit_code"] != 0 and receipt.get("source_copy_created") is False
                and receipt.get("original_rust_executed") is False,
                "Invalid public input was not actually rejected")
        positive_int(receipt.get("elapsed_ns"), "Public rejection duration absent")
        for channel in ("stdout", "stderr"):
            require(identity(folder / (channel + ".raw")) == receipt.get(channel),
                    "Actual public rejection output differs")
        argv = receipt["argv"]
        require(isinstance(argv, list) and argv and Path(argv[0]).is_absolute(),
                "Actual public gate Python executable is not absolute")
        selected = (directory / "unexecuted-empty-bundle" if name.startswith("override-") or name == "optimized-python"
                    else bundle if name == "target-inside-repository" else directory / "mutant-bundle")
        expected_argv = [argv[0], "-B"] + (["-O"] if name == "optimized-python" else []) + [
            "-m", "hia.platform.execution_application.rust_oracle",
            "--repository", str(repository), "--bundle", str(selected), "--output", str(folder / "output")]
        if name == "target-inside-repository":
            expected_argv += ["--target-dir", str(repository / "tria-invalid-application-target")]
        require(argv == expected_argv and not (folder / "output/isolated-source").exists()
                and not (folder / "output/isolated-source").is_symlink(),
                "Public negative control reached source-copy or ran a different entry")
        target = folder / "output/report.json"
        if name == "optimized-python":
            require(receipt.get("report_written") is False and not target.exists()
                    and b"Optimized Python is not admitted" in base.regular(folder / "stderr.raw").read_bytes(),
                    "Optimized public entry was not refused before running")
        else:
            rejected = read(target)
            require(receipt.get("report_written") is True and rejected.get("status") == "FAIL"
                    and rejected.get("stages") == [] and rejected.get("original_test_binary") is None
                    and rejected.get("actual_rust_tools") is None
                    and rejected.get("original_case_rows_observed") == 0
                    and rejected.get("controls") == rejected.get("passed") == rejected.get("failed") == 0
                    and rejected.get("original_tests") == []
                    and isinstance(rejected.get("failure"), dict) and rejected["failure"].get("error"),
                    "Rejected public input executed original Rust or lost its failure")
    return {"integrity_report": identity(directory / "report.json"), "integrity_groups": 9,
            "integrity_controls": len(expected), "public_cli_rejections": 16}


def original(directory, repository, admitted, *, capture=False, expected_target=None):
    """Recompute the differential solely from actual retained Rust stdout."""
    import tempfile
    from hia.platform.execution_application import rust_oracle as oracle
    report = read(directory / "report.json")
    require(report.get("schema") == "trnm.execution-application-original.v1"
            and report.get("status") == "PASS" and report.get("failure") is None
            and report.get("final_errors") == [] and report.get("missing_actual_tools") == []
            and all(type(report.get(key)) is int and report[key] == 328
                    for key in ("controls", "passed", "original_case_rows_observed"))
            and type(report.get("failed")) is int and report["failed"] == 0
            and report.get("original_tests") == report.get("required_original_tests") == list(oracle.TESTS)
            and report.get("source_inputs") == admitted["source_inputs"]
            and report.get("original_sources") == admitted["original_sources"]
            and report.get("bundle_artifacts") == admitted["bundle_artifacts"],
            "Complete bound actual original application comparison is required")
    for key in ("complete_node", "production_runtime_dependency", "runtime_host_proxy"):
        require(report.get(key) is False, "Original application scope changed")
    require(report.get("original_production_function_bytes_preserved") is True
            and identity(directory / "corpus.jsonl") == bytes_id(admitted["corpus_raw"]),
            "Original production prefix or actual corpus changed")
    labels = ("rustc-version", "rustc-sysroot", "rustc-selected-version", "cargo-original-metadata",
              "cargo-original-test-build", "list-original-tests",
              *(f"retained-original-{i}" for i in range(8)), "actual-execution-application-corpus")
    rows = shared.original_stages(directory, report, labels)
    isolated = directory / "isolated-source"
    production = base.regular(repository / oracle.STORE).read_bytes()
    hook = base.regular(repository / oracle.OWNED / "rust_reference.rs").read_bytes()
    hook_name = (Path(oracle.STORE).parent / oracle.HOOK).as_posix()
    adapted = {**admitted["original_sources"], oracle.STORE: bytes_id(production + oracle.DECL),
               hook_name: bytes_id(hook)}
    require(oracle.original_manifest(isolated) == adapted
            and base.regular(isolated / oracle.STORE).read_bytes() == production + oracle.DECL
            and base.regular(isolated / hook_name).read_bytes() == hook,
            "Original copied source or sole private hook differs")
    tools = report.get("actual_rust_tools")
    require(type(tools) is dict and set(tools) == {"rustc", "cargo", "rustdoc"},
            "Actual original compiler/Cargo identities absent")
    sysroot = Path(rows["rustc-sysroot"][1].decode().strip())
    require(sysroot.is_absolute() and sysroot.resolve(strict=True) == sysroot, "Actual Rust sysroot is not canonical")
    for name, item in tools.items():
        path = Path(item["path"])
        require(path == (sysroot / "bin" / name).resolve(strict=True) and path.is_absolute()
                and identity(path) == {key: item[key] for key in ("bytes", "sha256")},
                "Actually invoked absolute Rust tool changed")
    require(rows["rustc-version"][0]["argv"] == ["rustc", "-Vv"]
            and rows["rustc-sysroot"][0]["argv"] == ["rustc", "--print", "sysroot"]
            and rows["rustc-selected-version"][0]["argv"] == [tools["rustc"]["path"], "-Vv"]
            and rows["rustc-version"][1] == rows["rustc-selected-version"][1]
            and re.search(rb"(?m)^host: x86_64-unknown-linux-gnu$", rows["rustc-version"][1])
            and all(rows[label][0]["stderr"]["bytes"] == 0 for label in labels[:3]),
            "Actual compiler selection or version differs")
    manifest = str(isolated / "trillionnium/Cargo.toml")
    require(rows["cargo-original-metadata"][0]["argv"] == [
        tools["cargo"]["path"], "metadata", "--locked", "--format-version=1", "--filter-platform",
        "x86_64-unknown-linux-gnu", "--manifest-path", manifest], "Actual Cargo metadata entry differs")
    build_prefix = [tools["cargo"]["path"], "test", "--locked", "--manifest-path", manifest,
                    "-p", "trnm-mvcc-fee", "--lib", "--no-run", "--message-format=json", "--target-dir"]
    argv = rows["cargo-original-test-build"][0]["argv"]
    require(argv[:-1] == build_prefix and len(argv) == len(build_prefix) + 1
            and all(row[0].get("cwd") == str(isolated) for row in rows.values()),
            "Actual Cargo/test working directory or arguments differ")
    target = Path(argv[-1])
    require(target.is_absolute() and target.resolve(strict=True) == target
            and target != repository and repository not in target.parents
            and target != directory and directory not in target.parents
            and (expected_target is None or target == expected_target),
            "Actual Cargo target is not the admitted isolated CI target")
    events = [json.loads(line, object_pairs_hook=base.unique_object)
              for line in rows["cargo-original-test-build"][1].splitlines() if line.startswith(b"{")]
    libraries, binaries = oracle.utility.original_artifacts(
        [row for row in events if row.get("reason") == "compiler-artifact"])
    require(len(libraries) == len(binaries) == 1, "Actual serde lib or M06 binary is not unique")
    before = read(directory / "original-binary-before.json")
    binary_path = directory / "original-test-binary"
    binary = identity(binary_path)
    require(same(before.get("artifact"), binaries[0])
            and before.get("source") == binaries[0]["executable"]
            and target in Path(binaries[0]["executable"]).parents
            and before.get("retained") == str(binary_path)
            and {key: before[key] for key in ("bytes", "sha256")} == binary
            and report.get("original_test_binary") == {"path": str(binary_path), **binary},
            "Independent original binary does not match the actual compiler artifact")
    meta = base.regular(binary_path).stat()
    require(meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o500,
            "Original independent executable mode or links changed")
    require(rows["list-original-tests"][0]["argv"] == [str(binary_path), "--list"], "Different linked test roster")
    linked = {line.removesuffix(": test") for line in rows["list-original-tests"][1].decode().splitlines()
              if line.endswith(": test")}
    require({oracle.TEST, *oracle.TESTS} <= linked, "Required actual original tests are absent")
    for label, name in [(f"retained-original-{i}", name) for i, name in enumerate(oracle.TESTS)] + [
        ("actual-execution-application-corpus", oracle.TEST)]:
        require(rows[label][0]["argv"] == [str(binary_path), "--exact", name, "--nocapture", "--test-threads=1"],
                "Actual original test invocation differs")
        shared.positive_test(rows[label][1], name)
    output = rows["actual-execution-application-corpus"][1]
    contexts = [json.loads(line.split(b"APCONTEXT:", 1)[1], object_pairs_hook=base.unique_object)
                for line in output.splitlines() if b"APCONTEXT:" in line]
    actual = [json.loads(line.split(b"AP_ORIGINAL:", 1)[1], object_pairs_hook=base.unique_object)
              for line in output.splitlines() if b"AP_ORIGINAL:" in line]
    require(len(contexts) == 1 and same(contexts[0], report.get("actual_original_context")),
            "Actual original Config observation missing or changed")
    for name in ("network", "parameters", "family", "plan", "params", "fees", "evaluators"):
        require(same(contexts[0][name], admitted["context"][name]), "Actual original/native Config differs")
    require(len(actual) == 328 and [row.get("name") for row in actual] ==
            [row["name"] for row in admitted["inputs"]], "Actual original histories missing or reordered")
    controls = read(directory / "comparison.json")
    require(controls.get("schema") == "trnm.execution-application-original-controls.v1"
            and len(controls.get("controls", [])) == 328, "Complete original comparison file missing")
    transactions = 0
    for row, native, control in zip(actual, admitted["comparison"]["cases"], controls["controls"], strict=True):
        require(all(same(native[key], row[key]) for key in ("name", "before_hex", "observations"))
                and row.get("actual_private_preparation") is True
                and row.get("actual_original_application") is True
                and row.get("native_runtime_host_proxy") is False,
                "Actual original application observation differs")
        require(same(control, {"name": native["name"], "status": "PASS", "differences": [],
                               "native": native, "original": row}), "Original comparison summary differs from actual stdout")
        transactions += len(row["observations"])
    require(transactions == 335 and same(read(directory / "original-observations.json"),
            {"cases": actual, "complete_differential_pass": True}), "Original observed transaction count differs")
    metadata = json.loads(rows["cargo-original-metadata"][1], object_pairs_hook=base.unique_object)
    with tempfile.TemporaryDirectory(prefix="application-ci-registry-read-") as temporary:
        serde, recapture = oracle.utility.capture_serde_graph(metadata, isolated, Path(temporary))
        require(same(serde, report.get("serde_json_source"))
                and same(serde, read(directory / "serde-json-source-before.json"))
                and recapture() == serde["crate_sources"], "Actual locked registry source binding differs")
    library = report.get("actual_serde_library")
    require(type(library) is dict and same(read(directory / "actual-serde-library-before.json"), library)
            and same(library.get("artifact"), libraries[0])
            and libraries[0]["package_id"] == serde["package"]["id"]
            and set(libraries[0].get("features", [])) == {"default", "std"}
            and libraries[0]["target"].get("kind") == ["lib"]
            and libraries[0]["target"].get("src_path") == str(Path(serde["crate_directory"]) / "src/lib.rs"),
            "Actually compiled serde library source/features differ")
    rlibs = [value for value in libraries[0]["filenames"] if value.endswith(".rlib")]
    require(rlibs == [library["source_path"]] and target in Path(rlibs[0]).parents
            and library.get("retained_path") == str(directory / "actual-serde-library.rlib")
            and identity(directory / "actual-serde-library.rlib") == library.get("identity"),
            "Retained actual serde library differs")
    common = {
        "complete_native_source": {"status": "MATCH", "files": len(admitted["source_inputs"]),
                                   "sha256": object_hash(admitted["source_inputs"])},
        "actual_original_source": {"status": "MATCH", "files": len(admitted["original_sources"]),
                                   "sha256": object_hash(admitted["original_sources"])},
        "complete_native_artifacts_and_corpus": {"status": "MATCH", "files": len(admitted["bundle_artifacts"]),
                                                "sha256": object_hash(admitted["bundle_artifacts"])}}
    isolated_check = {"status": "MATCH", "files": len(adapted), "sha256": object_hash(adapted)}
    compiled = {"actual_original_binary": {"status": "MATCH", **binary},
                "actual_serde_source": {"status": "MATCH", "files": len(serde["crate_sources"]),
                                       "sha256": object_hash(serde["crate_sources"])},
                "actual_serde_library": {"status": "MATCH", **library},
                "actual_compilers": {"status": "MATCH", "tools": tools}}
    expected_fences = []
    for label in ("source-before", "isolated-source-before", "compiled-source-and-binary-before", "source-and-binary-after"):
        checks = dict(common)
        if label != "source-before":
            checks["isolated_original_and_exact_hook"] = isolated_check
        if label in ("compiled-source-and-binary-before", "source-and-binary-after"):
            checks.update(compiled)
        expected_fences.append({"label": label, "status": "PASS", "checks": checks, "errors": []})
    require(same(report.get("source_fences"), expected_fences), "Exact source/tool/binary fence inventory differs")
    for fence in expected_fences:
        require(same(read(directory / (fence["label"] + ".json")), fence), "Independent actual fence differs")
    if capture:
        selected = {oracle.STORE: adapted[oracle.STORE], hook_name: adapted[hook_name],
                    "trillionnium/Cargo.lock": adapted["trillionnium/Cargo.lock"]}
        selected.update({name: expected for name, expected in adapted.items()
                         if Path(name).parts[0] not in ("trillionnium", "config", "formal")})
        for name, expected in selected.items():
            capture_file(isolated / name, directory / "source-capture" / name, expected)
        archive = serde["registry_archive"]
        capture_file(Path(archive["path"]), directory / "dependency-snapshot/serde_json.crate",
                     {key: archive[key] for key in ("bytes", "sha256")})
        for name, expected in serde["crate_sources"].items():
            capture_file(Path(serde["crate_directory"]) / base.member_path(name),
                         directory / "dependency-snapshot/serde-json" / name, expected)
        capture_file(repository / oracle.STORE, directory / "source-capture/original-production-prefix.rs",
                     admitted["original_sources"][oracle.STORE])
    return {"original_report": identity(directory / "report.json"), "original_binary": binary,
            "original_histories": 328, "original_transactions": transactions,
            "retained_original_tests": list(oracle.TESTS), "actual_rust_tools": tools,
            "actual_serde_library": library["identity"],
            "actual_serde_source_set_sha256": serde["crate_source_set_sha256"],
            "locked_registry_archive": {key: serde["registry_archive"][key] for key in ("bytes", "sha256")},
            "complete_original_source_files": len(adapted)}


def evidence_roots(root):
    return {"observations": observations(root), "bootstrap": root / "hia-bootstrap",
            "native": root / (PREFIX + "-native"), "physical": root / (PREFIX + "-physical"),
            "integrity": root / (PREFIX + "-integrity"), "original": root / (PREFIX + "-original")}


def excluded(name):
    # Exclude only the explicit reproducible Rust source tree. Capture its exact
    # production prefix, hook, lock and out-of-tree include fixtures before bind.
    return name == "original/isolated-source" or name.startswith("original/isolated-source/")


def diagnostic_in_progress(name):
    # CI's tee for this invocation is still open while binding/packing runs.
    return name in {"observations/binding.log", "observations/packaging.log"}


def special_metadata(path, before):
    kind = ("symlink" if stat.S_ISLNK(before.st_mode) else "fifo" if stat.S_ISFIFO(before.st_mode)
            else "socket" if stat.S_ISSOCK(before.st_mode) else "other")
    row = {"type": kind, "mode": stat.S_IMODE(before.st_mode), "device": before.st_dev,
           "inode": before.st_ino, "uid": before.st_uid, "gid": before.st_gid,
           "links": before.st_nlink, "bytes": before.st_size, "opened": False}
    if kind == "symlink":
        row["link_text"] = os.readlink(path)
    return row


def evidence_inventory(roots):
    regular, special = {}, {}
    def visit(path, name):
        base.member_path(name)
        if excluded(name) or diagnostic_in_progress(name) or name == "observations/binding.json":
            return
        before = path.lstat()
        if stat.S_ISDIR(before.st_mode):
            for child in sorted(path.iterdir()):
                visit(child, name + "/" + child.name)
        elif stat.S_ISREG(before.st_mode):
            regular[name] = identity(path)
        else:
            special[name] = special_metadata(path, before)
    for label, directory in roots.items():
        if directory.exists() or directory.is_symlink():
            require(directory.resolve(strict=True) == directory and directory.is_dir(), "Aliased evidence root")
            visit(directory, label)
    return regular, special


def check_binding(value, expected):
    require(type(value) is dict and value.get("schema") == SCHEMA and value.get("stage") == STAGE
            and value.get("status") == "PASS" and same(value.get("lineage"), expected),
            "Application binding is failed or belongs to another head/run/attempt")
    expected_counts = {"native_histories": 328, "native_transactions": 335, "native_state_commands": 8784,
                       "native_processes": 9, "physical_controls": 32, "physical_processes": 23,
                       "integrity_groups": 9, "public_cli_rejections": 16, "original_histories": 328,
                       "original_transactions": 335}
    require(all(type(value.get(key)) is int and value[key] == count for key, count in expected_counts.items())
            and type(value.get("integrity_controls")) is int
            and value["integrity_controls"] == len(integrity_roster(value["source_inputs"]))
            and value.get("source_set_sha256") == object_hash(value["source_inputs"])
            and value.get("original_source_set_sha256") == object_hash(value["original_sources"])
            and value.get("physical_trace") == value.get("original_rust") == "PASS",
            "Application binding omits a complete qualification stage")
    for name in ("whole_node_or_commit_authority", "admission_persistence", "batch_execution_qualified",
                 "physical_power_loss", "nondefault_configurations"):
        require(value.get(name) is False, "Application binding scope expanded")
    from hia.platform.execution_application import rust_oracle as oracle
    require(value.get("retained_original_tests") == list(oracle.TESTS), "Complete retained original tests absent")
    require(type(value.get("evidence_files")) is dict and value["evidence_files"]
            and value.get("evidence_set_sha256") == object_hash(value["evidence_files"]),
            "Complete bound evidence roster absent")
    for name, field in (("native/report.json", "native_report"), ("physical/report.json", "physical_report"),
                        ("integrity/report.json", "integrity_report"), ("original/report.json", "original_report"),
                        ("original/original-test-binary", "original_binary")):
        require(transfer.file_id(value.get(field)) and value["evidence_files"].get(name) == value[field],
                "Mandatory full qualification artifact absent: " + name)
    for name, row in value["evidence_files"].items():
        path = base.member_path(name)
        require(path.parts[0] in evidence_roots(Path("/unused")) and transfer.file_id(row),
                "Invalid bound evidence path/identity")


def bind(root):
    from hia.platform.execution_application import rust_oracle as oracle
    expected = base.lineage()
    source_pair = transfer.source_pair(observations(root), expected)
    native = root / (PREFIX + "-native")
    admitted = oracle.validate_bundle(ROOT, native / "bundle")
    require(same(read(native / "report.json"), admitted["report"])
            and admitted["report"]["histories_total"] == 328
            and admitted["report"]["transactions"] == 335
            and admitted["report"]["state_commands"] == 8784
            and admitted["report"]["actual_processes"] == 9, "Complete actual native application suite differs")
    built = native_build(native / "build", ROOT, admitted)
    require(same(built, admitted["comparison"]["build"]), "Native suite build differs from its full actual compiler streams")
    result = {"schema": SCHEMA, "stage": STAGE, "status": "PASS", "lineage": expected,
              "source_observations": source_pair,
              "whole_node_or_commit_authority": False, "admission_persistence": False,
              "batch_execution_qualified": False, "physical_power_loss": False,
              "nondefault_configurations": False,
              "source_inputs": admitted["source_inputs"], "original_sources": admitted["original_sources"],
              "source_set_sha256": object_hash(admitted["source_inputs"]),
              "original_source_set_sha256": object_hash(admitted["original_sources"]),
              "native_report": identity(native / "report.json"), "bundle_artifacts": admitted["bundle_artifacts"],
              "executable": built["executable"], "native_histories": 328, "native_transactions": 335,
              "native_state_commands": 8784, "native_processes": 9, "original_rust": "PASS"}
    result.update(physical(root / (PREFIX + "-physical"), ROOT, admitted))
    result.update(integrity(root / (PREFIX + "-integrity"), ROOT, admitted, native / "bundle"))
    result.update(original(root / (PREFIX + "-original"), ROOT, admitted, capture=True,
                           expected_target=root / (PREFIX + "-cargo-target")))
    # The two source maps may overlap, but a union must never hide a disagreement.
    require(all(admitted["source_inputs"][name] == admitted["original_sources"][name]
                for name in set(admitted["source_inputs"]) & set(admitted["original_sources"])),
            "Overlapping source identities differ")
    readers = {name: identity(ROOT / name) for name in (
        "hia/tools/qualify_application_ci.py", "hia/tests/test_application_ci.py",
        "hia/tools/qualify_execution_ci.py", "hia/tools/qualify_foundation_ci.py",
        "hia/tools/qualify_genesis_ci.py")}
    base.check_committed_sources({**admitted["original_sources"], **admitted["source_inputs"], **readers}, ROOT)
    result["ci_reader_sources"] = readers
    require(same(source_pair, transfer.source_pair(observations(root), expected)), "Source proof changed during binding")
    files, special = evidence_inventory(evidence_roots(root))
    result.update(evidence_files=files, evidence_set_sha256=object_hash(files), special_evidence_metadata=special)
    check_binding(result, expected)
    write_new(observations(root) / "binding.json", result)
    return result


def verify_archive(archive, entries):
    """Reopen every written byte/member before declaring a package complete."""
    import lzma
    import tempfile
    require(type(entries) is dict and entries, "Written archive inventory is empty")
    bound = 2 * tarfile.RECORDSIZE
    for name, row in entries.items():
        path = base.member_path(name)
        require(path.parts[0] in {"native", "physical", "integrity", "original", "observations", "bootstrap"}
                and type(row) is dict and row.get("type") in ("0", "5") and row.get("linkname") == ""
                and type(row.get("bytes")) is int and row["bytes"] >= 0,
                "Invalid written archive inventory")
        require((row["type"] == "0" and transfer.file_id({key: row[key] for key in ("bytes", "sha256")}))
                or (row["type"] == "5" and row["bytes"] == 0), "Invalid written member identity")
        # One normal header plus bounded optional PAX path metadata. Actual data
        # extent comes only from the descriptor-bound write inventory.
        bound += ((row["bytes"] + 511) // 512) * 512
        bound += 1024 + ((len(name.encode("utf-8")) + 1023) // 512) * 512
    before = identity(archive)
    try:
        with tempfile.TemporaryFile() as expanded:
            decoder = lzma.LZMADecompressor(memlimit=64 << 20)
            expanded_bytes = 0
            with base.regular(archive).open("rb") as incoming:
                while not decoder.eof:
                    chunk = incoming.read(1 << 20) if decoder.needs_input else b""
                    require(chunk or not decoder.needs_input, "Truncated written XZ archive")
                    block = decoder.decompress(chunk, max_length=min(1 << 20, bound - expanded_bytes + 1))
                    expanded_bytes += len(block)
                    require(expanded_bytes <= bound, "Written archive exceeds its declared member extent")
                    expanded.write(block)
                require(not decoder.unused_data and not incoming.read(1), "Trailing or concatenated written XZ archive")
            expanded.seek(0)
            seen, regular_bytes, last_end = set(), 0, 0
            with tarfile.open(fileobj=expanded, mode="r:") as packed:
                for member in packed:
                    require(member.name in entries and member.name not in seen,
                            "Extra or duplicate written archive member")
                    seen.add(member.name)
                    row = entries[member.name]
                    base.member_path(member.name)
                    require(member.type.decode("ascii") == row["type"]
                            and member.size == row["bytes"] and member.linkname == ""
                            and not member.sparse and set(member.pax_headers) <= {"path"}
                            and member.mode == (0o700 if member.isdir() else
                                                0o500 if member.name == "original/original-test-binary" else 0o600),
                            "Written archive member metadata differs")
                    last_end = member.offset_data + ((member.size + 511) // 512) * 512
                    if member.isfile():
                        digest, size = hashlib.sha256(), 0
                        with packed.extractfile(member) as stream:
                            while block := stream.read(1 << 20):
                                size += len(block)
                                require(size <= row["bytes"], "Written member exceeded its recorded extent")
                                digest.update(block)
                        require({"bytes": size, "sha256": digest.hexdigest()} ==
                                {key: row[key] for key in ("bytes", "sha256")},
                                "Written archive regular bytes differ")
                        regular_bytes += size
            require(seen == set(entries), "Missing written archive member")
            expanded.seek(last_end)
            tail = expanded.read(tarfile.RECORDSIZE + 1025)
            require(1024 <= len(tail) <= tarfile.RECORDSIZE + 1024 and not any(tail)
                    and not expanded.read(1) and expanded_bytes % tarfile.RECORDSIZE == 0,
                    "Noncanonical or hidden trailing tar bytes")
        require(identity(archive) == before, "Written archive changed during independent reread")
    except (lzma.LZMAError, tarfile.TarError) as error:
        raise ValueError("Unreadable written evidence archive") from error
    return {"status": "PASS", "archive": before, "members": len(seen),
            "regular_members": sum(row["type"] == "0" for row in entries.values()),
            "regular_bytes": regular_bytes, "expanded_tar_bytes": expanded_bytes,
            "complete_xz_stream_and_tar_padding_verified": True,
            "special_files_remain_metadata_only": True}


def pack(root):
    """Always retain actual bytes; absence/failure of binding stays unqualified."""
    output = root / (PREFIX + "-artifact")
    output.mkdir(mode=0o700)
    observed = observations(root)
    observed.mkdir(mode=0o700, exist_ok=True)
    record = {"schema": PACKAGE, "stage": STAGE, "packing_status": "FAIL",
              "qualification_status": "NOT_BOUND", "qualification_status_not_changed_by_packaging": True,
              "complete_original_test_binary_is_not_excluded": True,
              "excluded_reconstructible_original_source": "original/isolated-source",
              "entries": {}, "special_entries": {}, "capture_errors": []}
    archive = output / "complete-evidence.tar.xz"
    errors = record["capture_errors"]
    try:
        record["lineage"] = base.lineage()
    except BaseException as error:
        errors.append({"stage": "lineage", "error": repr(error)})
        record["lineage"] = None
    try:
        with tarfile.open(archive, "x:xz", preset=1) as packed:
            def retain(path, name):
                relative = base.member_path(name)
                if excluded(name):
                    return
                require(name not in record["entries"] and name not in record["special_entries"],
                        "Duplicate archive evidence path")
                before = path.lstat()
                if stat.S_ISDIR(before.st_mode):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, 0o700
                    packed.addfile(member)
                    record["entries"][name] = {"type": "5", "bytes": 0, "linkname": ""}
                    children = sorted(path.iterdir())
                    for child in children:
                        retain(child, name + "/" + child.name)
                    require([p.name for p in children] == [p.name for p in sorted(path.iterdir())],
                            "Evidence directory changed during capture")
                elif stat.S_ISREG(before.st_mode):
                    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(descriptor, "rb") as stream:
                        held = os.fstat(stream.fileno())
                        require(stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino) ==
                                (before.st_dev, before.st_ino), "Evidence path changed before capture")
                        member = tarfile.TarInfo(name)
                        member.size = held.st_size
                        member.mode = 0o500 if name == "original/original-test-binary" else 0o600
                        digest = hashlib.sha256()
                        class HashedReader:
                            def read(self, length):
                                raw = stream.read(length)
                                digest.update(raw)
                                return raw
                        packed.addfile(member, HashedReader())
                        after = os.fstat(stream.fileno())
                    current = path.lstat()
                    require((held.st_size, held.st_mtime_ns, held.st_ctime_ns) ==
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                            "Evidence file changed while capturing complete bytes")
                    record["entries"][name] = {"type": "0", "bytes": held.st_size,
                        "sha256": digest.hexdigest(), "linkname": "", "source_mode": stat.S_IMODE(held.st_mode)}
                else:
                    record["special_entries"][name] = special_metadata(path, before)
            for label, directory in evidence_roots(root).items():
                if not directory.exists() and not directory.is_symlink():
                    continue
                try:
                    require(directory.resolve(strict=True) == directory and directory.is_dir(), "Aliased evidence root")
                    retain(directory, label)
                except BaseException as error:
                    errors.append({"stage": "capture-" + label, "error": repr(error),
                                   "traceback": traceback.format_exc()})
        record["archive_verification"] = verify_archive(archive, record["entries"])
        record["archive"] = record["archive_verification"]["archive"]
        path = observed / "binding.json"
        if path.exists() or path.is_symlink():
            value = read(path)
            check_binding(value, record["lineage"])
            require(same(transfer.source_pair(observed, record["lineage"]), value["source_observations"]),
                    "Bound source observations changed before packaging")
            for name, expected in value["evidence_files"].items():
                entry = record["entries"].get(name)
                require(type(entry) is dict and entry.get("type") == "0"
                        and {key: entry[key] for key in ("bytes", "sha256")} == expected,
                        "Bound evidence omitted or changed before packaging: " + name)
            from hia.platform.execution_application import source_graph as graph
            current, _ = graph.complete_sources(ROOT)
            require(current == value["source_inputs"] and graph.original_manifest(ROOT) == value["original_sources"],
                    "Bound source closure changed before packaging")
            base.check_committed_sources({**value["original_sources"], **value["source_inputs"],
                                          **value["ci_reader_sources"]}, ROOT)
            require(record["special_entries"] == value["special_evidence_metadata"],
                    "Special evidence metadata changed before packaging")
            capture_file(path, output / "binding.json", identity(path))
            record["binding"] = identity(output / "binding.json")
            record["qualification_status"] = "PASS"
        require(not errors, "One or more evidence roots could not be captured completely")
        record["packing_status"] = "PASS"
    except BaseException as error:
        errors.append({"stage": "package", "error": repr(error), "traceback": traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():
            record["partial_archive"] = identity(archive)
    finally:
        write_new(output / "package-manifest.json", record)
    require(record["packing_status"] == "PASS", "Partial archive and exact packaging failure retained")
    return {"stage": STAGE, "packing_status": record["packing_status"],
            "qualification_status": record["qualification_status"],
            "archive": record["archive"], "members": len(record["entries"]),
            "special_metadata_entries": len(record["special_entries"]),
            "qualification_status_not_changed_by_packaging": True}


def main():
    require(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized application CI evidence reader is not admitted")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bind", "pack"))
    args = parser.parse_args()
    root = Path(os.environ["RUNNER_TEMP"]).absolute()
    require(root.resolve(strict=True) == root, "Unaliased runner evidence root required")
    try:
        result = globals()[args.action](root)
    except BaseException as error:
        directory = observations(root)
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / (args.action + "-error.json")
        failure = {"schema": "trnm.hia.application-ci-action-error.v1", "status": "FAIL",
                   "action": args.action, "error": repr(error), "traceback": traceback.format_exc(),
                   "qualification_status_not_changed": True}
        write_new(path, failure)
        print(json.dumps(failure, sort_keys=True))
        return 1
    print(json.dumps({key: value for key, value in result.items() if key not in {
        "source_inputs", "original_sources", "bundle_artifacts", "evidence_files", "ci_reader_sources"}},
        sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
