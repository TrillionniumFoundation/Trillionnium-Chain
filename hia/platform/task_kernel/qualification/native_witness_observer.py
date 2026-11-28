"""Independent current C/native witness ABI, dynamic-input and rejection controls."""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.task_kernel.build_witness import (
    EXPORTS, emit, emitter_function, frame, identity, inspect_object, need, observation, write_json,
)


def qualify(build, output):
    build = build.resolve(strict=True)
    output = output.absolute()
    need(__debug__ and not output.exists() and output.resolve() == output and ROOT not in output.parents,
         "Fresh canonical controls output outside checkout required")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "trnm.hia.task-kernel.native-witness-controls.v1", "status": "FAIL",
              "finalized": False, "controls": []}
    def save():
        write_json(output / "report.json", report)
    save()
    try:
        built = json.loads((build / "build.json").read_text())
        need(built["status"] == "PASS" and built["finalized"] and built["source_before"] == built["source_after"],
             "Complete source-bound witness build required")
        before = {**built["source_before"], str(build / "build.json"): identity(build / "build.json"),
                  str(Path(__file__).resolve()): identity(Path(__file__).resolve())}
        for name, expected in built["artifacts"].items():
            need(identity(build / name) == expected, "Witness artifact identity differs")
            before[str(build / name)] = expected
        need({name: identity(name) for name in before} == before, "Witness input fence differs")
        report["source_before"] = before
        original = ctypes.CDLL(str(build / "probe.so"))
        native = ctypes.CDLL(str(build / "witness.so"))
        expected, actual = observation(original), observation(native)
        need(expected == actual == built["observed_identity"], "Actual native/C witness metadata differs")
        request = (build / "emitter-input.bin").read_bytes()
        need(request == frame(expected), "Emitted witness does not use actual ordered probe data")
        emitter = ctypes.CDLL(str(build / "witness-emitter.so"))
        function = emitter_function(emitter)
        report["identity"] = actual
        def row(name, **values):
            report["controls"].append({"name": name, **values})
            save()
        for index in [-(1 << 31), -1, *range(21), (1 << 31) - 1]:
            a, b = original.trnm_io_witness_layout(index), native.trnm_io_witness_layout(index)
            need(a == b and a == (expected["layout"][index] if 0 <= index < 19 else (1 << 64) - 1),
                 "Native layout index ABI differs")
            row("layout-index", index=index, original=a, native=b)
        count = len(actual["options"])
        for index in [-(1 << 31), -1, *range(count + 2), (1 << 31) - 1]:
            a, b = original.trnm_io_witness_compileoption(index), native.trnm_io_witness_compileoption(index)
            need(a == b and a == (actual["options"][index].encode() if 0 <= index < count else None),
                 "Native option index ABI differs")
            row("option-index", index=index, original=a.decode() if a else None, native=b.decode() if b else None)
        row("version", original=expected["version"], native=actual["version"])
        row("source-id", original=expected["source_id"], native=actual["source_id"])
        # SysV only defines the low int bits; upper argument bits cannot become
        # part of a table address after an otherwise valid low 32-bit index.
        address = ctypes.cast(native.trnm_io_witness_layout, ctypes.c_void_p).value
        wide_layout = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address)
        address = ctypes.cast(native.trnm_io_witness_compileoption, ctypes.c_void_p).value
        wide_option = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint64)(address)
        for low in (0, 18, 19, (1 << 32) - 1):
            value = 0xFEDCBA9800000000 | low
            wanted = actual["layout"][low] if low < 19 else (1 << 64) - 1
            need(wide_layout(value) == wanted, "Layout used undefined upper int argument bits")
            row("layout-upper-register", argument=value, result=wanted)
        for low in (0, count - 1, count, (1 << 32) - 1):
            value = 0xFEDCBA9800000000 | low
            pointer = wide_option(value)
            result = ctypes.string_at(pointer).decode() if pointer else None
            wanted = actual["options"][low] if low < count else None
            need(result == wanted, "Option used undefined upper int argument bits")
            row("option-upper-register", argument=value, result=result)
        obj = (build / "witness.o").read_bytes()
        inspect_object(obj)
        code, result = emit(function, request, len(obj) + 8)
        need(code == 0 and result == struct.pack("<Q", len(obj)) + obj, "Exact-capacity emission differs")
        row("exact-output-capacity", capacity=len(result), return_code=code)
        def reject(name, payload, capacity, expected_code):
            source = ctypes.create_string_buffer(payload)
            arena = ctypes.create_string_buffer(bytes([0xA5]) * (capacity + 128), capacity + 128)
            pointer = ctypes.c_void_p(ctypes.addressof(arena) + 64)
            scratch = ctypes.create_string_buffer(1)
            code = function(source, len(payload), pointer, capacity, scratch, 0)
            need(code == expected_code and arena.raw == bytes([0xA5]) * (capacity + 128) and
                 source.raw[:-1] == payload, "Rejected emitter call changed output/input or returned the wrong status: " + name)
            row(name, return_code=code, input_bytes=len(payload), capacity=capacity,
                input_unchanged=True, output_and_guards_unchanged=True)
        for size in (0, 1, 7, 8, 39, 40, 191, len(request) - 1):
            reject("truncated-frame", request[:size], 131072, 100)
        reject("wrong-magic", b"X" + request[1:], 131072, 100)
        reject("trailing-byte", request + b"\0", 131072, 100)
        for label, offset, value in (("zero-version", 8, 0), ("version-outside-int", 8, 1 << 31),
                                      ("option-count-too-large", 16, 257), ("option-count-disagrees", 16, count + 1),
                                      ("zero-source-length", 24, 0), ("source-length-too-large", 24, 1025),
                                      ("option-bytes-too-large", 32, 65537), ("layout-outside-bound", 40, 1048577)):
            changed = bytearray(request); struct.pack_into("<Q", changed, offset, value)
            reject(label, bytes(changed), 131072, 100)
        option_bytes = struct.unpack_from("<Q", request, 32)[0]
        for label, offset, value in (("empty-option", 192, 0), ("non-ascii-option", 192, 128),
                                      ("control-option", 192, 9), ("missing-option-terminator", 192 + option_bytes - 1, 65),
                                      ("embedded-source-zero", 192 + option_bytes, 0), ("control-source", 192 + option_bytes, 9)):
            changed = bytearray(request); changed[offset] = value
            reject(label, bytes(changed), 131072, 100)
        long_option = {**actual, "options": ["A" * 1025]}
        reject("overlong-option", frame(long_option), 131072, 100)
        for capacity in (0, 7, 8, len(obj) + 7):
            reject("output-capacity", request, capacity, 101)
        reject("invalid-before-capacity", b"X" + request[1:], 0, 100)
        # Valid unit fixtures prove that all data is input-derived, including
        # options and version; they are not substituted for production probing.
        for index, changed in enumerate((
            {"layout": list(range(19)), "options": [], "version": 1, "source_id": "empty-options-test"},
            {"layout": [value + 1 for value in actual["layout"]], "options": ["COMPILER=fixture-two", "FEATURE=7"],
             "version": (1 << 31) - 1, "source_id": "dynamic-metadata-test"},
        )):
            payload = frame(changed)
            code, out = emit(function, payload)
            need(code == 0, "Valid dynamic metadata rejected")
            size = struct.unpack_from("<Q", out)[0]
            current = out[8:8 + size]
            inspect_object(current)
            path = output / ("dynamic-" + str(index) + ".o"); path.write_bytes(current)
            so = path.with_suffix(".so")
            command = ["ld", "-shared", "-z", "defs", "-z", "noexecstack", "--build-id=none", str(path), "-o", str(so)]
            linked = subprocess.run(command, input=b"", capture_output=True, timeout=30, cwd=ROOT)
            (output / ("dynamic-" + str(index) + ".stdout.raw")).write_bytes(linked.stdout)
            (output / ("dynamic-" + str(index) + ".stderr.raw")).write_bytes(linked.stderr)
            linked.check_returncode()
            dynamic = observation(ctypes.CDLL(str(so)))
            need(dynamic == changed, "Witness metadata was hardcoded instead of read from emitter input")
            row("dynamic-metadata", index=index, actual=dynamic, object=identity(path),
                library=identity(so), argv=command, exit_code=linked.returncode)
        report["source_after"] = {path: identity(path) for path in before}
        need(report["source_after"] == before, "Witness control inputs changed")
        report.update(status="PASS", finalized=True, controls_count=len(report["controls"]),
                      actual_c_native_abi_equal=True, no_native_relocations=True, no_native_undefined_symbols=True)
        save()
        return report
    except BaseException as error:
        report.update(status="FAIL", finalized=False, failure=repr(error))
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.build, args.output)
    print(json.dumps({"status": result["status"], "controls": result["controls_count"], "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
