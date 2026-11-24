"""Source-bound build for the finite Bench Linux process; no host runtime."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

from hia.platform.build import Build, INPUTS, inspect_executable, sha256
from hia.tools.toolchain import HIA_ROOT, build_native, checked_source

COMPONENTS = (
    "src/bench/main_cli.hepta",
    "src/bench/workload.hepta",
    "src/executor/schedule.hepta",
    "src/bench/digests.hepta",
    "src/bench/report.hepta",
    "src/bench/profile.hepta",
    "src/bench/environment.hepta",
    "src/bench/main_diagnostics.hepta",
    "src/bench/launcher_env.hepta",
)
EMITTER = "platform/bench/main_emitter.hepta"
DIAGNOSTIC_SOURCE = "src/bench/main_diagnostics.json"
ADAPTER_SHA256 = "9ef5ba70dbc52a3a294a60a81ff0fe3cb79a406ac101c27f21c28dd94180f0ce"
PREFIX, BASE = 4656, 0x400000


def exact_native_text(data):
    """Only the pinned compiler's resolved import-free f0 entry, with no patching."""
    from hepta.object_symbols import inspect_object_symbols
    inventory = inspect_object_symbols(data, "ELF64", 62)
    if inventory["defined"] != {"f0"} or inventory["undefined"]:
        raise ValueError("Unexpected imports/exports in Bench argument object")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[1] != 1 or h[2] != 62 or h[11] != 64:
        raise ValueError("Expected ELF64 x86-64 relocatable object")
    shapes = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + 64 * i) for i in range(h[12])]
    names_at, names_len = shapes[h[13]][4:6]
    names = data[names_at:names_at + names_len]
    section = {}
    for row in shapes:
        name_at, typ, _, _, at, n, _, _, _, _ = row
        name = names[name_at:names.index(b"\0", name_at)]
        if typ in (4, 9) or (typ != 8 and at + n > len(data)) or name in section:
            raise ValueError("Unexpected relocations or malformed Bench argument section")
        section[name] = row
    txt, sym = section[b".text"], section[b".symtab"]
    if txt[1:4] != (1, 6, 0) or sym[9] != 24:
        raise ValueError("Unexpected argument code or symbol layout")
    symbols = [struct.unpack_from("<IBBHQQ", data, sym[4] + j)
               for j in range(0, sym[5], 24)]
    global_funcs = [row for row in symbols if row[1] == 0x12]
    if (len(global_funcs) != 1 or shapes[global_funcs[0][3]] != txt
            or global_funcs[0][4] != 0 or not 0 < global_funcs[0][5] <= txt[5]):
        raise ValueError("Argument f0 does not start exact resolved .text")
    return data[txt[4]:txt[4] + txt[5]]


def diagnostics_catalog(raw: bytes) -> bytes:
    """Pack a reviewed static text table, without classifying or rendering argv."""
    def unique(pairs):
        values = dict(pairs)
        if len(values) != len(pairs):
            raise ValueError("Duplicate diagnostic source key")
        return values
    source = json.loads(raw, object_pairs_hook=unique)
    numeric_fields = (0, 1, 2, 4, 5)
    existing = {3, *(16+i for i in (*numeric_fields, 6, 8)), *range(32, 41)}
    numeric = {base + i for base in (64, 80, 96) for i in numeric_fields}
    enums = {102, 103}
    reflected = numeric | enums
    if (set(source) != {"schema", "entries", "suggestions"} or source["schema"] != "trnm.hia.bench-plain-diagnostic-text.v2"
            or set(source["entries"]) != {str(code) for code in existing | reflected}):
        raise ValueError("Incorrect diagnostic text roster")
    words = source["suggestions"]
    if (type(words) is not list or len(words) != 11 or len(set(words[:10])) != 10
            or any(type(word) is not str or not 1 <= len(word) <= 21
                   or not all(ch.isascii() and (ch.islower() or ch == "-") for ch in word) for word in words[:10])
            or words[10] != "\n\n  tip: a similar value exists: '"):
        raise ValueError("Incorrect source text for enum suggestions")
    table = bytearray(104 * 8 + 11 * 4)
    payload = bytearray()
    for code in sorted(existing | reflected):
        row = source["entries"][str(code)]
        if type(row) is not list or len(row) != 2 or any(type(text) is not str for text in row):
            raise ValueError("Incorrect diagnostic text definition")
        before, after = (text.encode("ascii") for text in row)
        if (not before or bool(after) != (code in reflected) or not (after or before).endswith(b"\n")
                or any(b != 10 and not 32 <= b <= 126 for b in before + after)
                or len(before) + len(after) + (127 if code in reflected else 0) > 2048):
            raise ValueError("Out-of-domain diagnostic template")
        struct.pack_into("<4H", table, code * 8, len(table) + len(payload), len(before), len(after), 0)
        payload += before + after
    footer = "\n\nFor more information, try '--help'.\n"
    for code, roster in ((102, words[:3]), (103, words[3:10])):
        if not source["entries"][str(code)][1].endswith("  [possible values: " + ", ".join(roster) + "]" + footer):
            raise ValueError("Enum diagnostic text disagrees with its ordered suggestions")
    for idx, word in enumerate(words):
        raw_word = word.encode("ascii")
        struct.pack_into("<2H", table, 104 * 8 + idx * 4, len(table) + len(payload), len(raw_word))
        payload += raw_word
    result = bytes(table + payload)
    if len(result) > 8048:
        raise ValueError("Packed diagnostic catalog exceeded 8048 bytes")
    return result


def build(output: Path, *, bind_profile_output=False):
    # The only eligible output authority is this build's private, repo-shaped
    # original Cargo anchor. No path is supplied by any process argv or env.
    root = output.parent / "isolated-source/trillionnium"
    anchor = b""
    if bind_profile_output:
        root = root.absolute()
        if (root != root.resolve(strict=True) or not root.is_dir()
                or root.is_relative_to(HIA_ROOT.parent)
                or (root / "Cargo.lock").read_bytes() != (HIA_ROOT.parent / "trillionnium/Cargo.lock").read_bytes()
                or output.parent.lstat().st_mode & 0o077
                or output.parent.lstat().st_uid != os.geteuid()):
            raise ValueError("Expected private, exact, repo-shaped Bench profile anchor")
        anchor = str(root).encode("utf-8")
        if len(anchor) > 1024 or b"\0" in anchor or b"\n" in anchor:
            raise ValueError("Bench profile anchor is not in the bounded display path domain")
    if not __debug__:
        raise RuntimeError("Optimized Python source qualification refused")
    pinned = Build(output)
    sources, wires, parts, object_receipts = {}, {}, [], {}
    for rel in (*COMPONENTS, EMITTER):
        _, wire, _, _, captured = checked_source(HIA_ROOT / rel)
        sources[rel] = {p.relative_to(HIA_ROOT).as_posix(): sha256(raw) for p, raw in captured}
        wires[rel] = wire
    explicit_object = {"src/bench/main_cli.hepta": "cli", "src/bench/report.hepta": "report",
                       "src/bench/main_diagnostics.hepta": "diagnostics",
                       "src/bench/launcher_env.hepta": "launcher_env"}
    for rel in COMPONENTS:
        if rel in explicit_object:
            # The fixed-core flat profile refuses these CFGs. The self-host
            # object profile is selected explicitly; there is no host fallback.
            name = explicit_object[rel]
            obj = output / f"{name}.o"
            receipt, _ = build_native(HIA_ROOT / rel, obj, byte_exports=("f0",), kind="object",
                backend="selfhost", compiler=os.environ["HIA_NATIVE_COMPILER"],
                compiler_sha256=os.environ["HIA_NATIVE_COMPILER_SHA256"])
            object_receipts[name] = receipt
            record = output / f"{name}.canonical-input.hepta"
            value = checked_source(HIA_ROOT / rel)[0].as_dict()
            value["module"] = "selfhost_elf"
            from hepta.hia_agent_assembly import render_assembly
            wire = render_assembly(value).encode()
            if sha256(wire) != receipt["compiler_wire_sha256"]:
                raise ValueError("Exact Bench object compiler request changed: " + name)
            record.write_bytes(wire)
            raw = exact_native_text(obj.read_bytes())
        else:
            raw = pinned.stage(pinned.compiler, wires[rel], "compile-" + Path(rel).stem)
        if not raw:
            raise ValueError("Empty native Bench component")
        parts.append(raw)
    catalog_raw = (HIA_ROOT / DIAGNOSTIC_SOURCE).read_bytes()
    catalog = diagnostics_catalog(catalog_raw)
    sources[DIAGNOSTIC_SOURCE] = {DIAGNOSTIC_SOURCE: sha256(catalog_raw)}
    addresses = []
    position = BASE + PREFIX + 8 * (len(parts) + 4)
    for raw in parts:
        addresses.append(position)
        position += len(raw)
    payload = struct.pack("<13Q", *addresses[:6], position + len(catalog) if anchor else 0, len(anchor),
                          *addresses[6:8], position, len(catalog), addresses[8]) + b"".join(parts) + catalog
    if anchor:
        payload += anchor + b"\0"
    if len(payload) > 950272:
        raise ValueError("Native Bench ELF exceeds original filter packing capacity")
    # The larger machine prefix selects the pinned object profile explicitly.
    # A disposable host process transports bytes to the emitted HIA emitter;
    # the packed Bench executable has no loader or host runtime.
    emitter_path = output / "emitter.so"
    emitter_receipt, emitter_canonical = build_native(HIA_ROOT / EMITTER, emitter_path,
        byte_exports=("f0",), kind="shared", backend="selfhost",
        compiler=os.environ["HIA_NATIVE_COMPILER"],
        compiler_sha256=os.environ["HIA_NATIVE_COMPILER_SHA256"])
    emitter_case = output / "emit-bench-main"
    emitter_case.mkdir(mode=0o700)
    (emitter_case / "stdin.raw").write_bytes(payload)
    from hepta.hia_agent_assembly import render_assembly
    emitter_wire = emitter_canonical.copy()
    emitter_wire["module"] = "selfhost_elf"
    rendered = render_assembly(emitter_wire).encode()
    if sha256(rendered) != emitter_receipt["compiler_wire_sha256"]:
        raise ValueError("Emitter compiled request differs")
    (emitter_case / "compiler-input.hepta").write_bytes(rendered)
    runner = """import ctypes as c, sys
library = c.CDLL(sys.argv[1])
entry = library.f0
entry.argtypes = [c.c_void_p,c.c_size_t] * 3
entry.restype = c.c_uint32
source = sys.stdin.buffer.read()
raw = c.create_string_buffer(source)
out = c.create_string_buffer(1 << 20)
scratch = c.create_string_buffer(1)
n = entry(raw,len(source),out,len(out),scratch,len(scratch))
if not 0 < n <= len(out): raise SystemExit(2)
sys.stdout.buffer.write(out.raw[:n])
"""
    result = subprocess.run([sys.executable,"-B","-c",runner,str(emitter_path)],
        input=payload, capture_output=True, env={"PATH": ""}, timeout=30)
    (emitter_case / "stdout.raw").write_bytes(result.stdout)
    (emitter_case / "stderr.raw").write_bytes(result.stderr)
    (emitter_case / "receipt.json").write_text(json.dumps({
        "exit": result.returncode, "payload_sha256": sha256(payload),
        "output_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr),
        "emitter_sha256": sha256(emitter_path.read_bytes())}, indent=2) + "\n")
    if (result.returncode or result.stderr
            or sha256(emitter_path.read_bytes()) != emitter_receipt["artifact_sha256"]):
        raise ValueError("The pinned HIA emitter refused or changed")
    image = result.stdout
    elf = inspect_executable(image)
    if image[PREFIX:] != payload or sha256(image[176:PREFIX]) != ADAPTER_SHA256:
        raise ValueError("Unexpected machine adapter or component output")
    for captured in sources.values():
        for relative, identity in captured.items():
            if sha256((HIA_ROOT / relative).read_bytes()) != identity:
                raise ValueError("Native Bench source changed during construction")
    pinned.check_pin()
    report = {"diagnostics_catalog": {"sha256": sha256(catalog), "bytes": len(catalog)},
              "schema": "trnm.hia.bench-main.build.v9",
              "status": "BUILD_PASS", "compiler_sha256": sha256(pinned.compiler),
              "toolchain_revision": pinned.lock["revision"], "source_inputs": sources,
              "native_elf": {**elf, "sha256": sha256(image), "bytes": len(image)},
              "adapter_sha256": ADAPTER_SHA256, "adapter_bytes": PREFIX - 176,
              "argument_object": object_receipts["cli"], "report_object": object_receipts["report"],
              "diagnostics_object": object_receipts["diagnostics"],
              "launcher_environment_object": object_receipts["launcher_env"],
              "emitter_object": emitter_receipt,
              "contained_parts": [{"source": rel, "entry_address": addr, "sha256": sha256(raw),
                                   "bytes": len(raw)}
                                  for rel, addr, raw in zip(COMPONENTS, addresses, parts, strict=True)],
              "stages": pinned.stages, "whole_bench_native_qualified": False,
              "production_entrypoint_activated": False,
              "runtime_rust_or_python_fallback": False,
              "compiled_profile_root": anchor.decode("utf-8") if anchor else None}
    (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return image, report


TARGET_NAME = "trnm-bench-hia"
_REPO = HIA_ROOT.parent
_TARGET_BUILD_INPUTS = (
    "hia/platform/bench/main_build.py",
    "hia/platform/build.py",
    "hia/tools/toolchain.py",
    "trillionnium/Cargo.lock",
    *("hia/" + name for name in INPUTS),
)


def _target_git(*args) -> bytes:
    return subprocess.check_output(["git", *args], cwd=_REPO, timeout=15,
                                   stderr=subprocess.PIPE)


def _target_source(head: str, relative: str) -> str:
    path = _REPO / relative
    if not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("Named Bench target requires a regular committed source: " + relative)
    raw = path.read_bytes()
    if raw != _target_git("cat-file", "blob", head + ":" + relative):
        raise ValueError("Named Bench target source differs from the committed bytes: " + relative)
    return sha256(raw)


def _target_output(path: Path) -> Path:
    output = path.absolute()
    parent = output.parent
    st = parent.lstat()
    if (parent.resolve(strict=True) != parent or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid() or st.st_mode & 0o077
            or output.name in ("", ".", "..") or output.is_relative_to(_REPO)):
        raise ValueError("Use a new output directory under an existing private directory outside the checkout")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Named Bench target will not overwrite an existing output")
    return output


def build_named_target(output: Path, *, bind_profile_output: bool = False) -> dict:
    """Materialize the same native entry; never install it or make a profile directory."""
    output = _target_output(output)
    head = _target_git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    sources = {name: _target_source(head, name) for name in _TARGET_BUILD_INPUTS}
    selected = {DIAGNOSTIC_SOURCE}
    for relative in (*COMPONENTS, EMITTER):
        _, _, _, _, captured = checked_source(HIA_ROOT / relative)
        selected.update(path.relative_to(HIA_ROOT).as_posix() for path, _ in captured)
    # Reject any modified selected source before a compiler or emitter executes.
    sources.update(("hia/" + name, _target_source(head, "hia/" + name)) for name in sorted(selected))
    image, report = build(output, bind_profile_output=bind_profile_output)
    reported = set()
    for captured in report["source_inputs"].values():
        for relative, expected in captured.items():
            path = "hia/" + relative
            reported.add(relative)
            if sources.get(path) != expected:
                raise ValueError("Inconsistent named Bench target source capture: " + path)
    if selected != reported:
        raise ValueError("Missing named Bench target source capture")
    if (_target_git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip() != head
            or any(_target_source(head, path) != identity for path, identity in sources.items())
            or sha256(image) != report["native_elf"]["sha256"]):
        raise ValueError("Named Bench target inputs or executable changed during the build")
    destination = output / TARGET_NAME
    # The creation is exclusive, and the regular file gains execute
    # permission only after all bytes have been flushed and read back.
    fd = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w+b") as binary:
        if binary.write(image) != len(image):
            raise OSError("Short named Bench target write")
        binary.flush()
        binary.seek(0)
        if sha256(binary.read(len(image) + 1)) != report["native_elf"]["sha256"]:
            raise OSError("Named Bench target executable readback differed")
        os.fchmod(binary.fileno(), 0o500)
    receipt = {"schema": "trnm.hia.bench.named-target.v1", "result": "BUILD_PASS",
               "source_commit": head, "source_sha256": sources,
               "executable": TARGET_NAME, "elf": report["native_elf"],
               "compiled_profile_root": report["compiled_profile_root"],
               "compiler_sha256": report["compiler_sha256"],
               "toolchain_revision": report["toolchain_revision"],
               "installed": False, "production_entrypoint_activated": False,
               "runtime_rust_or_python_fallback": False}
    with (output / "named-target.json").open("x", encoding="utf-8") as file:
        json.dump(receipt, file, indent=2, sort_keys=True)
        file.write("\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the scoped Linux x86-64 trnm-bench-hia executable")
    parser.add_argument("--output", required=True, type=Path, help="fresh child of an existing private directory")
    parser.add_argument("--bind-profile-output", action="store_true",
                        help="reuse the verified private repo-shaped profile root beside the output")
    args = parser.parse_args()
    try:
        receipt = build_named_target(args.output, bind_profile_output=args.bind_profile_output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Bench native target refused: {exc}\n")
    print(json.dumps({"target": TARGET_NAME, "sha256": receipt["elf"]["sha256"],
                      "compiled_profile_root": receipt["compiled_profile_root"]}, sort_keys=True))


if __name__ == "__main__":
    main()
