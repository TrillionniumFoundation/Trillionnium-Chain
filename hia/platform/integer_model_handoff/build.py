"""Build a private read-only selfhost IMP1→IMD2 library. No runtime build host."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from hia.platform.integer_model_snapshot.build import digest, fresh_directory
from hia.tests.native_support import NativeModule
from hia.tools.toolchain import HIA_ROOT, build_native, pinned_toolchain

HERE = Path(__file__).resolve().parent
EMITTER = HERE / "emitter.hepta"
ENTRY = "trnm_integer_model_handoff_v1"
LIBRARY = "libtrnm_integer_model_handoff_v1.so"
PROGRAMS = (
    ("imp1", "integer_model_project", 32419, "8c01af0924a0bd00f1780724701fc9d28f1b0fe547204f18ad0c15a93ac4fb81",
     "661768effc9d33a0cbe512e45bd2e1c68e2e868560127cf0bf171cdd4479cfad"),
    ("imd2", "integer_model_load", 102915, "b3de3ac9d63cc33e99aab198cf5f832baaff15c7f325a1b988cd0d78436b9316",
     "0c1d6f297711837734b89990a6af6c86e9f64cbcd2dec40ded7672c825fdcfe9"),
)
CARRIER = 136192
THUNK = 282
THUNK_SHA = "e4188b9bea5b89a7e608cc2998c0655ebcdb73a3b870f667d285229746727197"
WORK = 37296
BODY = 7790
EDGE = ((206, 282), (247, 32701))
FLAGS = ("-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now")
TOOLS = {name: Path("/usr/bin", name).resolve(strict=True)
         for name in ("ld", "objcopy", "objdump", "readelf")}


def run(name, *args):
    return subprocess.run([str(TOOLS[name]), *map(str, args)], check=True, capture_output=True,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=30).stdout


def only_text(obj, out):
    run("objcopy", "--only-section=.text", "-O", "binary", obj, out)
    return out.read_bytes()


def disassemble(path, *extra):
    decoded = run("objdump", "-w", "--no-show-raw-insn", "--disassemble-zeroes", "-D", "-b",
                  "binary", "-m", "i386:x86-64", *extra, path).decode("ascii")
    instructions = []
    for line in decoded.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*?)\s*$", line)
        if match:
            at, operation, operands = match.groups()
            instructions.append((int(at, 16), operation, operands))
    if not instructions:
        raise ValueError("No decoded native instructions")
    return instructions


def inspect_text(text_path):
    raw = text_path.read_bytes()
    if len(raw) != THUNK + sum(row[2] for row in PROGRAMS) or digest(raw[:THUNK]) != THUNK_SHA:
        raise ValueError("Exact handoff machine-text extent/hash differs")
    instructions = disassemble(text_path, f"--stop-address={THUNK}")
    allowed = {"test", "je", "cmp", "ja", "jb", "mov", "add", "jae", "push",
               "call", "jne", "lea", "pop", "ret", "movabs"}
    if any(op not in allowed for _, op, _ in instructions):
        raise ValueError("Unreviewed thunk instruction")
    edges = tuple((p, int(args, 16)) for p, op, args in instructions if op == "call")
    if edges != EDGE or instructions[-1] != (281, "ret", ""):
        raise ValueError("Thunk call targets or final boundary differ")
    by_at = {p: (op, args) for p, op, args in instructions}
    if (by_at[211] != ("test", "%rax,%rax") or by_at[214] != ("jne", "0xfc")
            or by_at[252] != ("pop", "%r14")):
        raise ValueError("The only loader edge must be conditional on packed zero")
    for _, op, args in instructions:
        if op.startswith("j") and int(args, 16) not in by_at:
            raise ValueError("A thunk branch escaped its decoded instruction boundaries")
    if any(op in {"syscall", "sysenter", "int", "int1", "int3", "lcall", "lret", "(bad)"}
           for _, op, _ in disassemble(text_path)):
        raise ValueError("System or invalid instruction in composed code")
    return {"thunk_sha256": digest(raw[:THUNK]), "decoded_count": len(instructions),
            "direct_calls": edges, "system_instruction_count": 0}


def build(output):
    pinned_toolchain()
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    from hepta.object_symbols import inspect_object_symbols

    output = fresh_directory(output)
    file = lambda name: output / name
    fixed = {p: digest(p.read_bytes()) for p in
             (Path(__file__).resolve(), EMITTER, *TOOLS.values())}
    compiler = os.environ.get("HIA_NATIVE_COMPILER_SHA256")
    pinned = json.loads((HIA_ROOT / "qualification/compiler-binding.json").read_bytes())
    if compiler != pinned["compiler_sha256"]:
        raise ValueError("Handoff requires the qualified pinned selfhost compiler")
    receipts = {}
    parts = []
    for role, source_name, length, object_sha, text_sha in PROGRAMS:
        source = HIA_ROOT / "src/state" / (source_name + ".hepta")
        obj = file(role + ".o")
        receipt, _ = build_native(source, obj, backend="selfhost", kind="object",
                                  byte_exports=("f0",), compiler=os.environ.get("HIA_NATIVE_COMPILER"),
                                  compiler_sha256=compiler)
        surface = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
        syms = run("readelf", "-Ws", obj).decode("ascii")
        entries = [line.split() for line in syms.splitlines() if line.split()[-1:] == ["f0"]]
        if (surface["defined"] != {"f0"} or surface["undefined"] or len(entries) != 1
                or int(entries[0][1], 16) != 0 or entries[0][3] != "FUNC"
                or b"There are no relocations" not in run("readelf", "-rW", obj)
                or digest(obj.read_bytes()) != object_sha or receipt["artifact_sha256"] != object_sha
                or receipt["claims"].get("fallback_used")):
            raise ValueError("Exact held " + role + " object differs from prior qualification")
        text = only_text(obj, file(role + ".raw"))
        if len(text) != length or digest(text) != text_sha:
            raise ValueError("Exact held " + role + " machine text differs")
        parts.append(text)
        receipts[role] = receipt

    joined = b"".join(parts)
    poison = b"J" * (CARRIER + 11)
    with NativeModule(EMITTER, backend="selfhost", byte_exports=("f0",)) as encoder:
        emitted = encoder.call("f0", [joined, poison, b"work"]).require_returned()
        if (emitted.value != CARRIER or emitted.arguments[0] != joined
                or emitted.arguments[1][CARRIER:] != b"J" * 11 or emitted.arguments[2] != b"work"):
            raise ValueError("Native HIA carrier emitter differs")
        for input_bytes, size in ((joined[:-1], CARRIER), (joined, CARRIER - 1)):
            control = encoder.call("f0", [input_bytes, poison[:size], b""]).require_returned()
            if control.value != 102 or control.arguments != [input_bytes, poison[:size], b""]:
                raise ValueError("Native carrier partially wrote a refusal")
        emitter_receipt = encoder.receipt
    carrier = file("carrier.o")
    carrier.write_bytes(emitted.arguments[1][:CARRIER])
    surface = inspect_object_symbols(carrier.read_bytes(), "ELF64", 62)
    header = run("readelf", "-hW", carrier)
    syms = run("readelf", "-Ws", carrier).decode("ascii")
    entries = [line.split() for line in syms.splitlines() if line.split()[-1:] == [ENTRY]]
    if (surface["defined"] != {ENTRY} or surface["undefined"]
            or len(entries) != 1 or int(entries[0][1], 16) != 0
            or (int(entries[0][2]), entries[0][3]) != (THUNK, "FUNC")
            or b"REL (Relocatable file)" not in header
            or b"There are no relocations" not in run("readelf", "-rW", carrier)):
        raise ValueError("Carrier symbol/relocation surface differs")
    code = only_text(carrier, file("carrier.raw"))
    if code[THUNK:] != joined:
        raise ValueError("HIA emitter altered either held kernel")
    decoded = inspect_text(file("carrier.raw"))
    so = file(LIBRARY)
    run("ld", "-m", "elf_x86_64", "-shared", *FLAGS, "--build-id=none",
        "--hash-style=both", carrier, "-o", so)
    final = so.read_bytes()
    if only_text(so, file("linked.raw")) != code or so.read_bytes() != final:
        raise ValueError("Linked text changed or linking artifact changed while checking")
    dll = inspect_owned_shared_elf(final, (ENTRY,))
    dynamic = run("readelf", "-dW", so).decode("ascii")
    disallowed = ("NEEDED", "INIT", "FINI", "INIT_ARRAY", "FINI_ARRAY", "PREINIT_ARRAY",
                  "RPATH", "RUNPATH", "TEXTREL", "AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY")
    if (dll["unresolved_imports"] or any(f"({tag})" in dynamic for tag in disallowed)
            or b"There are no relocations" not in run("readelf", "-rW", so)
            or any(digest(path.read_bytes()) != sha for path, sha in fixed.items())):
        raise ValueError("Unexpected library dependency, relocation or source/tool drift")
    for receipt in (*receipts.values(), emitter_receipt):
        for row in receipt["chain_migration"]["inputs"]:
            if digest((HIA_ROOT / row["path"]).read_bytes()) != row["sha256"]:
                raise ValueError("Compiled source closure drift")
    proof = {"schema": "trnm.integer-model-handoff.v1", "backend": "selfhost-only",
             "artifact_sha256": digest(final), "artifact_bytes": len(final),
             "entry": ENTRY, "stock_object_receipts": receipts, "carrier_emitter": emitter_receipt,
             "linked_machine_text_sha256": digest(code), "held_text_unchanged": True,
             "private_scratch_bytes": WORK, "decoded": decoded, "dynamic": dll,
             "build_tools_sha256": {p.name: fixed[p] for p in TOOLS.values()},
             "runtime_host_shuttle": False, "production_dispatch": False}
    file("build.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    return so, proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path, proof = build(args.output)
    print(json.dumps({"library": str(path), "sha256": proof["artifact_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
