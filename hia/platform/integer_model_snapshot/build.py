"""Build a private named integer model snapshot library from exact HIA."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess

from hia.tools.toolchain import HIA_ROOT, build_native, pinned_toolchain

HERE = Path(__file__).resolve().parent
SOURCE = HIA_ROOT / "src/state/integer_model_load.hepta"
ENTRY = "trnm_integer_model_snapshot_load_v1"
LIBRARY = "libtrnm_integer_model_snapshot_v1.so"
TOOLS = {name: Path("/usr/bin", name) for name in ("ld", "objcopy", "readelf")}


def digest(data):
    return sha256(data).hexdigest()


def fresh_directory(output):
    output = Path(output).absolute()
    parent = output.parent
    if (output.is_relative_to(HIA_ROOT.parent) or parent.resolve(strict=True) != parent
            or parent.stat().st_uid != os.geteuid()
            or stat.S_IMODE(parent.stat().st_mode) & 0o077):
        raise ValueError("Use a fresh directory inside a private owned directory outside the checkout")
    output.mkdir(mode=0o700)
    return output


def run(tool, *args):
    return subprocess.run([str(tool), *map(str, args)], check=True, capture_output=True,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=30).stdout


def check_direct_refusal(output):
    """Observe the actual pinned unsupported direct object; never link it."""
    pinned_toolchain()
    from hepta.object_symbols import inspect_object_symbols

    output = fresh_directory(output)
    obj = output / "direct-not-installable.o"
    receipt, _ = build_native(SOURCE, obj, kind="object", byte_exports=("f0",), backend="direct")
    raw = obj.read_bytes()
    surface = inspect_object_symbols(raw, "ELF64", 62)
    expected = frozenset({"f0", "il_unhex", "im_graph", "imd_row", "tr_sha_rotr"})
    if (surface["defined"] != expected or frozenset(receipt["exports"]) != expected
            or surface["undefined"] != {"abort", "memset"}
            or digest(raw) != receipt["artifact_sha256"]):
        raise ValueError("Pinned direct refusal changed; requalify rather than silently install it")
    return {"result": "NOT_INSTALLABLE", "imports": sorted(surface["undefined"]),
            "reason": "direct emitter introduces a memset library dependency",
            "native_object_receipt": receipt}


def build(output):
    pinned_toolchain()
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    from hepta.object_symbols import inspect_object_symbols

    output = fresh_directory(output)
    b = lambda name: output / name
    tools = {name: path.resolve(strict=True) for name, path in TOOLS.items()}
    tool_ids = {name: digest(path.read_bytes()) for name, path in tools.items()}
    binding = HIA_ROOT / "qualification/compiler-binding.json"
    fixed = (Path(__file__).resolve(), HERE / "exports.map", HERE / "integer_model_snapshot.h",
             binding, HIA_ROOT / "toolchain.lock.json")
    static = {p: digest(p.read_bytes()) for p in fixed}
    expected = json.loads(binding.read_bytes())["compiler_sha256"]
    if os.environ.get("HIA_NATIVE_COMPILER_SHA256") != expected:
        raise ValueError("Named selfhost artifact requires the repository-qualified compiler")
    receipt, _ = build_native(SOURCE, b("raw.o"), kind="object", byte_exports=("f0",),
                              backend="selfhost", compiler=os.environ.get("HIA_NATIVE_COMPILER"),
                              compiler_sha256=expected)
    if receipt["claims"].get("fallback_used"):
        raise ValueError("No fallback native emitter is supported")
    raw = b("raw.o").read_bytes()
    before = inspect_object_symbols(raw, "ELF64", 62)
    if (frozenset(receipt["exports"]) != {"f0"} or before["defined"] != {"f0"}
            or before["undefined"] != set() or digest(raw) != receipt["artifact_sha256"]):
        raise ValueError(f"Unexpected compiled Model Snapshot object surface: {before}")
    run(tools["objcopy"], "--redefine-sym", "f0=" + ENTRY, b("raw.o"), b("named.o"))
    after = inspect_object_symbols(b("named.o").read_bytes(), "ELF64", 62)
    if after != {**before, "defined": frozenset({ENTRY})}:
        raise ValueError("Named Model Snapshot object surface differs")
    for name in ("raw", "named"):
        # A copy destination prevents objcopy touching the compared input.
        run(tools["objcopy"], "--dump-section", ".text=" + str(b(name + ".text")),
            b(name + ".o"), b(name + "-dump-copy.o"))
    emitted = b("raw.text").read_bytes()
    if (not emitted or emitted != b("named.text").read_bytes()
            or digest(raw) != digest(b("raw.o").read_bytes())):
        raise ValueError("Name binding changed compiled machine bytes")
    run(tools["ld"], "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
        "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both",
        "--version-script=" + str(HERE / "exports.map"),
        b("named.o"), "-o", b(LIBRARY))
    library = b(LIBRARY).read_bytes()
    run(tools["objcopy"], "--dump-section", ".text=" + str(b("linked.text")),
        b(LIBRARY), b("linked-dump-copy.so"))
    linked_text = b("linked.text").read_bytes()
    if (b(LIBRARY).read_bytes() != library or not linked_text
            or linked_text != emitted):
        raise ValueError("Link unexpectedly changed the exact relocation-free selfhost text")
    surface = inspect_owned_shared_elf(library, (ENTRY,))
    dynamic = run(tools["readelf"], "-dW", b(LIBRARY)).decode("ascii").splitlines()
    needed = [line.rsplit("[", 1)[-1].removesuffix("]") for line in dynamic
              if "(NEEDED)" in line]
    disallowed_tags = ("INIT", "FINI", "INIT_ARRAY", "FINI_ARRAY", "PREINIT_ARRAY",
                       "RPATH", "RUNPATH", "TEXTREL", "AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY")
    if (surface["unresolved_imports"] != [] or needed != []
            or any(f"({tag})" in line for tag in disallowed_tags for line in dynamic)
            or {name: digest(path.read_bytes()) for name, path in tools.items()} != tool_ids
            or {p: digest(p.read_bytes()) for p in fixed} != static):
        raise ValueError("Linked ABI, dependencies, or source inputs changed")
    for row in receipt["chain_migration"]["inputs"]:
        path = HIA_ROOT / row["path"]
        if digest(path.read_bytes()) != row["sha256"]:
            raise ValueError("HIA source changed during naming or linking")
    proof = {
        "schema": "trnm.integer-model-snapshot-library.v1", "backend": "selfhost",
        "entry": ENTRY, "artifact_sha256": digest(library), "artifact_bytes": len(library),
        "text_sha256_before_and_after_symbol_binding": digest(emitted),
        "linked_text_sha256": digest(linked_text),
        "linked_text_equals_relocatable_text": linked_text == emitted,
        "raw_object_sha256": digest(raw), "named_object_sha256": digest(b("named.o").read_bytes()),
        "dynamic": surface, "needed": needed, "tools_sha256": tool_ids,
        "package_sources_sha256": {str(p.relative_to(HIA_ROOT)): h for p, h in static.items()},
        "native_object_receipt": receipt, "runtime_bridge": False,
        "production_dispatch": False, "local_offline_fixture_only": True,
    }
    b("build.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    return b(LIBRARY), proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    library, proof = build(args.output)
    print(json.dumps({"library": str(library), "entry": ENTRY, "sha256": proof["artifact_sha256"]}))


if __name__ == "__main__":
    main()
