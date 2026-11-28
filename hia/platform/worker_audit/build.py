"""Build a private, named shared library from the exact native Worker body."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess

from hia.tools.toolchain import HIA_ROOT, build_native

HERE = Path(__file__).resolve().parent
SOURCE = HIA_ROOT / "src/worker_agent/audit_owned_entry.hepta"
ENTRY = "trnm_worker_audit_export_v1"
LIBRARY = "libtrnm_worker_audit_v1.so"
TOOLS = {name: Path("/usr/bin", name) for name in ("ld", "objcopy", "readelf")}
BACKENDS = ("selfhost", "direct")
MAX_EXTENT = 1 << 20


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


def build(output, backend):
    return build_named(output, backend, source=SOURCE, entry=ENTRY, library_name=LIBRARY,
                       exports_map=HERE / "exports.map", header=HERE / "worker_audit.h",
                       schema="trnm.worker-audit-owned-library.v1")


def build_named(output, backend, *, source, entry, library_name, exports_map, header, schema, extra=()):
    """Private mechanics for fixed project-owned source/ABI profiles."""
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    from hepta.object_symbols import inspect_object_symbols

    if backend not in BACKENDS:
        raise ValueError("Select a fixed HIA emitter")
    output = fresh_directory(output)
    b = lambda name: output / name
    tools = {name: path.resolve(strict=True) for name, path in TOOLS.items()}
    tool_ids = {name: digest(path.read_bytes()) for name, path in tools.items()}
    binding = HIA_ROOT / "qualification/compiler-binding.json"
    fixed = (Path(__file__).resolve(), exports_map, header,
             binding, HIA_ROOT / "toolchain.lock.json", *extra)
    static = {p: digest(p.read_bytes()) for p in fixed}
    options = {}
    if backend == "selfhost":
        expected = json.loads(binding.read_bytes())["compiler_sha256"]
        if os.environ.get("HIA_NATIVE_COMPILER_SHA256") != expected:
            raise ValueError("Named selfhost artifact requires the repository-qualified compiler")
        options = {"compiler": os.environ.get("HIA_NATIVE_COMPILER"), "compiler_sha256": expected}
    receipt, _ = build_native(source, b("raw.o"), kind="object", byte_exports=("f0",),
                              backend=backend, **options)
    if receipt["claims"].get("fallback_used"):
        raise ValueError("No fallback native emitter is supported")
    raw = b("raw.o").read_bytes()
    before = inspect_object_symbols(raw, "ELF64", 62)
    expected_imports = frozenset() if backend == "selfhost" else frozenset({"abort"})
    declared_exports = frozenset(receipt["exports"])
    if ("f0" not in declared_exports or before["defined"] != declared_exports
            or before["undefined"] != expected_imports
            or backend == "selfhost" and declared_exports != {"f0"}
            or digest(raw) != receipt["artifact_sha256"]):
        raise ValueError(f"Unexpected compiled Worker object surface: {before}")
    local = sorted(declared_exports - {"f0"})
    run(tools["objcopy"], "--redefine-sym", "f0=" + entry,
        *(f"--localize-symbol={name}" for name in local), b("raw.o"), b("named.o"))
    after = inspect_object_symbols(b("named.o").read_bytes(), "ELF64", 62)
    if after != {**before, "defined": frozenset({entry})}:
        raise ValueError("Named Worker object surface differs")
    for name in ("raw", "named"):
        # A copy destination prevents objcopy touching the compared input.
        run(tools["objcopy"], "--dump-section", ".text=" + str(b(name + ".text")),
            b(name + ".o"), b(name + "-dump-copy.o"))
    emitted = b("raw.text").read_bytes()
    if (not emitted or emitted != b("named.text").read_bytes()
            or digest(raw) != digest(b("raw.o").read_bytes())):
        raise ValueError("Name binding changed compiled machine bytes")
    if backend == "direct" and digest(emitted) != receipt["machine_text_sha256"]:
        raise ValueError("Direct compiler text receipt differs")
    run(tools["ld"], "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
        "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both",
        "--version-script=" + str(exports_map),
        b("named.o"), *(("-lc",) if backend == "direct" else ()), "-o", b(library_name))
    library = b(library_name).read_bytes()
    run(tools["objcopy"], "--dump-section", ".text=" + str(b("linked.text")),
        b(library_name), b("linked-dump-copy.so"))
    linked_text = b("linked.text").read_bytes()
    if (b(library_name).read_bytes() != library or not linked_text
            or backend == "selfhost" and linked_text != emitted):
        raise ValueError("Link unexpectedly changed the exact relocation-free selfhost text")
    surface = inspect_owned_shared_elf(library, (entry,))
    needed = [line.rsplit("[", 1)[-1].removesuffix("]") for line
              in run(tools["readelf"], "-dW", b(library_name)).decode("ascii").splitlines()
              if "(NEEDED)" in line]
    if (set(surface["unresolved_imports"]) != expected_imports
            or needed != (["libc.so.6"] if backend == "direct" else [])
            or {name: digest(path.read_bytes()) for name, path in tools.items()} != tool_ids
            or {p: digest(p.read_bytes()) for p in fixed} != static):
        raise ValueError("Linked ABI, dependencies, or source inputs changed")
    for row in receipt["chain_migration"]["inputs"]:
        path = HIA_ROOT / row["path"]
        if digest(path.read_bytes()) != row["sha256"]:
            raise ValueError("HIA source changed during naming or linking")
    proof = {
        "schema": schema, "backend": backend,
        "entry": entry, "artifact_sha256": digest(library), "artifact_bytes": len(library),
        "text_sha256_before_and_after_symbol_binding": digest(emitted),
        "linked_text_sha256": digest(linked_text),
        "linked_text_equals_relocatable_text": linked_text == emitted,
        "raw_object_sha256": digest(raw), "named_object_sha256": digest(b("named.o").read_bytes()),
        "dynamic": surface, "needed": needed, "tools_sha256": tool_ids,
        "package_sources_sha256": {str(p.relative_to(HIA_ROOT)): h for p, h in static.items()},
        "native_object_receipt": receipt, "runtime_bridge": False,
        "production_dispatch": False,
    }
    b("build.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    return b(library_name), proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=BACKENDS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    library, proof = build(args.output, args.backend)
    print(json.dumps({"library": str(library), "entry": ENTRY, "sha256": proof["artifact_sha256"]}))


if __name__ == "__main__":
    main()
