"""Pinned upstream HIA compiler support for migration qualification.

This module is build/test tooling. It is not part of a native chain runtime.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

HIA_ROOT = Path(__file__).resolve().parents[1]
LOCK = HIA_ROOT / "toolchain.lock.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_toolchain() -> tuple[Path, dict]:
    """Require the exact clean upstream revision; never fetch or substitute it."""
    pin = json.loads(LOCK.read_text())
    configured = os.environ.get("HIA_TOOLCHAIN_ROOT")
    if not configured:
        raise RuntimeError("Set HIA_TOOLCHAIN_ROOT to the checkout in hia/toolchain.lock.json")
    root = Path(configured).resolve(strict=True)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if head != pin["revision"]:
        raise RuntimeError(f"HIA toolchain revision differs: {head}")
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=no"],
                           check=True, capture_output=True, text=True, timeout=10).stdout
    if dirty:
        raise RuntimeError("The pinned HIA checkout has tracked modifications")
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("This qualification target requires Linux x86-64")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    package = importlib.import_module("hepta")
    if Path(package.__file__).resolve().parent != root / "hepta":
        raise RuntimeError("A different hepta package is already loaded")
    return root, pin


def _source_path(relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("Noncanonical HIA dependency path")
    path = Path(relative)
    if (path.is_absolute() or ".." in path.parts
            or path.as_posix() != relative
            or not relative.startswith(("src/", "platform/", "storage/"))
            or path.suffix != ".hepta"):
        raise ValueError("Noncanonical HIA dependency path")
    current = HIA_ROOT
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlinked HIA dependency")
    if not current.is_file():
        raise ValueError("Missing HIA dependency")
    return current


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate component manifest key")
        result[key] = value
    return result


def compose_source(source: Path) -> tuple[bytes, list[tuple[Path, bytes]]]:
    """Compose only explicitly named HIA functions, then let Core verify them.

    This build step does not synthesize instructions, infer missing callees,
    execute includes, or substitute a host-language implementation. Each
    included component must independently pass Core with its own explicit
    declarations. Only its original functions can be selected: its imported
    helpers are neither implicitly copied nor re-exported to the caller.
    """
    from hepta.hia_agent_assembly import assemble_program
    source = source.absolute()
    relative = source.relative_to(HIA_ROOT).as_posix()
    _source_path(relative)
    entry = source.read_bytes()
    manifest_path = HIA_ROOT / "components.json"
    if manifest_path.is_symlink():
        raise ValueError("Symlinked component manifest")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes, object_pairs_hook=_unique_keys)
    if (set(manifest) != {"schema", "includes"}
            or manifest["schema"] != "trnm.hia.component-includes.v1"
            or not isinstance(manifest["includes"], dict)):
        raise ValueError("Unsupported component manifest")
    for key in manifest["includes"]:
        _source_path(key)
    # Capture every source used for either independent admission or the final
    # caller exactly once. build_native rechecks all these bytes after emission.
    captured = {source: entry, manifest_path: manifest_bytes}
    admitted = {}

    def captured_source(path):
        if path not in captured:
            captured[path] = path.read_bytes()
        return captured[path]

    def owned_functions(raw):
        declarations = [name.decode() for name in
            re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)]
        matches = list(re.finditer(
            rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw))
        available = {match.group(1).decode(): match.group(0) for match in matches}
        if (len(declarations) != len(set(declarations))
                or len(matches) != len(available) or set(available) != set(declarations)):
            raise ValueError("Dependency function boundaries are ambiguous")
        return available

    def compose_component(name, ancestry):
        if name in ancestry:
            raise ValueError("Cyclic HIA component declarations are not admitted")
        path = _source_path(name)
        raw = captured_source(path)
        own = owned_functions(raw)
        names = set(own)
        blocks = [raw.rstrip() + b"\n"]
        rows = manifest["includes"].get(name, [])
        if not isinstance(rows, list):
            raise ValueError("HIA includes must be an explicit list")
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"source", "functions"}
                    or not isinstance(row["functions"], list) or not row["functions"]
                    or any(not isinstance(value, str) for value in row["functions"])):
                raise ValueError("Malformed HIA include")
            dependency = _source_path(row["source"])
            if row["source"] in (*ancestry, name):
                raise ValueError("Cyclic HIA component declarations are not admitted")
            if dependency not in admitted:
                independent, available = compose_component(row["source"], (*ancestry, name))
                checked = assemble_program(independent)
                defined = {fn["name"] for fn in checked.as_dict()["functions"]}
                if not set(available) <= defined:
                    raise ValueError("Dependency function boundaries differ from Core")
                admitted[dependency] = available
            available = admitted[dependency]
            for function in row["functions"]:
                if function not in available or function in names:
                    raise ValueError("Unknown or duplicate included function: " + function)
                names.add(function)
                blocks.append(available[function].rstrip() + b"\n")
        return b"".join(blocks), own

    combined, _ = compose_component(relative, ())
    return combined, list(captured.items())


def checked_source(source: Path):
    root, pin = pinned_toolchain()
    from hepta.hia_agent_assembly import assemble_program
    raw, inputs = compose_source(source)
    checked = assemble_program(raw)
    if checked.as_dict()["schema"] != pin["language_schema"]:
        raise ValueError("Chain migration sources must use the locked Core schema")
    return checked, raw, root, pin, inputs


def build_native(source: Path, output: Path, *, byte_exports=(), kind="shared",
                 backend="direct", compiler=None, compiler_sha256=None) -> tuple[dict, dict]:
    """Compile actual HIA source with an explicit backend and retain provenance.

    `direct` uses upstream's Python-hosted direct machine emitter. `selfhost`
    invokes an explicitly pinned native compiler and supports scalar exports
    or its exact legacy f0(readbuf, mutbuf, mutbuf) -> u32 buffer contract.
    Unsupported native profiles are errors, with no direct-emitter fallback.
    """
    checked, raw, root, pin, inputs = checked_source(source)
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if not output.parent.is_dir():
        raise ValueError("Build output parent must already exist")
    if kind not in {"object", "shared"}:
        raise ValueError("Unsupported output kind")
    names = tuple(byte_exports)
    if backend == "direct":
        if compiler is not None or compiler_sha256 is not None:
            raise ValueError("Compiler pins are only valid for selfhost")
        from hepta.hia_program_native import build_program_machine
        receipt = build_program_machine(checked, output, kind=kind, linker="ld",
            foreign_buffer_exports=tuple((name, 1 << 20) for name in names))
    elif backend == "selfhost":
        if compiler is None or compiler_sha256 is None:
            raise ValueError("selfhost requires an explicit compiler path and SHA256")
        executable = Path(compiler).resolve(strict=True)
        executable_bytes = executable.read_bytes()
        if sha256(executable_bytes) != compiler_sha256:
            raise ValueError("Native compiler SHA256 differs from the explicit pin")
        from hepta.hia_agent_assembly import render_assembly
        from hepta.object_symbols import inspect_object_symbols
        value = checked.as_dict()
        if names:
            first = value["functions"][0]
            if (names != ("f0",) or first["name"] != "f0"
                    or [p["type"] for p in first["params"]] != ["readbuf", "mutbuf", "mutbuf"]
                    or first["returns"] != ["u32"] or "exports" in value):
                raise ValueError("selfhost borrowed entry must be exactly first f0(readbuf,mutbuf,mutbuf)->u32")
            # Explicit native-backend object-profile selection. This canonical
            # representation changes no function body, signature, or effect.
            value["module"] = "selfhost_elf"
            exports = ["f0"]
        else:
            exports = value.get("exports", sorted(checked.scalar_entrypoints))
            if not exports:
                raise ValueError("selfhost object builds require scalar exports")
            value["exports"] = exports
        wire = render_assembly(value).encode()
        import fcntl
        captured = os.memfd_create("trnm-hia-compiler", os.MFD_ALLOW_SEALING)
        try:
            position = 0
            while position < len(executable_bytes):
                written = os.write(captured, executable_bytes[position:])
                if written <= 0:
                    raise OSError("short native compiler capture")
                position += written
            os.fchmod(captured, 0o500)
            fcntl.fcntl(captured, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
            result = subprocess.run(["/proc/self/fd/" + str(captured)], input=wire,
                capture_output=True, env={"PATH": ""}, timeout=30, check=False,
                pass_fds=(captured,))
        finally:
            os.close(captured)
        if result.returncode or result.stderr:
            raise RuntimeError(f"Native compiler refused source: exit {result.returncode}; {result.stderr!r}")
        object_bytes = result.stdout
        inventory = inspect_object_symbols(object_bytes, "ELF64", 62)
        if inventory["defined"] != frozenset(exports) or not inventory["undefined"] <= {"calloc", "free"}:
            raise ValueError("Native object import/export inventory differs")
        if executable.read_bytes() != executable_bytes:
            raise ValueError("Native compiler changed while building")
        if kind == "object":
            with output.open("xb") as stream:
                stream.write(object_bytes)
        else:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="hia-link-", dir=output.parent) as temp:
                obj, linked = Path(temp) / "program.o", Path(temp) / "program.so"
                obj.write_bytes(object_bytes)
                subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both", str(obj),
                    "-lc", "-o", str(linked)], check=True, capture_output=True, timeout=30)
                from hepta.elf_shared_abi import inspect_owned_shared_elf
                inspect_owned_shared_elf(linked.read_bytes(), tuple(exports))
                os.link(linked, output)
        receipt = {"schema": "trnm.hia.selfhost-build.v1", "ok": True,
            "status": "native_emitted_not_executed", "output": str(output), "kind": kind,
            "compiler_sha256": compiler_sha256, "compiler_wire_sha256": sha256(wire),
            "object_sha256": sha256(object_bytes), "artifact_sha256": sha256(output.read_bytes()),
            "artifact_bytes": output.stat().st_size, "exports": exports,
            "borrowed_entry_profile": "legacy-f0-private-buffers" if names else None,
            "output_profile_selection": "selfhost_elf" if names else "explicit_scalar_exports",
            "claims": {"direct_machine_code": True, "self_hosted": True,
                "python_emitter_used": False, "fallback_used": False,
                "external_linker_used": kind == "shared", "whole_native_delivery_qualified": False}}
    else:
        raise ValueError("Select direct or selfhost explicitly")
    for input_path, captured_bytes in inputs:
        if input_path.is_symlink() or input_path.read_bytes() != captured_bytes:
            raise ValueError("HIA source or dependency changed during build")
    receipt["chain_migration"] = {"toolchain_repository": pin["repository"],
        "toolchain_revision": pin["revision"], "source_sha256": sha256(inputs[0][1]),
        "composed_source_sha256": sha256(raw), "core_sha256": checked.sha256,
        "inputs": [{"path": path.relative_to(HIA_ROOT).as_posix(),
                    "sha256": sha256(value)} for path, value in inputs],
        "backend": backend, "hosted_build_driver": True, "whole_chain_native": False}
    return receipt, checked.as_dict()
