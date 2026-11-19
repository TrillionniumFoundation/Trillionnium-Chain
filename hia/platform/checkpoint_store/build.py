"""Build and read back the complete native Linux checkpoint-store image set.

Python performs source admission, pinned compiler execution and opaque byte
concatenation. Every instruction, syscall command and storage decision comes
from the checked HIA sources and their compiled HIA Linux emitter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import time
import traceback

from hia.platform.build import Build as PinnedBuild
from hia.platform.build import INPUTS as PIN_INPUTS
from hia.platform.build import inspect_executable, sha256, write_json
from hia.tools.toolchain import checked_source

ROOT = Path(__file__).absolute().parents[3]
HERE = ROOT / "hia/platform/checkpoint_store"
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
ORDER = (
    "main", "io", "filesystem", "authority_open", "authority_fence",
    "authority_head", "socket_owner", "transport_frame", "value_bridge",
    "ledger_open", "ledger_recovery", "ledger_operations", "error_formatter",
    "authority_operations", "api_driver", "socket_path", "unix_client",
    "unix_daemon", "ledger_files", "ledger_inventory", "checkpoint_files",
    "error_text_a", "error_text_b", "errno_text", "api_methods", "api_objects",
)
PROFILES = {"trnm-external-node-checkpoint-v2": 1, "checkpoint-store-api": 2}


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": sha256(raw)}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def exact(left, right) -> bool:
    """JSON equality must not accept True where the schema requires integer 1."""
    return canonical(left) == canonical(right)


def decode(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate JSON field: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def read(root: Path, name: str) -> bytes:
    need(isinstance(name, str), "Relative input must be text")
    path = Path(name)
    need(path.as_posix() == name
         and not path.is_absolute() and ".." not in path.parts,
         "Noncanonical relative input")
    actual = root
    for part in path.parts:
        actual = actual / part
        need(not actual.is_symlink(), "Symlinked input: " + name)
    need(actual.is_file(), "Missing regular input: " + name)
    return actual.read_bytes()


def capture() -> tuple[dict, dict, dict]:
    inputs: dict[str, bytes] = {}
    sources, cores = {}, {}
    for name in (*ORDER, "linux_emitter"):
        checked, raw, _, _, captured = checked_source(HERE / (name + ".hepta"))
        from hepta.hia_agent_assembly import render_assembly
        value = checked.as_dict()
        cores[name] = {
            "functions": len(value["functions"]),
            "blocks": sum(len(f["blocks"]) for f in value["functions"]),
            "ops": sum(len(b["ops"]) for f in value["functions"] for b in f["blocks"]),
            "maximum_function_blocks": max(len(f["blocks"]) for f in value["functions"]),
        }
        count = cores[name]
        need(count["functions"] <= 128 and count["blocks"] <= 1536
             and count["ops"] <= 8192 and count["maximum_function_blocks"] <= 256,
             "Original pinned compiler budget exceeded: " + name)
        sources[name] = {"composed": raw, "compiler_input": render_assembly(value).encode()}
        for path, data in captured:
            relative = path.relative_to(ROOT).as_posix()
            need(read(ROOT, relative) == data, "Source changed during capture")
            need(relative not in inputs or inputs[relative] == data,
                 "Inconsistent captured source: " + relative)
            inputs[relative] = data
    for path in sorted(HERE.rglob("*")):
        need(not path.is_symlink(), "Symlinked owned source")
        if path.is_dir():
            need(path.name != "__pycache__", "Stale Python bytecode in owned source")
            continue
        need(path.suffix in {".py", ".hepta", ".json", ".md", ".rs"},
             "Unexpected owned source type")
        name = path.relative_to(ROOT).as_posix()
        inputs[name] = read(ROOT, name)
    for name in (
        "hia/platform/build.py", "hia/tools/toolchain.py", "hia/toolchain.lock.json",
        "hia/qualification/compiler-binding.json", "trillionnium/Cargo.toml",
        "trillionnium/Cargo.lock", "trillionnium/crates/trnm-checkpoint-store/Cargo.toml",
        "hia/tests/rust_checkpoint_api_reference.rs",
    ):
        inputs[name] = read(ROOT, name)
    for package in ("trnm-checkpoint-store", "trnm-checkpoint-types"):
        for path in sorted((ROOT / "trillionnium/crates" / package).rglob("*.rs")):
            name = path.relative_to(ROOT).as_posix()
            inputs[name] = read(ROOT, name)
        name = "trillionnium/crates/" + package + "/Cargo.toml"
        inputs[name] = read(ROOT, name)
    # Cargo resolves the workspace even for one selected package. Keep its
    # complete manifest roster, as well as the selected original test sources.
    for path in sorted((ROOT / "trillionnium/crates").glob("*/Cargo.toml")):
        name = path.relative_to(ROOT).as_posix()
        inputs[name] = read(ROOT, name)
    for name in PIN_INPUTS:
        relative = "hia/" + name
        inputs[relative] = read(ROOT, relative)
    return inputs, sources, cores


def check_inputs(inputs: dict) -> None:
    for name, before in inputs.items():
        need(read(ROOT, name) == before, "Source changed: " + name)
    current_owned = {p.relative_to(ROOT).as_posix() for p in HERE.rglob("*") if p.is_file()}
    need(current_owned == {n for n in inputs if n.startswith("hia/platform/checkpoint_store/")},
         "Owned input roster changed")


def build(output: Path) -> dict:
    output = output.absolute()
    need(not output.exists() and not output.is_symlink(), "Fresh build output required")
    need(output.parent.resolve(strict=True) == output.parent,
         "Canonical existing build parent required")
    need(ROOT != output.resolve() and ROOT not in output.resolve().parents,
         "Generated build must be outside source tree")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic_ns()
    inputs, sources, cores, images, artifacts, failures = {}, {}, {}, {}, {}, []
    pinned = None
    failure = None
    try:
        inputs, sources, cores = capture()
        expected = decode(read(ROOT, "hia/platform/checkpoint_store/native_images.json"))
        check_expected(expected, sources, cores)
        pinned = PinnedBuild(output / "compiler")
        need(sha256(pinned.compiler) == COMPILER, "Exact qualified compiler differs")
        for name in (*ORDER, "linux_emitter"):
            for suffix, data in sources[name].items():
                (output / (name + "." + suffix + ".hepta")).write_bytes(data)
            image = pinned.stage(pinned.compiler, sources[name]["compiler_input"], "compile-" + name)
            need(name == "linux_emitter" or 0 < len(image) <= 524288,
                 "Pinned native image extent differs")
            need(exact(identity(image), expected["images"][name]),
                 "Actual native image differs from the frozen source-bound image: " + name)
            images[name] = image
            (output / (name + (".elf" if name == "linux_emitter" else ".flat"))).write_bytes(image)
            check_inputs(inputs)
        inspect_executable(images["linux_emitter"])
        for name, profile in PROFILES.items():
            metadata = b"HCSHD001" + struct.pack("<QQ", len(ORDER), profile)
            metadata += b"".join(struct.pack("<Q", len(images[role])) for role in ORDER)
            prefix = pinned.stage(images["linux_emitter"], metadata, "emit-" + name)
            need(len(prefix) == 5120, "HIA emitter header extent differs")
            need(exact(identity(prefix), expected["prefixes"][name]), "Frozen emitted prefix differs")
            # The build driver neither makes ISA nor modifies addresses. The
            # HIA emitter supplies every header, dispatch and relocation byte.
            executable = prefix + b"".join(images[role] for role in ORDER)
            structure = inspect_executable(executable)
            (output / (name + ".prefix")).write_bytes(prefix)
            path = output / name
            path.write_bytes(executable)
            path.chmod(0o500)
            artifacts[name] = {**identity(executable), "profile": profile, "structure": structure}
            need(exact(artifacts[name], expected["artifacts"][name]), "Frozen native executable differs")
        pinned.check_pin()
    except BaseException as error:
        failure = {"error": repr(error), "traceback": traceback.format_exc()}
    finally:
        if inputs:
            try:
                check_inputs(inputs)
            except BaseException as error:
                failures.append(repr(error))
        if pinned is not None:
            try:
                pinned.check_pin()
            except BaseException as error:
                failures.append(repr(error))
        manifest = {name: identity(raw) for name, raw in sorted(inputs.items())}
        report = {
            "schema": "trnm.hia.checkpoint-store-build.v1",
            "output_root": str(output),
            "status": "PASS" if failure is None and not failures else "FAIL",
            "source_inputs": manifest, "source_set_sha256": sha256(canonical(manifest)),
            "image_order": list(ORDER), "profiles": PROFILES, "core": cores,
            "sources": {name: {k: identity(v) for k, v in row.items()} for name, row in sources.items()},
            "images": {name: identity(raw) for name, raw in images.items()},
            "artifacts": artifacts, "compiler_sha256": COMPILER,
            "toolchain": None if pinned is None else pinned.lock,
            "compiler_qualification_binding": None if pinned is None else pinned.binding,
            "stages": [] if pinned is None else pinned.stages,
            "failure": failure, "source_after": {"status": "MATCH" if not failures else "FAIL", "errors": failures},
            "elapsed_ns": time.monotonic_ns() - started,
            "runtime": "NOT_RUN", "native_runtime_has_python_rust_c_or_dynamic_loader": False,
            "complete_image_roster": len(images) == len(ORDER) + 1,
        }
        write_json(output / "build.json", report)
    need(report["status"] == "PASS", "Native build failed; actual failure receipt retained")
    return report


def check_expected(expected: dict, sources: dict, cores: dict) -> None:
    need(set(expected) == {"schema", "compiler_sha256", "image_order", "profiles", "core",
                           "sources", "images", "artifacts", "prefixes"},
         "Frozen native image schema differs")
    need(expected["schema"] == "trnm.hia.checkpoint-store-native-images.v1"
         and expected["compiler_sha256"] == COMPILER
         and exact(expected["image_order"], list(ORDER))
         and exact(expected["profiles"], PROFILES)
         and exact(expected["core"], cores)
         and exact(expected["sources"], {n: {k: identity(v) for k, v in row.items()}
                                         for n, row in sources.items()}),
         "Canonical source differs from the frozen native composition")
    need(set(expected["images"]) == set((*ORDER, "linux_emitter"))
         and set(expected["artifacts"]) == set(PROFILES)
         and set(expected["prefixes"]) == set(PROFILES), "Frozen native image roster differs")


def validate(directory: Path) -> dict:
    directory = directory.absolute()
    need(directory.resolve(strict=True) == directory and not directory.is_symlink(),
         "Canonical build directory required")
    report = decode(read(directory, "build.json"))
    executed_root = Path(report["output_root"])
    need(executed_root.is_absolute() and executed_root.as_posix() == report["output_root"]
         and ".." not in executed_root.parts, "Noncanonical native build execution root")
    inputs, sources, cores = capture()
    expected = decode(read(ROOT, "hia/platform/checkpoint_store/native_images.json"))
    check_expected(expected, sources, cores)
    manifest = {name: identity(raw) for name, raw in sorted(inputs.items())}
    need(report["schema"] == "trnm.hia.checkpoint-store-build.v1" and report["status"] == "PASS"
         and report["failure"] is None and exact(report["source_after"], {"status": "MATCH", "errors": []}),
         "Incomplete build observation")
    need(exact(report["source_inputs"], manifest) and report["source_set_sha256"] == sha256(canonical(manifest)),
         "Captured source closure differs")
    need(exact(report["image_order"], list(ORDER)) and exact(report["profiles"], PROFILES)
         and exact(report["core"], cores) and report["compiler_sha256"] == COMPILER,
         "Native composition or compiler differs")
    need(report["runtime"] == "NOT_RUN" and report["native_runtime_has_python_rust_c_or_dynamic_loader"] is False
         and report["complete_image_roster"] is True, "Unbound runtime claim")
    need(exact(report["sources"], {name: {k: identity(v) for k, v in row.items()} for name, row in sources.items()}),
         "Compiler source identities differ")
    lock = decode(read(ROOT, "hia/toolchain.lock.json"))
    binding = decode(read(ROOT, "hia/qualification/compiler-binding.json"))
    need(exact(report["toolchain"], lock) and exact(report["compiler_qualification_binding"], binding),
         "Original compiler qualification binding differs")
    labels = ["compile-" + role for role in (*ORDER, "linux_emitter")]
    labels += ["emit-" + name for name in PROFILES]
    need([row["stage"] for row in report["stages"]] == labels, "Complete compiler execution roster differs")
    rows = dict(zip(labels, report["stages"], strict=True))

    def stage(label: str, payload: bytes, executable: dict) -> bytes:
        folder = "compiler/" + label + "/"
        row = rows[label]
        need(exact(decode(read(directory, folder + "receipt.json")), row), "Compiler receipt differs")
        stdout = read(directory, folder + "stdout.raw")
        stderr = read(directory, folder + "stderr.raw")
        need(read(directory, folder + "stdin.raw") == payload and row["input_sha256"] == sha256(payload)
             and type(row["input_bytes"]) is int and row["input_bytes"] == len(payload), "Actual compiler input differs")
        need(type(row["exit_code"]) is int and row["exit_code"] == 0 and row["timed_out"] is False
             and row["cleanup"] is None and stderr == b"" and row["stderr_hex"] == ""
             and row["stderr_sha256"] == sha256(stderr), "Failed native stage")
        need(row["executable_sha256"] == executable["sha256"]
             and type(row["executable_bytes"]) is int and row["executable_bytes"] == executable["bytes"],
             "Executed compiler identity differs")
        need(row["output_sha256"] == sha256(stdout)
             and type(row["output_bytes"]) is int and row["output_bytes"] == len(stdout),
             "Actual compiler output differs")
        need(type(row["wall_limit_seconds"]) is int and row["wall_limit_seconds"] == 30
             and type(row["cleanup_limit_seconds"]) is int and row["cleanup_limit_seconds"] == 3,
             "Original stage budget differs")
        need(type(row["start_monotonic_ns"]) is int and type(row["end_monotonic_ns"]) is int
             and 0 < row["start_monotonic_ns"] <= row["end_monotonic_ns"]
             and row["cwd"] == str(executed_root / "compiler" / label)
             and exact(row["environment"], {"PATH": ""})
             and len(row["argv"]) == 1 and row["argv"][0].startswith("/proc/self/fd/")
             and row["argv"][0].removeprefix("/proc/self/fd/").isdigit(),
             "Native stage execution boundary differs")
        return stdout

    compiler = {"sha256": COMPILER, "bytes": binding.get("compiler_bytes", 673903)}
    images = {}
    for role in (*ORDER, "linux_emitter"):
        for suffix, raw in sources[role].items():
            need(read(directory, role + "." + suffix + ".hepta") == raw, "Saved composed input differs")
        image = stage("compile-" + role, sources[role]["compiler_input"], compiler)
        need(exact(identity(image), expected["images"][role]), "Frozen compiler output differs: " + role)
        need(read(directory, role + (".elf" if role == "linux_emitter" else ".flat")) == image,
             "Saved compiled image differs")
        images[role] = image
    need(exact(report["images"], {name: identity(raw) for name, raw in images.items()}), "Actual image set differs")
    artifacts = {}
    for name, profile in PROFILES.items():
        metadata = b"HCSHD001" + struct.pack("<QQ", len(ORDER), profile)
        metadata += b"".join(struct.pack("<Q", len(images[role])) for role in ORDER)
        prefix = stage("emit-" + name, metadata, identity(images["linux_emitter"]))
        need(exact(identity(prefix), expected["prefixes"][name]), "Frozen HIA prefix differs")
        need(len(prefix) == 5120 and read(directory, name + ".prefix") == prefix, "Actual HIA prefix differs")
        executable = prefix + b"".join(images[role] for role in ORDER)
        need(read(directory, name) == executable, "Actual final executable differs")
        artifacts[name] = {**identity(executable), "profile": profile, "structure": inspect_executable(executable)}
    need(exact(report["artifacts"], artifacts) and exact(artifacts, expected["artifacts"]),
         "Complete executable receipt differs")
    check_inputs(inputs)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.output is not None:
        result = build(args.output)
        validate(args.output)
    else:
        result = validate(args.verify)
    print(json.dumps({key: result[key] for key in ("status", "source_set_sha256", "artifacts")}, sort_keys=True))


if __name__ == "__main__":
    main()
