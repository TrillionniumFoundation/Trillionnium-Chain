#!/usr/bin/env python3
"""Independent lightweight import checks, never model-execution evidence."""
import argparse
import ast
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import py_compile
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import types
import zipfile

EVIDENCE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", choices=("metadata", "bytecode", "project", "zip"))
parser.add_argument("--chain-root", type=Path, default=EVIDENCE.parents[1])
parser.add_argument("--runtime-root", type=Path, help="Hepta checkout; required for project mode")
parser.add_argument("--output", type=Path, required=True, help="New output directory; must not exist")
args = parser.parse_args()
if args.mode == "project" and args.runtime_root is None:
    parser.error("project mode requires --runtime-root")
if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    parser.error("run this review with Python -I -S -B")
HERE = args.output.resolve()
HERE.mkdir(mode=0o700, parents=False, exist_ok=False)
CHAIN = args.chain_root.resolve()
RUNTIME = args.runtime_root.resolve() if args.runtime_root is not None else None
HELPER_PATH = CHAIN / "scripts/llm_python_runtime_contract.py"
HELPER_RAW = HELPER_PATH.read_bytes()
HELPER_SHA = hashlib.sha256(HELPER_RAW).hexdigest()
helper = types.ModuleType("independent_runtime_review")
helper.__file__ = str(HELPER_PATH)
exec(compile(HELPER_RAW, str(HELPER_PATH), "exec"), helper.__dict__)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metadata_check():
    with tempfile.TemporaryDirectory(prefix="metadata-", dir=HERE) as directory:
        root = Path(directory)
        info = root / "review_dist-1.2.3.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: review-dist\nVersion: 1.2.3\n")
        sys.path.insert(0, str(root))
        before = importlib.metadata.version("review-dist")
        original = sys.meta_path[:]
        helper.install_import_guard({"files": {}}, {str(HELPER_PATH): HELPER_SHA})
        try:
            after = {"version": importlib.metadata.version("review-dist")}
        except importlib.metadata.PackageNotFoundError as error:
            after = {"error": type(error).__name__, "message": str(error)}
        finally:
            sys.meta_path[:] = original
        return {"before_guard": before, "after_guard": after}


def bytecode_check():
    with tempfile.TemporaryDirectory(prefix="bytecode-", dir=HERE) as directory:
        root = Path(directory)
        source = root / "review_pinned_source.py"
        bad, good = b'OBSERVED = "pyc"\n', b'OBSERVED = "raw"\n'
        source.write_bytes(bad)
        original_stat = source.stat()
        py_compile.compile(str(source), doraise=True)
        source.write_bytes(good)
        os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        sys.path.insert(0, str(root))
        baseline = importlib.import_module("review_pinned_source").OBSERVED
        del sys.modules["review_pinned_source"]
        original = sys.meta_path[:]
        helper.install_import_guard({"files": {}}, {str(source): digest(source)})
        try:
            guarded = importlib.import_module("review_pinned_source").OBSERVED
        finally:
            sys.meta_path[:] = original
        return {"ambient_timestamp_pyc_executed": baseline, "guarded_executed": guarded}


def source_roster():
    tree = ast.parse((CHAIN / "scripts/llm_cell_host_handoff.py").read_bytes())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == "SOURCES" for name in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("source roster absent")


def project_checks():
    roster = source_roster()
    with tempfile.TemporaryDirectory(prefix="project-", dir=HERE) as directory:
        root = Path(directory)
        pins = {}
        for relative in roster.values():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((CHAIN / relative).read_bytes())
            pins[str(path)] = digest(path)
        worker_path = root / "scripts/llm_neural_read_worker.py"
        marker = root / "unadmitted-shadow-executed"
        canary = "open(" + repr(str(marker)) + ", 'w').write('unadmitted import')\n"
        for name in ("hashlib.py", "json.py"):
            (root / "scripts" / name).write_text(canary + "raise RuntimeError('SCRIPT_SHADOW')\n")
        bootstrap = subprocess.run([sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=" + str(root / "unused-pyc"), str(worker_path), "--help"], capture_output=True, text=True, timeout=10)
        stdlib = Path(sysconfig.get_path("stdlib")).resolve()
        runtime_files = {str(path.resolve()): digest(path) for path in stdlib.rglob("*") if "site-packages" not in path.relative_to(stdlib).parts and path.is_file()}
        sys.path.append(str(root / "scripts"))
        original = sys.meta_path[:]
        helper.install_import_guard({"files": runtime_files}, pins)
        try:
            worker = importlib.import_module("llm_neural_read_worker")
            runtime = importlib.import_module("llm_runtime_pilot")
            inherited = importlib.import_module("llm_inherited_runtime")
            worker.python_runtime = types.SimpleNamespace(__file__=str(root / "scripts/llm_python_runtime_contract.py"))
            worker.runtime, worker.inherited = runtime, inherited
            observed = worker.worker_sources()
            expected = {Path(path).name: value for path, value in pins.items() if Path(path).name != "llm_neural_read_worker.py"}
            plan = {"inherited_sources": observed, "worker_source": pins[str(worker_path)]}
            loaded_paths = worker.source_paths(plan)
            (root / "formal/pon-nakamoto-v1/torch.py").write_text(canary + "raise RuntimeError('TORCH_SHADOW')\n")
            try:
                importlib.import_module("torch")
                shadow_result = "unexpectedly imported"
            except ValueError as error:
                shadow_result = str(error).replace(str(root), "<temporary-project>")
        finally:
            sys.meta_path[:] = original
        host_raw = (RUNTIME / "codex-rs/hepta-infer-worker-host/src/smollm_neural_profile.rs").read_text()
        required = re.findall(r'"([^"]+)"', host_raw.split("let required = [", 1)[1].split("];", 1)[0])
        return {"script_shadow_help_exit": bootstrap.returncode, "unadmitted_shadow_executed": marker.exists(), "worker_sources_equal_host_pin_projection": observed == expected, "host_required_names_match": sorted(roster) == required, "source_path_count": len(loaded_paths), "source_paths_match_actual_pins": all(pins[path] == value for path, value in loaded_paths.items()), "torch_shadow_result": shadow_result, "worker_source_sha256": digest(worker_path)}


def zip_check():
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    executable = Path(sys.executable).resolve()
    worker = CHAIN / "scripts/llm_neural_read_worker.py"
    with tempfile.TemporaryDirectory(prefix="startup-zip-", dir=HERE) as directory:
        root = Path(directory)
        base, prefix = root / "base", root / "venv"
        (base / "bin").mkdir(parents=True)
        (base / "lib").mkdir()
        (prefix / "bin").mkdir(parents=True)
        version = "%d.%d" % sys.version_info[:2]
        python = base / "bin" / ("python" + version)
        shutil.copy2(executable, python)
        (base / "lib" / ("python" + version)).symlink_to(stdlib, target_is_directory=True)
        (prefix / "bin/python3").symlink_to(python)
        (prefix / "pyvenv.cfg").write_text("home = " + str(base / "bin") + "\ninclude-system-site-packages = false\nversion = " + version + "\n")
        command = [str(prefix / "bin/python3"), "-I", "-S", "-B", "-X", "pycache_prefix=" + str(root / "unused-pyc")]
        before = subprocess.run(command + [str(worker), "--help"], capture_output=True, text=True, timeout=10)
        contract = {"prefix": str(prefix), "stdlib_root": str(stdlib)}
        inventory_before = helper.managed_inventory(contract)
        binary_before = digest(python)
        archive = base / "lib" / ("python%d%d.zip" % sys.version_info[:2])
        marker = root / "unadmitted-hashlib-executed"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
            output.writestr("hashlib.py", "open(" + repr(str(marker)) + ", 'w').write('unadmitted bootstrap module ran')\nraise RuntimeError('UNADMITTED_STARTUP_ZIP_CANARY')\n")
        after = subprocess.run(command + [str(worker), "--help"], capture_output=True, text=True, timeout=10)
        return {"before_exit": before.returncode, "after_exit": after.returncode, "zip_canary_executed": marker.exists(), "actual_canary_trace": "UNADMITTED_STARTUP_ZIP_CANARY" in after.stderr, "managed_inventory_unchanged": inventory_before == helper.managed_inventory(contract), "inventory_count": len(inventory_before), "declared_interpreter_bytes_unchanged": binary_before == digest(python), "zip_is_under_pinned_prefix_or_stdlib": archive.is_relative_to(prefix) or archive.is_relative_to(stdlib), "worker_source_sha256": digest(worker)}


mode = args.mode
result = {"scope": "independent lightweight import behavior only; no model or successful admission", "mode": mode, "reproduction_script_sha256": digest(__file__), "helper_sha256": HELPER_SHA, "python": sys.version, "observed": {"metadata": metadata_check, "bytecode": bytecode_check, "project": project_checks, "zip": zip_check}[mode]()}
encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
receipt = HERE / (mode + "-" + HELPER_SHA + ".json")
with receipt.open("x", encoding="utf-8") as output:
    output.write(encoded)
print(encoded, end="")
