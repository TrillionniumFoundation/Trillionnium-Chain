#!/usr/bin/env python3
"""Actual startup ._pth canary, never a native-guard or model acceptance test."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import types

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--chain-root", type=Path, default=Path(__file__).resolve().parents[2])
parser.add_argument("--output", type=Path, required=True, help="New output directory; must not exist")
args = parser.parse_args()
if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    parser.error("run this review with Python -I -S -B")
out = args.output.resolve()
out.mkdir(mode=0o700, parents=False, exist_ok=False)
chain = args.chain_root.resolve()
helper_path = chain / "scripts/llm_python_runtime_contract.py"
raw = helper_path.read_bytes()
helper = types.ModuleType("independent_pth_review")
helper.__file__ = str(helper_path)
exec(compile(raw, str(helper_path), "exec"), helper.__dict__)
stdlib = Path(sysconfig.get_path("stdlib")).resolve()
worker = chain / "scripts/llm_neural_read_worker.py"
version = "%d.%d" % sys.version_info[:2]

with tempfile.TemporaryDirectory(prefix="startup-underscore-pth-", dir=out) as directory:
    root = Path(directory)
    base, prefix, evil = root / "base", root / "venv", root / "modules"
    (base / "bin").mkdir(parents=True)
    (base / "lib").mkdir()
    (prefix / "bin").mkdir(parents=True)
    evil.mkdir()
    exe = base / "bin" / ("python" + version)
    shutil.copy2(Path(sys.executable).resolve(), exe)
    (base / "lib" / ("python" + version)).symlink_to(stdlib, target_is_directory=True)
    (prefix / "bin/python3").symlink_to(exe)
    (prefix / "pyvenv.cfg").write_text("home = " + str(base / "bin") + "\ninclude-system-site-packages = false\nversion = " + version + "\n")
    command = [str(prefix / "bin/python3"), "-I", "-S", "-B", "-X", "pycache_prefix=" + str(root / "unused-pyc")]
    declared = {"prefix": str(prefix), "stdlib_root": str(stdlib)}
    inventory_before = helper.managed_inventory(declared)
    before = subprocess.run(command + [str(worker), "--help"], capture_output=True, text=True, timeout=10)
    marker = root / "unadmitted-underscore-pth-executed"
    (evil / "hashlib.py").write_text("open(" + repr(str(marker)) + ", 'w').write('unpinned _pth bootstrap')\nraise RuntimeError('UNADMITTED_UNDERSCORE_PTH_CANARY')\n")
    sidecar = exe.with_name(exe.name + "._pth")
    sidecar.write_text(str(evil) + "\n" + str(stdlib) + "\n" + str(stdlib / "lib-dynload") + "\n")
    after = subprocess.run(command + [str(worker), "--help"], capture_output=True, text=True, timeout=10)
    report = {
        "scope": "actual CPython startup _pth source canary only; no native guard invocation/model admission",
        "reproduction_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(raw).hexdigest(),
        "worker_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
        "before_exit": before.returncode,
        "after_exit": after.returncode,
        "canary_executed": marker.exists(),
        "canary_trace": "UNADMITTED_UNDERSCORE_PTH_CANARY" in after.stderr,
        "declared_inventory_unchanged": inventory_before == helper.managed_inventory(declared),
        "sidecar_under_declared_prefix_or_stdlib": sidecar.is_relative_to(prefix) or sidecar.is_relative_to(stdlib),
        "stderr_tail": after.stderr[-1000:].replace(str(chain), "<CHAIN>").replace(str(root), "<TEMP>"),
    }
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    with (out / "observation.json").open("x", encoding="utf-8") as output:
        output.write(encoded)
    print(encoded, end="")
