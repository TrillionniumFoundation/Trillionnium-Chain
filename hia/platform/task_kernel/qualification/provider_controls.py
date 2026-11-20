"""Actual provider build rejection controls; all mutated inputs are isolated copies."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
BUILDER = ROOT / "hia/platform/task_kernel/build_provider.py"
positive = Path(sys.argv[1]).resolve(strict=True)
output = Path(sys.argv[2]).absolute()
assert __debug__ and not output.exists() and ROOT not in output.parents
output.mkdir(mode=0o700)
build = json.loads((positive / "build.json").read_text())
assert build["status"] == "PASS" and build["finalized"]
dependency = Path(next(p for p in build["source_before"] if p.endswith("/libsqlite3-sys-0.39.1/Cargo.toml"))).parent
before = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in build["source_before"]}
report = {"status": "FAIL", "finalized": False, "cases": [], "positive_build": str(positive / "build.json")}
def save():
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
def reject(name, argv, expected, env=None, result_dir=None):
    started = time.monotonic_ns()
    row = {"name": name, "argv": list(map(str, argv)), "started": True, "completed": False}
    report["cases"].append(row);save()
    p = subprocess.run(row["argv"], input=b"", capture_output=True, env=env, cwd=ROOT, timeout=60)
    (output / (name + ".stdin.raw")).write_bytes(b"")
    (output / (name + ".stdout.raw")).write_bytes(p.stdout)
    (output / (name + ".stderr.raw")).write_bytes(p.stderr)
    row.update(completed=True, exit_code=p.returncode, elapsed_ns=time.monotonic_ns() - started)
    assert p.returncode != 0 and expected.encode() in p.stderr, row
    if result_dir is not None:
        observed = json.loads((result_dir / "build.json").read_text())
        row["observed_status"], row["observed_finalized"] = observed["status"], observed["finalized"]
        assert observed["status"] == "FAIL" and not observed["finalized"]
    save()
try:
    def command(name, dep=dependency):
        return [sys.executable, BUILDER, "--dependency", dep, "--output", output / name]
    reject("unsupported-target", command("unsupported-target") + ["--target", "aarch64-unknown-linux-gnu"],
           "Unsupported native target", result_dir=output / "unsupported-target")
    reject("environment-override", command("environment-override"), "External native build override refused: CC",
           env={**os.environ, "CC": "/usr/bin/false"}, result_dir=output / "environment-override")
    reject("missing-dependency", command("missing-dependency", output / "absent"), "No such file or directory",
           result_dir=output / "missing-dependency")
    reject("existing-output", [sys.executable, BUILDER, "--dependency", dependency, "--output", positive],
           "Fresh canonical output required")
    copied = output / "modified-source" / dependency.name
    copied.mkdir(parents=True)
    for name in ("Cargo.toml", "build.rs", "sqlite3/sqlite3.c", "sqlite3/sqlite3.h"):
        target = copied / name;target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(dependency / name, target)
    with (copied / "sqlite3/sqlite3.h").open("ab") as stream:
        stream.write(b"\n/* qualification identity mismatch */\n")
    reject("modified-header", command("modified-header", copied), "SQLite public C header differs",
           result_dir=output / "modified-header")
    abi_copy = output / "modified-abi-source"
    abi_copy.mkdir()
    for name in ("provider_native.hepta", "witness_emitter.hepta", "build_witness.py", "provider_abi.json"):
        shutil.copyfile(BUILDER.parent / name, abi_copy / name)
    abi = json.loads((abi_copy / "provider_abi.json").read_text())
    abi["build_fence"] += "-wrong"
    (abi_copy / "provider_abi.json").write_text(json.dumps(abi) + "\n")
    # Only the test process changes the module's source-directory binding. This
    # exercises the real builder against a copied ABI, without changing the repo.
    worker = output / "modified-abi-worker.py"
    worker.write_text("""import importlib.util,sys
from pathlib import Path
p=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('provider_build',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.HERE=Path(sys.argv[2]);m.ProviderBuild(sys.argv[3],sys.argv[4]).run()
""")
    reject("modified-abi", [sys.executable, worker, BUILDER, abi_copy, dependency, output / "modified-abi"],
           "Provider ABI identity differs", result_dir=output / "modified-abi")
    spec = importlib.util.spec_from_file_location("provider_build_controls", BUILDER)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    instance = module.ProviderBuild(dependency, output / "stage-errors")
    for name, argv, expected, timeout in [
        ("real-timeout", [sys.executable, "-c", "import sys,time;print('partial stdout',flush=True);print('partial stderr',file=sys.stderr,flush=True);time.sleep(5)"], subprocess.TimeoutExpired, 0.05),
        ("missing-executable", [str(output / "not-an-executable")], FileNotFoundError, 1),
    ]:
        try:
            instance.stage(name, argv, timeout=timeout)
        except expected as error:
            report["cases"].append({"name": name, "actual_exception": type(error).__name__})
            save()
        else:
            raise AssertionError("Missing expected real failure: " + name)
    assert before == {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in before}
    report.update(status="PASS", finalized=True, negative_controls=8, positive_source_unchanged=True)
    save()
except BaseException as error:
    report.update(status="FAIL", failure=repr(error));save();raise
print(json.dumps({"status": "PASS", "negative_controls": 8, "positive_source_unchanged": True}))
