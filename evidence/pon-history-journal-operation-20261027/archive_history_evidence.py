#!/usr/bin/env python3
"""Retain raw observations and exact reconstruction inputs without executables."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

BASE = Path(__file__).resolve().parent
OUT = BASE / "prepared" / "repository-evidence"
OUT.mkdir(parents=True, exist_ok=True)
# Raw tool output can legitimately contain trailing spaces and blank lines.
# Compress its exact bytes instead of editing observations to satisfy Git's
# source-whitespace check. The original scratch captures remain unchanged.
for previous in OUT.rglob("*.log"):
    previous.unlink()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def copy(source, destination):
    raw = source.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix == ".log":
        destination = destination.with_name(destination.name + ".gz")
        destination.write_bytes(gzip.compress(raw, mtime=0))
        assert gzip.decompress(destination.read_bytes()) == raw
    else:
        destination.write_bytes(raw)

def zipped(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(gzip.compress(source.read_bytes(), mtime=0))

for attempt in sorted(BASE.glob("native-attempt-*")):
    for source in sorted(attempt.iterdir()):
        if not source.is_file() or source.name.endswith(".bin"):
            continue
        target = OUT / attempt.name / source.name
        if source.name.startswith("source-") or source.suffix in (".patch", ".jsonl"):
            zipped(source, target.with_name(target.name + ".gz"))
        else:
            copy(source, target)
    if (attempt / "retained").is_dir():
        for source in sorted((attempt / "retained").iterdir()):
            if source.is_file():
                copy(source, OUT / attempt.name / "retained" / source.name)
    process = attempt / "native-artifacts" / "real-process-sigkill"
    if process.is_dir():
        stream = io.BytesIO()
        def normalized(info):
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            return info
        with tarfile.open(fileobj=stream, mode="w") as archive:
            archive.add(process, arcname="real-process-sigkill", filter=normalized)
        target = OUT / attempt.name / "actual-process-fixture.tar.gz"
        target.write_bytes(gzip.compress(stream.getvalue(), mtime=0))

for name in [
    "ci503-job-122130374036.log", "ci503-job-122130374464.log",
    "ci503-pinned-blob-diagnosis.json", "followup-sixteen-pins.json",
    "source-integrity-final.log", "ci-contract-final.log", "ci-contract-tests-final.log",
    "repository-check-final.log", "sixteen-pins-final.json", "final-static-verification.json", "formatter-final.log",
    "raw-evidence-whitespace-observation.log", "raw-evidence-whitespace-observation.json",
    "pid-namespace-mapping-failure.json", "pidfd-observation-probe.json",
    "pidfd-and-parent-observation-probe.json", "pidfd-positive-and-real-descendant-negative.json",
    "run_history_native.py", "run_history_retained.py", "archive_history_evidence.py",
]:
    copy(BASE / name, OUT / name)

clippy = BASE / "clippy-final"
if clippy.is_dir():
    for source in sorted(clippy.iterdir()):
        if source.name.startswith("source-"):
            zipped(source, OUT / "clippy-final" / (source.name + ".gz"))
        elif source.is_file():
            copy(source, OUT / "clippy-final" / source.name)

files = {str(path.relative_to(OUT)): {"bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
         for path in sorted(OUT.rglob("*"))
         if path.is_file() and path.name not in ("SHA256_MANIFEST.json", "README.md")}
manifest = {"schema": "history-journal-increment-evidence-sha256-v1",
            "parent": "081c04e893850a42b539d98d6ccfa659496e99ee",
            "hash_scope": "all archived evidence files except this manifest and explanatory README.md; the Git tree binds both",
            "native_executables_omitted": True,
            "exact_failed_and_successful_native_source_patches_retained": True,
            "process_material_uses_disclosed_test_keys_and_synthetic_model_bytes": True,
            "entire_history_qualified": False, "production_qualified": False,
            "files": files}
(OUT / "SHA256_MANIFEST.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
print(json.dumps({"directory": str(OUT), "files": len(files), "bytes": sum(row["bytes"] for row in files.values())}))
