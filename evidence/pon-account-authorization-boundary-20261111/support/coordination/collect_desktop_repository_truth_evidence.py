#!/usr/bin/env python3
"""Freeze completed desktop repository-truth evidence without editing source or logs."""
from pathlib import Path
import datetime
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile

HEAD = "cdd984808a088e6c2e13b1e1ae6630a94d500c89"
TREE = "1ed39b6ebe55cb00c238f26f6bfc9361ab93faec"
SOURCE = Path("/home/qian-qi/chain-pq-profile-boundary-20261111-a418-final")
RECORDS = Path("/home/qian-qi/chain-pq-a418-final-records")
ROOT = "repository-truth-evidence-v1"
ARCHIVE = RECORDS / "archives" / (ROOT + ".tar.gz")
MANIFEST_PATH = RECORDS / "archives" / (ROOT + ".manifest.json")
RECORD_IDS = ("repository-truth", "llm-runtime-release-python", "repository-truth-runtime-python")
REQUIREMENTS_SHA256 = "2acf07322b544b1d2318642b59877dd035bc7808590619f3cf23e75eedd0bbe7"
WHEEL_SHA256 = "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(["git", *args], cwd=SOURCE).decode().strip()

def source_identity():
    value = {"head": git("rev-parse", "HEAD"),
             "tree": git("rev-parse", "HEAD^{tree}"),
             "status_porcelain": git("status", "--porcelain=v1", "--untracked-files=all")}
    assert value == {"head": HEAD, "tree": TREE, "status_porcelain": ""}, value
    return value

def read_json(path):
    return json.loads(path.read_bytes())

identity_before = source_identity()
record_summaries = {}
selected = []

def select_tree(directory, archive_prefix):
    assert directory.is_dir(), str(directory)
    for path in sorted(directory.rglob("*")):
        mode = path.lstat().st_mode
        assert stat.S_ISDIR(mode) or stat.S_ISREG(mode), str(path)
        if stat.S_ISREG(mode):
            selected.append((path, ROOT + "/" + archive_prefix + "/" + path.relative_to(directory).as_posix()))

for record_id in RECORD_IDS:
    directory = RECORDS / "validation" / HEAD / record_id
    result = read_json(directory / "result.json")
    context = read_json(directory / "context.json")
    assert result["id"] == record_id
    assert result["source_head_before"] == HEAD
    assert result["source_head_after"] == HEAD
    assert result["source_status_after"] == ""
    assert context["source_commit"] == HEAD and context["source_tree"] == TREE
    assert isinstance(result["returncode"], int) and isinstance(result["pass"], bool)
    for stream in ("stdout", "stderr"):
        assert digest((directory / (stream + ".log")).read_bytes()) == result[stream + "_sha256"]
    record_summaries[record_id] = {
        "result": result, "context_sha256": digest((directory / "context.json").read_bytes()),
        "result_sha256": digest((directory / "result.json").read_bytes())
    }
    select_tree(directory, "validation/" + record_id)

failed = RECORDS / "validation" / HEAD / "repository-truth"
assert record_summaries["repository-truth"]["result"]["returncode"] == 1
assert record_summaries["repository-truth"]["result"]["pass"] is False
assert b"RUNTIME_PACKAGING_VERSION_REQUIRES_25" in (failed / "stderr.log").read_bytes()
targeted = RECORDS / "validation" / HEAD / "llm-runtime-release-python"
assert record_summaries["llm-runtime-release-python"]["result"]["pass"] is True
targeted_text = (targeted / "stderr.log").read_text()
assert re.findall(r"^Ran ([0-9]+) tests in ", targeted_text, re.M) == ["25"]
assert re.search(r"^OK$", targeted_text, re.M)
assert record_summaries["repository-truth-runtime-python"]["result"]["argv"] == [
    "env",
    "TRNM_RUNTIME_RELEASE_PYTHON=/home/qian-qi/chain-pq-a418-final-python-venv/bin/python",
    "bash", "scripts/ci/ci_job.sh", "repository-truth"
]

setup_dir = RECORDS / "runtime-release-venv-setup"
setup = read_json(setup_dir / "setup.json")
assert setup["pass"] is True and setup["installed"]["version"] == "26.3"
assert setup["source_head"] == HEAD and setup["source_head_after"] == HEAD
assert setup["source_status_after"] == ""
assert setup["requirements_sha256"] == REQUIREMENTS_SHA256
assert digest((setup_dir / "runtime-release-requirements.txt").read_bytes()) == REQUIREMENTS_SHA256
pip_report = read_json(setup_dir / "runtime-release-dependencies.json")
matches = [item for item in pip_report["install"] if item["metadata"]["name"].lower() == "packaging"]
assert len(matches) == 1 and matches[0]["metadata"]["version"] == "26.3"
assert matches[0]["download_info"]["archive_info"]["hashes"]["sha256"] == WHEEL_SHA256
select_tree(setup_dir, "runtime-release-venv-setup")
selected.append((RECORDS / "run_validation.py", ROOT + "/harness/run_validation.py"))
for relative in ("scripts/ci/runtime-release-requirements.txt", "scripts/ci/ci_job.sh",
                 ".github/workflows/trnm-required-baseline.yml"):
    selected.append((SOURCE / relative, ROOT + "/source/" + relative))
assert digest((SOURCE / "scripts/ci/runtime-release-requirements.txt").read_bytes()) == REQUIREMENTS_SHA256

snapshots = []
seen = set()
for path, name in sorted(selected, key=lambda item: item[1]):
    assert name not in seen
    seen.add(name)
    before = path.stat()
    assert stat.S_ISREG(path.lstat().st_mode)
    data = path.read_bytes()
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    snapshots.append((path, name, data, {
        "original_path": str(path), "archive_member": name, "bytes": len(data),
        "sha256": digest(data), "mode": stat.S_IMODE(before.st_mode),
        "mtime_ns": before.st_mtime_ns, "device": before.st_dev, "inode": before.st_ino
    }))
identity_after = source_identity()
manifest = {
    "schema": "trnm-desktop-repository-truth-evidence-v1",
    "collected_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host": "desktop", "source_identity_before": identity_before,
    "source_identity_after": identity_after,
    "read_only_source_and_original_records": True,
    "original_stdout_stderr_bytes_unmodified": True,
    "wrapper_log_hashes_checked": True,
    "records": record_summaries,
    "setup": {"requirements_sha256": REQUIREMENTS_SHA256, "packaging_version": "26.3",
              "wheel_sha256": WHEEL_SHA256, "setup_sha256": digest((setup_dir / "setup.json").read_bytes())},
    "jobs": {
        "repository-truth": "1a1c858278f-135c4-36",
        "runtime-release-venv-setup": "1a1c8692974-135c4-5a",
        "llm-runtime-release-python": "1a1c86b248c-135c4-60",
        "repository-truth-runtime-python": "1a1c86d5a18-135c4-66"
    },
    "files": [entry for _, _, _, entry in snapshots],
    "qualification_granted": False
}
manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
assert not ARCHIVE.exists() and not MANIFEST_PATH.exists()
with tarfile.open(ARCHIVE, "x:gz", format=tarfile.PAX_FORMAT) as archive:
    for path, name, data, entry in snapshots:
        item = tarfile.TarInfo(name)
        item.size = len(data)
        item.mode = entry["mode"]
        item.mtime = entry["mtime_ns"] // 1_000_000_000
        archive.addfile(item, io.BytesIO(data))
    item = tarfile.TarInfo(ROOT + "/manifest.json")
    item.size = len(manifest_bytes)
    item.mode = 0o444
    archive.addfile(item, io.BytesIO(manifest_bytes))
for path, _, data, _ in snapshots:
    assert digest(path.read_bytes()) == digest(data), str(path)
source_identity()
with MANIFEST_PATH.open("xb") as out:
    out.write(manifest_bytes)
os.chmod(ARCHIVE, 0o444)
os.chmod(MANIFEST_PATH, 0o444)
print(json.dumps({
    "archive": str(ARCHIVE), "archive_bytes": ARCHIVE.stat().st_size,
    "archive_sha256": digest(ARCHIVE.read_bytes()),
    "manifest": str(MANIFEST_PATH), "manifest_sha256": digest(manifest_bytes),
    "file_count": len(snapshots), "source_head": HEAD, "source_tree": TREE,
    "full_lane_pass": record_summaries["repository-truth-runtime-python"]["result"]["pass"],
    "full_lane_returncode": record_summaries["repository-truth-runtime-python"]["result"]["returncode"],
    "qualification_granted": False
}, sort_keys=True))

