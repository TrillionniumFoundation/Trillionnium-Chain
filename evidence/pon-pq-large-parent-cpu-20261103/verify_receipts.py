#!/usr/bin/env python3
"""Verify preserved bytes, source identities and actual outcomes; execute no recorded workload."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import lzma
import zipfile

ROOT = Path(__file__).resolve().parent
def digest(data):
    return hashlib.sha256(data).hexdigest()
manifest = json.loads((ROOT / "manifest.json").read_text())
assert manifest["schema"] == "trnm-pq-large-parent-cpu-evidence-v1"
assert manifest["whole_chain_quantum_security_qualified"] is False
for name, item in manifest["attachments"].items():
    data = (ROOT / name).read_bytes()
    assert len(data) == item["bytes"] and digest(data) == item["sha256"], name
with zipfile.ZipFile(ROOT / "raw-observations.zip") as archive:
    names = archive.namelist()
    assert len(names) == len(set(names)) == len(manifest["members"])
    assert set(names) == set(manifest["members"])
    assert sum(item.file_size for item in archive.infolist()) <= 32 * 1024 * 1024
    contents = {}
    for name in names:
        assert PurePosixPath(name).name == name and not name.startswith("."), name
        info = archive.getinfo(name)
        assert not info.is_dir() and info.file_size <= 4 * 1024 * 1024, name
        data = archive.read(name)
        expected = manifest["members"][name]
        assert len(data) == expected["bytes"] and digest(data) == expected["sha256"], name
        contents[name] = data
    assert archive.testzip() is None
commands = {}
for name, data in contents.items():
    if not name.endswith(".json"):
        continue
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        continue
    if not isinstance(obj, dict) or obj.get("schema") != "trnm-pq-native-command-v1":
        continue
    status = obj["status"]
    assert status in ("command_succeeded", "command_failed", "record_failed"), (name, status)
    assert obj["whole_chain_quantum_security_qualified"] is False
    commands[name] = {"status": status, "exit_code": obj.get("exit_code")}
    if status == "record_failed":
        continue
    assert obj["before"] == obj["after"], name
    assert obj["before"]["tracked_worktree_verified"] is True, name
    assert (obj["exit_code"] == 0) == (status == "command_succeeded"), name
    log = contents[obj["log_file"]]
    assert len(log) == obj["log_bytes"] and digest(log) == obj["log_sha256"], name
assert commands == manifest["command_results"]
for prefix in ("baseline", "fixed", "combined", "final", "projection"):
    for suffix in ("large-genesis", "auth-parent"):
        assert commands[f"{prefix}-{suffix}.json"] == {"status": "command_failed", "exit_code": 101}
binding = json.loads(contents["projection-node-binary-binding.json"])
assert binding["all_native_commands_terminal"] is True and binding["aggregate_exit"] == 1
assert len(binding["native_commands"]) == 16
assert binding["binary_sha256_before"] == binding["binary_sha256_after_latest"]
failed = {item["label"] for item in binding["native_commands"] if item["recorded_exit"] != 0}
assert failed == {"projection-large-genesis", "projection-auth-parent"}
for item in binding["native_commands"]:
    assert commands[item["label"] + ".json"]["exit_code"] == item["recorded_exit"]
    if item["label"] in failed:
        assert item["reader_exit"] == 1
checkpoint = json.loads(contents["projection-node-rebuild-checkpoint.json"])
assert checkpoint["reproduced_identical_elf"] is True
assert checkpoint["execution_path_remains_original_artifact"] is True
assert checkpoint["source_sha256"] == checkpoint["copied_sha256"] == checkpoint["previous_build_sha256"]
assert checkpoint["source_sha256"] == binding["binary_sha256_before"]
with zipfile.ZipFile(ROOT / "encoder-review.zip") as archive:
    assert len(archive.namelist()) == 30 and archive.testzip() is None
patch = lzma.decompress((ROOT / "source-series.patch.xz").read_bytes())
assert len(patch) == manifest["source_patch"]["bytes"]
assert digest(patch) == manifest["source_patch"]["sha256"]
history = json.loads((ROOT / "local-source-history.json").read_text())
assert history["execution_identity_scope"] == "local commits and exact full trees"
assert history["commits"][-1]["commit"] == binding["head"]
assert history["commits"][-1]["tree"] == manifest["tested_local_tree"]
assert manifest["tested_local_commit"] == binding["head"]
print(json.dumps({"status": "PASS", "verified_raw_files": len(contents),
                  "verified_command_receipts": len(commands), "original_cpu_selectors_passed": False,
                  "whole_chain_quantum_security_qualified": False}, sort_keys=True))
