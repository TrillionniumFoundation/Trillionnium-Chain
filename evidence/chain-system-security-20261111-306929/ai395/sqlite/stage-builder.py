#!/usr/bin/env python3
"""Curate completed SQLite native observations without rerunning native work."""
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

SOURCE = "bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
REPO = Path("/home/qq/chain-system-security-20261112-306929")
BASE = Path("/home/qq/chain-system-security-native-receipts-20261112-306929")
RAW = BASE / "sqlite-fixed-bac6b765"
STAGE = Path("/home/qq/chain-system-security-sqlite-evidence-stage-20261112-306929/evidence/chain-system-security-20261111-306929/ai395/sqlite")
OBS = BASE / "sqlite-fixed-bac6b765.owner-observations.json"
LAUNCH = BASE / "sqlite-fixed-bac6b765.launch-input.json"
DRIVER = Path("/home/qq/chain-system-security-sqlite-fixed-driver-20261112-306929.py")
PLAN = Path("/home/qq/chain-system-security-sqlite-fixed-plan-20261112-306929.json")

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def read_json(path):
    return json.loads(path.read_bytes())

def head():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()

require(head() == SOURCE, "source changed before evidence curation")
require(sha(OBS) == "f8a1812b68ad3442f263dea83154c22ee837433f3b4c5358c495d01c4d1c9f98", "owner observations changed")
require(sha(LAUNCH) == "2de84ffe0d960f4b6d0f20604090f86fa173bac3e4ebf0f7626875214bf7f63a", "launch input changed")
require(sha(DRIVER) == "7fe40feffcc9553b310d2a8adc8ce2b1e67eb283d7bdda6667bd3e6f6d60001a", "driver changed")
require(sha(PLAN) == "b6cba7eba2f5403202237860a39bc8b846d2f082849448728424a372b1964bd3", "plan changed")
obs, launch, plan = read_json(OBS), read_json(LAUNCH), read_json(PLAN)
summary = read_json(RAW / "driver-summary.json")
terminal = obs["terminal"]
require(terminal["status"]["state"] == "exited" and terminal["status"]["exit_code"] == 0, "native owner has no exit zero")
require(terminal["output_complete"] and terminal["status"]["output_complete"], "owner output is incomplete")
require(terminal["status"]["capture_error"] is None, "owner capture error")
require(obs["start"]["session_id"] == terminal["session_id"], "owner identity differs")
require(summary["status"] == "command_set_succeeded", "command set incomplete")
require(summary["source_expected"] == SOURCE, "wrong source")
require(summary["focused_passed"] == 17 and summary["retained_passed"] == 15, "wrong test counts")
require(summary["strict_clippy_passed"] is True, "strict Clippy incomplete")
require(summary["driver_sha256"] == sha(DRIVER) and summary["plan_sha256"] == sha(PLAN), "executed input pins differ")
require(summary["acceptance_granted"] is False and summary["production_activation"] is False, "unexpected acceptance claim")
require(summary["environment"]["CARGO_BUILD_JOBS"] == "1", "jobs changed")
require(summary["environment"]["RUSTC"] == launch["env"]["RUSTC"], "Rust compiler differs")

pty_path = Path(terminal["archive_path"])
pty_bytes = pty_path.read_bytes()
require(len(pty_bytes) == terminal["available_end"] == terminal["status"]["bytes_stored"] == terminal["status"]["bytes_seen"], "incomplete owner archive")
tail = bytes.fromhex(terminal["bytes_hex"])
require(pty_bytes[terminal["offset"]:terminal["next_offset"]] == tail, "owner tail differs")
require(hashlib.sha256(tail).hexdigest() == terminal["chunk_sha256"], "owner tail hash differs")
events = [json.loads(line) for line in pty_bytes.decode().splitlines() if line]
require(events[0]["event"] == "immutable_launch_inputs_verified", "missing launch verification")
require(events[0]["launch_input_sha256"] == sha(LAUNCH), "launch observation differs")
require(events[-1]["event"] == "finished" and events[-1]["status"] == "command_set_succeeded", "missing final owner event")

steps = {row["label"]: row for row in summary["steps"]}
require(len(steps) == len(summary["steps"]) == 20, "missing or duplicate command steps")
expected_files = {"driver-summary.json"}
receipts = []
observations = []
source_identity = None
labels = []
cargo = summary["toolchain"]["cargo"]["path"]

def command(label, expected_argv, pin=None):
    global source_identity
    labels.append(label)
    step = steps[label]
    require(step["status"] == "command_succeeded" and step["exit_code"] == 0, "incomplete step " + label)
    require(step["preflight_exit"] == step["recorder_exit"] == 0, "failed preflight/recorder " + label)
    path = RAW / (label + ".json")
    receipt = read_json(path)
    require(sha(path) == step["receipt_sha256"], "receipt identity differs " + label)
    require(receipt["status"] == "command_succeeded" and receipt["exit_code"] == 0, "command failed " + label)
    require(receipt["argv"] == expected_argv == step["argv"], "wrong argv " + label)
    require(receipt["before"] == receipt["after"], "source changed " + label)
    before = receipt["before"]
    require(before["tested_commit"] == SOURCE and before["tracked_worktree_verified"] is True, "source unqualified " + label)
    if source_identity is None:
        source_identity = before
    require(before == source_identity, "different full source identity between commands")
    log_path = RAW / receipt["log_file"]
    require(receipt["log_file"] == label + ".log", "unexpected log path")
    require(log_path.stat().st_size == receipt["log_bytes"] and sha(log_path) == receipt["log_sha256"], "raw log differs " + label)
    for suffix in (".preflight.log", ".recorder.stdout", ".recorder.stderr", ".json", ".log"):
        expected_files.add(label + suffix)
    if pin is not None:
        require(receipt["native_execution"]["status"] == "PINNED_AND_OBSERVED", "ELF was not observed " + label)
        wrapper = step["recorder_argv"]
        require(wrapper[wrapper.index("--native-executable-sha256") + 1] == pin, "wrong executable pin " + label)
    receipts.append({"label": label, "receipt": "records/" + path.name, "receipt_sha256": sha(path), "raw_log": "records/" + log_path.name, "raw_log_sha256": sha(log_path), "exit_code": 0, "native_pin_observed": pin is not None})
    return log_path.read_text()

def test_roster(text, names):
    running = re.findall(r"^running ([0-9]+) tests?$", text, re.MULTILINE)
    actual = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\.", text, re.MULTILINE)
    final = re.findall(r"^test result: (\w+)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured;", text, re.MULTILINE)
    require(running == [str(len(names))], "wrong harness count")
    require(sorted(actual) == sorted(names) and len(actual) == len(names), "wrong named test roster")
    require(final == [("ok", str(len(names)), "0", "0", "0")], "nonpassing or ignored tests")

for item in plan["focused"]:
    package = item["package"]
    argv = [cargo, "test", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline", "-p", package, "--lib", "sqlite_", "--", "--nocapture", "--test-threads=1"]
    text = command("sqlite-focused-" + package, argv)
    test_roster(text, item["tests"])
    observations.extend({"package": package, "test": name, "selection": "focused", "passed": True} for name in item["tests"])

for package, tests in plan["retained"].items():
    binary = summary["binaries"][package]
    for index, name in enumerate(tests, 1):
        label = "sqlite-retained-" + package + "-" + str(index)
        text = command(label, [binary["path"], "--exact", name, "--nocapture", "--test-threads=1"], binary["sha256"])
        test_roster(text, [name])
        require(steps[label]["named_checker_exit"] == 0 and steps[label]["named_test"] == name, "named checker failed")
        expected_files.update((label + ".named.stdout", label + ".named.stderr"))
        observations.append({"package": package, "test": name, "selection": "retained", "passed": True})

argv = [cargo, "clippy", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline"]
for item in plan["focused"]:
    argv += ["-p", item["package"]]
argv += ["--all-targets", "--", "-D", "warnings"]
command("sqlite-strict-four-package-clippy", argv)
require(set(labels) == set(steps) and len(labels) == 20, "unaccounted command")
require(len(observations) == len({(o["package"], o["test"]) for o in observations}) == 32, "duplicate native crate/test pair")
require([e["label"] for e in events if e["event"] == "start"] == labels, "owner start sequence differs")
require([e["label"] for e in events if e["event"] == "command_succeeded"] == labels, "owner success sequence differs")
require(len(expected_files) == 131, "unexpected evidence roster size")

excluded = []
for path in RAW.iterdir():
    if path.name not in expected_files:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == 0 and "hepta" in path.name.lower() and "lock" in path.name.lower(), "unexpected non-evidence file: " + path.name)
        excluded.append({"path": str(path), "bytes": 0, "reason": "Hepta transport lock; original left in place"})
for name in expected_files:
    path = RAW / name
    require(path.is_file() and not path.is_symlink(), "missing regular evidence " + name)

binary_checks = []
for package, row in summary["binaries"].items():
    path = Path(row["path"])
    require(path.stat().st_size == row["bytes"] and sha(path) == row["sha256"], "test ELF changed after native execution")
    binary_checks.append({"package": package, **row, "matches_after_clippy": True, "executable_bytes_packaged": False})

provider_path = Path(launch["provider_env_path"])
require(provider_path.stat().st_size == launch["provider_env_bytes"] and sha(provider_path) == launch["provider_env_sha256"], "provider environment changed")
provider_receipt = read_json(provider_path.parent / "observations/pq-provider/provider.json")
provider_inputs = []
for row in provider_receipt["native_backend_inputs"]:
    path = Path(row["path"])
    require(path.stat().st_size == row["bytes"] and sha(path) == row["sha256"], "provider input changed")
    provider_inputs.append({**row, "matches_preparation_receipt_after_sqlite": True})
for key in ("cargo", "rustc"):
    tool = summary["toolchain"][key]
    require(sha(Path(tool["path"])) == tool["sha256"], "compiler tool changed")
clippy = summary["toolchain"]["clippy"]
require(sha(Path(clippy["launcher"])) == clippy["launcher_sha256"], "Clippy launcher changed")
require(sha(Path(clippy["driver"])) == clippy["driver_sha256"], "Clippy driver changed")
require(head() == SOURCE, "source changed during readback")

STAGE.mkdir(parents=True, exist_ok=False)
payload_sources = {}
def put(relative, data, source=None):
    path = STAGE / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    payload_sources[relative] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "source": source}
def copy(relative, source):
    put(relative, source.read_bytes(), str(source))

for name in sorted(expected_files):
    copy("records/" + name, RAW / name)
copy("inputs/driver.py", DRIVER)
copy("inputs/plan.json", PLAN)
copy("inputs/launch-input.json", LAUNCH)
put("inputs/launcher.py", obs["launcher_code"].encode(), "exact Python -c launcher retained by controller")
copy("inputs/provider.env", provider_path)
copy("owner-observations.json", OBS)
put("owner-output.log", pty_bytes, str(pty_path))
copy("stage-builder.py", Path(__file__).resolve())

verification = {
    "schema": "sqlite-ai395-independent-artifact-verification-v1",
    "artifact_integrity": "PASS",
    "tested_source": SOURCE,
    "native_owner_exit_code": 0,
    "native_owner_output_complete": True,
    "focused_passed": 17,
    "retained_passed": 15,
    "unique_crate_test_pairs": 32,
    "strict_four_package_clippy": "PASS",
    "recorded_commands_verified": 20,
    "full_source_identity": source_identity,
    "all_twenty_commands_full_source_before_after_equal": True,
    "default_cargo_features": True,
    "default_cargo_profiles": True,
    "build_jobs": 1,
    "observations": observations,
    "receipts": receipts,
    "native_test_executables": binary_checks,
    "provider_env_unchanged_from_startup": True,
    "provider_inputs_match_preparation_receipt_after_execution": provider_inputs,
    "excluded_non_evidence_files": excluded,
    "original_zero_byte_stdout_stderr_preserved": True,
    "this_curation_reran_native_tests": False,
    "whole_chain_quantum_security_qualified": False,
    "acceptance_granted": False,
    "production_activation": False,
}
put("verification.json", json_bytes(verification), "independent readback of original observations")
table_rows = []
for item in plan["focused"]:
    package = item["package"]
    table_rows.append("| " + package + " | " + str(len(item["tests"])) + " | " + str(len(plan["retained"][package])) + " |")
readme = f"""# SQLite fixed-source native observations on AI395

All 17 focused controls and 15 retained compatibility controls passed. The four
affected packages' strict Clippy command also passed. The original native owner
exited with code 0 and complete captured output.

Tested source: {SOURCE}. The 20 command receipts each record matching full
tracked-source identities before and after execution: {source_identity['tracked_entries']}
entries and {source_identity['tracked_bytes']} bytes. Builds used Rust 1.95,
the default Cargo features and profiles, one build job and one libtest thread.

| Package | Focused | Retained |
| --- | ---: | ---: |
{chr(10).join(table_rows)}
| Total | 17 | 15 |

The retained controls use the exact current ELFs identified by the focused Cargo
runs. All 15 were pinned and observed by the repository's native-process
recorder, and their exact named-test checks passed. ELF hashes were checked
again after Clippy. Executable bytes are retained in the build target, not
packaged in this evidence directory.

The strict command is cargo clippy for these four packages with --locked,
--offline, --all-targets and -- -D warnings, without an all-features override.
The exact argv, environment, source identity, raw output and terminal status
remain in the original receipts. The driver, test plan, launch input, actual
launcher and original owner output are preserved alongside them.

[verification.json](verification.json) checks 32 distinct crate/test pairs,
20 successful command receipts, their raw-log bindings, full-source equality,
native executable pins and the provider/tool input identities.
[manifest.json](manifest.json) lists every published payload by path, size and
SHA-256. [native-records.tar.gz](native-records.tar.gz) is an exact copy of the
curated raw records and execution inputs. Original zero-byte command streams are
preserved; Hepta temporary lock/cache files are excluded without modifying the
original receipt directory.

Two controller binary-read requests timed out while observing already durable
files. Those transport errors are retained in owner-observations.json. The AI
startup verified the launch, driver, plan and provider bytes before execution;
the original native owner and all command receipts completed independently.

These observations qualify the recorded local SQLite opening and compatibility
controls on the specified candidate. The earlier old-source negatives and the
original 9021 native observations keep their own source identities. The original
cloud Clippy interruption remains an incomplete historical observation.

The local metadata refusal still has a check/open race boundary. Ordinary WAL
owners keep their existing contracts. This work does not establish a remote
consensus exploit, global network liveness, external-effect rollback or
whole-chain security. Production activation and release acceptance remain false.
"""
put("README.md", readme.encode(), "curated evidence scope and observations")

raw_members = sorted(name for name in payload_sources if name.startswith("records/") or name.startswith("inputs/") or name in ("owner-observations.json", "owner-output.log"))
archive_path = STAGE / "native-records.tar.gz"
with archive_path.open("xb") as output:
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|") as archive:
            for name in raw_members:
                data = (STAGE / name).read_bytes()
                member = tarfile.TarInfo(name)
                member.size = len(data); member.mode = 0o644; member.mtime = 0
                archive.addfile(member, io.BytesIO(data))
payload_sources["native-records.tar.gz"] = {"bytes": archive_path.stat().st_size, "sha256": sha(archive_path), "source": "curated exact original records and execution inputs"}

with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    require(len(members) == len(raw_members) and {m.name for m in members} == set(raw_members), "raw archive membership differs")
    for member in members:
        require(member.isfile(), "nonregular raw archive member")
        data = archive.extractfile(member).read()
        expected = payload_sources[member.name]
        require(len(data) == expected["bytes"] and hashlib.sha256(data).hexdigest() == expected["sha256"], "raw archive payload differs")

for name in sorted(expected_files):
    require(sha(RAW / name) == payload_sources["records/" + name]["sha256"], "original receipt changed during curation")
require(head() == SOURCE, "source changed before curation completed")
manifest = {
    "schema": "sqlite-ai395-curated-payload-manifest-v1",
    "tested_source": SOURCE,
    "files": [{"path": name, **info} for name, info in sorted(payload_sources.items())],
    "raw_archive_members": raw_members,
    "excluded_non_evidence_files": excluded,
    "production_activation": False,
}
with (STAGE / "manifest.json").open("xb") as stream:
    stream.write(json_bytes(manifest))
actual = {str(p.relative_to(STAGE)) for p in STAGE.rglob("*") if p.is_file()}
require(actual == set(payload_sources) | {"manifest.json"}, "stage contains unlisted files")
result = {
    "schema": "sqlite-ai395-stage-result-v1",
    "status": "CURATED_AND_VERIFIED",
    "stage": str(STAGE),
    "tested_source": SOURCE,
    "focused_passed": 17,
    "retained_passed": 15,
    "strict_four_package_clippy": "PASS",
    "native_owner_exit_code": 0,
    "native_owner_output_complete": True,
    "source_head_unchanged": True,
    "original_native_records": len(expected_files),
    "payload_count_excluding_manifest": len(payload_sources),
    "manifest_sha256": sha(STAGE / "manifest.json"),
    "verification_sha256": sha(STAGE / "verification.json"),
    "raw_archive_bytes": archive_path.stat().st_size,
    "raw_archive_sha256": sha(archive_path),
    "original_record_bytes_preserved": True,
    "excluded_non_evidence_files": excluded,
    "new_native_execution_by_curation": False,
    "production_activation": False,
    "completed_utc": datetime.now(timezone.utc).isoformat(),
}
with (BASE / "sqlite-fixed-bac6b765.stage-result.json").open("xb") as stream:
    stream.write(json_bytes(result))
print(json.dumps(result, sort_keys=True), flush=True)
