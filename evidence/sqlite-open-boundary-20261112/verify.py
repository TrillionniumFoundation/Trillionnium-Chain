"""Check packaged bytes and recorded observations; do not execute native tests."""

import hashlib
import json
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parent
FIXED = "9021d15ffe1dfdfb1358a2372b5a472babbf80ac"
T1 = "52cf278e4c3d08931b3e890c26b2b1af5653d32d"
T2 = "857d661de6265459d4af3323f4000c2c04fb90e1"
PACKAGES = (
    "trnm-data-availability",
    "trnm-mvcc-fee",
    "trnm-service-settlement",
    "trnm-task-kernel",
)


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def check_file(name, expected):
    path = ROOT / name
    assert path.is_file(), name
    assert path.stat().st_size == expected["bytes"], name
    assert digest(path) == expected["sha256"], name


def native_summary(prefix):
    output = (ROOT / (prefix + ".stdout")).read_text()
    return re.findall(
        r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", output
    )


manifest = read("manifest.json")
assert manifest["native_tested_commit"] == FIXED
assert manifest["acceptance_granted"] is False
assert manifest["production_activation"] is False
actual_names = {p.name for p in ROOT.iterdir() if p.is_file()} - {"manifest.json"}
assert actual_names == set(manifest["payloads"])
for name, expected in manifest["payloads"].items():
    check_file(name, expected)

negative = (
    ("negative-native", T1, 4, 3),
    ("negative-owners-trnm-mvcc-fee", T2, 1, 2),
    ("negative-owners-trnm-service-settlement", T2, 0, 2),
    ("negative-owners-trnm-task-kernel", T2, 1, 3),
)
for prefix, source, passed, failed in negative:
    receipt = read(prefix + ".json")
    assert receipt["exit_code"] == 101
    if prefix == "negative-native":
        assert receipt["head"] == source
    else:
        assert receipt["source_before"] == receipt["source_after"]
        assert receipt["source_after"]["head"] == source
        assert receipt["selected_sources_unchanged"]
    for stream in ("stdout", "stderr"):
        check_file(prefix + "." + stream, receipt[stream])
    assert native_summary(prefix) == [("FAILED", str(passed), str(failed), "0")]

positive = {}
for package, expected_count in zip(PACKAGES, (8, 3, 2, 4)):
    prefix = "positive-owners-" + package
    receipt = read(prefix + ".json")
    assert receipt["exit_code"] == 0
    assert receipt["source_before"] == receipt["source_after"]
    assert receipt["source_after"]["head"] == FIXED
    assert receipt["selected_sources_unchanged"]
    assert len(receipt["source_after"]["files_sha256"]) == 297
    for stream in ("stdout", "stderr"):
        check_file(prefix + "." + stream, receipt[stream])
    assert native_summary(prefix) == [("ok", str(expected_count), "0", "0")]
    positive[package] = receipt

retained = read("retained-compatibility-summary.json")
assert retained["source_commit"] == FIXED
assert retained["all_passed"]
assert len(retained["tests"]) == 15
assert len({(x["package"], x["test"]) for x in retained["tests"]}) == 15
for receipt in retained["tests"]:
    assert receipt["exit_code"] == 0 and receipt["passed"]
    assert receipt["source_commit"] == FIXED
    assert receipt["selected_source_and_binary_unchanged"]
    assert receipt["native_summaries"] == [["ok", "1", "0", "0"]]
    assert receipt["binary"] == positive[receipt["package"]]["binaries_after"][0]
    for stream in ("stdout", "stderr"):
        check_file(receipt[stream]["path"], receipt[stream])
    stdout = (ROOT / receipt["stdout"]["path"]).read_text()
    assert "test " + receipt["test"] + " ... ok" in stdout

for gate in ("format", "metadata", "source-integrity"):
    prefix = "gate-" + gate
    receipt = read(prefix + ".json")
    assert receipt["exit_code"] == 0
    assert receipt["source_before"] == receipt["source_after"]
    assert receipt["source_after"]["head"] == FIXED
    assert receipt["selected_sources_unchanged"]
    for stream in ("stdout", "stderr"):
        check_file(prefix + "." + stream, receipt[stream])
integrity = (ROOT / "gate-source-integrity.stderr").read_text()
assert re.search(r"Ran 43 tests in [0-9.]+s\s+OK\s*$", integrity)

graph = read("gate-metadata.stdout")
assert len(graph["workspace_members"]) == 26
assert len(graph["packages"]) == 177
for name, version in (("libsqlite3-sys", "0.39.0"), ("rusqlite", "0.41.0"), ("rustix", "1.1.6")):
    assert [p["version"] for p in graph["packages"] if p["name"] == name] == [version]

partial = read("clippy-incomplete-observation.json")
assert partial["status"] == "INCOMPLETE"
assert partial["terminal_receipt_observed"] is False
assert partial["command_exit_code"] is None
assert partial["cause_established"] is False
assert partial["serial_retry_started"] is False
assert partial["gzip_completion_receipt_observed"] is False
assert partial["acceptance_granted"] is False
for name, expected in partial["streams"].items():
    check_file(name, expected)
assert (ROOT / "gate-clippy.stderr").read_text().count("(signal: 9, SIGKILL: kill)") == 2

archive = ROOT / "sqlite900-quality-13843531543.zip"
readback = read("sqlite900-quality-independent-readback.json")
assert digest(archive) == readback["archive_sha256"]
with zipfile.ZipFile(archive) as zipped:
    assert len(zipped.namelist()) == len(set(zipped.namelist())) == 14
    assert zipped.testzip() is None
    original = json.loads(zipped.read("supply-chain/manifest.json"))
    assert original["result"] == "FAIL"
    assert len(original["artifact_sha256"]) == 8
    for name, expected in original["artifact_sha256"].items():
        assert hashlib.sha256(zipped.read("supply-chain/" + name)).hexdigest() == expected
assert readback["new_native_or_ci_execution"] is False

print(json.dumps({
    "artifact_integrity": "PASS",
    "payloads_verified": len(manifest["payloads"]),
    "negative_native_commands_with_preserved_exit_101": 4,
    "recorded_negative_test_failures": 10,
    "recorded_positive_focused_tests": 17,
    "recorded_positive_retained_tests": 15,
    "recorded_source_integrity_tests": 43,
    "clippy": "INCOMPLETE_SIGKILL_REPORTS_NO_TERMINAL_RECEIPT",
    "new_native_execution": False,
    "acceptance_granted": False,
    "production_activation": False,
}, sort_keys=True))
