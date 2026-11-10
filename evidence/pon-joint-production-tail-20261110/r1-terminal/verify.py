"""Reconcile recovered original r1 receipts; never execute native work."""
from pathlib import Path
import base64
import hashlib
import io
import json
import tarfile

ROOT = Path(__file__).resolve().parent
JOB = "1a1c474c012-cf39-350"
SOURCE = "4716bade250f327b012a098418f4eece6b73fcaa"
TREE = "bbc0278f87282d9bcf4e22b167040233516da310"
RUNNER = "66f2e33da06d9e1167a5240027d6363defa79ff7e235e7763d96980c47d603b8"
ARCHIVE = "f804c99db721cff21206eabb4b54aff4628e9b624a8101a6a2091c43d0bc3000"


def raw(name):
    return json.loads((ROOT / name).read_bytes())


def tool(name):
    value = raw(name)
    assert value.get("isError") is False
    if value.get("structuredContent") is not None:
        return value["structuredContent"]
    texts = [item["text"] for item in value["content"] if item["type"] == "text"]
    assert len(texts) == 1
    return json.loads(texts[0])


def api(name):
    return json.loads(tool(name)["content"])


def verify():
    assert __debug__, "run without optimization"
    original = json.loads((ROOT.parent / "native-control/start-request.json").read_bytes())
    assert raw("recovery-request.json") == original
    recovery = tool("recovery.json")
    job = recovery["job"]
    assert recovery["reused"] is True and recovery["retried_launch"] is False
    assert job["id"] == JOB and job["host"] == original["host"] == "rog"
    for field in ("args", "cwd", "executable", "idempotency_key"):
        assert job[field] == original[field]
    assert original["idempotency_key"] == "joint-tail-rust-gates-20261110-8e76-r1"
    status = tool("final_status.json")
    for terminal in (status, recovery["status"]):
        assert terminal["job_id"] == JOB and terminal["state"] == "failed"
        assert terminal["exit_code"] == 2 and terminal["timed_out"] is False
        assert terminal["terminal_publication_confirmed"] is True
        assert terminal["output_complete"] is True and terminal["output_durable"] is True
        for stream in ("stdout", "stderr"):
            assert terminal["log_truncated"][stream] is False
            assert terminal["log_errors"][stream] is None
    read = tool("process_read.json")
    assert read["job_id"] == JOB
    for stream in ("stdout", "stderr"):
        row = read[stream]
        data = bytes.fromhex(row["bytes_hex"])
        assert row["offset"] == 0 and row["eof"] is True
        assert len(data) == row["size"] == row["next_offset"]
        assert data.decode("utf-8") == row["text"]
        assert (ROOT / f"process.{stream}.log").read_bytes() == data
        assert status["log_bytes"][stream] == {"seen": len(data), "stored": len(data)}
    info, archive = tool("archive_info.json"), tool("archive_read.json")
    data = base64.b64decode(archive["data_base64"], validate=True)
    assert len(data) == archive["size"] == archive["next_offset"] == info["size"] == 7178
    assert archive["offset"] == 0 and archive["eof"] is True
    assert archive["version"] == info["version"]
    assert hashlib.sha256(data).hexdigest() == info["sha256"] == archive["chunk_sha256"] == ARCHIVE
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        assert len(members) == 5 and len({m.name for m in members}) == 5
        assert {m.name for m in members} == {"environment.json", "ownership.json", "runner.py", "summary.json", "raw-records-index.json"}
        for member in members:
            assert member.isfile() and "/" not in member.name and member.size < 100000
            assert tar.extractfile(member).read() == (ROOT / "raw" / member.name).read_bytes()
    index = raw("raw/raw-records-index.json")
    assert len(index["files"]) == 4
    for row in index["files"]:
        blob = (ROOT / "raw" / row["path"]).read_bytes()
        assert len(blob) == row["bytes"] and hashlib.sha256(blob).hexdigest() == row["sha256"]
    runner = (ROOT / "raw/runner.py").read_bytes()
    assert hashlib.sha256(runner).hexdigest() == tool("runner_info.json")["sha256"] == RUNNER
    assert runner == (ROOT.parent / "native-control/rog_runner.py").read_bytes()
    assert b"MIN_START_FREE = 6 * 1024**3" in runner
    summary = raw("raw/summary.json")
    assert summary["source_commit"] == SOURCE and summary["source_tree"] == TREE
    assert summary["commands"] == [] and summary["all_requested_gates_passed"] is False
    assert summary["error"] == {"type": "AssertionError", "message": "insufficient free space before setup"}
    assert summary["disk_final"]["free"] == 5414273024 < 6 * 1024**3
    lines = [json.loads(line) for line in (ROOT / "process.stdout.log").read_text().splitlines()]
    assert len(lines) == 2 and lines[1]["summary"] == summary
    assert lines[1]["archive"]["sha256"] == ARCHIVE
    assert summary["native_common_prefix_failure_bound"] is None
    assert summary["native_six_successor_risk_bound"] is None
    assert summary["native_probability_qualified"] is False and summary["production_activation"] is False
    source = api("source_jobs.json")
    assert source["total_count"] == len(source["jobs"]) == 18
    assert all(j["status"] == "queued" and j["conclusion"] is None
               and j["steps"] == [] and j["runner_id"] == 0 for j in source["jobs"])
    assert api("source_artifacts.json") == {"total_count": 0, "artifacts": []}
    head = api("head_runs.json")
    assert len(head["workflow_runs"]) == head["total_count"] == 16
    assert all(r["head_sha"] == "a782b1b501c9030d9f9f6fecd27b5858a702c9a8"
               and r["status"] in ("pending", "queued") and r["conclusion"] is None
               for r in head["workflow_runs"])
    preview = api("preview_commit.json")
    assert preview["sha"] == "b2dae0c0510ee95570e0f1729d3a3db8c9c6be93"
    assert [p["sha"] for p in preview["parents"]] == ["0ff81958a611d2c0be54d2ca839b955ae7cb2772", "a782b1b501c9030d9f9f6fecd27b5858a702c9a8"]
    return {"packet_consistency": "PASS", "original_job": JOB,
            "original_request_reused": True, "original_terminal": "FAILED", "exit_code": 2,
            "failure_stage": "pre-setup free-space guard", "commands_executed": 0,
            "rust_gates": "NOT_RUN", "binary_identity": None,
            "archive_sha256": ARCHIVE, "archive_files_verified": 5,
            "tested_source_unchanged": SOURCE, "native_probability_qualified": False,
            "native_common_prefix_failure_bound": None, "native_six_successor_risk_bound": None,
            "actual_joint_obligations_open": 13, "production_activation": False,
            "qualification": "HOLD_NO_GO"}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True, indent=2))
