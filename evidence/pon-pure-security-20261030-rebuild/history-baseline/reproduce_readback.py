#!/usr/bin/env python3
"""Read retained historical bytes; never execute or certify a new native run."""

import gzip
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile


HERE = Path(__file__).resolve().parent
PREFIX = "campaign/pressure-native/baseline/independent-client/"
MAX_ENTRY_BYTES = 4 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    provenance = json.loads((HERE / "provenance.json").read_text())
    retained = {}
    for entry in provenance["entries"]:
        path = (HERE / entry["retained_path"]).resolve()
        assert path.is_relative_to(HERE / "original")
        assert path.stat().st_size == entry["compressed_bytes"] <= MAX_ENTRY_BYTES
        compressed = path.read_bytes()
        assert sha(compressed) == entry["compressed_sha256"]
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(MAX_ENTRY_BYTES + 1)
        assert len(raw) == entry["raw_bytes"] <= MAX_ENTRY_BYTES
        assert sha(raw) == entry["raw_sha256"]
        assert entry["archive_entry"] not in retained
        retained[entry["archive_entry"]] = raw

    def read(name):
        return json.loads(retained[name])

    baseline = read("campaign/pressure-native/baseline.json")
    ready = read(PREFIX + "ready.json")
    report = read(PREFIX + "report.json")
    assert baseline["history_verifier_process"]["ready"] == ready
    assert baseline["history_verifier_process"]["report"] == report
    assert baseline["actors"] == []
    assert baseline["client_execution_profile"] == "pure-pon-fixed-host-client-v1"
    assert baseline["history_resource_profile"] == "strict-every-native-checkpoint-v1"
    responses = []
    calls = report["result"]["calls"]
    for i in range(10):
        request_name = PREFIX + f"request-{i:03}.json"
        response_name = PREFIX + f"response-{i:03}.json"
        request = read(request_name)
        response = read(response_name)
        assert request["sequence"] == response["sequence"] == calls[i]["sequence"] == i
        assert response["request_sha256"] == calls[i]["request_sha256"] == sha(retained[request_name])
        assert calls[i]["response_sha256"] == sha(retained[response_name])
        assert response["measurement"] == calls[i]["measurement"]
        assert request["operation"] == calls[i]["operation"]
        assert response["error"] is None and calls[i]["succeeded"]
        responses.append(response)

    imports = []
    for i in range(7):
        request = read(PREFIX + f"request-{i:03}.json")
        measured = responses[i]["measurement"]
        assert request["operation"] == "import"
        assert len(request["page"]["packets"]) == 1
        assert request["page"]["complete"] == (i == 6)
        assert all(baseline["history"][i]["client_import"][key] == value for key, value in measured.items())
        imports.append({
            "sequence": i,
            "complete_page": request["page"]["complete"],
            **{key: measured[key] for key in (
                "started_ns", "ended_ns", "process_cpu_ns", "process_wall_ns", "wall_ns"
            )},
            "network_response_wall_ns": baseline["history"][i]["ended_ns"] - baseline["history"][i]["started_ns"],
        })

    before = ready["native_history_arithmetic"]
    after = responses[8]["value"]["native_history_arithmetic"]
    initial_stages = {entry["stage"]: entry["totals"] for entry in before["stages"]}
    stages = {}
    for entry in after["stages"]:
        stages[entry["stage"]] = {
            key: entry["totals"][key] - initial_stages[entry["stage"]][key]
            for key in ("calls", "cpu_ns", "wall_ns")
        }
    decode = {
        key: after["account_node_decode_arithmetic"]["counters"][key] - value
        for key, value in before["account_node_decode_arithmetic"]["counters"].items()
    }

    database = retained[PREFIX + "native/native.sqlite"]
    roots = []
    # A byte-identical temporary copy is opened read-only/immutable. Do not
    # reinterpret this SQL inspection as native graph or cryptographic replay.
    with tempfile.TemporaryDirectory(prefix="pon-retained-history-read-") as folder:
        file = Path(folder) / "native.sqlite"
        file.write_bytes(database)
        connection = sqlite3.connect(file.as_uri() + "?mode=ro&immutable=1", uri=True)
        connection.execute("PRAGMA query_only=ON")
        try:
            for block, height, raw_record, raw_state in connection.execute(
                "SELECT b.id,b.height,n.data,s.state FROM blocks b "
                "JOIN native_state_commitments n ON n.block=b.id "
                "JOIN snapshots s ON s.block=b.id ORDER BY b.height"
            ):
                record, state = json.loads(raw_record), json.loads(raw_state)
                accounts = {key: value for key, value in state.items() if key.startswith("account:")}
                encoded = json.dumps(accounts, sort_keys=True, separators=(",", ":")).encode()
                root = record["accounts"]
                roots.append({
                    "height": height, "block": block.hex(),
                    "account_node": bytes(root["node"]).hex() if root["node"] else None,
                    "account_digest": bytes(root["digest"]).hex(),
                    "account_count": root["count"], "account_balance": root["balance"],
                    "account_map_entries": len(accounts), "account_map_sha256": sha(encoded),
                    "state_bytes": len(raw_state), "state_bytes_sha256": sha(raw_state),
                    "record_bytes_sha256": sha(raw_record),
                })
        finally:
            connection.close()

    assert [item["height"] for item in roots] == list(range(12))
    assert len({item["account_map_sha256"] for item in roots[5:12]}) == 1
    assert len({item["account_digest"] for item in roots[5:12]}) == 1
    assert len({item["state_bytes_sha256"] for item in roots[5:12]}) == 7
    import_cpu = sum(item["process_cpu_ns"] for item in imports)
    confirmation_cpu = responses[7]["measurement"]["process_cpu_ns"]
    quota, period = map(int, baseline["history_verifier_process"]["parent_before_spawn"]["cpu.max"].split())
    assert (quota, period) == (25_000, 100_000)
    result = {
        "schema": "pon-retained-history-baseline-readback-v1",
        "source_commit": provenance["source_commit"],
        "workflow_run_id": provenance["workflow_run_id"],
        "artifact_id": provenance["artifact_id"],
        "archive_sha256": provenance["archive_sha256"],
        "retained_entry_hashes_verified": len(retained),
        "scope": "Readback of historical CI output. Cumulative native stage deltas include confirmation and final snapshot as well as imports. Stage timings are nested and not additive. No new native execution, graph replay, timing measurement, independent host attestation or optimization result.",
        "new_native_execution": False,
        "client_execution_profile": baseline["client_execution_profile"],
        "history_resource_profile": baseline["history_resource_profile"],
        "window_ns": baseline["window_ns"],
        "actor_count": len(baseline["actors"]),
        "rounds": baseline["rounds"],
        "imports": imports,
        "confirmation_measurement": responses[7]["measurement"],
        "snapshot_measurement": responses[8]["measurement"],
        "import_cpu_sum_ns": import_cpu,
        "import_and_confirmation_cpu_sum_ns": import_cpu + confirmation_cpu,
        "idealized_quarter_cpu_import_wall_ns": import_cpu * period // quota,
        "idealized_thirty_second_cpu_allowance_ns": baseline["window_ns"] * quota // period,
        "post_setup_through_snapshot_stage_deltas": stages,
        "post_setup_through_snapshot_decode_deltas": decode,
        "setup_process_cpu_ns": ready["setup_process_cpu_ns"],
        "setup_wall_ns": ready["setup_wall_ns"],
        "whole_verifier_process_cpu_ns": report["result"]["whole_verifier_process_cpu_ns"],
        "whole_verifier_wall_ns": report["result"]["whole_verifier_wall_ns"],
        "database_bytes": len(database), "database_sha256": sha(database),
        "retained_database_account_roots": roots,
        "source_inferred_walk_decomposition": {
            "scope": "Caller mapping from original source, cross-checked against cumulative counts; not a per-call measured trace or an optimized run.",
            "admission_state_checks": 7 * 8,
            "activation_state_checks": (1 + 7 + 1) * 3,
            "confirmation_and_snapshot_state_checks": 2,
            "non_genesis_walks": 62,
            "genesis_walks": 23,
            "non_genesis_accounts": roots[4]["account_count"],
            "genesis_accounts": roots[0]["account_count"],
            "predicted_node_loads": 62 * (2 * roots[4]["account_count"] - 1) + 23 * (2 * roots[0]["account_count"] - 1),
        },
    }
    assert result["source_inferred_walk_decomposition"]["predicted_node_loads"] == decode["calls"]
    assert stages["account_graph"]["calls"] == 85
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
