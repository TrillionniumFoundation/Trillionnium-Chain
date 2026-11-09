#!/usr/bin/env python3
"""Reconstruct the six retained synthetic JSON inputs; this is not a new experiment."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

def materialize(root):
    sys.path.insert(0, str(Path(root) / "formal/pon-nakamoto-v1"))
    from test_grouped_fresh_deployment_cost_v0 import synthetic_worker
    from test_grouped_fanout_reanalysis_v1 import synthetic_campaign, encode
    result = {}
    def direct(name, workers, planned):
        result[name] = json.dumps(dict(planned_receivers=planned, workers=workers),
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    worker = synthetic_worker()
    worker["worker_report"]["transport_records"][1]["verification"]["work_id"] = "third"
    direct("carrier_replay_relabel", [worker], 1)
    workers = [synthetic_worker(i) for i in range(2)]
    for row in workers[1]["worker_report"]["transport_records"]:
        if row["case"] in ("valid", "carrier_replay", "discarded_response"):
            row["verification"]["work_id"] = "second" if row["verification"]["work_id"] == "first" else "first"
    direct("cross_receiver_slot_swap", workers, 2)
    worker = synthetic_worker()
    worker["worker_report"]["transport_records"][4]["verification"]["work_id"] = "first"
    direct("distinct_nonce_alias", [worker], 1)
    for label in ("one_topology_renamed", "all_topologies_swapped", "producer_roster_missing"):
        original = synthetic_campaign()
        original["produced"] = [{"nonce": 1, "work_id": "first"}, {"nonce": 2, "work_id": "second"}]
        if label == "producer_roster_missing":
            del original["produced"]
        else:
            topologies = original["topologies"][1:2] if label == "one_topology_renamed" else original["topologies"]
            for topology in topologies:
                for worker in topology["workers"]:
                    for row in worker["worker_report"]["transport_records"]:
                        if row["case"] in ("valid", "carrier_replay", "discarded_response"):
                            current = row["verification"]["work_id"]
                            row["verification"]["work_id"] = (current + "-renamed" if label == "one_topology_renamed"
                                else "second" if current == "first" else "first")
        result[label] = encode(original)
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    reference = json.loads((Path(__file__).parent / "legacy-counterexamples.json").read_text())
    expected = {row["case"]: row["input_sha256"] for row in reference["cases"]}
    values = materialize(args.root)
    assert set(values) == set(expected)
    for name, raw in values.items():
        assert hashlib.sha256(raw).hexdigest() == expected[name], name
    args.out.mkdir(parents=True, exist_ok=False)
    for name, raw in values.items():
        with (args.out / (name + ".json")).open("xb") as handle:
            handle.write(raw)
    print(json.dumps({"status": "PASS", "kind": "hash-verified-input-reconstruction",
                      "new_native_experiment": False, "input_count": len(values)}, sort_keys=True))
