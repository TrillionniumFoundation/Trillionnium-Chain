#!/usr/bin/env python3
"""Read actual original F0 work/cost observations without rerunning any workload."""
import argparse, collections, hashlib, io, json, pathlib, sqlite3, subprocess, tempfile, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[4]
SPECS = [
    (44315121617, "7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8", "docs/development/evidence/chain-fixed-root-f0-20261118-2e9b/original.zip", "5f91007e3ef15216caca24d898ca07438fd43a199ccfa94253023cf66b44095e"),
    (44328450170, "eeef078c7dd12dd2456d6a202c2839f7b8af316d", "docs/development/evidence/chain-host-stat-20261118-2e9b/f0-original.zip", "ccc502e88fac262153d821eadb53dedd549c405d65fd8d331a687284295314d9"),
    (44335832525, "e6af21fd47347ba900ef87842447ed6fe227a6f0", "docs/development/evidence/chain-executed-deltas-20261118-2e9b/f0-original.zip", "6ab6d65c68a2d0b36e49995507dbcc7f7728e16fec3fe6e20de53cb1fdff62fa"),
]
SELECTED_PHASES = ("work", "admission", "admission_prepare", "commit", "submit_result")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def integer(value):
    assert type(value) is int and value >= 0
    return value

def observed_sum(rows, field):
    values = [row.get(field) for row in rows]
    known = [integer(value) for value in values if value is not None]
    return {"known_sum": sum(known), "observed_rows": len(rows),
            "unknown_rows": len(values)-len(known),
            "complete_observed_sum": sum(known) if len(known)==len(values) else None}

def graph_frequency(archive, phase, owner, temporary):
    member = "execution/raw/"+phase+"/"+owner+"/native.sqlite"
    contents = archive.read(member)
    directory = pathlib.Path(temporary)/(phase+"-"+owner)
    directory.mkdir()
    database = directory/"native.sqlite"
    database.write_bytes(contents)
    for suffix in ("-wal", "-shm"):
        if member+suffix in archive.namelist():
            (directory/("native.sqlite"+suffix)).write_bytes(archive.read(member+suffix))
    with sqlite3.connect("file:"+str(database)+"?mode=ro", uri=True) as db:
        records = {bytes(block): json.loads(data)
                   for block,data in db.execute("SELECT block,data FROM native_state_commitments")}
        heights = {bytes(block).hex(): height for height,block in db.execute("SELECT height,id FROM blocks")}
        rows = []
        for height,block,parent in db.execute("SELECT height,id,parent FROM blocks WHERE height>4 ORDER BY height,id"):
            before,after = records[bytes(parent)],records[bytes(block)]
            changes = list(db.execute("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key", (block,)))
            account_changes = [key for key,_,_ in changes if key.startswith("account:")]
            same = before["accounts"] == after["accounts"]
            rows.append({"height":height, "block":bytes(block).hex(), "actual_delta_rows":len(changes),
                         "actual_account_delta_rows":len(account_changes),
                         "same_complete_account_root":same, "account_count":after["accounts"]["count"],
                         "no_account_change":not account_changes and same,
                         "full_graph_nodes":max(0,2*after["accounts"]["count"]-1)})
        triggers = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name")]
    return {"owner":owner, "database_sha256":sha(contents), "actual_trigger_names":triggers,
            "completed_business_blocks":len(rows), "no_account_change_blocks":sum(row["no_account_change"] for row in rows),
            "potential_one_graph_node_visits":sum(row["full_graph_nodes"] for row in rows if row["no_account_change"]),
            "potential_is_not_measured_saved_work":True, "actual_blocks":rows}, heights

def profile(data, run, head):
    with zipfile.ZipFile(io.BytesIO(data)) as archive, tempfile.TemporaryDirectory(prefix="chain-f0-cost-") as temporary:
        read = lambda name: json.loads(archive.read(name))
        source = read("source-before.json")
        assert source["tested_commit"]==head and source==read("source-after.json")
        report = read("execution/raw/report.json")
        prepared = read("prepared/prepared.json")
        execution = read("execution/results.json")
        result = {"run_id":run, "head":head, "tree":source["tested_tree"],
                  "archive_sha256":sha(data), "report_sha256":sha(archive.read("execution/raw/report.json")),
                  "native_exit_code":execution["step"]["returncode"],
                  "original_window_confirmations":sum(row["confirmed_inside_original_window"] for row in execution["all_planned_rounds"]),
                  "four_second_confirmations":execution["four_second_slo_successes"],
                  "preparation_steps": [{key:step.get(key) for key in ("name","elapsed_ns","returncode","complete_success")}
                                        for step in prepared["steps"]],
                  "compiler_and_dependency_acquisition_cpu_ns":None,
                  "original_honest_preparation":{key:report["preparation"].get(key) for key in ("cpu_ns","wall_ns","rss","state_backend","actual_signed_seed_transfers","seed_blocks","business_blocks")}, "phases":[]}
        for phase in report["phases"]:
            frequencies = []
            known_heights = {}
            for owner in ("receiver","independent-client"):
                frequency,heights = graph_frequency(archive,phase["mode"],owner,temporary)
                frequencies.append(frequency);known_heights.update(heights)
            history = []
            for index,attempt in enumerate(phase["history"]):
                imported = attempt.get("client_import")
                if imported is None:
                    history.append({"history_index":index, "import_observed":False,
                                    "client_cpu_ns":None,"host_checkpoint_calls":None,"host_checkpoint_cpu_ns":None})
                    continue
                obs = imported["native_import_observation"]
                checkpoint = next(row for row in obs["host_checks"] if row["phase"]=="checkpoint")
                attributed = obs["host_checkpoint_attribution"]
                assert attributed["all_checkpoint_calls_attributed"] is True
                assert sum(row["calls"]["calls_completed"] for row in attributed["buckets"])==checkpoint["calls_completed"]
                buckets = [{**row["calls"], "owner_phase":row["owner_phase"]} for row in attributed["buckets"]]
                packet_rows = []
                for packet in obs["packets"]:
                    packet_id = bytes(packet["packet_id"]).hex()
                    packet_rows.append({"packet_id":packet_id,"height_if_present_in_actual_final_databases":known_heights.get(packet_id),
                                        "phases":[row for row in packet["phases"] if row["phase"] in SELECTED_PHASES]})
                history.append({"history_index":index,"import_observed":True,
                                "import_error":imported["error"],"client_cpu_ns":imported["thread_cpu_ns"],
                                "client_wall_ns":imported["wall_ns"],"host_checkpoint_calls":checkpoint["calls_completed"],
                                "host_checkpoint_cpu_ns":checkpoint["thread_cpu_ns"],"checkpoint_observation":checkpoint,
                                "host_checkpoint_buckets":buckets,"actual_packets":packet_rows})
            stage_deltas = {}
            for owner,prefix in (("receiver","native_history_arithmetic"),("client","client_native_history_arithmetic")):
                before,after = phase[prefix+"_before"],phase[prefix+"_after"]
                assert before["stage_observation_failed"] is False and after["stage_observation_failed"] is False
                stages = {}
                for row in after["stages"]:
                    prior = next(item["totals"] for item in before["stages"] if item["stage"]==row["stage"])
                    stages[row["stage"]] = {key:integer(row["totals"][key]-prior[key]) for key in ("calls","cpu_ns","wall_ns")}
                stage_deltas[owner] = stages
            observer = phase["receiver_observation"]
            records = observer["records"]
            observed = [row for row in history if row["import_observed"]]
            buckets = collections.defaultdict(list)
            for row in observed:
                for bucket in row["host_checkpoint_buckets"]:
                    buckets[bucket["owner_phase"]].append(bucket)
            bucket_totals = []
            for label,rows in buckets.items():
                active = [row for row in rows if row["calls_started"]>0]
                bucket_totals.append({"owner_phase":label,"calls":sum(row["calls_completed"] for row in rows),
                                      "cpu":observed_sum(active,"thread_cpu_ns"),
                                      "unknown_cpu_calls":sum(row["cpu_clock_unknown_calls"] for row in rows),
                                      "unfinished_calls":sum(row["calls_unfinished"] for row in rows)})
            result["phases"].append({
                "phase":phase["mode"],"history_attempts":history,"observed_imports":len(observed),
                "history_client_cpu":observed_sum(observed,"client_cpu_ns"),
                "history_host_cpu_nested":observed_sum(observed,"host_checkpoint_cpu_ns"),
                "history_host_calls":sum(row["host_checkpoint_calls"] for row in observed),
                "host_checkpoint_bucket_totals":bucket_totals,
                "native_stage_deltas_nested_not_additive":stage_deltas,
                "actual_graph_frequency":frequencies,
                "whole_public_phase_cpu_ns":phase["whole_parent_phase_cpu_ns"],
                "whole_public_phase_wall_ns":phase["whole_parent_phase_wall_ns"],
                "public_setup_cpu_ns_nested":phase["receiver_and_verifier_setup_cpu_ns"],
                "public_setup_wall_ns_nested":phase["receiver_and_verifier_setup_wall_ns"],
                "receiver_observer_complete":phase["observer_complete"],
                "receiver_records_not_retained":observer["records_not_retained"],
                "receiver_measurement_failures":observer["measurement_failures"],
                "receiver_application_read_bytes":observed_sum(records,"application_bytes_read"),
                "receiver_application_written_bytes":observed_sum(records,"application_bytes_written"),
                "receiver_physical_network_bytes":observed_sum(records,"physical_network_bytes"),
                "final_actual_cpu_credit_flow":phase["final_actual_flow"],
                "complete_physical_cost":None})
        return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=pathlib.Path,required=True)
    args=parser.parse_args()
    results=[]
    for run,head,name,digest in SPECS:
        path=ROOT/name
        data=path.read_bytes() if path.exists() else subprocess.check_output(["git","show","HEAD:"+name],cwd=ROOT)
        assert sha(data)==digest
        results.append(profile(data,run,head))
    output={"schema":"chain-original-f0-cost-comparison-v1",
            "scope":"Same declared inputs on different GitHub runner allocations. Actual completed/failed work counts differ; not paired causal speed estimates. Host bucket CPU partitions the checkpoint accumulator; graph/publish/admission/work CPU is nested and must not be added.",
            "source_result_qualification":"All three original four-second gates failed; complete physical costs remain unknown.",
            "unknown_physical_cost_dimensions":["compiler and dependency acquisition CPU","concurrent whole-system RSS","physical storage I/O","storage byte-seconds","physical network bytes","GPU activity","energy","provider charges"],
            "runs":results}
    with args.out.open("x") as target:json.dump(output,target,indent=2,sort_keys=True);target.write("\n")
    for run in results:
        print(json.dumps({"run":run["run_id"],"original_window":run["original_window_confirmations"],
                          "four_second":run["four_second_confirmations"],
                          "phases":[{"phase":p["phase"],"imports":p["observed_imports"],"host_calls":p["history_host_calls"],
                                     "host_cpu":p["history_host_cpu_nested"],
                                     "eligible_graphs":[{"owner":f["owner"],"eligible":f["no_account_change_blocks"],
                                                        "potential_nodes":f["potential_one_graph_node_visits"]}
                                                       for f in p["actual_graph_frequency"]]}
                                    for p in run["phases"]]}))
if __name__=="__main__":main()
