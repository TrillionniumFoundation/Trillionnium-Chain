"""Task-specific R1 CI progress metadata. Main only issues bounded GitHub GETs.
Each invocation owns a fresh ROOT/R1-required-ci-progress-v1-* directory.
This is not the fixed final observer, hosted evidence collector or a merge gate.
"""
import argparse, concurrent.futures, datetime, hashlib, json, math, os
import pathlib, re, signal, stat, subprocess, sys, time

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SELF = pathlib.Path("/private/tmp/chain-prci-R1-ci-progress-reader-preparation-20261114-v1/read_R1_required_ci_progress_v1.py")
WT = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
REPO = "TrillionniumFoundation/Trillionnium-Chain"
R1 = "2a86462a1ab20c68151719ba4635e3c294391e64"
TREE = "5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
MAIN = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
HEAD_REF = "fix/chain-hepta-closure-candidate-20261109-481716"
WORKFLOW = ".github/workflows/trnm-required-baseline.yml"
APP_ID = 15368
GH = "/opt/homebrew/bin/gh"
MAX_RUNS = 20

def need(value, message):
    if not value:
        raise ValueError(message)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def counts(rows):
    result = {}
    for row in rows:
        key = str(row.get("status", "UNKNOWN")) + "/" + str(row.get("conclusion"))
        result[key] = result.get(key, 0) + 1
    return result

def run_view(row):
    return {key: row.get(key) for key in (
        "id", "name", "path", "head_sha", "head_branch", "event", "status", "conclusion",
        "run_attempt", "created_at", "updated_at", "run_started_at", "html_url",
        "check_suite_id", "pull_requests")}

def run_matches(row):
    return (type(row) is dict and type(row.get("id")) is int and row["id"] > 0
            and row.get("head_sha") == R1 and row.get("event") == "pull_request"
            and row.get("path") == WORKFLOW
            and type(row.get("run_attempt")) is int and row["run_attempt"] > 0)

def main():
    need(sys.flags.optimize == 0, "optimized progress reader forbidden")
    need(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected fixed producer path")
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    directory = pathlib.Path(args.evidence_dir)
    need(ROOT.resolve(strict=True) == ROOT and directory.parent == ROOT
         and re.fullmatch(r"R1-required-ci-progress-v1-[a-z0-9][a-z0-9-]{0,63}", directory.name),
         "fresh task-specific output directory required")
    own = SELF.lstat()
    need(stat.S_ISREG(own.st_mode) and own.st_nlink == 1, "ordinary producer file required")
    producer_raw = SELF.read_bytes()
    os.umask(0o077)
    directory.mkdir(mode=0o700, exist_ok=False)

    def save(name, value):
        raw = value if isinstance(value, bytes) else encode(value)
        path = directory / name
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        need(path.read_bytes() == raw, "local output readback differs")
        return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}

    def info(path):
        raw = path.read_bytes()
        return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}

    save("producer.py", producer_raw)
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("GIT_TRACE") or key == "GIT_CURL_VERBOSE":
            del env[key]
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_NAMESPACE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        need(key not in env, "unexpected inherited Git override")
    env.update(GH_PROMPT_DISABLED="1", PYTHONDONTWRITEBYTECODE="1",
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1")
    started = now()
    deadline = time.monotonic() + 240
    results, errors = {}, []

    def api(endpoint):
        return [GH, "api", "--method", "GET", endpoint]

    def run(label, argv):
        out = directory / (label + ".stdout")
        err = directory / (label + ".stderr")
        began, tick = now(), time.monotonic()
        budget = min(120, max(0, int(deadline - tick)))
        timed, launched, exit_code, spawn_error = False, False, None, None
        with out.open("xb") as so, err.open("xb") as se:
            if budget == 0:
                spawn_error = "overall observation deadline exhausted before launch"
            else:
                try:
                    proc = subprocess.Popen(argv, cwd=WT, env=env, stdin=subprocess.DEVNULL,
                        stdout=so, stderr=se, start_new_session=True)
                    launched = True
                    try:
                        exit_code = proc.wait(timeout=budget)
                    except subprocess.TimeoutExpired:
                        timed = True
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            exit_code = proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            exit_code = proc.wait(timeout=5)
                except Exception as exc:
                    spawn_error = type(exc).__name__ + ": " + str(exc)
        receipt = {"label": label, "argv": argv, "cwd": str(WT), "started_at": began,
            "finished_at": now(), "timeout_seconds": budget, "launched": launched,
            "exit": exit_code, "timed_out": timed, "spawn_error": spawn_error,
            "elapsed_seconds": round(time.monotonic() - tick, 3),
            "stdout": info(out), "stderr": info(err)}
        value, parse_error = None, None
        if exit_code == 0 and not timed and spawn_error is None:
            try:
                need(receipt["stdout"]["bytes"] <= 16 * 1024 * 1024,
                     "accepted metadata response exceeds 16 MiB")
                value = json.loads(out.read_bytes())
            except Exception as exc:
                parse_error = type(exc).__name__ + ": " + str(exc)
        return {"receipt": receipt, "value": value, "parse_error": parse_error}

    def execute(batch):
        if not batch:
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(batch))) as pool:
            futures = {pool.submit(run, label, argv): (label, argv) for label, argv in batch}
            for future in concurrent.futures.as_completed(futures):
                label, argv = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"receipt": {"label": label, "argv": argv, "cwd": str(WT),
                        "exit": None, "launched": None,
                        "stdout_path": str(directory / (label + ".stdout")),
                        "stderr_path": str(directory / (label + ".stderr"))},
                        "value": None, "parse_error": type(exc).__name__ + ": " + str(exc)}
                results[label] = result
                print(json.dumps({"phase": "metadata_read_finished", "label": label,
                    "exit": result["receipt"]["exit"], "parse_error": result["parse_error"]}), flush=True)

    def paginate(family, endpoint, array, maximum, first_done=False):
        if not first_done:
            execute([(family + "-page-001", api(endpoint + "&page=1"))])
        first = results[family + "-page-001"]["value"]
        if (type(first) is not dict or type(first.get("total_count")) is not int
                or first["total_count"] < 0 or type(first.get(array)) is not list):
            return [], {"complete": False, "reason": "first page UNKNOWN or invalid",
                        "maximum_pages": maximum, "observations_non_atomic": True}
        total = first["total_count"]
        pages = max(1, math.ceil(total / 100))
        execute([(family + "-page-" + f"{number:03d}", api(endpoint + "&page=" + str(number)))
                 for number in range(2, min(pages, maximum) + 1)])
        rows, totals, failed = [], [], []
        for number in range(1, min(pages, maximum) + 1):
            label = family + "-page-" + f"{number:03d}"
            value = results[label]["value"]
            if (type(value) is not dict or type(value.get("total_count")) is not int
                    or type(value.get(array)) is not list
                    or not all(type(row) is dict for row in value[array])):
                failed.append(label)
                continue
            totals.append(value["total_count"])
            rows.extend(value[array])
        ids = [row.get("id") for row in rows]
        valid_ids = all(type(i) is int and i > 0 for i in ids)
        unique = len(set(ids)) if valid_ids else None
        complete = (not failed and bool(totals) and len(set(totals)) == 1
                    and valid_ids and unique == len(ids) == total and pages <= maximum)
        return rows, {"complete": complete, "reported_total": total, "required_pages": pages,
            "maximum_pages": maximum, "actual_rows": len(rows), "unique_ids": unique,
            "page_total_counts": totals, "failed_pages": failed, "observations_non_atomic": True}

    checks_endpoint = "repos/" + REPO + "/commits/" + R1 + "/check-runs?filter=latest&per_page=100"
    runs_endpoint = ("repos/" + REPO + "/actions/workflows/trnm-required-baseline.yml/runs?head_sha="
                     + R1 + "&per_page=100")
    observations = []
    status = "UNKNOWN"
    details = {}
    try:
        execute([("pr847", api("repos/" + REPO + "/pulls/847")),
                 ("R1-latest-checks-page-001", api(checks_endpoint + "&page=1")),
                 ("R1-required-runs-page-001", api(runs_endpoint + "&page=1"))])
        checks, check_pages = paginate("R1-latest-checks", checks_endpoint, "check_runs", 5, True)
        runs, run_pages = paginate("R1-required-runs", runs_endpoint, "workflow_runs", 3, True)
        pr = results["pr847"]["value"]
        pr_view = None
        if type(pr) is dict:
            pr_view = {key: pr.get(key) for key in (
                "number", "state", "draft", "auto_merge", "created_at", "updated_at",
                "mergeable", "mergeable_state", "merge_commit_sha", "html_url")}
            for side in ("head", "base"):
                source = pr.get(side) or {}
                pr_view[side] = {key: source.get(key) for key in ("sha", "ref", "label")}
                pr_view[side]["repo_full_name"] = (source.get("repo") or {}).get("full_name")
            pr_view["identity_matches_R1_and_main"] = (
                type(pr.get("number")) is int and pr["number"] == 847
                and pr_view["head"]["sha"] == R1 and pr_view["head"]["ref"] == HEAD_REF
                and pr_view["base"]["sha"] == MAIN and pr_view["base"]["ref"] == "main"
                and pr_view["head"]["repo_full_name"] == REPO
                and pr_view["base"]["repo_full_name"] == REPO)
            pr_view["open_ready_without_auto_merge"] = (
                pr.get("state") == "open" and pr.get("draft") is False and pr.get("auto_merge") is None)
        normalized_checks = []
        for check in checks:
            row = {key: check.get(key) for key in (
                "id", "name", "head_sha", "status", "conclusion", "started_at", "completed_at",
                "details_url", "html_url", "check_suite", "external_id")}
            app = check.get("app") or {}
            row["app"] = {key: app.get(key) for key in ("id", "slug", "name")}
            row["app15368"] = type(app.get("id")) is int and app["id"] == APP_ID
            row["actual_tested_source_verified"] = False
            normalized_checks.append(row)
        check_pin = save("R1-latest-checks-normalized.json", normalized_checks)
        run_pin = save("R1-required-runs-normalized.json", [run_view(row) for row in runs])
        eligible = [row for row in runs if run_matches(row)]
        excluded = [{"metadata": run_view(row), "reason":
            "not exact R1 / pull_request / workflow path / positive run-id-and-attempt"}
            for row in runs if not run_matches(row)]
        selected = eligible[:MAX_RUNS]
        unobserved = []
        for listed in selected:
            if time.monotonic() >= deadline:
                unobserved.append(listed["id"])
                continue
            rid = listed["id"]
            family = "R1-run-" + str(rid)
            execute([(family + "-metadata", api("repos/" + REPO + "/actions/runs/" + str(rid)))])
            actual = results[family + "-metadata"]["value"]
            same = run_matches(actual) and actual["id"] == rid
            if not same:
                observations.append({"run_id": rid, "metadata":
                    run_view(actual) if type(actual) is dict else None,
                    "metadata_matches_R1_pull_request_workflow": False,
                    "jobs_not_fetched": "actual run identity unavailable or differs"})
                continue
            endpoint = "repos/" + REPO + "/actions/runs/" + str(rid) + "/jobs?filter=all&per_page=100"
            jobs, job_pages = paginate(family + "-jobs", endpoint, "jobs", 3)
            normalized = []
            for job in jobs:
                row = {key: job.get(key) for key in (
                    "id", "run_id", "run_attempt", "name", "head_sha", "head_branch", "status",
                    "conclusion", "created_at", "started_at", "completed_at", "html_url",
                    "check_run_url", "labels", "runner_id", "runner_name")}
                name = str(job.get("name", "")).lower()
                row["source_kind_hint_from_name"] = (
                    "prospective" if "prospective" in name else
                    "head" if re.search(r"(^|[^a-z])head([^a-z]|$)", name) else "not_explicit_in_name")
                row["matches_observed_run_attempt"] = (
                    job.get("run_id") == rid and job.get("head_sha") == R1
                    and type(job.get("run_attempt")) is int
                    and job["run_attempt"] == actual["run_attempt"])
                row["steps"] = [{key: step.get(key) for key in (
                    "number", "name", "status", "conclusion", "started_at", "completed_at")}
                    for step in job.get("steps", [])]
                row["actual_tested_commit"] = None
                row["actual_tested_tree"] = None
                row["actual_tested_source_verified"] = False
                normalized.append(row)
            current_jobs = [row for row in normalized if row["matches_observed_run_attempt"]]
            job_pin = save(family + "-jobs-normalized.json", normalized)
            observations.append({"run_id": rid, "metadata": run_view(actual),
                "metadata_matches_R1_pull_request_workflow": True,
                "listed_attempt": listed["run_attempt"], "observed_attempt": actual["run_attempt"],
                "attempt_changed_during_snapshot": listed["run_attempt"] != actual["run_attempt"],
                "jobs_pagination": job_pages, "all_attempt_job_counts": counts(jobs),
                "observed_attempt_job_counts": counts(current_jobs),
                "all_returned_jobs_match_run_and_R1": all(
                    row.get("run_id") == rid and row.get("head_sha") == R1 for row in jobs),
                "jobs": job_pin, "observed_attempt_job_count": len(current_jobs)})
        complete = (check_pages["complete"] and run_pages["complete"] and pr_view is not None
            and len(eligible) <= MAX_RUNS and not unobserved
            and all(row.get("metadata_matches_R1_pull_request_workflow") is True
                    and row.get("jobs_pagination", {}).get("complete") is True
                    and row.get("all_returned_jobs_match_run_and_R1") is True
                    and not row.get("attempt_changed_during_snapshot", False)
                    for row in observations)
            and all(row.get("head_sha") == R1 for row in checks)
            and not any(result["value"] is None for result in results.values()))
        status = ("DRIFT" if pr_view is not None and not pr_view["identity_matches_R1_and_main"]
                  else "OBSERVED" if complete else "UNKNOWN")
        details = {"pr": pr_view, "latest_checks": {"pagination": check_pages,
            "filter": "latest", "status_counts": counts(checks),
            "app15368_status_counts": counts([row for row in normalized_checks if row["app15368"]]),
            "all_returned_head_sha_equal_R1": all(row.get("head_sha") == R1 for row in checks),
            "normalized": check_pin},
            "required_runs": {"pagination": run_pages, "normalized": run_pin,
                "eligible_pull_request_runs": len(eligible), "excluded_run_metadata": excluded,
                "selected_cap": MAX_RUNS, "unselected_due_to_cap": [row["id"] for row in eligible[MAX_RUNS:]],
                "unobserved_due_to_deadline": unobserved, "no_required_run_observed_yet": not eligible,
                "run_jobs": observations},
            "metadata_pages_complete": complete}
    except Exception as exc:
        errors.append(type(exc).__name__ + ": " + str(exc))
    summary = {"schema": "trnm-R1-required-ci-progress-v1", "status": status,
        "started_at": started, "finished_at": now(), "expected_candidate": R1,
        "expected_candidate_tree": TREE, "expected_main": MAIN, "required_workflow": WORKFLOW,
        "required_run_event": "pull_request", "expected_check_app_id": APP_ID,
        "producer": {"path": str(SELF), "bytes": len(producer_raw), "sha256": sha(producer_raw)},
        **details, "steps": [results[key]["receipt"] for key in sorted(results)],
        "unknown_reads": [key for key, value in results.items() if value["value"] is None],
        "errors": errors, "observations_non_atomic": True,
        "job_name_source_kind_is_only_a_hint": True, "PR_prospective_SHA_is_not_tested_source_proof": True,
        "actual_tested_source_verified": False, "older_N_N2_results_inherited": False,
        "pending_or_in_progress_is_not_pass": True, "hosted_qualification_granted": False,
        "final_observer_or_collector_substituted": False, "network_readonly": True,
        "no_source_refs_stage_or_config_changes": True, "policy_data_collected": False,
        "artifacts_or_job_logs_downloaded": False, "CI_dispatch_rerun_cancel_PR_writes": False}
    summary_pin = save("summary.json", summary)
    index_pin = save("EVIDENCE_INDEX.json", {"schema": "trnm-readonly-progress-index-v1",
        "files": [info(path) for path in sorted(directory.iterdir()) if path.is_file()],
        "self_excluded": "EVIDENCE_INDEX.json"})
    print(json.dumps({"status": status, "summary": summary_pin, "index": index_pin,
                     "hosted_qualification_granted": False}), flush=True)
    return 0 if status == "OBSERVED" else 1

if __name__ == "__main__":
    sys.exit(main())
