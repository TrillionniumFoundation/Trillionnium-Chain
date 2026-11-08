#!/usr/bin/env python3
"""One read-only metadata snapshot. Never launches CI or qualifies a native gate."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import uuid

REPO = "TrillionniumFoundation/Trillionnium-Chain"
REPO_ID = 1323087357
WORKFLOWS = {378180520: "priority", 403419146: "w1"}
ROOT = Path("/home/qian-qi/throughput-final-ci-observation-20261107")
MAX_RESPONSE = 16 * 1024 * 1024
MAX_PAGES = 100

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def parse_http(raw):
    parts = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)
    if len(parts) != 2:
        raise ValueError("missing HTTP header/body boundary")
    head, body = parts
    lines = head.decode("utf-8", "strict").splitlines()
    match = re.fullmatch(r"HTTP/\S+\s+(\d{3})(?:\s+.*)?", lines[0])
    if not match:
        raise ValueError("unexpected gh HTTP status line")
    headers = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError("malformed HTTP header")
        headers.setdefault(key.lower(), []).append(value.strip())
    return int(match.group(1)), headers, json.loads(body)

def self_test():
    status, headers, body = parse_http(
        b'HTTP/2.0 200 OK\r\nDate: today\r\nLink: <https://api.github.com/x?page=2>; rel="next"\r\n\r\n'
        b'{"total_count": 1, "jobs":[{"id":2}]}')
    assert status == 200 and body["jobs"][0]["id"] == 2 and headers["date"] == ["today"]
    assert parse_http(b'HTTP/1.1 404 Not Found\nContent-Type: application/json\n\n{"message":"Not Found"}')[0] == 404
    for invalid in (b'{}', b'warning\n\n{}', b'HTTP/2.0 200 OK\nbad header\n\n{}'):
        try:
            parse_http(invalid)
        except (ValueError, IndexError):
            pass
        else:
            raise AssertionError("malformed response accepted")
    print("HTTP parser controls passed; no API call was made")

class Collector:
    def __init__(self, head):
        self.head = head
        self.path = ROOT / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                            + "-" + head[:12] + "-" + uuid.uuid4().hex[:8])
        self.path.mkdir(parents=True, exist_ok=False)
        self.result = {
            "schema": "trnm-independent-ci-metadata-snapshot-v1",
            "requested_head": head, "started_utc": utc(), "queries": [], "collections": [],
            "issues": [], "target_runs": [], "job_roster": [],
            "native_gate_validated": False,
            "scope": "GET metadata only; artifacts/logs and strict retained receipts require separate audit",
        }

    def issue(self, text):
        self.result["issues"].append(text)

    def get(self, endpoint, label):
        number = len(self.result["queries"]) + 1
        stem = str(number).zfill(4) + "-" + label
        rawpath = self.path / (stem + ".http")
        errpath = self.path / (stem + ".stderr")
        argv = ["/usr/bin/gh", "api", "--hostname", "github.com", "--method", "GET",
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2022-11-28", "--include", endpoint]
        record = {"endpoint": endpoint, "argv": argv, "started_utc": utc(),
                  "http_file": rawpath.name, "stderr_file": errpath.name}
        self.result["queries"].append(record)
        try:
            with rawpath.open("xb") as stdout, errpath.open("xb") as stderr:
                completed = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=90)
            record["exit_code"] = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record["execution_error"] = type(error).__name__ + ": " + str(error)
            record["exit_code"] = None
        finally:
            record["finished_utc"] = utc()
        try:
            size = rawpath.stat().st_size
            record["http_bytes"] = size
            record["stderr_sha256"] = sha(errpath.read_bytes())
            if size > MAX_RESPONSE:
                raise ValueError("metadata response exceeded bounded parser; raw retained")
            raw = rawpath.read_bytes()
            record["http_sha256"] = sha(raw)
            status, headers, body = parse_http(raw)
            record.update(http_status=status, response_headers=headers)
            if record["exit_code"] != 0 or status != 200:
                raise ValueError("GET did not return HTTP 200 and exit 0")
            return body, headers
        except (OSError, ValueError, TypeError, IndexError) as error:
            record["read_error"] = type(error).__name__ + ": " + str(error)
            self.issue(label + ": " + record["read_error"])
            return None, {}

    def pages(self, endpoint, key, label):
        rows, totals, ids = [], [], []
        complete = True
        record = {"label": label, "endpoint": endpoint, "key": key, "pages": 0}
        self.result["collections"].append(record)
        for page in range(1, MAX_PAGES + 1):
            body, headers = self.get(endpoint + ("&" if "?" in endpoint else "?")
                                     + "per_page=100&page=" + str(page),
                                     label + "-page-" + str(page))
            record["pages"] += 1
            if not isinstance(body, dict) or type(body.get("total_count")) is not int or not isinstance(body.get(key), list):
                self.issue(label + ": missing exact list/total_count")
                complete = False
                break
            totals.append(body["total_count"])
            page_rows = body[key]
            rows.extend(page_rows)
            for item in page_rows:
                if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= 0:
                    self.issue(label + ": row lacks positive integer ID")
                    complete = False
                else:
                    ids.append(item["id"])
            next_links = re.findall(r'<([^>]+)>;\s*rel="next"', ",".join(headers.get("link", [])))
            if not next_links:
                break
            if len(next_links) != 1:
                self.issue(label + ": ambiguous next Link")
                complete = False
                break
            parsed = urllib.parse.urlsplit(next_links[0])
            query = urllib.parse.parse_qs(parsed.query)
            expected_path = "/" + endpoint.split("?", 1)[0]
            if (parsed.scheme != "https" or parsed.netloc != "api.github.com"
                    or parsed.path != expected_path or parsed.fragment
                    or query.get("page") != [str(page + 1)]
                    or query.get("per_page") != ["100"]):
                self.issue(label + ": unexpected next Link; did not follow it")
                complete = False
                break
        else:
            self.issue(label + ": page cap reached; coverage incomplete")
            complete = False
        unique = len(set(ids))
        if not totals or len(set(totals)) != 1 or totals[0] != len(rows) or unique != len(rows):
            self.issue(label + ": declared/page/unique denominator mismatch")
            complete = False
        record.update(declared_totals=totals, returned=len(rows), unique_ids=unique,
                      ids=ids, coverage_complete=complete)
        return rows

    def collect(self):
        user, _ = self.get("user", "identity")
        if not isinstance(user, dict) or user.get("login") != "ProfHepta" or user.get("id") != 102159240:
            raise ValueError("expected existing ProfHepta identity; no identity switch attempted")
        repository, _ = self.get("repos/" + REPO, "repository")
        if not isinstance(repository, dict) or repository.get("id") != REPO_ID or repository.get("full_name") != REPO:
            raise ValueError("repository identity mismatch")
        permissions = repository.get("permissions") or {}
        self.result["authority"] = {
            "login": user.get("login"), "user_id": user.get("id"),
            "repository_id": repository.get("id"),
            "permissions": permissions,
        }
        if permissions.get("admin") is not True or permissions.get("push") is not True:
            raise ValueError("expected existing repository admin/push authority; no identity switch attempted")
        prefix = "repos/" + REPO
        all_runs = self.pages(prefix + "/actions/runs?head_sha=" + self.head, "workflow_runs", "head-all-events")
        selected = {}
        specific = {}
        for workflow, name in WORKFLOWS.items():
            specific[workflow] = self.pages(prefix + "/actions/workflows/" + str(workflow)
                                             + "/runs?head_sha=" + self.head, "workflow_runs", name + "-all-events")
            for run in specific[workflow]:
                if isinstance(run, dict) and type(run.get("id")) is int:
                    selected[run["id"]] = run
                if run.get("head_sha") != self.head or run.get("workflow_id") != workflow:
                    self.issue(name + ": returned run has foreign source/workflow")
        for run in all_runs:
            if run.get("head_sha") != self.head:
                self.issue("head-all-events: returned foreign SHA")
            if run.get("workflow_id") in WORKFLOWS:
                selected[run["id"]] = run
        for workflow, name in WORKFLOWS.items():
            general = {r["id"] for r in all_runs if r.get("workflow_id") == workflow}
            narrower = {r["id"] for r in specific[workflow]}
            if general != narrower:
                self.issue(name + ": repository and workflow endpoint snapshot mismatch; refresh required")
        self.pages(prefix + "/commits/" + self.head + "/check-runs?filter=all", "check_runs", "check-runs-all")
        self.pages(prefix + "/commits/" + self.head + "/status", "statuses", "combined-status")
        for run_id in sorted(selected):
            tag = "run-" + str(run_id)
            path = prefix + "/actions/runs/" + str(run_id)
            run, _ = self.get(path, tag)
            if not isinstance(run, dict):
                continue
            if run.get("head_sha") != self.head or run.get("workflow_id") not in WORKFLOWS:
                self.issue(tag + ": detail source/workflow mismatch")
                continue
            self.result["target_runs"].append({key: run.get(key) for key in (
                "id", "workflow_id", "name", "event", "head_sha", "head_branch", "run_attempt",
                "status", "conclusion", "created_at", "updated_at", "html_url", "actor", "triggering_actor")})
            all_jobs = self.pages(path + "/jobs?filter=all", "jobs", tag + "-all-attempt-jobs")
            attempts = run.get("run_attempt")
            attempt_jobs = []
            if type(attempts) is not int or not 1 <= attempts <= 100:
                self.issue(tag + ": unsupported attempt count; no silent truncation")
            else:
                for attempt in range(1, attempts + 1):
                    apath = path + "/attempts/" + str(attempt)
                    self.get(apath, tag + "-attempt-" + str(attempt))
                    attempt_jobs.extend(self.pages(apath + "/jobs", "jobs", tag + "-attempt-" + str(attempt) + "-jobs"))
                if {j["id"] for j in all_jobs} != {j["id"] for j in attempt_jobs}:
                    self.issue(tag + ": all-attempt and per-attempt job sets differ; refresh required")
            for job in all_jobs:
                self.result["job_roster"].append({key: job.get(key) for key in (
                    "id", "run_id", "run_attempt", "name", "head_sha", "status", "conclusion",
                    "started_at", "completed_at", "runner_name", "labels", "html_url")})
            artifacts = self.pages(path + "/artifacts", "artifacts", tag + "-artifacts")
            for artifact in artifacts:
                binding = artifact.get("workflow_run") or {}
                if binding.get("id") != run_id or binding.get("head_sha") != self.head:
                    self.issue(tag + ": artifact workflow_run binding missing/mismatched: " + str(artifact.get("id")))

        user_after, _ = self.get("user", "identity-after")
        if (not isinstance(user_after, dict) or user_after.get("login") != "ProfHepta"
                or user_after.get("id") != 102159240):
            self.issue("identity-after: expected same ProfHepta identity")
        else:
            self.result["authority"]["identity_after"] = {
                "login": user_after["login"], "user_id": user_after["id"]}

    def finish(self):
        self.result["finished_utc"] = utc()
        self.result["metadata_coverage_complete"] = not self.result["issues"]
        raw = (json.dumps(self.result, indent=2, sort_keys=True) + "\n").encode()
        (self.path / "snapshot.json").write_bytes(raw)
        print(json.dumps({"directory": str(self.path), "snapshot_sha256": sha(raw),
                          "target_run_ids": [r["id"] for r in self.result["target_runs"]],
                          "query_count": len(self.result["queries"]),
                          "metadata_coverage_complete": self.result["metadata_coverage_complete"],
                          "issues": self.result["issues"], "native_gate_validated": False},
                         sort_keys=True))
        return 0 if self.result["metadata_coverage_complete"] else 2

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", help="exact 40-character published commit; no event filter")
    parser.add_argument("--self-test", action="store_true", help="local HTTP parser controls only; no API request")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.head or re.fullmatch(r"[0-9a-f]{40}", args.head) is None:
        parser.error("--head requires an exact lowercase 40-character commit")
    collector = Collector(args.head)
    try:
        collector.collect()
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        collector.issue("collector stopped: " + type(error).__name__ + ": " + str(error))
    return collector.finish()

if __name__ == "__main__":
    sys.exit(main())
