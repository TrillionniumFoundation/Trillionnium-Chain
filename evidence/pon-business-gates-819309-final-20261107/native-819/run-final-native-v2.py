#!/usr/bin/env python3
"""Frozen-source final validation. Explicit prepush or full-node phase; no retries."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

BASE = Path("/home/qian-qi/chain-throughput-local-admin-20261107")
ROOT = BASE / "work-final-business-20261107"
PACKAGE = ROOT / "trillionnium/crates/trnm-pon-node"
WORK = BASE / "final-native-validation-20261107"
TARGET = BASE / "local-build/final-target"
CARGO = "/home/qian-qi/.cargo/bin/cargo"
PROVIDER_SHA = "79bd5e815ce341387d8299e66419fb8a56ba952892df8e3edc967cab60e83437"
REQ = json.loads((WORK / "requirements.json").read_text())
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$"
)
RUNNING = re.compile(r"^\s*Running (.*?) \(([^()]+)\)\s*$")
LISTING = re.compile(r"^(.+): (test|benchmark)$")

def utc():
    return datetime.now(timezone.utc).isoformat()

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def file_record(path):
    path = Path(path)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}

def save_json(path, value, exclusive=False):
    path = Path(path)
    if exclusive:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2) + "\n")
    else:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)

def disk():
    stat = os.statvfs(BASE)
    usage = shutil.disk_usage(BASE)
    return {"time_utc": utc(), "path": str(BASE), "total_bytes": usage.total,
            "used_bytes": usage.used, "available_bytes": usage.free,
            "f_bavail": stat.f_bavail, "f_bfree": stat.f_bfree, "f_frsize": stat.f_frsize}

def environment():
    env = os.environ.copy()
    removed = []
    for key in list(env):
        if (key.startswith("OPENSSL_") or key.startswith("TRNM_PQ_OPENSSL")
            or key in {"RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                       "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
                       "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS"}
            or key.startswith("CARGO_PROFILE_") or key.endswith("_RUSTFLAGS")):
            removed.append(key)
            env.pop(key, None)
    # These are data assignments, not shell exports. Never execute their text.
    for line in (BASE / "local-build/provider.exports").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            raise ValueError("noncanonical provider assignment key")
        if not (key.startswith("OPENSSL_") or key.startswith("TRNM_PQ_OPENSSL")):
            raise ValueError("unexpected provider assignment: " + key)
        env[key] = value
    env.update({
        "PATH": "/home/qian-qi/.cargo/bin:" + env.get("PATH", ""),
        "CARGO_HOME": str(BASE / "local-build/cargo"), "CARGO_TARGET_DIR": str(TARGET),
        "CARGO_BUILD_JOBS": "8", "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
        "RUST_TEST_THREADS": "1", "CARGO_TERM_COLOR": "never", "GIT_OPTIONAL_LOCKS": "0",
    })
    # This host is not a GitHub runner. Refuse accidental CI identity injection.
    for key in ("GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ARCH"):
        if env.get(key):
            raise ValueError("unexpected CI identity in local environment: " + key)
    if env.get("OPENSSL_STATIC") != "1" or env.get("TRNM_PQ_OPENSSL_VERSION") != "3.5.9":
        raise ValueError("provider exports do not select the pinned static OpenSSL 3.5.9")
    if env.get("TRNM_PQ_OPENSSL_SHA256") != PROVIDER_SHA:
        raise ValueError("provider export hash differs from fixed provider")
    if digest(env["TRNM_PQ_OPENSSL"]) != PROVIDER_SHA:
        raise ValueError("actual OpenSSL binary hash differs")
    version = subprocess.check_output([env["TRNM_PQ_OPENSSL"], "version"], env=env, text=True).strip()
    if not version.startswith("OpenSSL 3.5.9 "):
        raise ValueError("actual OpenSSL version differs")
    return env, removed, version

class Run:
    def __init__(self, args):
        self.args = args
        self.env, removed, provider_version = environment()
        if not re.fullmatch(r"[0-9a-f]{40}", args.frozen_sha):
            raise ValueError("a full frozen commit SHA is mandatory")
        self.sha = args.frozen_sha
        self.candidate = WORK / "runs" / self.sha
        self.candidate.mkdir(parents=True, exist_ok=True)
        self.owner = (self.candidate / "driver-owner.lock").open("a")
        fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.out = self.candidate / args.phase
        self.out.mkdir()  # Existing phase = prior attempt. Never overwrite or retry.
        self.destination = self.out / "manifest.json"
        self.m = {
            "schema": "trnm-final-native-validation-v1", "phase": args.phase,
            "commit": self.sha, "started_utc": utc(), "started_unix": time.time(),
            "result": "RUNNING", "current_step": None, "steps": [],
            "source_root": str(ROOT), "target_directory": str(TARGET),
            "driver": file_record(__file__), "requirements": file_record(WORK / "requirements.json"),
            "disk_before": disk(), "runner_pid": os.getpid(),
            "provider_exports": file_record(BASE / "local-build/provider.exports"),
            "provider_version": provider_version, "provider_binary": file_record(self.env["TRNM_PQ_OPENSSL"]),
            "removed_inherited_build_override_names": sorted(removed),
            "environment": {key: self.env.get(key) for key in (
                "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
                "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUST_TEST_THREADS",
                "OPENSSL_DIR", "OPENSSL_STATIC", "OPENSSL_CONF", "OPENSSL_MODULES",
                "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION",
                "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", "CARGO_TERM_COLOR", "GIT_OPTIONAL_LOCKS",
                "CELL_NATIVE_V1_EVIDENCE_DIR", "GITHUB_ACTIONS", "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT", "RUNNER_ARCH"
            )},
            "phase_rules": {
                "prepush_test_bodies": False,
                "full_node_package_attempts": 1,
                "full_node_command_timeout_seconds": 21600,
                "recommended_hepta_supervisor_timeout_seconds": 22200,
                "outer_timeout_changes_internal_test_deadlines": False,
                "native_ignored_benchmarks_enabled": False,
                "favorable_reruns": False,
            },
            "qualification": {"original_business_gates": False, "history_4105": False,
                              "four_second_pressure": False, "throughput": False,
                              "whole_chain_quantum_security": False},
        }
        self.save()

    def save(self):
        save_json(self.destination, self.m)

    def command(self, label, argv, timeout=10800, native=False, fail_fast=True):
        self.m["current_step"] = label
        self.m["current_step_started_utc"] = utc()
        self.m["current_step_started_unix"] = time.time()
        self.m["current_step_timeout_seconds"] = timeout
        self.save()
        log = self.out / (label + ".log")
        started = time.monotonic()
        timed_out = False
        print(json.dumps({"phase": "begin", "label": label, "argv": argv, "timeout_seconds": timeout}), flush=True)
        with log.open("xb") as stream:
            process = subprocess.Popen(argv, cwd=ROOT, env=self.env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            self.m["current_step_pid"] = process.pid
            self.save()
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = 124
        item = {"label": label, "argv": argv, "exit_code": code, "timed_out": timed_out,
                "seconds": time.monotonic() - started, "log": file_record(log)}
        if native:
            receipt = self.out / "records" / (label + ".json")
            raw = self.out / "records" / (label + ".log")
            if receipt.exists():
                item["source_command_receipt"] = file_record(receipt)
                record = json.loads(receipt.read_text())
                item["native_status"] = record.get("status")
                item["native_exit_code"] = record.get("exit_code")
                item["source_unchanged"] = record.get("before") is not None and record.get("before") == record.get("after")
                if not item["source_unchanged"] or record.get("status") not in ("command_succeeded", "command_failed"):
                    item["receipt_incomplete_or_invalid"] = True
                    code = code or 1
            else:
                item["receipt_missing"] = True
                code = code or 1
            if raw.exists():
                item["native_log"] = file_record(raw)
        item["effective_exit_code"] = code
        self.m["steps"].append(item)
        self.save()
        print(json.dumps({"phase": "end", "label": label, "exit_code": code,
                          "seconds": item["seconds"], "log": item["log"]}), flush=True)
        if code and fail_fast:
            raise RuntimeError(label + " failed with exit " + str(code))
        return code

    def native(self, label, cargo_args, timeout=10800, fail_fast=True):
        command = [CARGO, "+1.95.0", *cargo_args]
        argv = ["/usr/bin/python3", "scripts/ci/record_pq_native_command.py",
                "--kind", "head", "--candidate", self.sha, "--tested", self.sha,
                "--output", str(self.out / "records"), "--label", label, "--", *command]
        return self.command(label, argv, timeout=timeout, native=True, fail_fast=fail_fast)

    def source(self, label):
        return self.command(label, ["/usr/bin/python3", "scripts/ci/verify_ci_source.py",
                    "--kind", "head", "--expected-head", self.sha, "--output",
                    str(self.out / (label + ".json"))], timeout=600)

    def common_before(self):
        self.command("preflight", ["/usr/bin/bash", "scripts/project-preflight.sh"], timeout=120)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, env=self.env, text=True).strip()
        if actual != self.sha:
            raise ValueError("current HEAD differs from explicit frozen SHA")
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, env=self.env, text=True)
        if status:
            raise ValueError("frozen source is not clean")
        self.m["tree"] = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"],
                                                cwd=ROOT, env=self.env, text=True).strip()
        self.source("source-before")
        self.command("toolchain", [CARGO, "+1.95.0", "--version"], timeout=120)
        self.command("rustc", ["/home/qian-qi/.cargo/bin/rustc", "+1.95.0", "--version", "--verbose"], timeout=120)
        self.command("rustdoc", ["/home/qian-qi/.cargo/bin/rustdoc", "+1.95.0", "--version"], timeout=120)

    def inventory(self):
        log = self.out / "records/node-no-run.log"
        by_path = {}
        all_executables = {}
        for line in log.read_text(errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("reason") != "compiler-artifact" or not obj.get("executable"):
                continue
            target = obj.get("target", {})
            source = Path(target.get("src_path", "/"))
            if not source.is_relative_to(PACKAGE):
                continue
            executable = Path(obj["executable"]).resolve()
            if not executable.is_relative_to(TARGET):
                raise ValueError("compiler emitted Node executable outside dedicated final target")
            item = {"target_name": target["name"], "target_kind": target["kind"],
                    "source": str(source), "cargo_package_id": obj.get("package_id"),
                    "profile_test": bool(obj.get("profile", {}).get("test")),
                    "binary": file_record(executable), "origin": "actual Cargo compiler-artifact executable"}
            all_executables[str(executable)] = item
            if item["profile_test"]:
                by_path[str(executable)] = item
        test_artifacts = sorted(by_path.values(), key=lambda x:(x["target_kind"],x["target_name"]))
        integration = sorted(x["target_name"] for x in test_artifacts if "test" in x["target_kind"])
        if integration != REQ["integration_targets"]:
            raise ValueError("actual integration target inventory differs from predeclared 65 targets")
        libraries = [x for x in test_artifacts if "lib" in x["target_kind"]]
        if len(libraries) != 1:
            raise ValueError("expected exactly one actual Node libtest executable")
        cli = [x for x in all_executables.values() if x["target_name"] == "trnm-pon-node"
               and "bin" in x["target_kind"] and not x["profile_test"]]
        if len(cli) != 1:
            raise ValueError("expected one actual native CLI compiler artifact")
        listed = []
        self.m["current_step"] = "linked-test-inventory"
        self.m["inventory_targets_completed"] = 0
        self.m["inventory_targets_total"] = len(test_artifacts)
        self.save()
        for index, artifact in enumerate(test_artifacts):
            executable = Path(artifact["binary"]["path"])
            if digest(executable) != artifact["binary"]["sha256"]:
                raise ValueError("binary changed before listing")
            values = {}
            logs = {}
            for kind, flags in (("all", []), ("ignored", ["--ignored"])):
                # --ignored is only ever passed with --list: no test body executes.
                argv = [str(executable), "--list", "--format", "terse", *flags]
                logfile = self.out / ("inventory-%03d-%s.log" % (index, kind))
                with logfile.open("xb") as stream:
                    result = subprocess.run(argv, cwd=ROOT, env=self.env, stdout=stream,
                                            stderr=subprocess.STDOUT, timeout=120)
                if result.returncode:
                    raise RuntimeError("test inventory listing failed: " + str(logfile))
                names = [match[1] for line in logfile.read_text().splitlines()
                         if (match := LISTING.fullmatch(line)) and match[2] == "test"]
                if len(names) != len(set(names)):
                    raise ValueError("duplicate test identities in linked inventory")
                values[kind] = names
                logs[kind] = {"argv":argv,"exit_code":result.returncode,"log":file_record(logfile),
                              "test_bodies_executed":False}
            if not set(values["ignored"]).issubset(values["all"]):
                raise ValueError("ignored inventory is not a subset")
            if digest(executable) != artifact["binary"]["sha256"]:
                raise ValueError("binary changed during listing")
            entry = {**artifact, "tests":values["all"], "ignored_tests":values["ignored"],
                     "test_count":len(values["all"]), "ignored_count":len(values["ignored"]),
                     "expected_default_executions":len(values["all"])-len(values["ignored"]),
                     "listing_logs":logs}
            listed.append(entry)
            self.m["inventory_targets_completed"] = index + 1
            self.save()
        library = next(x for x in listed if "lib" in x["target_kind"])
        for name in REQ["required_library_tests"]:
            if name not in library["tests"] or name in library["ignored_tests"]:
                raise ValueError("required original test missing or newly ignored: " + name)
        cell = [x for x in listed if x["target_name"] == "cell_native_v1" and "test" in x["target_kind"]]
        if len(cell) != 1 or set(cell[0]["tests"]) != set(REQ["cell_tests"]) or cell[0]["ignored_tests"]:
            raise ValueError("Cell integration must contain the exact 12 nonignored tests")
        record = {"schema":"trnm-final-linked-test-inventory-v1","commit":self.sha,"tree":self.m["tree"],
                  "test_bodies_executed":False,"test_artifacts":listed,"native_cli":cli[0],
                  "all_node_executables":list(all_executables.values()),
                  "doc_tests":"Cargo rustdoc phase runs only during full-node; no --no-run doctest body.",
                  "source_command_receipt":file_record(self.out/"records/node-no-run.json")}
        save_json(self.out/"inventory.json",record,exclusive=True)
        summary = {
            "schema":"trnm-final-linked-test-inventory-summary-v1","commit":self.sha,
            "integration_targets":len(integration),"cell_tests":cell[0]["test_count"],"cell_ignored":0,
            "library_tests":library["test_count"],"library_ignored":library["ignored_count"],
            "all_native_test_targets":len(listed),
            "native_test_inventory_total":sum(x["test_count"] for x in listed),
            "native_default_body_count":sum(x["expected_default_executions"] for x in listed),
            "native_ignored_total":sum(x["ignored_count"] for x in listed),
            "targets":[{k:x[k] for k in ("target_name","target_kind","test_count","ignored_count","expected_default_executions")} for x in listed],
            "required_library_tests":REQ["required_library_tests"],"cell_test_names":REQ["cell_tests"],
            "inventory":file_record(self.out/"inventory.json"),"test_bodies_executed":False,
            "counts_are_prior_to_execution":True,
        }
        save_json(self.out/"inventory-summary.json",summary,exclusive=True)
        self.m["inventory"] = file_record(self.out/"inventory.json")
        self.m["inventory_summary"] = file_record(self.out/"inventory-summary.json")
        self.m["expected_counts"] = {k:summary[k] for k in (
            "integration_targets","cell_tests","library_tests","library_ignored",
            "all_native_test_targets","native_test_inventory_total","native_default_body_count","native_ignored_total")}
        # Preserve primary actual executables separately. Other actual executables
        # remain in dedicated final-target, with every identity retained above.
        preserved = self.candidate/"preserved-binaries"
        preserved.mkdir()
        kept=[]
        for label,item in (("node-lib",library),("cell-native-v1",cell[0]),("native-cli",cli[0])):
            source=Path(item["binary"]["path"]); dest=preserved/label
            with source.open("rb") as src,dest.open("xb") as dst:
                shutil.copyfileobj(src,dst,1024*1024)
            dest.chmod(0o555)
            if digest(dest)!=item["binary"]["sha256"]:
                raise ValueError("preserved binary copy differs")
            kept.append({"label":label,"actual_source":item["binary"],"preserved":file_record(dest)})
        self.m["preserved_primary_binaries"]=kept
        self.save()

    def prepush(self):
        self.native("workspace-strict-clippy", ["clippy","--locked","--offline","--manifest-path",
                    "trillionnium/Cargo.toml","--workspace","--all-targets","--all-features","--","-D","warnings"])
        self.native("node-no-run", ["test","--locked","--offline","--manifest-path",
                    "trillionnium/Cargo.toml","-p","trnm-pon-node","--all-features","--no-run","--message-format=json"])
        self.inventory()

    def parse_full_log(self, inventory, cargo_exit_code):
        text=(self.out/"records/node-full.log").read_text(errors="replace")
        expected={x["binary"]["path"]:x for x in inventory["test_artifacts"]}
        sections=[];current=None
        # Preserve and attribute actual Cargo diagnostics separately from libtest
        # summaries. A child's final OK cannot certify an aborted outer harness.
        diagnostics=[];unbound=[]
        marker=chr(96)

        def target_from_rerun(line):
            match=re.search("to rerun pass "+marker+"([^"+marker+"]+)"+marker,line)
            if not match:
                # --no-fail-fast can also repeat failed target specs at the end.
                match=re.fullmatch(r"\s*"+marker+"([^"+marker+"]+)"+marker+r"\s*",line)
            if not match:
                return []
            try: tokens=shlex.split(match[1])
            except ValueError: return []
            if "--doc" in tokens:
                return ["doc:trnm_pon_node"]
            wanted=[]
            for flag,kind in (("--test","test"),("--bin","bin")):
                if flag in tokens:
                    position=tokens.index(flag)
                    if position+1<len(tokens):
                        wanted.extend(path for path,item in expected.items()
                                      if kind in item["target_kind"] and item["target_name"]==tokens[position+1])
            if "--lib" in tokens:
                wanted.extend(path for path,item in expected.items() if "lib" in item["target_kind"])
            return sorted(set(wanted))

        def diagnostic(line,number,active):
            rerun=("error: test failed" in line or "error: doctest failed" in line)
            process_failure=("process didn't exit successfully:" in line
                             or "could not execute process" in line
                             or "could not execute test" in line)
            targets=target_from_rerun(line)
            if not (rerun or process_failure or targets):
                return
            if process_failure:
                command=re.search(marker+"([^"+marker+"]+)"+marker,line)
                if command:
                    try: argv=shlex.split(command[1])
                    except ValueError: argv=[]
                    if argv:
                        actual=str(Path(argv[0]).resolve())
                        if actual in expected:
                            targets=[actual]
            # A generic immediate Cargo failure belongs to the current target
            # only when no explicit target or executable was available.
            if not targets and (rerun or process_failure) and active is not None:
                targets=[active["target_key"]]
            exit_status=re.search(r"exit status:\s*(-?\d+)",line)
            numeric=int(exit_status[1]) if exit_status else None
            abnormal=bool(process_failure and (
                "signal:" in line or "SIGABRT" in line or "SIGKILL" in line
                or "never executed" in line or "could not execute" in line
                or (numeric is not None and numeric not in (0,101))
            ))
            entry={"line":number,"text":line,"targets":targets,
                   "reports_nonzero_target":bool(rerun or process_failure or targets),
                   "abnormal_exit":abnormal,"reported_exit_status":numeric,
                   "confirmed_nonzero_cargo_call":cargo_exit_code!=0}
            diagnostics.append(entry)
            if not targets: unbound.append(entry)

        for number,line in enumerate(text.splitlines(),1):
            match=RUNNING.fullmatch(line)
            doc=re.fullmatch(r"\s*Doc-tests\s+(\S+)\s*",line)
            if match or doc:
                if current is not None: sections.append(current)
                path=str(Path(match[2]).resolve()) if match else None
                current={"description":match[1] if match else "Doc-tests "+doc[1],
                         "binary_path":path,"doc_tests":bool(doc),
                         "target_key":path if match else "doc:"+doc[1],
                         "start_line":number,"running_announcements":[],
                         "summaries":[],"named_announcements":[]}
                continue
            diagnostic(line,number,current)
            if current is None: continue
            count=re.fullmatch(r"running (\d+) tests?",line)
            if count: current["running_announcements"].append(int(count[1]))
            outcome=SUMMARY.fullmatch(line)
            if outcome:
                current["summaries"].append({
                    "status":outcome[1],"passed":int(outcome[2]),"failed":int(outcome[3]),
                    "ignored":int(outcome[4]),"measured":int(outcome[5]),"filtered_out":int(outcome[6]),
                    "seconds":float(outcome[7]),"log_line":number})
            name=re.match(r"^test ([A-Za-z0-9_:]+) \.\.\.",line)
            if name: current["named_announcements"].append(name[1])
        if current is not None: sections.append(current)
        problems=[];seen=[];totals={k:0 for k in ("passed","failed","ignored","measured","filtered_out")}
        native_totals=totals.copy();doc_totals=totals.copy();result=[]
        for index,section in enumerate(sections):
            info=expected.get(section["binary_path"]) if not section["doc_tests"] else None
            if not section["doc_tests"]:
                seen.append(section["binary_path"])
                if info is None:
                    problems.append("unknown actual Cargo Running binary: "+str(section["binary_path"]))
            candidate=section["summaries"][-1] if section["summaries"] else None
            complete=candidate is not None
            reasons=[]
            bound=[d for d in diagnostics if section["target_key"] in d["targets"]]
            failures=[d for d in bound if d["confirmed_nonzero_cargo_call"] and d["reports_nonzero_target"]]
            if any(d["abnormal_exit"] for d in failures):
                reasons.append("Cargo reported abnormal termination; outer completion is unknown")
            if failures and (candidate is None or candidate["status"]=="ok"):
                reasons.append("Cargo reported a nonzero target without a complete FAILED outer summary")
            if cargo_exit_code in (124,137,143) or cargo_exit_code<0:
                if index==len(sections)-1:
                    reasons.append("supervised Cargo call interrupted at this last target")
            if info is not None:
                actual=file_record(section["binary_path"])
                section["actual_binary"]=actual
                section["expected_binary"]=info["binary"]
                section["binary_unchanged"]=actual==info["binary"]
                if not section["binary_unchanged"]:
                    problems.append("actual Running binary differs: "+section["binary_path"])
                    complete=False
                if not section["running_announcements"] or section["running_announcements"][0]!=info["test_count"]:
                    problems.append("outer running count differs from prior linked inventory: "+info["target_name"])
                    complete=False
                if candidate is None or sum(candidate[k] for k in totals)!=info["test_count"] or candidate["filtered_out"]!=0:
                    problems.append("outer completion denominator differs: "+info["target_name"])
                    complete=False
                if candidate is not None and candidate["ignored"]!=info["ignored_count"]:
                    problems.append("default ignored denominator differs: "+info["target_name"])
                    complete=False
                section["target_name"]=info["target_name"]
                section["expected_test_count"]=info["test_count"]
                section["expected_ignored_count"]=info["ignored_count"]
                required=(REQ["cell_tests"] if info["target_name"]=="cell_native_v1" and "test" in info["target_kind"]
                          else REQ["required_library_tests"] if "lib" in info["target_kind"] else [])
                missing=[n for n in required if n not in section["named_announcements"]]
                section["required_names_missing_from_transcript"]=missing
                if missing:
                    problems.append("required test announcements missing: "+repr(missing));complete=False
            if section["doc_tests"] and (candidate is None or candidate["filtered_out"]!=0):
                problems.append("doctest completion missing or filtered");complete=False
            if reasons:
                complete=False
                problems.append("outer completion unknown for "+section["description"]+": "+"; ".join(reasons))
            section["cargo_target_diagnostics"]=bound
            section["outer_completion_unknown_reasons"]=reasons
            section["last_summary_candidate"]=candidate
            section["outer_summary"]=candidate if complete else None
            section["outer_completion_count_verified"]=complete
            # Unknown ownership includes every observed summary in the unadded
            # collection. A child OK is never relabelled a completed outer pass.
            section["nested_or_unattributed_summaries_not_added"]=(
                section["summaries"][:-1] if complete else section["summaries"])
            if complete:
                for key in totals:
                    totals[key]+=candidate[key]
                    (doc_totals if section["doc_tests"] else native_totals)[key]+=candidate[key]
            result.append(section)
        if len(seen)!=len(set(seen)):
            problems.append("duplicate top-level actual Running binary")
        if set(seen)!=set(expected):
            problems.append("not every predeclared native test executable ran exactly once")
        docs=[s for s in sections if s["doc_tests"]]
        if len(docs)!=1 or docs[0]["description"]!="Doc-tests trnm_pon_node":
            problems.append("expected one Node rustdoc package phase")
        if cargo_exit_code!=0 and unbound:
            problems.append("Cargo failure diagnostics could not be bound to an actual target")
        report={"schema":"trnm-final-node-package-results-v2","commit":self.sha,"tree":self.m["tree"],
                "cargo_exit_code":cargo_exit_code,
                "raw_log":file_record(self.out/"records/node-full.log"),
                "prior_inventory":file_record(self.candidate/"prepush/inventory.json"),
                "sections":result,"cargo_target_diagnostics":diagnostics,
                "unbound_cargo_failure_diagnostics":unbound,
                "coverage_errors":problems,"complete_package_coverage":not problems,
                "complete_outer_summary_totals":totals,"native_outer_summary_totals":native_totals,
                "doctest_outer_summary_totals":doc_totals,
                "nested_child_summaries_added_to_totals":False,
                "pass_claimed":False,"business_qualification":False}
        save_json(self.out/"node-results.json",report,exclusive=True)
        self.m["node_results"]=file_record(self.out/"node-results.json")
        self.m["complete_package_coverage"]=not problems
        self.m["actual_outer_totals"]=totals
        self.m["native_outer_totals"]=native_totals
        self.m["doctest_outer_totals"]=doc_totals
        self.m["coverage_errors"]=problems
        self.save()
        return not problems and totals["failed"]==0

    def full_node(self):
        previous=self.candidate/"prepush/manifest.json"
        prep=json.loads(previous.read_text())
        if prep.get("result")!="PREPUSH_NATIVE_CHECKS_PASS" or prep.get("commit")!=self.sha:
            raise ValueError("full-node requires the exact frozen source's completed prepush phase")
        if not prep.get("source_receipts",{}).get("byte_identical"):
            raise ValueError("prepush source identity was not stable")
        inventory_path=self.candidate/"prepush/inventory.json"
        if digest(inventory_path)!=prep["inventory"]["sha256"]:
            raise ValueError("prior binary inventory changed")
        inventory=json.loads(inventory_path.read_text())
        self.m["prepush_manifest"]=file_record(previous)
        self.m["expected_counts"]=prep["expected_counts"]
        before=[]
        for artifact in inventory["all_node_executables"]:
            actual=file_record(artifact["binary"]["path"])
            if actual!=artifact["binary"]:
                raise ValueError("actual final-target executable changed since prepush")
            before.append(actual)
        save_json(self.out/"binary-before.json",before,exclusive=True)
        self.m["binary_before"]=file_record(self.out/"binary-before.json")
        self.m["disk_before_full_package"]=disk()
        self.save()
        args=["test","--locked","--offline","--manifest-path","trillionnium/Cargo.toml",
              "-p","trnm-pon-node","--all-features","--no-fail-fast",
              "--","--nocapture","--test-threads=1"]
        assert args[-3:]==["--","--nocapture","--test-threads=1"]
        assert not any(x in args for x in ("--ignored","--include-ignored","--skip","--exact"))
        code=self.native("node-full",args,timeout=21600,fail_fast=False)
        # Parse all actual outcomes even when Cargo returned 101.
        parsed=False
        try:
            parsed=self.parse_full_log(inventory, code)
        finally:
            after=[file_record(a["binary"]["path"]) for a in inventory["all_node_executables"]]
            save_json(self.out/"binary-after.json",after,exclusive=True)
            self.m["binary_after"]=file_record(self.out/"binary-after.json")
            self.m["all_binaries_byte_identical"]=before==after
            self.save()
        if code or not parsed or before!=after:
            raise RuntimeError("full Node package failed or incomplete; all observed outcomes retained")

    def finish(self, failure):
        try:
            self.source("source-after")
            before=self.out/"source-before.json";after=self.out/"source-after.json"
            same=before.read_bytes()==after.read_bytes()
            self.m["source_receipts"]={"before":file_record(before),"after":file_record(after),"byte_identical":same}
            if not same: failure=failure or "source-changed"
        except BaseException as error:
            self.m["final_source_error"]=repr(error)
            failure=failure or "final-source"
        self.m["disk_after"]=disk()
        self.m["failed_step"]=failure
        self.m["finished_utc"]=utc()
        self.m["finished_unix"]=time.time()
        self.m["current_step"]=None
        self.m.pop("current_step_pid",None)
        if failure:
            self.m["result"]="NATIVE_FAILURE_OR_INCOMPLETE_RETAINED"
        else:
            self.m["result"]=("PREPUSH_NATIVE_CHECKS_PASS" if self.args.phase=="prepush"
                              else "FULL_NODE_PACKAGE_PASS_ORIGINAL_BUSINESS_UNQUALIFIED")
        self.save()
        print(json.dumps({"phase":"finished","result":self.m["result"],"failed_step":failure,
                          "manifest":file_record(self.destination)}),flush=True)
        return 1 if failure else 0

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-sha",required=True)
    parser.add_argument("--phase",choices=("prepush","full-node"),required=True)
    args=parser.parse_args()
    operation=Run(args)
    failure=None
    try:
        operation.common_before()
        if args.phase=="prepush":operation.prepush()
        else:operation.full_node()
    except BaseException as error:
        failure=operation.m.get("current_step") or "driver"
        operation.m["failure"]={"step":failure,"error":repr(error)}
        operation.save()
        print(json.dumps({"phase":"failure","step":failure,"error":repr(error)}),flush=True)
    return operation.finish(failure)

if __name__=="__main__":
    sys.exit(main())
