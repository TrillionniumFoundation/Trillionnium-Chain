#!/usr/bin/env python3
import argparse
import json
import os
import random
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


TERMINAL_SUCCESS = {"REVEAL_SUBMITTED"}
TERMINAL_FAILURE = {"REJECTED", "FAILED_ADAPTER", "FAILED_SUBMISSION"}


@dataclass
class CmdResult:
    ok: bool
    rc: int
    stdout: str
    stderr: str
    elapsed_ms: int


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_duration(s: str) -> float:
    s = s.strip().lower()
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60.0
    if s.endswith("h"):
        return float(s[:-1]) * 3600.0
    return float(s)


def run_cmd(args: List[str], cwd: Path, env: Dict[str, str]) -> CmdResult:
    t0 = time.time()
    p = subprocess.run(args, cwd=str(cwd), env=env, text=True, capture_output=True)
    dt = int((time.time() - t0) * 1000)
    return CmdResult(p.returncode == 0, p.returncode, p.stdout, p.stderr, dt)


def parse_json_stdout(res: CmdResult) -> Any:
    if not res.ok:
        return None
    text = res.stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def read_requests(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def status_hist(records: List[Dict[str, Any]]) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    for r in records:
        st = r.get("status", "UNKNOWN")
        hist[st] = hist.get(st, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: kv[0]))


def ensure_bins(rust_root: Path, env: Dict[str, str]) -> None:
    command = ["cargo", "build", "--locked"]
    if env.get("CARGO_NET_OFFLINE") == "true":
        command.append("--offline")
    command.extend(["-p", "trnm-rpc", "-p", "trnm-worker-agent"])
    # Never treat persistent self-hosted-runner target binaries as evidence that
    # they match this checkout. Cargo must validate the exact source and lock on
    # every run, even when it can reuse verified incremental artifacts.
    r = run_cmd(command, rust_root, env)
    if not r.ok:
        print(r.stderr)
        raise SystemExit("build failed")


def main() -> int:
    ap = argparse.ArgumentParser(description="TRNM 2h soak harness (sqlite reliability default)")
    ap.add_argument("--duration", default="2h", help="e.g. 2h(default), 5m smoke, 30s")
    ap.add_argument("--submit-batch", type=int, default=8)
    ap.add_argument("--dispatch-limit", type=int, default=24)
    ap.add_argument("--worker-limit", type=int, default=24)
    ap.add_argument("--query-sample", type=int, default=4)
    ap.add_argument("--loop-sleep", default="1s")
    ap.add_argument("--worker-id", default="worker-soak")
    ap.add_argument("--session-prefix", default="soak")
    ap.add_argument("--channel", default="imessage")
    ap.add_argument("--user-id", default="soak-user")
    ap.add_argument("--clean", action="store_true", help="clean request/submission logs before run")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    rust_root = repo_root / "trillionnium"
    run_health = repo_root / "run" / "health"
    run_health.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id = f"reliability-soak-{ts}"
    report_json = run_health / f"{run_id}.json"
    report_txt = run_health / f"{run_id}.txt"
    audit_jsonl = run_health / f"{run_id}.audit.jsonl"

    env = os.environ.copy()
    env.setdefault("RELIABILITY_STORE", "sqlite")

    ensure_bins(rust_root, env)

    rpc_bin = rust_root / "target" / "debug" / "trnm-rpc"
    worker_bin = rust_root / "target" / "debug" / "trnm-worker-agent"

    ingress_file = rust_root / "run" / "message-gateway" / "requests.jsonl"
    submit_log = rust_root / "run" / "worker-agent" / f"{run_id}-submissions.jsonl"
    ack_log = rust_root / "run" / "worker-agent" / f"{run_id}-acks.jsonl"
    event_log = rust_root / "run" / "worker-agent" / f"{run_id}-events.jsonl"
    progress_log = rust_root / "run" / "worker-agent" / f"{run_id}-progress.jsonl"
    submit_log.parent.mkdir(parents=True, exist_ok=True)

    if args.clean:
        for p in [ingress_file, submit_log, ack_log, event_log, progress_log]:
            if p.exists():
                p.unlink()

    duration_s = parse_duration(args.duration)
    sleep_s = parse_duration(args.loop_sleep)

    started = time.time()
    deadline = started + duration_s

    totals = {
        "submit_ok": 0,
        "submit_fail": 0,
        "dispatch_assigned": 0,
        "worker_run_ok": 0,
        "worker_run_fail": 0,
        "flush_ok": 0,
        "flush_fail": 0,
        "query_ok": 0,
        "query_fail": 0,
        "cycles": 0,
    }
    recent_request_ids: List[str] = []

    with audit_jsonl.open("w") as audit:
        while time.time() < deadline:
            cycle_idx = totals["cycles"] + 1
            cycle = {"cycle": cycle_idx, "ts": now_iso(), "events": []}

            for i in range(max(1, args.submit_batch)):
                idem = f"{run_id}-{cycle_idx}-{i}-{random.randint(1000, 999999)}"
                cmd = [
                    str(rpc_bin), "submit-message",
                    "--channel", args.channel,
                    "--user-id", args.user_id,
                    "--session-id", f"{args.session_prefix}-{cycle_idx}",
                    "--text", f"soak payload cycle={cycle_idx} idx={i}",
                    "--idempotency-key", idem,
                ]
                r = run_cmd(cmd, rust_root, env)
                payload = parse_json_stdout(r)
                req_id = payload.get("request_id") if isinstance(payload, dict) else None
                if r.ok and req_id:
                    totals["submit_ok"] += 1
                    recent_request_ids.append(req_id)
                else:
                    totals["submit_fail"] += 1
                cycle["events"].append({"step": "submit", "ok": r.ok, "rc": r.rc, "request_id": req_id, "elapsed_ms": r.elapsed_ms, "stderr": r.stderr[-300:]})

            dcmd = [str(rpc_bin), "dispatch-open", "--worker-id", args.worker_id, "--limit", str(max(1, args.dispatch_limit))]
            dr = run_cmd(dcmd, rust_root, env)
            djson = parse_json_stdout(dr)
            assigned = len(djson) if isinstance(djson, list) else 0
            totals["dispatch_assigned"] += assigned
            cycle["events"].append({"step": "dispatch", "ok": dr.ok, "rc": dr.rc, "assigned": assigned, "elapsed_ms": dr.elapsed_ms, "stderr": dr.stderr[-300:]})

            wcmd = [
                str(worker_bin), "run-assigned",
                "--worker", args.worker_id,
                "--ingress-file", str(ingress_file),
                "--limit", str(max(1, args.worker_limit)),
                "--submit-log", str(submit_log),
                "--llm-adapter-cmd", "./scripts/llm_adapter_mock.sh",
            ]
            wr = run_cmd(wcmd, rust_root, env)
            totals["worker_run_ok" if wr.ok else "worker_run_fail"] += 1
            cycle["events"].append({"step": "run_assigned", "ok": wr.ok, "rc": wr.rc, "elapsed_ms": wr.elapsed_ms, "stderr": wr.stderr[-300:]})

            fcmd = [
                str(worker_bin), "flush-submissions",
                "--submit-log", str(submit_log),
                "--ingress-file", str(ingress_file),
                "--execute",
                "--adapter-cmd", "./scripts/worker_tx_adapter.sh",
                "--ack-log", str(ack_log),
                "--event-log", str(event_log),
                "--progress-log", str(progress_log),
            ]
            fr = run_cmd(fcmd, rust_root, env)
            totals["flush_ok" if fr.ok else "flush_fail"] += 1
            cycle["events"].append({"step": "flush", "ok": fr.ok, "rc": fr.rc, "elapsed_ms": fr.elapsed_ms, "stderr": fr.stderr[-300:]})

            sample = recent_request_ids[-max(1, args.query_sample):]
            for req_id in sample:
                qr = run_cmd([str(rpc_bin), "query-request-full", "--request-id", req_id], rust_root, env)
                totals["query_ok" if qr.ok else "query_fail"] += 1
                cycle["events"].append({"step": "query", "request_id": req_id, "ok": qr.ok, "rc": qr.rc, "elapsed_ms": qr.elapsed_ms, "stderr": qr.stderr[-300:]})

            records = read_requests(ingress_file)
            cycle["status_hist"] = status_hist(records)
            cycle["totals"] = dict(totals)
            totals["cycles"] += 1

            audit.write(json.dumps(cycle, ensure_ascii=False) + "\n")
            audit.flush()

            time.sleep(max(0.0, sleep_s))

    records = read_requests(ingress_file)
    hist = status_hist(records)
    success = sum(hist.get(s, 0) for s in TERMINAL_SUCCESS)
    fail = sum(hist.get(s, 0) for s in TERMINAL_FAILURE)
    terminal = success + fail

    elapsed = max(0.001, time.time() - started)
    submit_tps = totals["submit_ok"] / elapsed
    terminal_tps = terminal / elapsed
    submit_success_rate = totals["submit_ok"] / max(1, totals["submit_ok"] + totals["submit_fail"])
    process_success_rate = success / max(1, terminal)

    report = {
        "run_id": run_id,
        "started_at": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
        "ended_at": now_iso(),
        "duration_seconds_target": duration_s,
        "duration_seconds_actual": elapsed,
        "reliability_store": env.get("RELIABILITY_STORE", "(unset)"),
        "params": vars(args),
        "artifacts": {
            "report_json": str(report_json),
            "report_txt": str(report_txt),
            "audit_jsonl": str(audit_jsonl),
            "ingress_file": str(ingress_file),
            "submit_log": str(submit_log),
            "ack_log": str(ack_log),
            "event_log": str(event_log),
            "progress_log": str(progress_log),
        },
        "totals": totals,
        "status_histogram": hist,
        "metrics": {
            "submit_tps": submit_tps,
            "terminal_tps": terminal_tps,
            "submit_success_rate": submit_success_rate,
            "terminal_success_rate": process_success_rate,
            "submitted_ok": totals["submit_ok"],
            "submitted_failed": totals["submit_fail"],
            "terminal_success": success,
            "terminal_failed": fail,
            "terminal_total": terminal,
        },
    }

    report_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    txt = []
    txt.append(f"run_id: {run_id}")
    txt.append(f"window: {report['started_at']} -> {report['ended_at']}")
    txt.append(f"duration_actual_s: {elapsed:.2f} (target={duration_s:.2f})")
    txt.append(f"reliability_store: {report['reliability_store']}")
    txt.append(f"submit_ok={totals['submit_ok']} submit_fail={totals['submit_fail']} submit_tps={submit_tps:.4f}")
    txt.append(f"terminal_success={success} terminal_fail={fail} terminal_tps={terminal_tps:.4f}")
    txt.append(f"submit_success_rate={submit_success_rate:.4%} terminal_success_rate={process_success_rate:.4%}")
    txt.append(f"status_histogram={json.dumps(hist, ensure_ascii=False)}")
    txt.append(f"audit_jsonl={audit_jsonl}")
    report_txt.write_text("\n".join(txt) + "\n")

    print(json.dumps({
        "run_id": run_id,
        "report_json": str(report_json),
        "report_txt": str(report_txt),
        "audit_jsonl": str(audit_jsonl),
        "submit_tps": submit_tps,
        "terminal_success_rate": process_success_rate,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
