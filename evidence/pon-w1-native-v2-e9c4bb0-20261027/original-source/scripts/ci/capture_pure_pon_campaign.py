#!/usr/bin/env python3
"""Capture a bounded native campaign, including failure, at an exact source commit."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import time


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3700:
        parser.error("timeout must be 1..3700 seconds")
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"]).returncode:
        raise SystemExit("commit source changes before capturing a campaign")
    root = Path(git("rev-parse", "--show-toplevel"))
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    argv = [str(binary), *(args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments)]
    code = root / "trillionnium/crates/trnm-pon-node/examples" / (binary.name + ".rs")
    source = {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
              "example_sha256": digest(code), "lock_sha256": digest(root / "trillionnium/Cargo.lock"),
              "workspace_manifest_sha256": digest(root / "trillionnium/Cargo.toml")}
    rustc = os.environ.get("RUSTC", "rustc")
    rust = subprocess.check_output([rustc, "--version", "--verbose"], text=True)
    before_hash = digest(binary)
    report = {"schema": "pon-pure-native-capture-v1", "source": source, "argv": argv,
              "rustc": rust, "build_profile": "cargo --profile test; repository package overrides",
              "package_opt_levels": {"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 1},
              "debug_info": 0, "incremental": False, "build_jobs": 1,
              "binary_sha256_before": before_hash, "timeout_seconds": args.timeout,
              "platform": platform.platform(), "machine": platform.machine(),
              "exclusive_host": False, "host_contention_controlled": False,
              "production_qualified": False, "hardness_proved": False}
    for name in ("cpu.max", "memory.max"):
        path = Path("/sys/fs/cgroup") / name
        report[name] = path.read_text().strip() if path.is_file() else None
    report_path = args.output / "capture.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    raw_path = args.output / "stdout.jsonl"
    stderr_path = args.output / "stderr.log"
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic_ns()
    timed_out = False
    with raw_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            returncode = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait()
    elapsed = time.monotonic_ns() - start
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    report.update(exit_code=returncode, timed_out=timed_out, elapsed_ns=elapsed,
                  child_user_cpu_seconds=usage.ru_utime - usage_before.ru_utime,
                  child_system_cpu_seconds=usage.ru_stime - usage_before.ru_stime,
                  child_max_rss_kib=usage.ru_maxrss,
                  binary_sha256_after=digest(binary), stdout_bytes=raw_path.stat().st_size,
                  stdout_uncompressed_sha256=digest(raw_path), stderr_sha256=digest(stderr_path))
    report["stable_binary"] = report["binary_sha256_before"] == report["binary_sha256_after"]
    # The examples bound their reports. Preserve an unexpected excess as failure,
    # rather than truncating it and qualifying a smaller apparent workload.
    report["stdout_within_bound"] = report["stdout_bytes"] <= 64 * 1024 * 1024
    compressed = args.output / "stdout.jsonl.gz"
    with raw_path.open("rb") as source_stream, compressed.open("xb") as compressed_stream:
        with gzip.GzipFile(fileobj=compressed_stream, mode="wb", mtime=0) as destination:
            for chunk in iter(lambda: source_stream.read(65536), b""):
                destination.write(chunk)
    report["stdout_gzip_sha256"] = digest(compressed)
    report["stdout_gzip_bytes"] = compressed.stat().st_size
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    raw_path.unlink()  # The complete exact bytes are retained losslessly in gzip.
    print(json.dumps(report))
    return 0 if returncode == 0 and not timed_out and report["stable_binary"] and report["stdout_within_bound"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
