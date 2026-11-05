#!/usr/bin/env python3
"""One bounded native diagnostic using the exact retained native-winning header."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency-note", default="Shared-host scheduling and external contention are not controlled.")
    args = parser.parse_args()
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], check=True, stdout=subprocess.DEVNULL)
    git = lambda argument: subprocess.check_output(["git", "rev-parse", argument], text=True).strip()
    source = Path("evidence/pon-pure-cost-bootstrap-20261027/cost-long/stdout.jsonl.gz")
    with gzip.open(source, "rt") as stream:
        begin = json.loads(stream.readline())
    assert begin["kind"] == "begin"
    binary = args.binary.resolve(strict=True)
    command = [str(binary), "--header", begin["native_seed_header"]]
    args.output.mkdir(parents=True, exist_ok=False)
    paths = ["trillionnium/crates/trnm-crypto-primitives/examples/pon_pure_rejection_tail_campaign.rs",
             "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
             "trillionnium/crates/trnm-crypto-primitives/src/pon_work/public_product.rs",
             "trillionnium/crates/trnm-protocol/src/pon_wire.rs", "trillionnium/Cargo.toml",
             "trillionnium/Cargo.lock", "scripts/ci/capture_pure_pon_rejection_tail.py"]
    record = dict(schema="pon-pure-rejection-tail-capture-v1", commit=git("HEAD"), tree=git("HEAD^{tree}"),
        sources={p: sha(Path(p).read_bytes()) for p in paths}, argv=command,
        native_header_source=str(source), native_header_source_gzip_sha256=sha(source.read_bytes()),
        binary_sha256_before=sha(binary.read_bytes()),
        rustc=subprocess.check_output([os.environ.get("RUSTC", "rustc"), "--version", "--verbose"], text=True),
        build_profile="cargo --profile test; crypto/protocol/sha2 package opt-level 3; debug 0; incremental false; one build job",
        platform=platform.platform(), started_at_utc=datetime.now(timezone.utc).isoformat(),
        exclusive_host=False, host_contention_controlled=False,
        concurrent_activity=args.concurrency_note,
        timeout_seconds=120, production_qualified=False, global_upper_bound_proved=False)
    manifest = args.output / "capture.json"
    manifest.write_text(json.dumps(record, indent=2) + "\n")
    start = time.monotonic_ns()
    with (args.output / "stdout.jsonl").open("xb") as stdout, (args.output / "stderr.log").open("xb") as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = child.wait(timeout=120)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
    raw = (args.output / "stdout.jsonl").read_bytes()
    compressed = gzip.compress(raw, mtime=0)
    (args.output / "stdout.jsonl.gz").write_bytes(compressed)
    record.update(ended_at_utc=datetime.now(timezone.utc).isoformat(), elapsed_ns=time.monotonic_ns()-start,
        exit_code=code, timed_out=timed_out, stdout_bytes=len(raw), stdout_sha256=sha(raw),
        stdout_gzip_bytes=len(compressed), stdout_gzip_sha256=sha(compressed),
        stderr_sha256=sha((args.output / "stderr.log").read_bytes()), binary_sha256_after=sha(binary.read_bytes()))
    record["stable_binary"] = record["binary_sha256_before"] == record["binary_sha256_after"]
    record["stdout_within_bound"] = len(raw) <= 8*1024*1024
    manifest.write_text(json.dumps(record, indent=2) + "\n")
    assert gzip.decompress(compressed) == raw
    (args.output / "stdout.jsonl").unlink()
    print(json.dumps(record))
    return int(code != 0 or timed_out or not record["stable_binary"] or not record["stdout_within_bound"])


if __name__ == "__main__":
    raise SystemExit(main())
