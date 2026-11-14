#!/usr/bin/env python3
"""Record the actual command, source context and child outcome without recasting failures."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
import time

directory = Path(__file__).resolve().parent
name, *command = sys.argv[1:]
log = directory / f"{name}.log"
receipt = directory / f"{name}.json"
git = lambda *args: subprocess.check_output(["git", *args], text=True).strip()
record = {"schema": "local-native-liveness-command-v1", "name": name,
          "command": command, "cwd": str(Path.cwd()),
          "head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
          "dirty_paths": git("status", "--porcelain").splitlines(),
          "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "returncode": None, "completed": False}
receipt.write_text(json.dumps(record, indent=2) + "\n")
started = time.monotonic_ns()
with log.open("wb") as output:
    result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
record.update({"returncode": result.returncode, "completed": True,
               "wall_ns": time.monotonic_ns() - started,
               "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "log_bytes": log.stat().st_size,
               "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
               "final_head": git("rev-parse", "HEAD"),
               "final_dirty_paths": git("status", "--porcelain").splitlines()})
receipt.write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record), flush=True)
tail = "\n".join(log.read_text(errors="replace").splitlines()[-18:])
print(tail if len(tail) <= 2400 else tail[:600] + "\n[display truncated; complete raw log retained]\n" + tail[-1800:], flush=True)
sys.exit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
