import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys

def read_raw(path, cap=65536):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(cap + 1)
        truncated = len(raw) > cap
        raw = raw[:cap]
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = base64.b64encode(raw).decode("ascii")
            encoding = "base64"
        return {"status": "read", "raw": text, "encoding": encoding,
                "captured_bytes": len(raw), "captured_sha256": hashlib.sha256(raw).hexdigest(),
                "capture_limit_bytes": cap, "truncated": truncated}
    except OSError as error:
        return {"status": "unavailable", "errno": error.errno, "raw": None,
                "capture_limit_bytes": cap, "truncated": None}

paths = ["/proc/cpuinfo", "/proc/self/status", "/proc/self/limits",
         "/proc/self/cgroup", "/proc/self/mountinfo", "/proc/meminfo",
         "/proc/pressure/cpu", "/proc/pressure/memory",
         "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/possible",
         "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu.stat",
         "/sys/fs/cgroup/cpu.pressure", "/sys/fs/cgroup/cpuset.cpus.effective",
         "/sys/fs/cgroup/cpuset.mems.effective", "/sys/fs/cgroup/memory.max",
         "/sys/fs/cgroup/memory.high", "/sys/fs/cgroup/memory.current",
         "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory.events",
         "/sys/fs/cgroup/memory.swap.max",
         "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
         "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us",
         "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us",
         "/sys/fs/cgroup/cpuset/cpuset.cpus", "/sys/fs/cgroup/cpuset/cpuset.mems",
         "/sys/fs/cgroup/memory/memory.limit_in_bytes"]
observations = {path: read_raw(path, 1048576 if path in ("/proc/cpuinfo", "/proc/self/mountinfo")
                               else 65536) for path in paths}
try:
    affinity = {"status": "read", "cpu_ids": sorted(os.sched_getaffinity(0)),
                "scope": "this snapshot process at capture time; not every proof descendant"}
except (AttributeError, OSError) as error:
    affinity = {"status": "unavailable", "errno": getattr(error, "errno", None), "cpu_ids": None}
rlimits = {}
for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_NOFILE", "RLIMIT_FSIZE"):
    try:
        rlimits[name] = {"status": "read", "raw_soft_hard": list(resource.getrlimit(getattr(resource, name)))}
    except (AttributeError, OSError, ValueError) as error:
        rlimits[name] = {"status": "unavailable", "errno": getattr(error, "errno", None)}
cpuinfo = observations["/proc/cpuinfo"]
models = sorted({line.split(":", 1)[1].strip() for line in (cpuinfo.get("raw") or "").splitlines()
                 if ":" in line and line.split(":", 1)[0].strip() in ("model name", "Hardware", "Processor")})
report = {"schema": "pon-w1-cost-host-resources-v1", "phase": sys.argv[2],
          "captured_utc": datetime.now(timezone.utc).isoformat(),
          "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
          "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "kernel": dict(zip(("system", "node", "release", "version", "machine", "processor"), platform.uname())),
          "cpu_model_values_from_captured_raw": models, "os_cpu_count": os.cpu_count(),
          "affinity": affinity, "process_rlimits": rlimits, "observations": observations,
          "configured_environment": {key: os.environ.get(key) for key in
              ("RAYON_NUM_THREADS", "CARGO_BUILD_JOBS", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_NAME")},
          "missing_means_unlimited": False, "resource_qualification": False,
          "effective_cpu_quota": None, "whole_family_affinity_qualified": False,
          "cgroup_scope": "raw mounted-root controller files plus self membership/mountinfo; no ancestor-resolved effective quota",
          "sampling_scope": "two host snapshots; proof owner retains its unchanged live process sampler"}
with Path(sys.argv[1]).open("x") as output:
    json.dump(report, output, indent=2, allow_nan=False)
    output.write("\n")
