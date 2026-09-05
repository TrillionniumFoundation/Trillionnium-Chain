#!/usr/bin/env python3
"""Read-only readiness probe for the authorized six-host PoCO G3 LAN fleet."""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import shutil
import socket
import subprocess
import time
import tomllib


MIN_TMP_FREE_BYTES = 4 * 1024**3
REQUIRED_TOOLS = ("python3", "tar")
PING_ATTEMPTS = 3
REMOTE = r'''set -u
printf 'hostname=%s\n' "$(hostname)"
printf 'os=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
if df -Pk /tmp >/dev/null 2>&1; then
  df -Pk /tmp | awk 'NR==2{print "tmp_free_bytes="$4*1024}'
else
  df -Pk /private/tmp | awk 'NR==2{print "tmp_free_bytes="$4*1024}'
fi
printf 'nofile_soft=%s\n' "$(ulimit -Sn)"
printf 'nofile_hard=%s\n' "$(ulimit -Hn)"
printf 'python3=%s\n' "$(command -v python3 || true)"
printf 'tar=%s\n' "$(command -v tar || true)"
printf 'sha256=%s\n' "$(command -v sha256sum || command -v shasum || true)"
printf 'cargo=%s\n' "$(command -v cargo || true)"
printf 'rustc=%s\n' "$(command -v rustc || true)"
if sudo -n true >/dev/null 2>&1; then
  printf 'sudo_nopass=ok\n'
else
  printf 'sudo_nopass=fail\n'
fi
if [ "$(uname -s)" = Darwin ]; then
  printf 'network_fault_tool=%s\n' "$(command -v pfctl || true)"
else
  tc_path="$(command -v tc || true)"
  nft_path="$(command -v nft || true)"
  [ -n "$tc_path" ] || [ ! -x /usr/sbin/tc ] || tc_path=/usr/sbin/tc
  [ -n "$nft_path" ] || [ ! -x /usr/sbin/nft ] || nft_path=/usr/sbin/nft
  if [ -n "$tc_path" ] && [ -n "$nft_path" ]; then
    printf 'network_fault_tool=%s+%s\n' "$tc_path" "$nft_path"
  else
    printf 'network_fault_tool=\n'
  fi
fi
printf 'process_inspector=%s\n' "$(command -v ss || command -v lsof || true)"
printf 'epoch=%s\n' "$(date +%s)"
if command -v ss >/dev/null; then
  # The topology owns only 31000-31099 (P2P) and 32000-32099 (metrics).
  # Unrelated listeners elsewhere in 31xxx/32xxx are not PoCO conflicts.
  printf 'poco_listeners=%s\n' "$(ss -ltnH 2>/dev/null | awk '$4 ~ /:(31|32)0[0-9][0-9]$/ {n++} END{print n+0}')"
elif command -v lsof >/dev/null; then
  printf 'poco_listeners=%s\n' "$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '$9 ~ /:(31|32)0[0-9][0-9]$/ {n++} END{print n+0}')"
else
  printf 'poco_listeners=unknown\n'
fi
failed=0
for ip in __LAN_IPS__; do
  status=1
  attempt=1
  while [ "$attempt" -le __PING_ATTEMPTS__ ]; do
    if [ "$(uname -s)" = Darwin ]; then
      ping -n -c 1 -W 2000 "$ip" >/dev/null 2>&1
    else
      ping -n -c 1 -W 2 "$ip" >/dev/null 2>&1
    fi
    status=$?
    [ "$status" -ne 0 ] || break
    attempt=$((attempt + 1))
  done
  if [ "$status" -eq 0 ]; then
    printf 'ping_%s=ok\n' "$ip"
  else
    printf 'ping_%s=fail\n' "$ip"
    failed=1
  fi
done
exit "$failed"
'''


def parse_lines(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise ValueError(f"invalid or duplicate readiness line: {line!r}")
        values[key] = value
    return values


def local_facts(lan_ips: list[str]) -> dict[str, str]:
    stat = shutil.disk_usage("/tmp")
    soft, hard = subprocess.check_output(
        ["bash", "-lc", "printf '%s %s' \"$(ulimit -Sn)\" \"$(ulimit -Hn)\""],
        text=True,
    ).split()
    listeners = subprocess.check_output(
        [
            "bash",
            "-lc",
            "ss -ltnH 2>/dev/null | awk '$4 ~ /:(31|32)0[0-9][0-9]$/ {n++} END{print n+0}'",
        ],
        text=True,
    ).strip()
    sudo_nopass = subprocess.run(
        ["sudo", "-n", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0
    tc = shutil.which("tc") or ("/usr/sbin/tc" if pathlib.Path("/usr/sbin/tc").is_file() else "")
    nft = shutil.which("nft") or ("/usr/sbin/nft" if pathlib.Path("/usr/sbin/nft").is_file() else "")
    pfctl = shutil.which("pfctl") or ("/sbin/pfctl" if pathlib.Path("/sbin/pfctl").is_file() else "")
    system = platform.system()
    fault_tool = pfctl if system == "Darwin" else (f"{tc}+{nft}" if tc and nft else "")
    facts = {
        "hostname": socket.gethostname(),
        "os": system,
        "arch": platform.machine(),
        "tmp_free_bytes": str(stat.free),
        "nofile_soft": soft,
        "nofile_hard": hard,
        "python3": shutil.which("python3") or "",
        "tar": shutil.which("tar") or "",
        "sha256": shutil.which("sha256sum") or shutil.which("shasum") or "",
        "cargo": shutil.which("cargo") or "",
        "rustc": shutil.which("rustc") or "",
        "sudo_nopass": "ok" if sudo_nopass else "fail",
        "network_fault_tool": fault_tool,
        "process_inspector": shutil.which("ss") or shutil.which("lsof") or "",
        "epoch": str(int(time.time())),
        "poco_listeners": listeners,
    }
    for ip in lan_ips:
        reachable = False
        for _ in range(PING_ATTEMPTS):
            result = subprocess.run(
                ["ping", "-n", "-c", "1", "-W", "2", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                reachable = True
                break
        facts[f"ping_{ip}"] = "ok" if reachable else "fail"
    return facts


def expected_os(value: str) -> str:
    return {"linux": "Linux", "macos": "Darwin"}[value]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inventory",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("inventory.toml"),
    )
    parser.add_argument("--timeout-seconds", type=int, default=20)
    args = parser.parse_args()
    with args.inventory.open("rb") as source:
        inventory = tomllib.load(source)
    lan_ips = [host["lan_ip"] for host in inventory["hosts"]]
    remote = REMOTE.replace("__LAN_IPS__", " ".join(lan_ips)).replace(
        "__PING_ATTEMPTS__", str(PING_ATTEMPTS)
    )
    observations = []
    failures = []
    epochs = []
    for host in inventory["hosts"]:
        try:
            remote_returncode = 0
            if host["management"] == "local":
                facts = local_facts(lan_ips)
            else:
                completed = subprocess.run(
                    [
                        "ssh",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        f"ConnectTimeout={args.timeout_seconds}",
                        host["management"],
                        "bash -s",
                    ],
                    input=remote,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=args.timeout_seconds,
                )
                # The remote probe deliberately exits 1 when any directed LAN
                # ping fails.  Parse its complete structured output even in
                # that case so the evidence names the exact failed edge instead
                # of collapsing it into an opaque SSH status.  Any other exit
                # code still denotes a probe/transport failure.
                if completed.returncode not in (0, 1):
                    detail = completed.stderr.strip()[:512]
                    raise ValueError(
                        f"remote readiness probe exited {completed.returncode}: {detail}"
                    )
                remote_returncode = completed.returncode
                facts = parse_lines(completed.stdout)
            if facts["os"] != expected_os(host["os"]) or facts["arch"] != host["arch"]:
                raise ValueError("OS/architecture differs from inventory")
            if int(facts["tmp_free_bytes"]) < MIN_TMP_FREE_BYTES:
                raise ValueError("temporary filesystem has less than 4 GiB free")
            if any(not facts[tool] for tool in REQUIRED_TOOLS) or not facts["sha256"]:
                raise ValueError("required probe/distribution tool is absent")
            if facts["sudo_nopass"] != "ok" or not facts["network_fault_tool"]:
                raise ValueError("bounded network-fault authority is unavailable")
            if not facts["process_inspector"]:
                raise ValueError("listener/process inspection tool is absent")
            if facts["poco_listeners"] != "0":
                raise ValueError("reserved PoCO port range is already in use")
            failed_edges = [ip for ip in lan_ips if facts[f"ping_{ip}"] != "ok"]
            if remote_returncode == 1:
                if not failed_edges:
                    raise ValueError("remote probe returned failure without a failed LAN edge")
            if failed_edges:
                raise ValueError(
                    "full LAN reachability matrix is incomplete for "
                    + ",".join(failed_edges)
                )
            epochs.append(int(facts["epoch"]))
            observations.append({"id": host["id"], "lan_ip": host["lan_ip"], "facts": facts})
        except (KeyError, OSError, subprocess.SubprocessError, ValueError) as error:
            failures.append({"id": host["id"], "error": str(error)})
    report = {
        "schema_version": 2,
        "fleet_id": inventory["fleet_id"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_run_completed": False,
        "probe_completed_at_epoch": int(time.time()),
        "observed_epoch_spread_seconds": max(epochs) - min(epochs) if epochs else None,
        "observations": observations,
        "failures": failures,
    }
    build_arches = {
        (facts["os"], facts["arch"])
        for observation in observations
        if (facts := observation["facts"])["cargo"] and facts["rustc"]
    }
    expected_build_arches = {
        (expected_os(host["os"]), host["arch"]) for host in inventory["hosts"]
    }
    if build_arches != expected_build_arches:
        report["failures"].append(
            {
                "id": "fleet",
                "error": "at least one native Rust build host is required per OS/architecture",
            }
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["failures"] or len(observations) != len(inventory["hosts"]):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
