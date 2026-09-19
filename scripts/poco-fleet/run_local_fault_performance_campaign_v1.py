#!/usr/bin/env python3
"""Run a bounded, real-process loopback transport fault campaign.

The campaign deliberately stays below the production and multi-host evidence
boundary.  It launches one process per endpoint and a separate fault proxy,
then exercises every configured link through baseline, partition, heal and
proxy-restart phases.  The resulting JSON records exact commands, config/source
digests, observations and measured round-trip latency.  A green result proves
only this local multiprocess transport contract; it never sets host-attestation,
independent-multihost or production-performance claims.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROXY = ROOT / "trillionnium" / "scripts" / "consensus" / "p2p_fault_proxy.py"
SCHEMA = "trnm-local-fault-performance-campaign-v1"


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def reserve_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        ports: list[int] = []
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            ports.append(int(sock.getsockname()[1]))
            sockets.append(sock)
        return ports
    finally:
        for sock in sockets:
            sock.close()


def read_ready(process: subprocess.Popen[bytes], marker: bytes, timeout: float = 5.0) -> str:
    if process.stdout is None:
        fail("child stdout was not captured")
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
            fail(f"child exited before readiness rc={process.returncode}: {stderr}")
        line = process.stdout.readline()
        if line:
            text = line.decode(errors="replace").rstrip("\n")
            lines.append(text)
            if marker in line:
                return text
        else:
            time.sleep(0.01)
    fail(f"child readiness timeout marker={marker!r} output={lines!r}")


def stop_process(process: subprocess.Popen[bytes], name: str) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    if process.returncode not in (0, -signal.SIGTERM):
        stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
        fail(f"{name} exited with rc={process.returncode}: {stderr}")


def start_endpoint(endpoint_id: str, port: int) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        str(pathlib.Path(__file__).resolve()),
        "endpoint",
        "--endpoint-id",
        endpoint_id,
        "--port",
        str(port),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    read_ready(process, b"TRNM_LOCAL_ENDPOINT_READY")
    return process


def start_proxy(config: pathlib.Path, control_port: int) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        str(PROXY),
        "serve",
        "--config",
        str(config),
        "--control-host",
        "127.0.0.1",
        "--control-port",
        str(control_port),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    read_ready(process, b"TRNM_P2P_FAULT_PROXY_READY")
    return process


def proxy_control(control_port: int, action: str, links: list[str] | None = None) -> dict[str, Any]:
    request = {"action": action, "links": links or []}
    command = [
        sys.executable,
        str(PROXY),
        "control",
        "--control-host",
        "127.0.0.1",
        "--control-port",
        str(control_port),
        action,
        *(links or []),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=5,
    )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"proxy control returned invalid JSON: {completed.stdout!r}")
    if not isinstance(response, dict) or response.get("ok") is not True:
        fail(f"proxy control failed request={request!r} response={response!r}")
    return response


def round_trip(port: int, expected_endpoint: str, payload: str, timeout: float = 1.0) -> float:
    started = time.monotonic_ns()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall((payload + "\n").encode())
            response = b""
            while not response.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
    except (ConnectionError, OSError, TimeoutError):
        return -1.0
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000.0
    expected = f"{expected_endpoint}:{payload}\n".encode()
    if not response:
        return -1.0
    if response != expected:
        fail(f"unexpected endpoint response expected={expected!r} actual={response!r}")
    return elapsed_ms


def denied_round_trip(port: int, payload: str) -> bool:
    result = round_trip(port, "unreachable", payload)
    return result < 0


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def _require(condition: bool, message: str) -> None:
    if not condition:
        fail(f"invalid campaign evidence: {message}")


def _require_digest(value: Any, field: str) -> None:
    _require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{field} must be a lowercase sha256 digest",
    )


def _validate_latency(value: Any, phase_name: str) -> None:
    _require(isinstance(value, dict), f"{phase_name}.latency_ms must be an object")
    expected = ("min", "p50", "p95", "max")
    _require(
        all(field in value for field in expected),
        f"{phase_name}.latency_ms is missing a percentile",
    )
    samples: list[float] = []
    for field in expected:
        sample = value[field]
        _require(
            isinstance(sample, (int, float))
            and not isinstance(sample, bool)
            and math.isfinite(sample)
            and sample >= 0,
            f"{phase_name}.latency_ms.{field} must be finite and non-negative",
        )
        samples.append(float(sample))
    _require(
        samples == sorted(samples),
        f"{phase_name}.latency_ms percentiles are not monotonic",
    )


def validate_campaign_result(result: Any) -> None:
    """Reject locally-produced evidence that cannot represent this campaign.

    This is an integrity check for the bounded loopback campaign, not a
    signature or an acceptance gate.  In particular, all claims that require
    independent hosts, physical power loss, production activation or a
    performance target stay explicitly false.
    """

    _require(isinstance(result, dict), "result must be an object")
    _require(result.get("schema") == SCHEMA, "schema mismatch")
    _require(
        result.get("campaign_scope") == "single-host-loopback-multiprocess",
        "campaign scope must remain single-host loopback",
    )
    _require(
        result.get("source_proxy") == str(PROXY.relative_to(ROOT)),
        "source_proxy does not identify the checked-in proxy",
    )
    _require_digest(result.get("source_proxy_sha256"), "source_proxy_sha256")
    _require(
        result["source_proxy_sha256"] == sha256_file(PROXY),
        "source_proxy_sha256 does not match the checked-in proxy",
    )
    _require_digest(result.get("config_sha256"), "config_sha256")

    _require(result.get("endpoint_count") == 3, "endpoint_count must be three")
    _require(result.get("link_count") == 3, "link_count must be three")
    messages = result.get("messages_per_link")
    _require(
        isinstance(messages, int) and not isinstance(messages, bool) and 1 <= messages <= 10_000,
        "messages_per_link is outside the accepted bound",
    )
    _require(result.get("restart_count") == 1, "exactly one proxy restart is required")

    started = result.get("started_monotonic_ns")
    completed = result.get("completed_monotonic_ns")
    elapsed = result.get("elapsed_ms")
    _require(
        isinstance(started, int)
        and not isinstance(started, bool)
        and isinstance(completed, int)
        and not isinstance(completed, bool)
        and completed > started,
        "monotonic timestamps must increase",
    )
    _require(
        isinstance(elapsed, (int, float))
        and not isinstance(elapsed, bool)
        and math.isfinite(elapsed)
        and elapsed > 0,
        "elapsed_ms must be finite and positive",
    )
    expected_elapsed = (completed - started) / 1_000_000.0
    _require(
        math.isclose(float(elapsed), expected_elapsed, rel_tol=1e-9, abs_tol=1e-6),
        "elapsed_ms does not match monotonic timestamps",
    )

    expected_flags = {
        "candidate_only": True,
        "host_attestation": False,
        "independent_multihost_evidence": False,
        "physical_power_loss_evidence": False,
        "performance_acceptance": False,
        "production_activation": False,
    }
    for field, expected in expected_flags.items():
        _require(type(result.get(field)) is bool and result[field] is expected, f"{field} flag drifted")

    phases = result.get("phases")
    _require(isinstance(phases, list) and len(phases) == 8, "phase list must contain eight phases")
    expected_names = [
        "baseline",
        "partition",
        "heal",
        "partition",
        "heal",
        "partition",
        "heal",
        "proxy_restart",
    ]
    _require(
        [phase.get("name") if isinstance(phase, dict) else None for phase in phases]
        == expected_names,
        "phase ordering does not match baseline/partition/heal/restart",
    )
    link_names = [f"link-{index}" for index in range(3)]
    baseline = phases[0]
    _require(isinstance(baseline, dict), "baseline phase must be an object")
    _require(baseline.get("links") == link_names, "baseline links do not cover all links")
    _require(baseline.get("accepted") == 3 * messages, "baseline accepted count mismatch")
    _require(baseline.get("rejected") == 0, "baseline rejected count must be zero")
    _validate_latency(baseline.get("latency_ms"), "baseline")

    for index in range(3):
        partition = phases[1 + index * 2]
        heal = phases[2 + index * 2]
        link_name = link_names[index]
        _require(isinstance(partition, dict), f"partition {index} must be an object")
        _require(isinstance(heal, dict), f"heal {index} must be an object")
        _require(partition.get("link") == link_name, f"partition {index} link mismatch")
        _require(heal.get("link") == link_name, f"heal {index} link mismatch")
        _require(
            partition.get("accepted") == 2 * messages
            and partition.get("rejected") == messages
            and partition.get("expected_rejected") == messages,
            f"partition {index} counts do not prove one-link isolation",
        )
        _require(
            heal.get("accepted") == messages and heal.get("rejected") == 0,
            f"heal {index} counts do not prove recovery",
        )

    restart = phases[-1]
    _require(isinstance(restart, dict), "proxy_restart phase must be an object")
    _require(restart.get("links") == link_names, "proxy_restart links do not cover all links")
    _require(restart.get("accepted") == 3 and restart.get("rejected") == 0, "proxy restart counts mismatch")
    _validate_latency(restart.get("latency_ms"), "proxy_restart")


def run_campaign(*, output: pathlib.Path, messages: int) -> dict[str, Any]:
    if messages < 1 or messages > 10_000:
        fail("messages must be between 1 and 10000")
    if not PROXY.is_file():
        fail(f"proxy script missing: {PROXY}")

    endpoint_ids = ["endpoint-0", "endpoint-1", "endpoint-2"]
    ports = reserve_ports(len(endpoint_ids) * 2 + 1)
    endpoint_ports = ports[: len(endpoint_ids)]
    listener_ports = ports[len(endpoint_ids) : -1]
    control_port = ports[-1]
    link_names = [f"link-{index}" for index in range(len(endpoint_ids))]
    links = [
        {
            "name": name,
            "listen_host": "127.0.0.1",
            "listen_port": listener,
            "target_host": "127.0.0.1",
            "target_port": target,
        }
        for name, listener, target in zip(link_names, listener_ports, endpoint_ports)
    ]

    endpoint_processes: list[subprocess.Popen[bytes]] = []
    proxy_process: subprocess.Popen[bytes] | None = None
    restart_count = 0
    started_ns = time.monotonic_ns()
    phases: list[dict[str, Any]] = []
    config_payload = {"links": links}
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-") as temporary:
        directory = pathlib.Path(temporary)
        config_path = directory / "proxy-config.json"
        config_bytes = canonical(config_payload)
        config_path.write_bytes(config_bytes)
        try:
            endpoint_processes = [
                start_endpoint(endpoint_id, port)
                for endpoint_id, port in zip(endpoint_ids, endpoint_ports)
            ]
            proxy_process = start_proxy(config_path, control_port)

            baseline_latencies: list[float] = []
            for index, (name, listener, endpoint_id) in enumerate(
                zip(link_names, listener_ports, endpoint_ids)
            ):
                for message_index in range(messages):
                    latency = round_trip(
                        listener,
                        endpoint_id,
                        f"baseline-{index}-{message_index}",
                    )
                    if latency < 0:
                        fail(f"baseline link failed: {name}")
                    baseline_latencies.append(latency)
            phases.append(
                {
                    "name": "baseline",
                    "links": link_names,
                    "accepted": len(baseline_latencies),
                    "rejected": 0,
                    "latency_ms": {
                        "min": min(baseline_latencies),
                        "p50": percentile(baseline_latencies, 0.50),
                        "p95": percentile(baseline_latencies, 0.95),
                        "max": max(baseline_latencies),
                    },
                }
            )

            for index, (name, listener, endpoint_id) in enumerate(
                zip(link_names, listener_ports, endpoint_ids)
            ):
                proxy_control(control_port, "disable", [name])
                denied = 0
                unaffected = 0
                for message_index in range(messages):
                    if denied_round_trip(listener, f"partition-{index}-{message_index}"):
                        denied += 1
                    else:
                        fail(f"partitioned link accepted traffic: {name}")
                    for other_index, (other_listener, other_endpoint) in enumerate(
                        zip(listener_ports, endpoint_ids)
                    ):
                        if other_index == index:
                            continue
                        if round_trip(
                            other_listener,
                            other_endpoint,
                            f"unaffected-{index}-{message_index}-{other_index}",
                        ) < 0:
                            fail(
                                "unaffected link failed during partition: "
                                f"{link_names[other_index]}"
                            )
                        unaffected += 1
                phases.append(
                    {
                        "name": "partition",
                        "link": name,
                        "accepted": unaffected,
                        "rejected": denied,
                        "expected_rejected": messages,
                    }
                )
                proxy_control(control_port, "enable", [name])
                healed = 0
                for message_index in range(messages):
                    if round_trip(
                        listener,
                        endpoint_id,
                        f"heal-{index}-{message_index}",
                    ) >= 0:
                        healed += 1
                if healed != messages:
                    fail(f"healed link did not recover: {name}")
                phases.append(
                    {
                        "name": "heal",
                        "link": name,
                        "accepted": healed,
                        "rejected": 0,
                    }
                )

            proxy_control(control_port, "shutdown")
            proxy_process.wait(timeout=5)
            if proxy_process.returncode != 0:
                fail(f"proxy clean shutdown failed rc={proxy_process.returncode}")
            proxy_process = start_proxy(config_path, control_port)
            restart_count += 1
            restart_latencies = []
            for index, (name, listener, endpoint_id) in enumerate(
                zip(link_names, listener_ports, endpoint_ids)
            ):
                latency = round_trip(listener, endpoint_id, f"restart-{index}")
                if latency < 0:
                    fail(f"link failed after proxy restart: {name}")
                restart_latencies.append(latency)
            phases.append(
                {
                    "name": "proxy_restart",
                    "links": link_names,
                    "accepted": len(restart_latencies),
                    "rejected": 0,
                    "latency_ms": {
                        "min": min(restart_latencies),
                        "p50": percentile(restart_latencies, 0.50),
                        "p95": percentile(restart_latencies, 0.95),
                        "max": max(restart_latencies),
                    },
                }
            )
        finally:
            if proxy_process is not None:
                try:
                    stop_process(proxy_process, "proxy")
                except RuntimeError:
                    proxy_process.kill()
                    proxy_process.wait(timeout=5)
            for index, process in enumerate(reversed(endpoint_processes)):
                stop_process(process, f"endpoint-{len(endpoint_processes) - index - 1}")

    completed_ns = time.monotonic_ns()
    result = {
        "schema": SCHEMA,
        "campaign_scope": "single-host-loopback-multiprocess",
        "source_proxy": str(PROXY.relative_to(ROOT)),
        "source_proxy_sha256": sha256_file(PROXY),
        "config_sha256": sha256_bytes(config_bytes),
        "endpoint_count": len(endpoint_ids),
        "link_count": len(link_names),
        "messages_per_link": messages,
        "restart_count": restart_count,
        "started_monotonic_ns": started_ns,
        "completed_monotonic_ns": completed_ns,
        "elapsed_ms": (completed_ns - started_ns) / 1_000_000.0,
        "phases": phases,
        "candidate_only": True,
        "host_attestation": False,
        "independent_multihost_evidence": False,
        "physical_power_loss_evidence": False,
        "performance_acceptance": False,
        "production_activation": False,
    }
    validate_campaign_result(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(result))
    digest_path = output.with_suffix(output.suffix + ".sha256")
    digest_path.write_text(sha256_file(output) + "  " + output.name + "\n", encoding="utf-8")
    return result


async def endpoint_server(endpoint_id: str, port: int) -> int:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                payload = line.decode().rstrip("\n")
                writer.write(f"{endpoint_id}:{payload}\n".encode())
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"TRNM_LOCAL_ENDPOINT_READY id={endpoint_id} port={port}", flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    server.close()
    await server.wait_closed()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    endpoint = subparsers.add_parser("endpoint")
    endpoint.add_argument("--endpoint-id", required=True)
    endpoint.add_argument("--port", required=True, type=int)
    campaign = subparsers.add_parser("campaign")
    campaign.add_argument("--output", required=True, type=pathlib.Path)
    campaign.add_argument("--messages", default=8, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "endpoint":
        return asyncio.run(endpoint_server(args.endpoint_id, args.port))
    try:
        result = run_campaign(output=args.output, messages=args.messages)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"campaign failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
