#!/usr/bin/env python3
"""Rootless, loopback-only TCP proxies for deterministic P2P partitions."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import signal
import sys
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def loopback_host(value: Any, context: str) -> str:
    require(isinstance(value, str), f"{context} must be a string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{context} must be a numeric loopback address") from exc
    require(address.is_loopback, f"{context} must be loopback-only")
    return value


def tcp_port(value: Any, context: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context} must be an integer") from exc
    require(1024 <= port <= 65535, f"{context} must be between 1024 and 65535")
    return port


@dataclass(eq=False)
class ProxyConnection:
    client_writer: asyncio.StreamWriter
    target_writer: asyncio.StreamWriter

    async def close(self) -> None:
        self.client_writer.close()
        self.target_writer.close()
        await asyncio.gather(
            self.client_writer.wait_closed(),
            self.target_writer.wait_closed(),
            return_exceptions=True,
        )


@dataclass(eq=False)
class ProxyLink:
    name: str
    listen_host: str
    listen_port: int
    target_host: str
    target_port: int
    enabled: bool = True
    connections: set[ProxyConnection] = field(default_factory=set)
    server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
        )

    async def handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        if not self.enabled:
            client_writer.close()
            await client_writer.wait_closed()
            return
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host,
                self.target_port,
            )
        except (ConnectionError, OSError):
            client_writer.close()
            await client_writer.wait_closed()
            return
        if not self.enabled:
            client_writer.close()
            target_writer.close()
            await asyncio.gather(
                client_writer.wait_closed(),
                target_writer.wait_closed(),
                return_exceptions=True,
            )
            return

        connection = ProxyConnection(client_writer, target_writer)
        self.connections.add(connection)

        async def forward(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            while True:
                data = await reader.read(64 * 1024)
                if not data:
                    return
                writer.write(data)
                await writer.drain()

        tasks = {
            asyncio.create_task(forward(client_reader, target_writer)),
            asyncio.create_task(forward(target_reader, client_writer)),
        }
        try:
            _, pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self.connections.discard(connection)
            await connection.close()

    async def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        if not enabled:
            connections = list(self.connections)
            if connections:
                await asyncio.gather(
                    *(connection.close() for connection in connections),
                    return_exceptions=True,
                )
                self.connections.difference_update(connections)

    async def close(self) -> None:
        await self.set_enabled(False)
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "active_connections": len(self.connections),
            "listen": f"{self.listen_host}:{self.listen_port}",
            "target": f"{self.target_host}:{self.target_port}",
        }


def load_links(config_path: Path) -> dict[str, ProxyLink]:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    require(isinstance(payload, dict), "proxy config must be an object")
    raw_links = payload.get("links")
    require(isinstance(raw_links, list) and raw_links, "proxy config links must be non-empty")
    links: dict[str, ProxyLink] = {}
    listeners: set[tuple[str, int]] = set()
    for index, item in enumerate(raw_links):
        require(isinstance(item, dict), f"links[{index}] must be an object")
        name = item.get("name")
        require(isinstance(name, str) and name, f"links[{index}].name is required")
        require(name not in links, f"duplicate link name {name!r}")
        listen_host = loopback_host(item.get("listen_host"), f"{name}.listen_host")
        listen_port = tcp_port(item.get("listen_port"), f"{name}.listen_port")
        target_host = loopback_host(item.get("target_host"), f"{name}.target_host")
        target_port = tcp_port(item.get("target_port"), f"{name}.target_port")
        listener = (listen_host, listen_port)
        require(listener not in listeners, f"duplicate proxy listener {listener}")
        listeners.add(listener)
        links[name] = ProxyLink(
            name=name,
            listen_host=listen_host,
            listen_port=listen_port,
            target_host=target_host,
            target_port=target_port,
        )
    return links


async def serve(args: argparse.Namespace) -> int:
    control_host = loopback_host(args.control_host, "control host")
    control_port = tcp_port(args.control_port, "control port")
    links = load_links(args.config)
    shutdown = asyncio.Event()

    async def control(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        response: dict[str, Any]
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=3.0)
            require(raw and len(raw) <= 64 * 1024, "invalid control request length")
            request = json.loads(raw)
            require(isinstance(request, dict), "control request must be an object")
            action = request.get("action")
            requested_links = request.get("links", [])
            require(isinstance(requested_links, list), "control links must be an array")
            require(
                all(isinstance(name, str) for name in requested_links),
                "control link names must be strings",
            )
            unknown = sorted(set(requested_links).difference(links))
            require(not unknown, f"unknown links: {','.join(unknown)}")
            if action == "disable":
                require(requested_links, "disable requires at least one link")
                for name in requested_links:
                    await links[name].set_enabled(False)
            elif action == "enable":
                require(requested_links, "enable requires at least one link")
                for name in requested_links:
                    await links[name].set_enabled(True)
            elif action == "status":
                require(not requested_links, "status does not accept links")
            elif action == "shutdown":
                require(not requested_links, "shutdown does not accept links")
                shutdown.set()
            else:
                raise ValueError(f"unsupported control action {action!r}")
            response = {
                "ok": True,
                "action": action,
                "links": [links[name].status() for name in sorted(links)],
            }
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        encoded = (json.dumps(response, sort_keys=True) + "\n").encode()
        writer.write(encoded)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    started: list[ProxyLink] = []
    control_server: asyncio.AbstractServer | None = None
    try:
        for name in sorted(links):
            await links[name].start()
            started.append(links[name])
        control_server = await asyncio.start_server(control, control_host, control_port)
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, shutdown.set)
            except NotImplementedError:
                pass
        print(
            "TRNM_P2P_FAULT_PROXY_READY "
            f"links={len(links)} control={control_host}:{control_port}",
            flush=True,
        )
        await shutdown.wait()
    finally:
        if control_server is not None:
            control_server.close()
            await control_server.wait_closed()
        await asyncio.gather(
            *(link.close() for link in started),
            return_exceptions=True,
        )
    print("TRNM_P2P_FAULT_PROXY_STOPPED", flush=True)
    return 0


async def send_control(args: argparse.Namespace) -> int:
    control_host = loopback_host(args.control_host, "control host")
    control_port = tcp_port(args.control_port, "control port")
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(control_host, control_port),
        timeout=args.timeout_seconds,
    )
    request = {"action": args.action, "links": args.links}
    writer.write((json.dumps(request, sort_keys=True) + "\n").encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.readline(), timeout=args.timeout_seconds)
    writer.close()
    await writer.wait_closed()
    require(raw, "proxy control returned an empty response")
    response = json.loads(raw)
    print(json.dumps(response, sort_keys=True))
    require(isinstance(response, dict) and response.get("ok") is True, "proxy control failed")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--config", type=Path, required=True)
    serve_parser.add_argument("--control-host", default="127.0.0.1")
    serve_parser.add_argument("--control-port", type=int, required=True)

    control_parser = subparsers.add_parser("control")
    control_parser.add_argument("--control-host", default="127.0.0.1")
    control_parser.add_argument("--control-port", type=int, required=True)
    control_parser.add_argument("--timeout-seconds", type=float, default=3.0)
    control_parser.add_argument(
        "action",
        choices=("enable", "disable", "status", "shutdown"),
    )
    control_parser.add_argument("links", nargs="*")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.mode == "serve":
            return asyncio.run(serve(args))
        return asyncio.run(send_control(args))
    except Exception as exc:
        print(f"TRNM_P2P_FAULT_PROXY_FAILED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
