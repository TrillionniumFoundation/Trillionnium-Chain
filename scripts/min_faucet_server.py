#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
RPC_WORKDIR = ROOT / "trillionnium"

HOST = os.environ.get("FAUCET_HOST", "127.0.0.1")
PORT = int(os.environ.get("FAUCET_PORT", "8546"))
DEFAULT_AMOUNT = os.environ.get("FAUCET_DEFAULT_AMOUNT", "1000")
MAXIMUM_BODY_BYTES = 4_096
MAXIMUM_COMMAND_SECONDS = 60
MAXIMUM_U128 = (1 << 128) - 1
TRNM_ADDRESS = re.compile(r"trnm1[0-9a-f]{40}\Z")
DECIMAL_AMOUNT = re.compile(r"[0-9]{1,39}\Z")


class RequestValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message


def canonical_address(value: Any) -> str:
    if not isinstance(value, str) or TRNM_ADDRESS.fullmatch(value) is None:
        raise RequestValidationError(
            "INVALID_ADDRESS",
            "address must be trnm1 followed by 40 lowercase hexadecimal characters",
        )
    # Reconstruct from decoded bytes so only the fixed address grammar reaches
    # the subprocess boundary; raw request text is never forwarded.
    suffix = bytes.fromhex(value[5:]).hex()
    return f"trnm1{suffix}"


def canonical_amount(value: Any) -> str:
    if isinstance(value, bool):
        raise RequestValidationError(
            "INVALID_AMOUNT",
            "amount must be a positive canonical decimal u128",
        )
    rendered = str(value)
    if DECIMAL_AMOUNT.fullmatch(rendered) is None:
        raise RequestValidationError(
            "INVALID_AMOUNT",
            "amount must be a positive canonical decimal u128",
        )
    parsed = int(rendered, 10)
    if parsed == 0 or parsed > MAXIMUM_U128 or str(parsed) != rendered:
        raise RequestValidationError(
            "INVALID_AMOUNT",
            "amount must be a positive canonical decimal u128",
        )
    return str(parsed)


def resolve_cargo_binary() -> pathlib.Path:
    configured = os.environ.get("TRNM_FAUCET_CARGO_BIN")
    if configured:
        candidate = pathlib.Path(configured)
        if not candidate.is_absolute():
            raise RuntimeError("TRNM_FAUCET_CARGO_BIN must be absolute")
    else:
        discovered = shutil.which("cargo")
        if discovered is None:
            raise RuntimeError("cargo executable is unavailable")
        candidate = pathlib.Path(discovered)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError("cargo executable is not a regular executable file")
    return resolved


def command_timeout_seconds() -> int:
    raw = os.environ.get("TRNM_FAUCET_COMMAND_TIMEOUT_SECONDS", "30")
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise RuntimeError("invalid faucet command timeout") from error
    if not 1 <= value <= MAXIMUM_COMMAND_SECONDS:
        raise RuntimeError("faucet command timeout is outside 1..60 seconds")
    return value


def faucet_command(cargo: pathlib.Path, address: str, amount: str) -> tuple[str, ...]:
    return (
        str(cargo),
        "run",
        "-q",
        "-p",
        "trnm-rpc",
        "--",
        "faucet-request",
        f"--address={address}",
        f"--amount={amount}",
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "trnm-faucet/1"

    def _json(self, code: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_request(self) -> tuple[str, str]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
            raise RequestValidationError("INVALID_REQUEST", "valid Content-Length required")
        length = int(raw_length, 10)
        if length <= 0 or length > MAXIMUM_BODY_BYTES:
            raise RequestValidationError(
                "INVALID_REQUEST",
                f"request body must contain 1..{MAXIMUM_BODY_BYTES} bytes",
            )
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestValidationError("INVALID_REQUEST", "request body is truncated")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RequestValidationError("INVALID_REQUEST", "valid UTF-8 JSON required") from error
        if not isinstance(data, dict):
            raise RequestValidationError("INVALID_REQUEST", "JSON object required")
        address = canonical_address(data.get("address"))
        amount = canonical_amount(data.get("amount", DEFAULT_AMOUNT))
        return address, amount

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"ok": True, "service": "trnm-faucet", "version": 1})
            return
        self._json(404, {"ok": False, "code": "NOT_FOUND"})

    def do_POST(self) -> None:
        if self.path != "/faucet/request":
            self._json(404, {"ok": False, "code": "NOT_FOUND"})
            return
        try:
            address, amount = self._read_request()
            cargo = resolve_cargo_binary()
            completed = subprocess.run(
                faucet_command(cargo, address, amount),
                cwd=RPC_WORKDIR,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                shell=False,
                close_fds=True,
                timeout=command_timeout_seconds(),
                check=False,
            )
            if completed.returncode != 0:
                self._json(
                    400,
                    {
                        "ok": False,
                        "code": "FAUCET_REQUEST_FAILED",
                        "message": "faucet request was rejected",
                    },
                )
                return
            try:
                body = json.loads(completed.stdout)
            except json.JSONDecodeError:
                self._json(
                    502,
                    {
                        "ok": False,
                        "code": "INVALID_UPSTREAM_RESPONSE",
                        "message": "faucet command returned invalid JSON",
                    },
                )
                return
            if not isinstance(body, dict):
                self._json(
                    502,
                    {
                        "ok": False,
                        "code": "INVALID_UPSTREAM_RESPONSE",
                        "message": "faucet command returned a non-object response",
                    },
                )
                return
            self._json(200, body)
        except RequestValidationError as error:
            self._json(
                400,
                {"ok": False, "code": error.code, "message": error.public_message},
            )
        except subprocess.TimeoutExpired:
            self._json(
                504,
                {
                    "ok": False,
                    "code": "FAUCET_TIMEOUT",
                    "message": "faucet command timed out",
                },
            )
        except Exception as error:
            self.log_error("faucet request failed: %s", type(error).__name__)
            self._json(
                500,
                {
                    "ok": False,
                    "code": "INTERNAL",
                    "message": "internal faucet error",
                },
            )


if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()
