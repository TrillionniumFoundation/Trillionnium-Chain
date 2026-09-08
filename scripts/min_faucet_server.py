#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Iterator, Mapping

ROOT = pathlib.Path(__file__).resolve().parent.parent

HOST = os.environ.get("FAUCET_HOST", "127.0.0.1")
PORT = int(os.environ.get("FAUCET_PORT", "8546"))
DEFAULT_AMOUNT = os.environ.get("FAUCET_DEFAULT_AMOUNT", "1000")
MAXIMUM_BODY_BYTES = 4_096
MAXIMUM_COMMAND_SECONDS = 60
MAXIMUM_COMMAND_OUTPUT_BYTES = 1_048_576
MAXIMUM_EXECUTABLE_BYTES = 536_870_912
MAXIMUM_LEDGER_RECORD_BYTES = 131_072
MAXIMUM_U128 = (1 << 128) - 1
TRNM_ADDRESS = re.compile(r"trnm1[0-9a-f]{40}\Z")
DECIMAL_AMOUNT = re.compile(r"[0-9]{1,39}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
_PR_SET_CHILD_SUBREAPER = 36


class RequestValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message


class FaucetCommandTimeout(RuntimeError):
    pass


class FaucetCommandLifecycleError(RuntimeError):
    pass


class IdempotencyConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class LedgerAdmission:
    is_new: bool
    state: str
    response: dict[str, Any] | None


def canonical_address(value: Any) -> str:
    if not isinstance(value, str) or TRNM_ADDRESS.fullmatch(value) is None:
        raise RequestValidationError(
            "INVALID_ADDRESS",
            "address must be trnm1 followed by 40 lowercase hexadecimal characters",
        )
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


def canonical_request_id(value: Any) -> str:
    if not isinstance(value, str) or REQUEST_ID.fullmatch(value) is None:
        raise RequestValidationError(
            "INVALID_REQUEST_ID",
            "request_id must be 64 lowercase hexadecimal characters",
        )
    return value


def request_fingerprint(request_id: str, address: str, amount: str) -> str:
    canonical = json.dumps(
        {
            "request_id": request_id,
            "address": address,
            "amount": amount,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"TRNM/FAUCET/REQUEST/V1\0" + canonical).hexdigest()


def command_timeout_seconds() -> int:
    raw = os.environ.get("TRNM_FAUCET_COMMAND_TIMEOUT_SECONDS", "30")
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise RuntimeError("invalid faucet command timeout") from error
    if not 1 <= value <= MAXIMUM_COMMAND_SECONDS:
        raise RuntimeError("faucet command timeout is outside 1..60 seconds")
    return value


def _required_sealing() -> tuple[int, int, int, int]:
    required = {
        "os.MFD_CLOEXEC": getattr(os, "MFD_CLOEXEC", None),
        "os.MFD_ALLOW_SEALING": getattr(os, "MFD_ALLOW_SEALING", None),
        "fcntl.F_ADD_SEALS": getattr(fcntl, "F_ADD_SEALS", None),
        "fcntl.F_GET_SEALS": getattr(fcntl, "F_GET_SEALS", None),
        "fcntl.F_SEAL_SEAL": getattr(fcntl, "F_SEAL_SEAL", None),
        "fcntl.F_SEAL_SHRINK": getattr(fcntl, "F_SEAL_SHRINK", None),
        "fcntl.F_SEAL_GROW": getattr(fcntl, "F_SEAL_GROW", None),
        "fcntl.F_SEAL_WRITE": getattr(fcntl, "F_SEAL_WRITE", None),
    }
    missing = [name for name, value in required.items() if not isinstance(value, int)]
    if not hasattr(os, "memfd_create") or missing:
        detail = ", ".join(missing) if missing else "os.memfd_create"
        raise RuntimeError(f"sealed Linux memfd support is required: {detail}")
    flags = int(required["os.MFD_CLOEXEC"]) | int(required["os.MFD_ALLOW_SEALING"])
    mask = (
        int(required["fcntl.F_SEAL_SEAL"])
        | int(required["fcntl.F_SEAL_SHRINK"])
        | int(required["fcntl.F_SEAL_GROW"])
        | int(required["fcntl.F_SEAL_WRITE"])
    )
    return flags, int(required["fcntl.F_ADD_SEALS"]), int(required["fcntl.F_GET_SEALS"]), mask


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("descriptor write made no progress")
        remaining = remaining[written:]


def _read_exact_fd(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1_048_576, size - offset), offset)
        if not chunk:
            raise RuntimeError("executable changed while being pinned")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise RuntimeError("executable grew while being pinned")
    return b"".join(chunks)


@contextlib.contextmanager
def pinned_rpc_executable() -> Iterator[int]:
    raw_path = os.environ.get("TRNM_FAUCET_RPC_BIN")
    expected_digest = os.environ.get("TRNM_FAUCET_RPC_SHA256")
    if not raw_path:
        raise RuntimeError("TRNM_FAUCET_RPC_BIN is required")
    if expected_digest is None or SHA256.fullmatch(expected_digest) is None:
        raise RuntimeError("TRNM_FAUCET_RPC_SHA256 must be a lowercase SHA-256 digest")
    candidate = pathlib.Path(raw_path)
    if not candidate.is_absolute():
        raise RuntimeError("TRNM_FAUCET_RPC_BIN must be absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int):
        raise RuntimeError("O_NOFOLLOW support is required")
    source = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    sealed = -1
    try:
        metadata = os.fstat(source)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("faucet RPC executable must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_EXECUTABLE_BYTES:
            raise RuntimeError("faucet RPC executable size is outside the accepted bound")
        if metadata.st_mode & 0o111 == 0:
            raise RuntimeError("faucet RPC executable lacks an execute bit")
        if metadata.st_mode & 0o022:
            raise RuntimeError("faucet RPC executable must not be group/world writable")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise RuntimeError("faucet RPC executable has an unexpected owner")
        payload = _read_exact_fd(source, metadata.st_size)
        observed_digest = hashlib.sha256(payload).hexdigest()
        if observed_digest != expected_digest:
            raise RuntimeError("faucet RPC executable digest mismatch")
        flags, add_seals, get_seals, seal_mask = _required_sealing()
        sealed = os.memfd_create("trnm-faucet-rpc-v1", flags)
        _write_all(sealed, payload)
        os.fchmod(sealed, 0o500)
        os.lseek(sealed, 0, os.SEEK_SET)
        fcntl.fcntl(sealed, add_seals, seal_mask)
        observed_seals = fcntl.fcntl(sealed, get_seals)
        if observed_seals != seal_mask:
            raise RuntimeError("faucet RPC executable memfd is not exactly sealed")
        yield sealed
    finally:
        if sealed >= 0:
            os.close(sealed)
        os.close(source)


def faucet_command(executable_descriptor: int, address: str, amount: str) -> tuple[str, ...]:
    return (
        f"/proc/self/fd/{executable_descriptor}",
        "faucet-request",
        f"--address={address}",
        f"--amount={amount}",
    )


def command_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    names = os.environ.get("TRNM_FAUCET_PASSTHROUGH_ENV", "")
    for name in filter(None, (item.strip() for item in names.split(","))):
        if ENVIRONMENT_NAME.fullmatch(name) is None:
            raise RuntimeError("invalid TRNM_FAUCET_PASSTHROUGH_ENV member")
        if name not in os.environ:
            raise RuntimeError(f"requested environment member is unavailable: {name}")
        environment[name] = os.environ[name]
    if extra is not None:
        for name, value in extra.items():
            if ENVIRONMENT_NAME.fullmatch(name) is None or not isinstance(value, str):
                raise RuntimeError("invalid explicit command environment")
            environment[name] = value
    return environment


def _ensure_child_subreaper() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Linux child-subreaper support is required")
    library = ctypes.CDLL(None, use_errno=True)
    prctl = library.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _reap_process_group(group: int, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        reaped = False
        while True:
            try:
                child, _status = os.waitpid(-group, os.WNOHANG)
            except ChildProcessError:
                break
            if child == 0:
                break
            reaped = True
        if not _process_group_exists(group):
            return
        if time.monotonic() >= deadline:
            raise FaucetCommandLifecycleError("faucet subprocess group did not terminate")
        if not reaped:
            time.sleep(0.02)


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=3)
    except subprocess.TimeoutExpired as error:
        raise FaucetCommandLifecycleError("direct faucet subprocess could not be reaped") from error
    _reap_process_group(process.pid)


def _execute_pinned_process(
    executable_descriptor: int,
    arguments: tuple[str, ...],
    timeout: int,
    *,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    executable = f"/proc/self/fd/{executable_descriptor}"
    if not arguments or arguments[0] != executable:
        raise ValueError("pinned process argv[0] must be the exact executable descriptor")
    _ensure_child_subreaper()
    process = subprocess.Popen(
        arguments,
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        pass_fds=(executable_descriptor,),
        start_new_session=True,
        env=command_environment(environment),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _kill_and_reap(process)
        raise FaucetCommandTimeout(
            "faucet command timed out and its process group was killed"
        ) from error
    if _process_group_exists(process.pid):
        _kill_and_reap(process)
        raise FaucetCommandLifecycleError("faucet command left descendant processes")
    _reap_process_group(process.pid, timeout=0.2)
    if len(stdout) > MAXIMUM_COMMAND_OUTPUT_BYTES or len(stderr) > MAXIMUM_COMMAND_OUTPUT_BYTES:
        raise FaucetCommandLifecycleError("faucet command output exceeded its bound")
    return subprocess.CompletedProcess(
        args=arguments,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def execute_faucet_process(
    executable_descriptor: int,
    address: str,
    amount: str,
    timeout: int,
    *,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return _execute_pinned_process(
        executable_descriptor,
        faucet_command(executable_descriptor, address, amount),
        timeout,
        environment=environment,
    )


class FaucetLedger:
    def __init__(self, path: pathlib.Path) -> None:
        if not path.is_absolute():
            raise RuntimeError("TRNM_FAUCET_LEDGER_DIR must be absolute")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if not isinstance(nofollow, int) or not isinstance(directory, int):
            raise RuntimeError("secure directory descriptor support is required")
        self._descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | nofollow | directory,
        )
        metadata = os.fstat(self._descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            self.close()
            raise RuntimeError("faucet ledger is not a directory")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            self.close()
            raise RuntimeError("faucet ledger must be owned by the service uid with mode 0700")

    @classmethod
    def from_environment(cls) -> FaucetLedger:
        raw = os.environ.get("TRNM_FAUCET_LEDGER_DIR")
        if not raw:
            raise RuntimeError("TRNM_FAUCET_LEDGER_DIR is required")
        return cls(pathlib.Path(raw))

    def __enter__(self) -> FaucetLedger:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._descriptor = -1

    @staticmethod
    def _name(request_id: str) -> str:
        return f"{request_id}.json"

    @staticmethod
    def _encode(record: dict[str, Any]) -> bytes:
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

    def _write_new(self, name: str, payload: bytes) -> None:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._descriptor,
        )
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self._descriptor)

    def _read(self, name: str) -> dict[str, Any]:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self._descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size <= 0
                or metadata.st_size > MAXIMUM_LEDGER_RECORD_BYTES
            ):
                raise RuntimeError("faucet ledger record metadata is invalid")
            payload = _read_exact_fd(descriptor, metadata.st_size)
        finally:
            os.close(descriptor)
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("faucet ledger record is invalid JSON") from error
        if not isinstance(value, dict):
            raise RuntimeError("faucet ledger record must be an object")
        return value

    @staticmethod
    def _validate_record(record: dict[str, Any], request_id: str, fingerprint: str) -> None:
        expected_keys = {"schema", "request_id", "fingerprint", "state", "response"}
        if set(record) != expected_keys or record.get("schema") != 1:
            raise RuntimeError("faucet ledger record schema drift")
        if record.get("request_id") != request_id:
            raise RuntimeError("faucet ledger request identity drift")
        if record.get("fingerprint") != fingerprint:
            raise IdempotencyConflict("request_id is already bound to a different request")
        if record.get("state") not in {"started", "succeeded", "uncertain"}:
            raise RuntimeError("faucet ledger state is invalid")
        response = record.get("response")
        if record["state"] == "succeeded" and not isinstance(response, dict):
            raise RuntimeError("successful faucet ledger record lacks a response")
        if record["state"] != "succeeded" and response is not None:
            raise RuntimeError("non-success faucet ledger record carries a response")

    def admit(self, request_id: str, fingerprint: str) -> LedgerAdmission:
        name = self._name(request_id)
        record = {
            "schema": 1,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "state": "started",
            "response": None,
        }
        try:
            self._write_new(name, self._encode(record))
            return LedgerAdmission(True, "started", None)
        except FileExistsError:
            existing = self._read(name)
            self._validate_record(existing, request_id, fingerprint)
            return LedgerAdmission(False, existing["state"], existing["response"])

    def finish(
        self,
        request_id: str,
        fingerprint: str,
        state: str,
        response: dict[str, Any] | None,
    ) -> None:
        if state not in {"succeeded", "uncertain"}:
            raise ValueError("invalid terminal faucet ledger state")
        current = self._read(self._name(request_id))
        self._validate_record(current, request_id, fingerprint)
        if current["state"] != "started":
            raise RuntimeError("faucet ledger transition is not started-to-terminal")
        record = {
            "schema": 1,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "state": state,
            "response": response if state == "succeeded" else None,
        }
        temporary = f".{request_id}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        payload = self._encode(record)
        self._write_new(temporary, payload)
        try:
            os.replace(
                temporary,
                self._name(request_id),
                src_dir_fd=self._descriptor,
                dst_dir_fd=self._descriptor,
            )
            os.fsync(self._descriptor)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=self._descriptor)
            except FileNotFoundError:
                pass
            raise


class Handler(BaseHTTPRequestHandler):
    server_version = "trnm-faucet/2"

    def _json(self, code: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_request(self) -> tuple[str, str, str]:
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
        if not isinstance(data, dict) or not set(data) <= {"address", "amount", "request_id"}:
            raise RequestValidationError("INVALID_REQUEST", "closed request object required")
        address = canonical_address(data.get("address"))
        amount = canonical_amount(data.get("amount", DEFAULT_AMOUNT))
        request_id = canonical_request_id(data.get("request_id"))
        return request_id, address, amount

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"ok": True, "service": "trnm-faucet", "version": 2})
            return
        self._json(404, {"ok": False, "code": "NOT_FOUND"})

    def do_POST(self) -> None:
        if self.path != "/faucet/request":
            self._json(404, {"ok": False, "code": "NOT_FOUND"})
            return
        ledger: FaucetLedger | None = None
        request_id: str | None = None
        fingerprint: str | None = None
        admitted = False
        try:
            request_id, address, amount = self._read_request()
            fingerprint = request_fingerprint(request_id, address, amount)
            ledger = FaucetLedger.from_environment()
            admission = ledger.admit(request_id, fingerprint)
            if not admission.is_new:
                if admission.state == "succeeded" and admission.response is not None:
                    self._json(200, admission.response)
                else:
                    self._json(
                        409,
                        {
                            "ok": False,
                            "code": "REQUEST_UNCERTAIN",
                            "message": "request was already admitted and will not be re-executed",
                        },
                    )
                return
            admitted = True
            with pinned_rpc_executable() as executable:
                completed = execute_faucet_process(
                    executable,
                    address,
                    amount,
                    command_timeout_seconds(),
                )
            if completed.returncode != 0:
                ledger.finish(request_id, fingerprint, "uncertain", None)
                admitted = False
                self._json(
                    400,
                    {
                        "ok": False,
                        "code": "FAUCET_REQUEST_FAILED",
                        "message": "faucet request was rejected or is uncertain",
                    },
                )
                return
            try:
                body = json.loads(completed.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise FaucetCommandLifecycleError("faucet command returned invalid JSON") from error
            if not isinstance(body, dict):
                raise FaucetCommandLifecycleError("faucet command returned a non-object response")
            ledger.finish(request_id, fingerprint, "succeeded", body)
            admitted = False
            self._json(200, body)
        except RequestValidationError as error:
            self._json(400, {"ok": False, "code": error.code, "message": error.public_message})
        except IdempotencyConflict:
            self._json(
                409,
                {
                    "ok": False,
                    "code": "REQUEST_ID_CONFLICT",
                    "message": "request_id is already bound to another request",
                },
            )
        except FaucetCommandTimeout:
            if admitted and ledger is not None and request_id is not None and fingerprint is not None:
                ledger.finish(request_id, fingerprint, "uncertain", None)
                admitted = False
            self._json(
                504,
                {
                    "ok": False,
                    "code": "FAUCET_TIMEOUT",
                    "message": "faucet command timed out; retry with this request_id is disabled",
                },
            )
        except Exception as error:
            if admitted and ledger is not None and request_id is not None and fingerprint is not None:
                try:
                    ledger.finish(request_id, fingerprint, "uncertain", None)
                    admitted = False
                except Exception:
                    pass
            self.log_error("faucet request failed: %s", type(error).__name__)
            self._json(
                500,
                {"ok": False, "code": "INTERNAL", "message": "internal faucet error"},
            )
        finally:
            if ledger is not None:
                ledger.close()


if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()
