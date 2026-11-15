"""Explicit native backend for the offline PQ reference oracles.

The operator supplies an absolute executable, version and SHA-256. These pins
identify a trusted local program; they are not a sandbox or production signer.
The Rust implementation remains independent of this Python protocol oracle.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time

from pq_operation_budget import BudgetExpired, OperationBudget


class BackendError(ValueError):
    pass


@dataclass(frozen=True)
class Binding:
    executable: Path
    sha256: str
    version: str
    modules: Path


def binding(*, budget: OperationBudget | None = None) -> Binding:
    if budget is not None:
        budget.check()
    raw = os.environ.get("TRNM_PQ_OPENSSL", "")
    expected = os.environ.get("TRNM_PQ_OPENSSL_SHA256", "")
    version = os.environ.get("TRNM_PQ_OPENSSL_VERSION", "")
    if not raw or any(c in raw for c in "\r\n\x00") or not Path(raw).is_absolute():
        raise BackendError("PQ reference requires an explicit absolute OpenSSL executable")
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise BackendError("PQ reference requires an explicit OpenSSL SHA-256")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise BackendError("PQ reference requires an explicit OpenSSL version")
    if tuple(map(int, version.split("."))) < (3, 5, 0):
        raise BackendError("PQ reference requires OpenSSL 3.5 or newer")
    try:
        executable = Path(raw)
        if (executable.is_symlink() or executable.resolve(strict=True) != executable
                or not executable.is_file() or not os.access(executable, os.X_OK)):
            raise BackendError("PQ OpenSSL executable is not a canonical regular executable")
        prefix = Path(os.environ.get("OPENSSL_DIR", ""))
        if not prefix.is_absolute() or prefix.resolve(strict=True) / "bin" / "openssl" != executable:
            raise BackendError("PQ OpenSSL CLI and native library prefix differ")
        digest = hashlib.sha256()
        with executable.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                if budget is not None:
                    budget.check()
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise BackendError("PQ OpenSSL executable digest differs from its declaration")
        modules = prefix.resolve() / "lib" / "ossl-modules"
    except OSError as error:
        raise BackendError("PQ OpenSSL declared executable is unavailable") from error
    return Binding(executable, expected, version, modules)


def _failure(label: str, result: subprocess.CompletedProcess, *, public: bool) -> BackendError:
    stderr = result.stderr or b""
    message = (f"PQ OpenSSL {label} rejected: exit={result.returncode}, "
               f"stderr_bytes={len(stderr)}, stderr_sha256={hashlib.sha256(stderr).hexdigest()}")
    # Only a public-key conversion/verification may expose a bounded diagnostic.
    # Signing/key generation never emits captured stdout or private-input stderr.
    if public:
        prefix = stderr[:1024].decode("utf-8", errors="replace")
        prefix = "".join(c if c in "\n\t" or ord(c) >= 32 else "?" for c in prefix)
        message += "; public_diagnostic=" + repr(prefix)
    return BackendError(message)


def _bounded_child(command: list[str], *, input_data: bytes | None,
                   environment: dict[str, str], budget: OperationBudget,
                   timeout: float) -> subprocess.CompletedProcess:
    """One child, original absolute budget, cancellation and actual reaping.

    This process-control helper is exercised with non-cryptographic fault drivers.
    It is never a successful cryptographic substitute or an OpenSSL selector.
    """
    budget.check()
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=environment) as child:
        try:
            with budget.abort_on_cancel(child.kill):
                stdout, stderr = child.communicate(input=input_data,
                                                    timeout=budget.remaining(timeout))
                budget.check()
        except BaseException:
            if child.poll() is None:
                child.kill()
            child.communicate()
            raise
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)


def run(args: list[str], *, input_data: bytes | None = None,
        budget: OperationBudget | None = None) -> bytes:
    if (not args or args[0] not in ("genpkey", "pkey", "pkeyutl")
            or any(type(arg) is not str or "\x00" in arg for arg in args)):
        raise BackendError("PQ OpenSSL command shape")
    if any(arg.split("=", 1)[0] in ("-provider", "-provider-path", "-engine", "-config")
           for arg in args):
        raise BackendError("PQ OpenSSL caller cannot replace declared provider/configuration")
    operation = budget if budget is not None else OperationBudget(time.monotonic() + 15)
    try:
        declared = binding(budget=operation)
        environment = dict(os.environ, OPENSSL_CONF=os.devnull,
                           OPENSSL_MODULES=str(declared.modules))
        version = _bounded_child([str(declared.executable), "version"], input_data=None,
                                 environment=environment, budget=operation, timeout=5)
        if version.returncode:
            raise _failure("version", version, public=True)
        if (len(version.stdout) > 512
                or not version.stdout.startswith(("OpenSSL " + declared.version + " ").encode())):
            raise BackendError("PQ OpenSSL actual version differs from its declaration")
        command = [str(declared.executable), args[0], "-provider", "default", *args[1:]]
        child = _bounded_child(command, input_data=input_data, environment=environment,
                               budget=operation, timeout=15)
    except (OSError, subprocess.TimeoutExpired, BudgetExpired) as error:
        raise BackendError("PQ OpenSSL declared backend unavailable or timed out") from error
    if child.returncode:
        public = "-pubin" in args and (args[0] == "pkey"
                                       or args[0] == "pkeyutl" and "-verify" in args)
        raise _failure(args[0], child, public=public)
    if len(child.stdout) > 65536 or len(child.stderr) > 65536:
        raise BackendError("PQ OpenSSL result exceeds the reference output bound")
    return child.stdout
