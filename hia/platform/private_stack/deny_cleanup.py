"""Test-only actual munmap denial against an unchanged sealed native fixture."""
from pathlib import Path
import os
import signal
import subprocess
import time

from hia.platform.build import sealed_executable, sha256, write_json

SOURCE = Path(__file__).with_suffix(".s")


def observe(executable: bytes, payload: bytes, output: Path):
    output.mkdir(mode=0o700)
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise ValueError("Missing or symlinked test launcher")
    source = SOURCE.read_bytes()
    (output / "launcher.s").write_bytes(source)
    commands = []
    for argv in (["as", "--64", "launcher.s", "-o", "launcher.o"],
                 ["ld", "-z", "noexecstack", "-o", "launcher.elf", "launcher.o"]):
        p = subprocess.run(argv, cwd=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        commands.append({"argv": argv, "exit_code": p.returncode,
            "stdout_sha256": sha256(p.stdout), "stderr_hex": p.stderr.hex()})
        if p.returncode:
            write_json(output / "build-failure.json", {"commands": commands})
            raise RuntimeError("Test-only cleanup-denial launcher could not be built")
    launcher = (output / "launcher.elf").read_bytes()
    launcher_fd = sealed_executable(launcher, "restrictive-cleanup-test-launcher")
    fixture_fd = None
    try:
        fixture_fd = sealed_executable(executable, "captured-response-fixture")
        argv = ["/proc/self/fd/" + str(launcher_fd), "/proc/self/fd/" + str(fixture_fd)]
        start = time.monotonic_ns()
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=output, env={"PATH": ""}, pass_fds=(launcher_fd, fixture_fd), start_new_session=True, umask=0o077)
    finally:
        os.close(launcher_fd)
        if fixture_fd is not None:
            os.close(fixture_fd)
    timed_out, cleanup = False, None
    try:
        stdout, stderr = p.communicate(payload, timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        begin = time.monotonic_ns()
        try:
            os.killpg(p.pid, signal.SIGKILL)
            outcome = "sent"
        except ProcessLookupError:
            outcome = "already_exited"
        stdout, stderr = p.communicate(timeout=3)
        cleanup = {"signal": "SIGKILL", "signal_outcome": outcome,
            "complete": p.returncode is not None, "elapsed_ns": time.monotonic_ns()-begin}
    row = {"argv": argv, "exit_code": p.returncode, "timed_out": timed_out,
        "elapsed_ns": time.monotonic_ns()-start, "cleanup": cleanup,
        "wall_limit_seconds": 30, "cleanup_limit_seconds": 3,
        "additional_restriction": "Linux seccomp: munmap returns EPERM",
        "launcher_source_sha256": sha256(source), "launcher_elf_sha256": sha256(launcher),
        "launcher_is_test_instrumentation": True, "captured_fixture_sha256": sha256(executable),
        "input_bytes": len(payload), "input_sha256": sha256(payload),
        "stdout_bytes": len(stdout), "stdout_sha256": sha256(stdout),
        "stderr_hex": stderr.hex(), "commands": commands}
    (output / "stdin.raw").write_bytes(payload)
    (output / "stdout.raw").write_bytes(stdout)
    (output / "stderr.raw").write_bytes(stderr)
    write_json(output / "receipt.json", row)
    if SOURCE.read_bytes() != source:
        raise ValueError("Test launcher source changed during execution")
    return stdout, row
