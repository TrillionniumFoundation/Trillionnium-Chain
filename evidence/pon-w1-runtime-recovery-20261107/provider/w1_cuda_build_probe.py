#!/usr/bin/env python3
"""Build-only, task-isolated CUDA r0vm 3.0.3 probe; never generate a W1 proof."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import traceback
import urllib.request

REQUEST_ID = "trnm-w1-7d418660-cuda-build-01"
SDK_REPO = "https://github.com/risc0/risc0.git"
SDK_COMMIT = "14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6"
SDK_TREE = "0358dc34fc9527379810fa2ba16d3f42de3c33eb"
SDK_LOCK = "15995a3395e61847c403182721c13c56f8735c8d22ed989dc350c5621d812024"
LFS_ZKR = "risc0/circuit/recursion/src/recursion_zkr.zip"
RUST_VERSION = "1.95.0"
WALL_SECONDS = 3600
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024
FIRST_SIGNAL = None


def signal_seen(signum, _frame):
    global FIRST_SIGNAL
    if FIRST_SIGNAL is None:
        FIRST_SIGNAL = {"signal": int(signum), "monotonic_ns": time.monotonic_ns()}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path, limit=MAX_BINARY):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "not a bounded ordinary file: " + str(path))
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed while hashing")
    return h.hexdigest()


def write_new(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def resource_snapshot():
    result = {"affinity": sorted(os.sched_getaffinity(0)), "scope_complete": False}
    for name in ("/proc/self/cgroup", "/proc/sys/kernel/random/boot_id", "/sys/fs/cgroup/cpu.max",
                 "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/cpu.stat"):
        try:
            result[name] = Path(name).read_text()[:16384]
        except OSError as error:
            result[name] = {"unavailable": type(error).__name__ + ": " + str(error)}
    return result


class Commands:
    def __init__(self, logs, deadline, env):
        self.logs, self.deadline, self.env, self.rows = logs, deadline, env, []

    def check(self):
        require(FIRST_SIGNAL is None, "cancellation observed")
        require(time.monotonic() < self.deadline, "build-only wall deadline exhausted")

    def run(self, label, argv, cwd, allow_failure=False):
        self.check()
        argv = [str(arg) for arg in argv]
        require(re.fullmatch(r"[a-z0-9-]+", label) is not None, "invalid command label")
        write_new(self.logs / (label + ".command.json"), {"argv": argv, "cwd": str(cwd)})
        start = time.monotonic_ns()
        row = {"label": label, "argv": argv, "started_monotonic_ns": start, "returncode": None,
               "timed_out": False, "cancellation": None, "cleanup_group_empty": None}
        self.rows.append(row)
        print(json.dumps({"starting": label}), flush=True)
        with (self.logs / (label + ".stdout")).open("xb") as stdout, (self.logs / (label + ".stderr")).open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            row["pid"] = process.pid
            try:
                while process.poll() is None:
                    if FIRST_SIGNAL is not None or time.monotonic() >= self.deadline:
                        row["timed_out"] = time.monotonic() >= self.deadline
                        row["cancellation"] = FIRST_SIGNAL
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait(timeout=5)
                        break
                    time.sleep(0.1)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                row["returncode"] = process.returncode
                try:
                    os.killpg(process.pid, 0)
                    row["cleanup_group_empty"] = False
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    row["cleanup_group_empty"] = True
                row["finished_monotonic_ns"] = time.monotonic_ns()
                stdout.flush(); stderr.flush()
                os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        for kind in ("stdout", "stderr"):
            p = self.logs / (label + "." + kind)
            row[kind] = {"path": p.name, "bytes": p.stat().st_size, "sha256": sha(p)}
        write_new(self.logs / (label + ".result.json"), row)
        self.check()
        require(row["cleanup_group_empty"] is True, "subprocess group remained after " + label)
        require(allow_failure or row["returncode"] == 0, label + " failed: exit " + str(row["returncode"]))
        return row, (self.logs / (label + ".stdout")).read_text(errors="replace")


def download(url, path, expected, limit, commands):
    commands.check()
    allowed = ("https://static.rust-lang.org/", "https://media.githubusercontent.com/media/risc0/risc0/" + SDK_COMMIT + "/")
    require(url.startswith(allowed), "download host outside this probe")
    h = hashlib.sha256(); count = 0
    with urllib.request.urlopen(url, timeout=30) as response, path.open("xb") as stream:
        require(response.geturl().startswith(allowed), "unexpected download redirect")
        while True:
            commands.check()
            block = response.read(1024 * 1024)
            if not block:
                break
            count += len(block); require(count <= limit, "download exceeds bound")
            h.update(block); stream.write(block)
        stream.flush(); os.fsync(stream.fileno())
    digest = h.hexdigest()
    require(expected is None or digest == expected, "official download digest differs")
    write_new(commands.logs / (path.name + ".download.json"), {"url": url, "bytes": count, "sha256": digest,
                                                              "expected_sha256": expected})
    return digest


def install_rust(task, commands):
    url = "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    checksum = task / "rustup-init.sha256"
    download(url + ".sha256", checksum, None, 4096, commands)
    expected = checksum.read_text().split()[0]
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid official installer checksum")
    installer = task / "rustup-init"
    download(url, installer, expected, 32 * 1024 * 1024, commands)
    installer.chmod(0o700)
    commands.run("install-rust-195", [installer, "-y", "--no-modify-path", "--profile", "minimal",
                                      "--default-toolchain", RUST_VERSION], task)
    toolchain = task / "rustup/toolchains" / (RUST_VERSION + "-x86_64-unknown-linux-gnu/bin")
    rustc, cargo = toolchain / "rustc", toolchain / "cargo"
    require(rustc.is_file() and cargo.is_file(), "requested task-private toolchain missing")
    commands.env["RUSTC"] = str(rustc)
    commands.env["RUSTDOC"] = str(toolchain / "rustdoc")
    commands.env["PATH"] = str(toolchain) + ":" + commands.env["PATH"]
    _, version = commands.run("rustc-version", [rustc, "--version", "--verbose"], task)
    require(version.startswith("rustc 1.95.0 "), "unexpected Rust version")
    commands.run("cargo-version", [cargo, "--version", "--verbose"], task)
    return cargo


def materialize_zkr(repo, task, commands):
    _, pointer = commands.run("lfs-zkr-pointer", ["git", "show", "HEAD:" + LFS_ZKR], repo)
    match = re.fullmatch(r"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n", pointer)
    require(match is not None, "unexpected fixed recursion program LFS pointer")
    digest, size = match.group(1), int(match.group(2))
    require(0 < size <= MAX_ARCHIVE, "recursion program LFS size exceeds bound")
    destination = repo / LFS_ZKR
    if destination.stat().st_size == size and sha(destination) == digest:
        method = "existing checkout with verified LFS object"
    else:
        require(destination.read_bytes() == pointer.encode(), "unexpected unqualified recursion program bytes")
        fetched = task / "recursion_zkr.zip.download"
        download("https://media.githubusercontent.com/media/risc0/risc0/" + SDK_COMMIT + "/" + LFS_ZKR,
                 fetched, digest, size, commands)
        require(fetched.stat().st_size == size, "LFS size differs")
        os.replace(fetched, destination)
        method = "fixed Git LFS pointer and independently checked object bytes"
    require(destination.read_bytes()[:4] == b"PK\x03\x04", "recursion program is not the actual ZIP object")
    value = {"path": LFS_ZKR, "sha256": digest, "bytes": size, "method": method}
    write_new(commands.logs / "lfs-zkr-materialization.json", value)
    return value


def check_sdk_source(repo, commands, label, lfs):
    # git-lfs may be absent in the image. The one excluded worktree blob is
    # checked against its exact pinned Git-LFS oid/size, never accepted by name.
    commands.run(label + "-tracked", ["git", "diff", "--exit-code", "HEAD", "--", ".", ":(exclude)" + LFS_ZKR], repo)
    _, untracked = commands.run(label + "-untracked", ["git", "ls-files", "--others", "--exclude-standard"], repo)
    require(not untracked.strip(), "unexpected files in fixed SDK source")
    require(sha(repo / "Cargo.lock") == SDK_LOCK, "fixed SDK lock changed")
    require((repo / LFS_ZKR).stat().st_size == lfs["bytes"] and sha(repo / LFS_ZKR) == lfs["sha256"],
            "fixed LFS recursion program changed")


def archive_logs(source, destination):
    index = []
    with destination.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(source.rglob("*")):
                    if path.is_dir() and not path.is_symlink():
                        continue
                    before = path.lstat()
                    require(stat.S_ISREG(before.st_mode), "nonordinary raw observation")
                    digest = sha(path, 64 * 1024 * 1024)
                    info = tarfile.TarInfo("raw/" + path.relative_to(source).as_posix())
                    info.size, info.mode, info.mtime = before.st_size, 0o444, 0
                    info.uid = info.gid = 0; info.uname = info.gname = ""
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                    require(sha(path, 64 * 1024 * 1024) == digest, "raw observation changed during archiving")
                    index.append({"path": info.name, "bytes": before.st_size, "sha256": digest})
        output.flush(); os.fsync(output.fileno())
    require(destination.stat().st_size <= MAX_ARCHIVE, "compressed raw archive exceeds bound")
    return index


CUDA_SMOKE = r'''
#include <cuda_runtime.h>
#include <cstdio>
__global__ void one_value(int *p) { if (blockIdx.x == 0 && threadIdx.x == 0) *p = 731; }
int main() {
  int count=0, driver=0, runtime=0; cudaDeviceProp p{};
  if(cudaGetDeviceCount(&count)!=cudaSuccess || count<1) return 10;
  if(cudaSetDevice(0)!=cudaSuccess || cudaGetDeviceProperties(&p,0)!=cudaSuccess) return 11;
  if(p.major!=7 || p.minor!=5) return 12;
  if(cudaDriverGetVersion(&driver)!=cudaSuccess || cudaRuntimeGetVersion(&runtime)!=cudaSuccess) return 13;
  int *device=nullptr, value=0;
  if(cudaMalloc(&device,sizeof(int))!=cudaSuccess) return 14;
  one_value<<<1,1>>>(device);
  if(cudaGetLastError()!=cudaSuccess || cudaDeviceSynchronize()!=cudaSuccess) return 15;
  if(cudaMemcpy(&value,device,sizeof(int),cudaMemcpyDeviceToHost)!=cudaSuccess) return 16;
  if(cudaFree(device)!=cudaSuccess || value!=731) return 17;
  std::printf("{\"device_count\":%d,\"device_name\":\"%s\",\"major\":%d,\"minor\":%d,\"driver_version\":%d,\"runtime_version\":%d,\"kernel_value\":%d}\n",count,p.name,p.major,p.minor,driver,runtime,value);
  return 0;
}
'''


def main():
    started = time.monotonic_ns()
    deadline = time.monotonic() + WALL_SECONDS
    task = Path(tempfile.mkdtemp(prefix="trnm-w1-cuda-build-", dir="/tmp"))
    logs = task / "raw"; logs.mkdir()
    working = Path("/kaggle/working"); working.mkdir(parents=True, exist_ok=True)
    for name in ("w1-cuda-build.json", "r0vm-3.0.3-cuda.gz", "w1-cuda-build-raw.tar.gz", "w1-cuda-build-manifest.json"):
        require(not os.path.lexists(working / name), "refusing output overwrite: " + name)
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    for sig in saved:
        signal.signal(sig, signal_seen)
    env = os.environ.copy()
    forbidden = [key for key in env if key in ("RISC0_SKIP_BUILD", "RISC0_SKIP_BUILD_KERNELS", "RISC0_DEV_MODE",
                                               "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                                               "CARGO_ENCODED_RUSTFLAGS", "NVCC_PREPEND_FLAGS", "NVCC_APPEND_FLAGS")]
    env.update({"RUSTUP_HOME": str(task / "rustup"), "CARGO_HOME": str(task / "cargo"),
                "RISC0_HOME": str(task / "risc0"), "RUSTUP_TOOLCHAIN": RUST_VERSION,
                "XDG_CACHE_HOME": str(task / "cache"), "RISC0_CUDART_LINKAGE": "static",
                "CARGO_TARGET_DIR": str(task / "target"), "CARGO_BUILD_JOBS": "4",
                "CARGO_INCREMENTAL": "0", "RAYON_NUM_THREADS": "4", "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_LFS_SKIP_SMUDGE": "1", "NVCC_APPEND_FLAGS": "-arch=sm_75"})
    commands = Commands(logs, deadline, env)
    report = {"schema": "TRNM-W1-R0VM-CUDA-BUILD1", "request_id": REQUEST_ID, "outcome": "failed",
              "sdk_repo": SDK_REPO, "sdk_tag": "v3.0.3", "sdk_commit": SDK_COMMIT, "sdk_tree": SDK_TREE,
              "sdk_lock_sha256": SDK_LOCK, "rust_version_requested": RUST_VERSION,
              "features_requested": ["cuda", "disable-dev-mode"], "cuda_arch_requested": "sm_75",
              "worker_wall_seconds": WALL_SECONDS, "started_monotonic_ns": started,
              "full_w1_proof_started": False, "full_w1_proofs_generated": 0,
              "guest_compilation_performed": False, "r0vm_cuda_proof_execution_observed": False,
              "resource_completeness_established": False, "gpu_ns": None,
              "resource_before": resource_snapshot(), "commands": commands.rows, "error": None,
              "binary": None, "features_resolved": None, "result_is_pre_handoff_snapshot": True}
    try:
        require(not forbidden, "unexpected build/proof override keys: " + ",".join(forbidden))
        require(len(os.sched_getaffinity(0)) <= 4, "provider exceeds this four-CPU affinity declaration")
        nvcc = shutil.which("nvcc")
        if nvcc is None and Path("/usr/local/cuda/bin/nvcc").is_file():
            nvcc = "/usr/local/cuda/bin/nvcc"
            commands.env["PATH"] = "/usr/local/cuda/bin:" + commands.env["PATH"]
        require(nvcc is not None, "CUDA compiler nvcc is unavailable; GPU presence alone is insufficient")
        report["nvcc_path"] = str(Path(nvcc).resolve())
        report["nvcc_sha256"] = sha(Path(nvcc).resolve())
        _, version = commands.run("nvcc-version", [nvcc, "--version"], task)
        report["nvcc_version_output"] = version
        smi = shutil.which("nvidia-smi")
        require(smi is not None, "nvidia-smi unavailable for device/compiler provenance")
        commands.run("gpu-inventory", [smi, "--query-gpu=index,uuid,name,driver_version,memory.total", "--format=csv,noheader"], task)
        smoke = task / "compiler-device-smoke.cu"; write_new(smoke, CUDA_SMOKE.encode())
        write_new(logs / "compiler-device-smoke.cu", CUDA_SMOKE.encode())
        commands.run("cuda-smoke-build", [nvcc, "-std=c++17", "-arch=sm_75", smoke, "-o", task / "cuda-smoke"], task)
        _, smoke_output = commands.run("cuda-smoke-run", [task / "cuda-smoke"], task)
        report["compiler_device_smoke"] = json.loads(smoke_output)
        cargo = install_rust(task, commands)
        repo = task / "sdk"; repo.mkdir()
        commands.run("git-init", ["git", "init", "--quiet"], repo)
        commands.run("git-origin", ["git", "remote", "add", "origin", SDK_REPO], repo)
        commands.run("git-fetch-fixed", ["git", "-c", "protocol.version=2", "fetch", "--depth=1", "--no-tags", "origin", SDK_COMMIT], repo)
        commands.run("git-checkout-fixed", ["git", "checkout", "--detach", SDK_COMMIT], repo)
        _, commit = commands.run("git-head", ["git", "rev-parse", "HEAD"], repo)
        _, tree = commands.run("git-tree", ["git", "rev-parse", "HEAD^{tree}"], repo)
        require(commit.strip() == SDK_COMMIT and tree.strip() == SDK_TREE, "fixed SDK source identity differs")
        require(sha(repo / "Cargo.lock") == SDK_LOCK, "fixed SDK Cargo.lock differs before build")
        report["lfs_recursion_program"] = materialize_zkr(repo, task, commands)
        check_sdk_source(repo, commands, "source-before", report["lfs_recursion_program"])
        write_new(logs / "Cargo.lock.before", (repo / "Cargo.lock").read_bytes())
        for relative in ("risc0/r0vm/Cargo.toml", "risc0/zkvm/Cargo.toml", "risc0/sys/build.rs",
                         "risc0/circuit/rv32im-sys/build.rs", "risc0/circuit/recursion-sys/build.rs"):
            write_new(logs / (relative.replace("/", "_") + ".source"), (repo / relative).read_bytes())
        # No kernel-skip flags, synthetic libraries, altered SDK sources or guest rebuilds.
        metadata_args = [cargo, "metadata", "--manifest-path", repo / "risc0/r0vm/Cargo.toml",
                         "--features", "cuda,disable-dev-mode", "--locked", "--format-version", "1"]
        commands.run("cargo-metadata-cuda", metadata_args, repo / "risc0/r0vm")
        metadata = json.loads((logs / "cargo-metadata-cuda.stdout").read_text())
        names = {package["id"]: package["name"] for package in metadata["packages"]}
        required = {"risc0-r0vm": {"cuda", "disable-dev-mode"}, "risc0-zkvm": {"cuda", "disable-dev-mode"},
                    "risc0-circuit-rv32im": {"cuda"}, "risc0-circuit-recursion": {"cuda"}, "risc0-zkp": {"cuda"}}
        resolved = {}
        for row in metadata["resolve"]["nodes"]:
            name = names[row["id"]]
            if name in required:
                resolved.setdefault(name, []).append({"id": row["id"], "features": row["features"]})
        for name, features in required.items():
            require(len(resolved.get(name, [])) == 1 and features <= set(resolved[name][0]["features"]),
                    "actual dependency graph lacks required CUDA/dev-mode guard: " + name)
        report["features_resolved"] = resolved
        commands.run("build-cuda-r0vm", [cargo, "build", "--release", "--locked", "-p", "risc0-r0vm",
                                         "--bin", "r0vm", "--features", "cuda,disable-dev-mode"], repo)
        binary = task / "target/release/r0vm"
        digest = sha(binary)
        _, version = commands.run("r0vm-version", [binary, "--version"], repo)
        require(re.search(r"\b3\.0\.3\b", version) is not None, "built r0vm version differs")
        require(sha(repo / "Cargo.lock") == SDK_LOCK, "fixed SDK lock changed during build")
        check_sdk_source(repo, commands, "source-after", report["lfs_recursion_program"])
        compressed = working / "r0vm-3.0.3-cuda.gz"
        with binary.open("rb") as source, compressed.open("xb") as output:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as stream:
                shutil.copyfileobj(source, stream, 1024 * 1024)
            output.flush(); os.fsync(output.fileno())
        require(compressed.stat().st_size <= MAX_ARCHIVE, "compressed executable exceeds bound")
        report["binary"] = {"path": compressed.name, "compressed_bytes": compressed.stat().st_size,
                            "compressed_sha256": sha(compressed), "uncompressed_bytes": binary.stat().st_size,
                            "uncompressed_sha256": digest, "version_output": version,
                            "prover_profile": "cuda-v3.0.3-sm75-build-candidate", "promoted_to_chain_allowlist": False}
        commands.check()
        report["outcome"] = "built"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        report["outcome"] = "cancelled" if FIRST_SIGNAL else ("timed_out" if time.monotonic() >= deadline else "failed")
    finally:
        report["resource_after"] = resource_snapshot()
        report["cancellation"] = FIRST_SIGNAL
        report["observed_monotonic_ns"] = time.monotonic_ns()
        write_new(logs / "build-observation.json", report)
        archive = working / "w1-cuda-build-raw.tar.gz"
        report["raw_archive_members"] = archive_logs(logs, archive)
        report["raw_archive"] = {"path": archive.name, "bytes": archive.stat().st_size, "sha256": sha(archive)}
        report["deadline_exhausted_at_report"] = time.monotonic() >= deadline
        if report["deadline_exhausted_at_report"] or FIRST_SIGNAL:
            report["outcome"] = "cancelled" if FIRST_SIGNAL else "timed_out"
        result = working / "w1-cuda-build.json"; write_new(result, report)
        files = []
        for path in sorted(working / name for name in ("w1-cuda-build.json", "w1-cuda-build-raw.tar.gz", "r0vm-3.0.3-cuda.gz")):
            if path.is_file():
                files.append({"path": path.name, "bytes": path.stat().st_size, "sha256": sha(path)})
        write_new(working / "w1-cuda-build-manifest.json", {"schema": "hepta-artifact-manifest-v1", "request_id": REQUEST_ID, "files": files})
        for sig, handler in saved.items():
            signal.signal(sig, handler)
    return 0 if report["outcome"] == "built" and FIRST_SIGNAL is None and time.monotonic() < deadline else 1


if __name__ == "__main__":
    raise SystemExit(main())
