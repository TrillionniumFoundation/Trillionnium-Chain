#!/usr/bin/env python3
"""Source-exact discovery server and announcement-lease differential controls.

Read one JSON object from stdin. Required: root, out, target, native_tmp,
provider_path, sha, tree, red_tests_path, candidate_auth_sha256,
candidate_tests_sha256, candidate_pq_sha256. Optional: rustup,
provider_receipt_path. All runtime paths are independently scoped under the
current user's existing work directory; red_tests_path is a tracked relative
path inside the fixed candidate. No fetch/install/retry or system change.

Four native commands: three server target-assertion reds on the exact #823
implementation plus committed regression fixtures; three candidate greens;
one candidate-minus-only-monotonic-clamp mutation red; one exact candidate
green. A compiler failure, a fixture failure, zero tests, ignored tests, extra
selected tests or the wrong panic never counts as a successful red control.
The three temporarily overridden source files are restored in finally. An
unexpected concurrent edit is saved and left intact, with a failed receipt.

Host/provider/Cargo-config checks are copied without semantic changes from
run_exact_gates_previous.py. This runner does not claim the nineteen full gates,
full-crate test coverage, actual clock rollback, or production activation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback

TOOLCHAIN = "1.95.0"


OPENSSL_VERSION = "3.5.9"


OPENSSL_ARCHIVE_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"


PROVIDER_EXPORTS = {
    "OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL",
    "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION",
    "OPENSSL_CONF", "OPENSSL_MODULES",
}


PROVIDER_INPUTS = (
    "bin/openssl", "include/openssl/opensslv.h",
    "include/openssl/configuration.h", "lib/libcrypto.a", "lib/libssl.a",
)


LOCAL_FILESYSTEMS = {"ext4", "xfs", "btrfs", "f2fs"}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def json_load(data: bytes) -> dict:
    result = json.loads(data, object_pairs_hook=unique_object)
    require(isinstance(result, dict), "expected a JSON object")
    return result


def file_identity(path: Path) -> dict:
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), "input is not a regular file: " + str(path))
    fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns)
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed before hashing: " + str(path))
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed during hashing: " + str(path))
    require(fingerprint(path.stat(follow_symlinks=False)) == fingerprint(before),
            "input path changed during hashing: " + str(path))
    return {"path": str(path), "bytes": before.st_size, "sha256": value.hexdigest()}


def read_json_file(path: Path) -> tuple[dict, dict]:
    require(path.stat().st_size <= 1024 * 1024, "JSON receipt exceeds 1 MiB")
    data = path.read_bytes()
    identity = file_identity(path)
    require(hashlib.sha256(data).hexdigest() == identity["sha256"], "JSON input changed")
    return json_load(data), identity


def scrub_environment(inherited: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Remove ambient profile, compiler, runner, Git and provider overrides.

    HOME is never changed. Cargo/Rustup homes remain inputs so installed tools
    and the already populated offline cache can be used; their configs are
    checked separately. Record only removed names, never credentials/values.
    """
    environment = inherited.copy()
    removed = []
    for key in list(environment):
        if ((key.startswith("CARGO_") and key != "CARGO_HOME")
                or (key.startswith("RUST") and key != "RUSTUP_HOME")
                or key.startswith("GIT_") or "OPENSSL" in key
                or key in {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
            removed.append(key)
            del environment[key]
    return environment, sorted(removed)


def cargo_config_inputs(root: Path, cargo_home: Path) -> list[dict]:
    """Hash only Cargo's discovery locations; reject execution/profile changes.

    Registry/cache configuration may remain. Never read credentials.toml or
    print configuration values. The current directory is the source root for
    every Cargo command, including those with an explicit --manifest-path.
    """
    directories = [cargo_home, *(parent / ".cargo" for parent in (root, *root.parents))]
    paths = sorted({directory / name for directory in directories for name in ("config", "config.toml")
                    if (directory / name).exists()}, key=str)
    identities = []
    for path in paths:
        raw = path.read_bytes()
        identity = file_identity(path)
        require(hashlib.sha256(raw).hexdigest() == identity["sha256"], "Cargo config changed during read")
        data = tomllib.loads(raw.decode("utf-8"))
        forbidden = []
        for key in ("profile", "unstable", "paths", "patch", "replace"):
            if data.get(key):
                forbidden.append(key)
        build = data.get("build", {})
        for key in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc", "rustflags",
                    "rustdocflags", "target"):
            if key in build:
                forbidden.append("build." + key)
        for target, settings in data.get("target", {}).items():
            if not isinstance(settings, dict):
                continue
            for key in ("runner", "linker", "rustflags", "rustdocflags"):
                if key in settings:
                    forbidden.append("target." + target + "." + key)
            for key, value in settings.items():
                if isinstance(value, dict):
                    forbidden.append("target." + target + "." + key + " (build-script override)")
        for key in data.get("env", {}):
            if (key.startswith(("CARGO_", "RUST", "GIT_")) or "OPENSSL" in key
                    or key in {"PATH", "TMPDIR", "TMP", "TEMP", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
                forbidden.append("env." + key)
        for key in ("metadata", "fmt", "test", "clippy"):
            if key in data.get("alias", {}):
                forbidden.append("alias." + key)
        require(not forbidden, "Cargo configuration changes native execution: " + str(path) + " keys=" + ",".join(forbidden))
        identities.append(identity)
    return identities


def save_summary(out: Path, manifest: dict) -> None:
    pending = out / "summary.json.pending"
    with pending.open("w") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, out / "summary.json")


def event(**values: object) -> None:
    print(json.dumps(values, sort_keys=True), flush=True)


BASELINE_SHA = "82750af38c9b900dff323522c53db86472005081"
AUTH_PATH = "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth.rs"
TESTS_PATH = "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth_tests.rs"
PQ_PATH = "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs"
BASELINE_HASHES = {
    AUTH_PATH: "1fac53a2a16ef8f6c5b2a8ed480ec5be8bebdec3a5c764585639e5a085659690",
    PQ_PATH: "9d7dbb4cd360a4e7100e1f385aac17620822786567f4ddc3766ca90fee39a5bb",
}
RED_TESTS_SHA256 = "288a2403fdcc8182f392fcc9e8f76b2b9de684fe69235e401199f22e34f564ce"
TEST_PREFIX = "cell::discovery::pq::auth::tests::"
SERVER_CASES = (
    TEST_PREFIX + "authenticated_v3_real_server_active_provider_precedes_eight_withdrawals",
    TEST_PREFIX + "authenticated_v3_real_server_expired_authority_preserves_verification_slots",
    TEST_PREFIX + "authenticated_v3_real_server_revoked_authority_preserves_verification_slots",
)
MONOTONIC_CASE = TEST_PREFIX + "authenticated_v3_announcement_original_monotonic_lease_cannot_be_renewed_by_wall_time"
CLAMP = "overall: overall.min(receipt.monotonic_expiry()),"



def parse_native(stdout: str, stderr: str, exit_code: int | None,
                 names: tuple[str, ...], mode: str) -> dict:
    """Validate actual harness execution and the precise intended red assertions."""
    require(mode in {"server-red", "mutation-red", "green"}, "unknown native phase mode")
    expected = set(names)
    require(len(expected) == len(names) and expected, "duplicate or empty native selection")
    running = re.findall(r"(?m)^running (\d+) tests?$", stdout)
    require(running == [str(len(names))], "wrong native harness/test selection")
    selected = re.findall(r"(?m)^test (\S+) \.\.\. (ok|FAILED|ignored)$", stdout)
    require(len(selected) == len(names) and {name for name, _ in selected} == expected,
            "native selected names differ, include duplicates, or did not finish")
    summaries = re.findall(
        r"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in .+$", stdout)
    require(len(summaries) == 1, "missing or extra native result summaries")
    label, *values = summaries[0]
    passed, failed, ignored, measured, filtered = map(int, values)
    require(ignored == 0 and measured == 0, "native tests were ignored or measured")
    require(filtered >= 17, "native selection omitted the retained auth cohort")
    panic_headers = list(re.finditer(
        r"(?m)^thread '([^']+)'(?: \([0-9]+\))? panicked at [^\n]*\n", stderr))
    panics = {}
    for index, header in enumerate(panic_headers):
        name = header.group(1)
        require(name not in panics, "multiple native panics for one case")
        end = panic_headers[index + 1].start() if index + 1 < len(panic_headers) else len(stderr)
        panics[name] = stderr[header.end():end]
    receipt = {"mode": mode, "selected_tests": [name for name, _ in selected],
               "passed": passed, "failed": failed, "ignored": ignored,
               "measured": measured, "filtered_out": filtered,
               "target_assertions": []}
    if mode == "green":
        require(exit_code == 0 and label == "ok" and passed == len(names) and failed == 0
                and all(status == "ok" for _, status in selected) and not panics,
                "candidate selected native tests did not all pass")
        return receipt
    require(exit_code == 101 and label == "FAILED" and passed == 0 and failed == len(names)
            and all(status == "FAILED" for _, status in selected) and set(panics) == expected,
            "red native result is not the exact expected failing test set")
    if mode == "server-red":
        require(names == SERVER_CASES, "server red has an unexpected selection")
        active = (
            "real rendezvous omitted the active provider behind eight valid withdrawals: "
            'Err(Invalid("authenticated discovery has no admissible provider"))'
        )
        require(active in panics[names[0]],
                "active-first red missed its target assertion; fixture/setup failure is not a red")
        receipt["target_assertions"].append({"test": names[0], "marker": active})
        authority = "inactive authority consumed server verification slots before the live provider"
        for name in names[1:]:
            body = panics[name]
            require(authority in body and re.search(r"(?m)^\s*left: 6\s*$", body)
                    and re.search(r"(?m)^\s*right: 4\s*$", body),
                    "authority red missed its exact 6-versus-4 target; fixture failure is not a red")
            receipt["target_assertions"].append({"test": name, "marker": authority,
                                                 "actual_verifications": 6, "expected_verifications": 4})
        require("authenticated-v3 inactive authority: revoked=false" in stderr
                and "authenticated-v3 inactive authority: revoked=true" in stderr,
                "authority red did not observe both intended authority states")
    else:
        require(names == (MONOTONIC_CASE,), "mutation red has an unexpected selection")
        marker = "an elapsed original monotonic lease was renewed by the current wall clock"
        require(marker in panics[MONOTONIC_CASE],
                "monotonic red missed its target assertion; expired wall fixture is not a red")
        observations = [line for line in stderr.splitlines()
                        if line.startswith("authenticated-v3 original monotonic announcement lease: result=")]
        require(len(observations) == 1 and "result=Ok(CellDiscoveryObservationV3 {" in observations[0],
                "mutation red lacks a successful actual signed TCP ACK observation")
        for field in ("connection_attempts", "record_validation_attempts",
                      "bootstrap_validation_attempts", "announcement_signature_attempts"):
            require(re.search(r"\b" + field + r": 1(?:,| })", observations[0]) is not None,
                    "mutation ACK observation lacks exactly one " + field)
        require("fixture wall lease expired before the monotonic-only refusal could be assessed"
                not in panics[MONOTONIC_CASE], "monotonic fixture premise failed")
        receipt["target_assertions"].append({"test": MONOTONIC_CASE, "marker": marker,
                                             "actual_ack_observation": observations[0],
                                             "clock_model": "private paired-time seam; host clock unchanged"})
    return receipt


class DifferentialRunner:
    def __init__(self, cfg: dict, raw_config: bytes):
        self.cfg = cfg
        self.manifest = {
            "schema": "cell-auth-convergence-differential-v1",
            "scope": "Linux x86_64; four filtered native commands only; original verification/socket/deadline limits; no production qualification",
            "started_unix": time.time(), "passed": False, "state": "initializing",
            "configuration_sha256": hashlib.sha256(raw_config).hexdigest(),
            "commands": [], "setup_checks": [], "errors": [],
        }
        self.out = Path(cfg["out"])
        require(self.out.is_absolute(), "out must be absolute")
        self.user_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.work = (self.user_home / "work").resolve(strict=True)
        require(self.work.stat().st_uid == os.getuid(), "work directory is not user-owned")
        self.out = self.out.resolve()
        require(self.out.is_relative_to(self.work) and self.out != self.work,
                "out must be a task directory under the user's work directory")
        source = Path(cfg["root"]).resolve(strict=True)
        require(not self.out.is_relative_to(source) and not source.is_relative_to(self.out),
                "out overlaps the source checkout")
        self.out.mkdir(parents=True, exist_ok=False)
        save_summary(self.out, self.manifest)
        self.env = os.environ.copy()
        self.root = self.work
        self.provider_before = None
        self.sources_ready = False
        self.candidate_restored = False


    def checkpoint(self) -> None:
        save_summary(self.out, self.manifest)


    def probe(self, label: str, command: list[str], *, env: dict | None = None) -> str:
        entry = {"label": label, "command": command, "exit_code": None}
        self.manifest["setup_checks"].append(entry)
        try:
            completed = subprocess.run(command, cwd=self.root, env=env or self.env,
                                       text=True, capture_output=True, timeout=30, check=False)
            entry.update(exit_code=completed.returncode, stdout=completed.stdout,
                         stderr=completed.stderr)
            require(completed.returncode == 0, label + " failed")
            return completed.stdout.strip()
        except BaseException as error:
            entry["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            self.checkpoint()


    def task_path(self, name: str, *, exists: bool = False) -> Path:
        raw = Path(self.cfg[name])
        require(raw.is_absolute(), name + " must be absolute")
        path = raw.resolve(strict=exists)
        require(path.is_relative_to(self.work) and path != self.work,
                name + " must be scoped under the user's work directory")
        return path


    def mount_receipt(self, label: str, path: Path, *, native: bool) -> dict:
        output = self.probe("mount-" + label,
                            ["findmnt", "--json", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
        mounts = json.loads(output)["filesystems"]
        require(len(mounts) == 1, "ambiguous mount for " + label)
        mount = mounts[0]
        usage = shutil.disk_usage(path)
        result = {"path": str(path), "mount": mount, "device_id": path.stat().st_dev,
                  "capacity_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        if native:
            require(mount["fstype"] in LOCAL_FILESYSTEMS and mount["source"].startswith("/dev/"),
                    label + " must use a persistent local block filesystem, never tmpfs/overlay/NFS")
            require("noexec" not in mount.get("options", "").split(","),
                    label + " must allow execution on the persistent filesystem")
        return result


    def host_receipt(self) -> dict:
        receipt = {"sample_unix": time.time(), "hostname": platform.node(),
                   "system": platform.system(), "release": platform.release(),
                   "machine": platform.machine(), "uid": os.getuid(),
                   "nice": os.getpriority(os.PRIO_PROCESS, 0), "pressure": {}}
        for resource in ("cpu", "io", "memory"):
            path = Path("/proc/pressure") / resource
            receipt["pressure"][resource] = path.read_text().strip()
        group = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                      if line.startswith("0::")), None)
        require(group is not None and group.startswith("/") and ".." not in Path(group).parts,
                "missing canonical cgroup v2 path")
        directory = Path("/sys/fs/cgroup") / group.lstrip("/")
        receipt["task_cgroup"] = {"path": group}
        for name in ("cpu.max", "cpu.stat", "cpu.pressure", "memory.max", "memory.current",
                     "memory.peak", "memory.events", "io.pressure", "pids.current", "pids.peak"):
            path = directory / name
            receipt["task_cgroup"][name] = path.read_text().strip() if path.exists() else "unavailable"
        return receipt


    def validate_provider(self, phase: str) -> dict:
        provider, provider_identity = read_json_file(self.provider_path)
        require(provider.get("result") == "PASS", "provider validation did not pass")
        exports = provider.get("exports")
        require(isinstance(exports, dict) and set(exports) == PROVIDER_EXPORTS,
                "provider exports differ from the seven approved variables")
        require(all(isinstance(v, str) and "\n" not in v and "\r" not in v for v in exports.values()),
                "noncanonical provider export")
        require(exports["OPENSSL_STATIC"] == "1" and exports["OPENSSL_CONF"] == "/dev/null"
                and exports["TRNM_PQ_OPENSSL_VERSION"] == OPENSSL_VERSION,
                "provider static/version/config exports differ")
        prefix = Path(exports["OPENSSL_DIR"])
        require(prefix.is_absolute() and prefix.resolve(strict=True) == prefix
                and prefix.is_relative_to(self.work), "provider prefix must be canonical under work")
        require(exports["TRNM_PQ_OPENSSL"] == str(prefix / "bin/openssl")
                and exports["OPENSSL_MODULES"] == str(prefix / "lib/ossl-modules"),
                "provider paths are not bound to the prefix")
        receipt, receipt_identity = read_json_file(self.provider_receipt_path)
        require(provider.get("provider_receipt_sha256") == receipt_identity["sha256"],
                "provider receipt hash mismatch")
        require(receipt.get("schema") == "trnm-ci-pq-provider-v3"
                and receipt.get("result") == "PREPARED_AND_SMOKE_VERIFIED"
                and receipt.get("exit_code") == 0 and receipt.get("last_stage") == "complete"
                and receipt.get("version") == OPENSSL_VERSION, "provider preparation receipt failed")
        for key in ("backend_exported", "source_digest_verified", "static_build",
                    "ml_dsa_65_sign_verify_and_wrong_message_rejection"):
            require(receipt.get(key) is True, "provider receipt lacks " + key)
        for key in ("native_rust_pq_tests_run_by_preparation", "independent_cryptographic_implementation_claim",
                    "whole_chain_quantum_security_qualified", "production_activation"):
            require(receipt.get(key) is False, "provider receipt scope changed: " + key)
        require(receipt.get("source_archive_sha256_expected") == OPENSSL_ARCHIVE_SHA256,
                "provider archive pin differs")
        preparation = file_identity(self.root / "scripts/ci/prepare_pq_provider.sh")
        require(receipt.get("preparation_script_sha256") == preparation["sha256"],
                "provider preparation script differs from the tested source")
        require(receipt.get("install_prefix") == str(prefix)
                and receipt.get("cli_executable") == exports["TRNM_PQ_OPENSSL"]
                and receipt.get("cli_sha256") == exports["TRNM_PQ_OPENSSL_SHA256"]
                and receipt.get("openssl_conf") == exports["OPENSSL_CONF"]
                and receipt.get("openssl_modules") == exports["OPENSSL_MODULES"],
                "provider receipt and exports disagree")
        rows = receipt.get("native_backend_inputs")
        require(isinstance(rows, list) and len(rows) == len(PROVIDER_INPUTS), "provider input list differs")
        identities = [file_identity(prefix / relative) for relative in PROVIDER_INPUTS]
        require(all(isinstance(row, dict) for row in rows), "invalid provider input row")
        expected = {row.get("path"): row for row in rows}
        require(len(expected) == len(identities) and set(expected) == {row["path"] for row in identities},
                "provider input paths differ")
        for identity in identities:
            pinned = expected[identity["path"]]
            require(pinned.get("sha256") == identity["sha256"] and pinned.get("bytes") == identity["bytes"],
                    "provider input hash/size mismatch: " + identity["path"])
        require(identities[0]["sha256"] == exports["TRNM_PQ_OPENSSL_SHA256"], "provider CLI pin differs")
        environment = self.env | exports
        version = self.probe("provider-version-" + phase, [exports["TRNM_PQ_OPENSSL"], "version"], env=environment)
        require(version.startswith("OpenSSL " + OPENSSL_VERSION + " ")
                and version == provider.get("version") == receipt.get("cli_version_output"),
                "actual provider version differs from its receipts")
        return {"validation_file": provider_identity, "receipt_file": receipt_identity,
                "preparation_script": preparation, "exports": exports, "actual_version": version,
                "native_backend_inputs": identities, "receipt": receipt}


    def prepare(self) -> None:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "expected Linux x86_64")
        self.root = self.task_path("root", exists=True)
        self.target = self.task_path("target")
        self.native_tmp = self.task_path("native_tmp")
        self.provider_path = self.task_path("provider_path", exists=True)
        receipt_default = self.provider_path.parent / "observations/pq-provider/provider.json"
        self.cfg["provider_receipt_path"] = self.cfg.get("provider_receipt_path", str(receipt_default))
        self.provider_receipt_path = self.task_path("provider_receipt_path", exists=True)
        for name, path in (("out", self.out), ("target", self.target), ("native_tmp", self.native_tmp)):
            require(not path.is_relative_to(self.root) and not self.root.is_relative_to(path),
                    name + " overlaps the source checkout")
        require(len({self.out, self.target, self.native_tmp}) == 3, "task output paths must differ")
        require(not any(a.is_relative_to(b) or b.is_relative_to(a)
                        for a, b in ((self.out, self.target), (self.out, self.native_tmp),
                                     (self.target, self.native_tmp))), "task output directories overlap")
        self.target.mkdir(parents=True, exist_ok=True)
        self.native_tmp.mkdir(parents=True, exist_ok=True)
        require(not any(self.native_tmp.iterdir()), "native_tmp must be an unused isolated directory")
        for path in (self.root, self.out, self.target, self.native_tmp):
            require(path.stat().st_uid == os.getuid(), "task directory is not user-owned: " + str(path))
        self.sha = self.cfg["sha"]
        require(isinstance(self.sha, str) and re.fullmatch(r"[0-9a-f]{40}", self.sha) is not None,
                "expected commit must be a canonical SHA-1")
        self.env, removed = scrub_environment(self.env)
        self.cargo_home = Path(self.env.get("CARGO_HOME", str(self.user_home / ".cargo")))
        require(self.cargo_home.is_absolute(), "CARGO_HOME must be absolute")
        self.cargo_home = self.cargo_home.resolve(strict=True)
        self.env["CARGO_HOME"] = str(self.cargo_home)
        self.env.update(RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTUP_AUTO_INSTALL="0", RUSTUP_SKIP_UPDATE_CHECK="1",
                        CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(self.target), CARGO_TERM_COLOR="never",
                        RUST_TEST_THREADS="1", PYTHONDONTWRITEBYTECODE="1", LC_ALL="C",
                        GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
                        TMPDIR=str(self.native_tmp), TMP=str(self.native_tmp), TEMP=str(self.native_tmp))
        self.manifest.update(commit=self.sha, paths={key: str(getattr(self, key)) for key in
                             ("root", "out", "target", "native_tmp", "provider_path", "provider_receipt_path")},
                             removed_inherited_environment_names=removed)
        self.manifest["mounts_before"] = {name: self.mount_receipt(name, path, native=True)
                                           for name, path in (("root", self.root), ("out", self.out),
                                                              ("target", self.target), ("native_tmp", self.native_tmp))}
        self.manifest["host_before"] = self.host_receipt()
        self.manifest["block_devices"] = []
        devices = sorted({value["mount"]["source"].split("[", 1)[0]
                          for value in self.manifest["mounts_before"].values()})
        for device in devices:
            info = self.probe("block-device", ["lsblk", "--json", "--inverse", "--output", "NAME,TYPE,ROTA,TRAN,SIZE", device])
            self.manifest["block_devices"].append({"source": device, "device": json.loads(info)})
        self.manifest["cargo_config_before"] = cargo_config_inputs(self.root, self.cargo_home)
        toolchain = {}
        rustup_raw = Path(self.cfg.get("rustup", str(self.user_home / ".cargo/bin/rustup")))
        require(rustup_raw.is_absolute(), "rustup must be an absolute executable path")
        rustup = rustup_raw.resolve(strict=True)
        require(os.access(rustup, os.X_OK), "rustup is not executable")
        toolchain["rustup"] = file_identity(rustup)
        self.env["PATH"] = str(rustup_raw.parent) + os.pathsep + self.env.get("PATH", os.defpath)
        for name in ("rustc", "cargo"):
            executable = self.probe(name + "-path", [str(rustup), "which", "--toolchain", TOOLCHAIN, name])
            path = Path(executable).resolve(strict=True)
            toolchain[name] = file_identity(path)
        bindir = str(Path(toolchain["cargo"]["path"]).parent)
        require(Path(toolchain["rustc"]["path"]).parent == Path(bindir), "compiler and Cargo toolchain differ")
        self.env["PATH"] = bindir + os.pathsep + self.env.get("PATH", os.defpath)
        for name, flag in (("rustc", "-vV"), ("cargo", "-Vv")):
            version = self.probe(name + "-actual-version", [name, flag])
            require(re.search(r"(?m)^release: " + re.escape(TOOLCHAIN) + r"$", version) is not None,
                    name + " is not actually " + TOOLCHAIN)
            require("host: x86_64-unknown-linux-gnu" in version, name + " host differs")
            toolchain[name]["version_output"] = version
        self.manifest["toolchain"] = toolchain
        self.tree = self.probe("initial-tree", ["git", "rev-parse", "HEAD^{tree}"])
        require(Path(self.probe("initial-root", ["git", "rev-parse", "--show-toplevel"])).resolve() == self.root,
                "Git worktree differs from the configured source root")
        require(self.probe("initial-head", ["git", "rev-parse", "HEAD"]) == self.sha, "HEAD mismatch")
        require("tree" not in self.cfg or self.cfg["tree"] == self.tree, "expected tree mismatch")
        require(not self.probe("initial-clean-source", ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"]),
                "source is not initially clean")
        self.manifest["tree"] = self.tree
        self.manifest["runner_before"] = file_identity(Path(__file__).resolve(strict=True))
        self.provider_before = self.validate_provider("before")
        self.manifest["provider_before"] = self.provider_before
        self.env.update(self.provider_before["exports"])
        environment_keys = ("RUSTUP_TOOLCHAIN", "RUSTUP_AUTO_INSTALL", "CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR",
                            "CARGO_TERM_COLOR", "RUST_TEST_THREADS", "PYTHONDONTWRITEBYTECODE", "LC_ALL",
                            "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT",
                            "TMPDIR", "TMP", "TEMP", "PATH")
        self.manifest["command_environment"] = {key: self.env[key] for key in environment_keys}
        self.manifest["command_environment"].update(self.provider_before["exports"])
        self.manifest["state"] = "running"
        self.checkpoint()

    def git_bytes(self, label: str, revision: str, relative: str) -> bytes:
        command = ["git", "show", revision + ":" + relative]
        entry = {"label": label, "command": command, "exit_code": None}
        self.manifest["setup_checks"].append(entry)
        try:
            completed = subprocess.run(command, cwd=self.root, env=self.env,
                                       capture_output=True, timeout=30, check=False)
            entry.update(exit_code=completed.returncode, stdout_bytes=len(completed.stdout),
                         stdout_sha256=hashlib.sha256(completed.stdout).hexdigest(),
                         stderr=completed.stderr.decode("utf-8", errors="replace"))
            require(completed.returncode == 0, label + " failed")
            return completed.stdout
        finally:
            self.checkpoint()

    def prepare_sources(self) -> None:
        require(self.sha != BASELINE_SHA, "candidate must be the new fixed implementation commit")
        require(isinstance(self.cfg["tree"], str)
                and re.fullmatch(r"[0-9a-f]{40}", self.cfg["tree"]) is not None,
                "expected tree must be a canonical SHA-1")
        hashes = dict(zip((AUTH_PATH, TESTS_PATH, PQ_PATH),
                          (self.cfg["candidate_auth_sha256"], self.cfg["candidate_tests_sha256"],
                           self.cfg["candidate_pq_sha256"])))
        require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in hashes.values()), "candidate file hashes must be canonical SHA-256")
        self.candidate = {}
        self.source_modes = {}
        for relative, expected in hashes.items():
            path = self.root / relative
            identity = file_identity(path)
            data = path.read_bytes()
            require(identity["sha256"] == expected == hashlib.sha256(data).hexdigest(),
                    "candidate source hash differs: " + relative)
            require(data == self.git_bytes("candidate-source-" + path.name, self.sha, relative),
                    "candidate worktree bytes differ from fixed commit: " + relative)
            self.candidate[relative] = data
            self.source_modes[relative] = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        red_relative = Path(self.cfg["red_tests_path"])
        require(not red_relative.is_absolute() and red_relative.parts
                and all(part not in (".", "..") for part in red_relative.parts)
                and str(red_relative) not in self.candidate, "red_tests_path must be a separate tracked relative file")
        red_path = self.root / red_relative
        red_identity = file_identity(red_path)
        red = red_path.read_bytes()
        require(red_identity["sha256"] == RED_TESTS_SHA256 == hashlib.sha256(red).hexdigest(),
                "committed red fixtures differ from the frozen regression source")
        require(red == self.git_bytes("committed-red-fixtures", self.sha, str(red_relative)),
                "red fixtures are not the exact candidate's tracked bytes")
        marker = b"\n#[test]\nfn authenticated_v3_observed_partial_reply_retains_original_shared_denominator()"
        full_tests = self.candidate[TESTS_PATH]
        require(full_tests.count(marker) == 1, "candidate test fixture boundary changed")
        fixture_prefix = full_tests.split(marker)[0].replace(b"io::{Read, Write},", b"io::Write,").rstrip()
        require(fixture_prefix == red.rstrip(), "red and green server fixtures differ")
        original = {}
        for relative, expected in BASELINE_HASHES.items():
            data = self.git_bytes("original-823-" + Path(relative).name, BASELINE_SHA, relative)
            require(hashlib.sha256(data).hexdigest() == expected, "original #823 implementation pin differs")
            original[relative] = data
        self.server_red = original | {TESTS_PATH: red}
        auth = self.candidate[AUTH_PATH]
        require(auth.count(CLAMP.encode()) == 1, "candidate does not have exactly the intended lease clamp")
        self.mutation = self.candidate | {AUTH_PATH: auth.replace(CLAMP.encode(), b"overall,")}
        self.known_hashes = {
            relative: {hashlib.sha256(stage[relative]).hexdigest()
                       for stage in (self.candidate, self.server_red, self.mutation)}
            for relative in self.candidate
        }
        for directory, sources in (("candidate-source", self.candidate),
                                    ("server-red-source", self.server_red),
                                    ("mutation-source", self.mutation)):
            destination = self.out / directory
            destination.mkdir()
            for relative, data in sources.items():
                (destination / Path(relative).name).write_bytes(data)
        self.manifest["source_inputs"] = {
            "original_commit": BASELINE_SHA, "original_files": BASELINE_HASHES,
            "candidate_commit": self.sha, "candidate_files": hashes,
            "committed_red_fixtures": red_identity,
            "red_green_server_fixtures_identical": True,
            "mutation": {"basis": "candidate, not original #823", "replacements": 1,
                         "removed": CLAMP, "replacement": "overall,",
                         "auth_sha256": hashlib.sha256(self.mutation[AUTH_PATH]).hexdigest()},
            "stages": {name: {relative: hashlib.sha256(data).hexdigest()
                               for relative, data in sources.items()}
                       for name, sources in (("candidate", self.candidate),
                                             ("server-red", self.server_red),
                                             ("mutation", self.mutation))},
        }
        self.sources_ready = True
        self.source_state("initial-candidate", self.candidate)

    def source_state(self, label: str, expected: dict[str, bytes]) -> None:
        require(self.probe(label + "-head", ["git", "rev-parse", "HEAD"]) == self.sha
                and self.probe(label + "-tree", ["git", "rev-parse", "HEAD^{tree}"]) == self.tree,
                "Git identity changed during differential controls")
        self.probe(label + "-index", ["git", "diff", "--no-ext-diff", "--cached", "--exit-code", "--"])
        changed = self.probe(label + "-changed-paths", ["git", "diff", "--no-ext-diff", "--name-only", "--"])
        expected_changed = {relative for relative in self.candidate
                            if expected[relative] != self.candidate[relative]}
        require(set(changed.splitlines()) == expected_changed,
                "unexpected tracked source changes during " + label)
        status = self.probe(label + "-status", ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])
        require(not any(line.startswith("??") for line in status.splitlines()),
                "unexpected untracked source during " + label)
        identities = {}
        for relative, data in expected.items():
            path = self.root / relative
            identity = file_identity(path)
            require(identity["sha256"] == hashlib.sha256(data).hexdigest()
                    and stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) == self.source_modes[relative],
                    "source bytes or mode changed during " + label + ": " + relative)
            identities[relative] = identity
        self.manifest.setdefault("source_stages", []).append({"label": label, "files": identities,
                                                             "changed_paths": sorted(expected_changed)})
        self.checkpoint()

    def replace_source(self, relative: str, data: bytes) -> None:
        path = self.root / relative
        current = file_identity(path)
        require(current["sha256"] in self.known_hashes[relative],
                "refusing to overwrite unknown concurrent source: " + relative)
        if current["sha256"] == hashlib.sha256(data).hexdigest():
            return
        before = path.stat(follow_symlinks=False)
        descriptor, temporary = tempfile.mkstemp(prefix=".discovery-differential-", dir=path.parent)
        temporary_path = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), stat.S_IMODE(before.st_mode))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            after = path.stat(follow_symlinks=False)
            fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                          value.st_mtime_ns, value.st_ctime_ns)
            require(fingerprint(before) == fingerprint(after) and file_identity(path) == current,
                    "source changed while preparing replacement: " + relative)
            os.replace(temporary_path, path)
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    def stage(self, label: str, sources: dict[str, bytes]) -> None:
        self.candidate_restored = False
        for relative, data in sources.items():
            self.replace_source(relative, data)
        self.source_state(label, sources)

    def restore_candidate(self) -> None:
        self.candidate_restored = False
        self.manifest["candidate_source_restored"] = False
        errors = []
        for relative, data in self.candidate.items():
            path = self.root / relative
            try:
                current = file_identity(path)
                if current["sha256"] not in self.known_hashes[relative]:
                    preserved = self.out / ("unexpected-current-" + path.name)
                    preserved.write_bytes(path.read_bytes())
                    self.manifest.setdefault("unexpected_source", []).append({
                        "current": current, "preserved": file_identity(preserved),
                        "action": "left intact; candidate was not written over unknown content"})
                    raise GateError("unknown concurrent content prevented restore: " + relative)
                self.replace_source(relative, data)
            except (OSError, GateError) as error:
                errors.append(type(error).__name__ + ": " + str(error))
        require(not errors, "; ".join(errors))
        self.source_state("restored-candidate", self.candidate)
        self.candidate_restored = True
        self.manifest["candidate_source_restored"] = True
        self.checkpoint()

    def run_command(self, label: str, command: list[str], *,
                    names: tuple[str, ...] | None = None, mode: str | None = None) -> dict:
        entry = {"label": label, "command": command, "state": "running", "exit_code": None,
                 "started_unix": time.time(), "errors": [], "native": names is not None}
        self.manifest["commands"].append(entry)
        self.checkpoint()
        event(event="start", label=label, command=command)
        started = time.monotonic()
        stdout, stderr = self.out / (label + ".stdout.log"), self.out / (label + ".stderr.log")
        interrupted = None
        process = None
        try:
            entry["host_before"] = self.host_receipt()
            entry["temporary_filesystem"] = "verified persistent local block filesystem"
            with stdout.open("xb") as so, stderr.open("xb") as se:
                process = subprocess.Popen(command, cwd=self.root, env=self.env, stdout=so, stderr=se,
                                           start_new_session=True)
                try:
                    entry["exit_code"] = process.wait()
                except BaseException:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=30)
                    entry["exit_code"] = process.returncode
                    raise
            if names is None:
                require(entry["exit_code"] == 0, label + " failed")
            else:
                require(mode is not None, "native command lacks an explicit expected result")
                entry["native_execution"] = parse_native(stdout.read_text(errors="replace"),
                                                          stderr.read_text(errors="replace"),
                                                          entry["exit_code"], names, mode)
        except BaseException as error:
            entry["errors"].append(type(error).__name__ + ": " + str(error))
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                interrupted = error
        finally:
            for name, path in (("stdout", stdout), ("stderr", stderr)):
                try:
                    entry[name] = file_identity(path)
                except (OSError, GateError) as error:
                    entry["errors"].append(name + " log unavailable: " + str(error))
            try:
                entry["host_after"] = self.host_receipt()
            except OSError as error:
                entry["errors"].append("host receipt failed: " + str(error))
            entry["elapsed_seconds"] = time.monotonic() - started
            entry["state"] = "passed" if not entry["errors"] else "failed"
            self.checkpoint()
            event(event="finish", label=label, state=entry["state"], exit_code=entry["exit_code"],
                  elapsed_seconds=entry["elapsed_seconds"], errors=entry["errors"],
                  native_execution=entry.get("native_execution"))
        if interrupted is not None:
            raise interrupted
        return entry

    def native_command(self, *, monotonic: bool) -> list[str]:
        command = ["cargo", "test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
                   "-p", "trnm-data-availability", "--lib"]
        if monotonic:
            return command + [MONOTONIC_CASE, "--", "--exact", "--test-threads=1", "--nocapture"]
        return command + ["authenticated_v3_real_server_", "--", "--test-threads=1", "--nocapture"]

    def final_identity(self) -> None:
        before, before_id = read_json_file(self.out / "source-before.json")
        after, after_id = read_json_file(self.out / "source-after.json")
        require(before == after and before_id["sha256"] == after_id["sha256"],
                "source-before differs from source-after")
        require(before.get("schema") == "trnm-ci-source-v1" and before.get("kind") == "head"
                and before.get("tested_commit") == before.get("candidate") == self.sha
                and before.get("tested_tree") == self.tree and before.get("tracked_worktree_verified") is True
                and before.get("tests_executed_by_identity_check") is False,
                "source receipt does not prove the exact tracked worktree")
        self.manifest["source_receipts_equal"] = True
        self.manifest["source_receipt_sha256"] = before_id["sha256"]
        self.manifest["final_status_porcelain"] = self.probe("final-clean-source", ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])
        require(not self.manifest["final_status_porcelain"], "source is not finally clean")
        self.manifest["provider_after"] = self.validate_provider("after")
        require(self.manifest["provider_after"] == self.provider_before,
                "provider inputs changed during differential controls")
        self.manifest["provider_inputs_unchanged"] = True
        self.manifest["cargo_config_after"] = cargo_config_inputs(self.root, self.cargo_home)
        require(self.manifest["cargo_config_before"] == self.manifest["cargo_config_after"],
                "Cargo configuration changed during differential controls")
        self.manifest["runner_after"] = file_identity(Path(__file__).resolve(strict=True))
        require(self.manifest["runner_before"] == self.manifest["runner_after"],
                "runner changed during differential controls")
        self.manifest["toolchain_after"] = {}
        for name, original in self.manifest["toolchain"].items():
            current = file_identity(Path(original["path"]))
            require(all(current[key] == original[key] for key in ("path", "sha256", "bytes")),
                    "toolchain bytes changed during differential controls: " + name)
            self.manifest["toolchain_after"][name] = current
        self.manifest["mounts_after"] = {name: self.mount_receipt(name + "-after", Path(value["path"]), native=True)
                                         for name, value in self.manifest["mounts_before"].items()}
        for name, value in self.manifest["mounts_before"].items():
            current = self.manifest["mounts_after"][name]
            require(value["device_id"] == current["device_id"] and value["mount"] == current["mount"],
                    "task filesystem changed during differential controls: " + name)
        self.manifest["host_after"] = self.host_receipt()

    def run(self) -> int:
        try:
            self.prepare()
            self.prepare_sources()
            preflight = self.run_command("preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            require(preflight["state"] == "passed", "preflight failed; no source staging or native execution allowed")
            identity_command = [sys.executable, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                                "--expected-head", self.sha, "--output"]
            identity = self.run_command("source-before", identity_command + [str(self.out / "source-before.json")])
            require(identity["state"] == "passed", "source identity failed; no source staging or native execution allowed")
            phases = (
                ("server-original-red", self.server_red, SERVER_CASES, "server-red", False),
                ("server-candidate-green", self.candidate, SERVER_CASES, "green", False),
                ("announcement-clamp-mutation-red", self.mutation, (MONOTONIC_CASE,), "mutation-red", True),
                ("announcement-candidate-green", self.candidate, (MONOTONIC_CASE,), "green", True),
            )
            for label, sources, names, mode, monotonic in phases:
                self.stage(label + "-before", sources)
                self.run_command(label, self.native_command(monotonic=monotonic), names=names, mode=mode)
                self.source_state(label + "-after", sources)
        except BaseException as error:
            self.manifest["errors"].append(type(error).__name__ + ": " + str(error))
            (self.out / "runner-error.log").write_text(traceback.format_exc())
        finally:
            if self.sources_ready:
                try:
                    self.restore_candidate()
                except BaseException as error:
                    self.manifest["errors"].append("restore failed: " + type(error).__name__ + ": " + str(error))
                    (self.out / "restore-error.log").write_text(traceback.format_exc())
            if self.candidate_restored and (self.out / "source-before.json").exists():
                try:
                    identity_command = [sys.executable, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                                        "--expected-head", self.sha, "--output", str(self.out / "source-after.json")]
                    identity = self.run_command("source-after", identity_command)
                    require(identity["state"] == "passed", "final source identity failed")
                    self.final_identity()
                except BaseException as error:
                    self.manifest["errors"].append("final identity failed: " + type(error).__name__ + ": " + str(error))
                    (self.out / "final-identity-error.log").write_text(traceback.format_exc())
            expected_labels = ["server-original-red", "server-candidate-green",
                               "announcement-clamp-mutation-red", "announcement-candidate-green"]
            native = [entry for entry in self.manifest["commands"] if entry["native"]]
            self.manifest["passed"] = (not self.manifest["errors"]
                                       and self.manifest.get("candidate_source_restored") is True
                                       and self.manifest.get("source_receipts_equal") is True
                                       and [entry["label"] for entry in native] == expected_labels
                                       and all(entry["state"] == "passed" for entry in self.manifest["commands"]))
            self.manifest["state"] = "passed" if self.manifest["passed"] else "failed"
            self.manifest["finished_unix"] = time.time()
            self.checkpoint()
            event(event="complete", passed=self.manifest["passed"], state=self.manifest["state"],
                  native_commands=len(native), commit=self.cfg.get("sha"), out=str(self.out),
                  source_restored=self.candidate_restored, errors=self.manifest["errors"])
        return 0 if self.manifest["passed"] else 1


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "configuration exceeds 1 MiB")
        cfg = json_load(raw)
        required = {"root", "out", "target", "native_tmp", "provider_path", "sha", "tree", "red_tests_path",
                    "candidate_auth_sha256", "candidate_tests_sha256", "candidate_pq_sha256"}
        require(required <= set(cfg), "missing required configuration key")
        require(set(cfg) <= required | {"rustup", "provider_receipt_path"}, "unknown configuration key")
        require(all(isinstance(value, str) and value for value in cfg.values()),
                "configuration values must be nonempty strings")
        return DifferentialRunner(cfg, raw).run()
    except BaseException as error:
        event(event="runner-initialization-failed", passed=False,
              error=type(error).__name__ + ": " + str(error))
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

