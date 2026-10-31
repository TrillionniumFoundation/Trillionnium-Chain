"""Owner-pinned TCD1 producer for the existing ordinary Cell-v2 host.

This module prepares data and finally execs the original daemon. It never
constructs a fleet, product bootstrap, signing key, resource grant or use receipt.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

_formal = Path(__file__).resolve().parents[1] / "formal/pon-nakamoto-v1/cell_dependency_closure.py"
_spec = importlib.util.spec_from_file_location("owner_cell_dependency_closure", _formal)
codec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(codec)

SCHEMA = "pon-smollm-cell-host-handoff-v2"
INSTALLED_SCHEMA = "pon-smollm-cell-host-handoff-v3"
HOST_SCHEMA = "hepta-smollm-cognitive-cell-host-v2"
NAMES = (
    "adapter/artifact.safetensors", "adapter/target-contract.json", "adapter/wrapped-adapter.json",
    "base/README.md", "base/config.json", "base/generation_config.json", "base/material-manifest.json",
    "base/model.safetensors", "base/special_tokens_map.json", "base/tokenizer.json", "base/tokenizer_config.json",
)
SOURCES = {
    "llm_adapter_contract.py": "formal/pon-nakamoto-v1/llm_adapter_contract.py",
    "llm_inherited_runtime.py": "scripts/llm_inherited_runtime.py",
    "llm_neural_read_worker.py": "scripts/llm_neural_read_worker.py",
    "llm_parent_material.py": "scripts/llm_parent_material.py",
    "llm_runtime_pilot.py": "scripts/llm_runtime_pilot.py",
    "model-family-smollm2-135m-v1.json": "config/pon/model-family-smollm2-135m-v1.json",
}
REQUIRED_ENV = ("HEPTA_FLEET_ROOT", "HEPTA_AGENT_ID", "HEPTA_AGENT_GENERATION",
                "HEPTA_AGENT_HOME", "HEPTA_AGENT_RUN_ROOT", "CODEX_HOME")
# Stable Linux UAPI values from linux/fcntl.h; some Python builds omit these names.
ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
EXECUTABLE_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008  # SEAL, SHRINK, GROW, WRITE


class NotConfigured(ValueError):
    pass


def exact(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError(label + " fields")


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field: " + key)
        value[key] = item
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_environment(environment):
    snapshot = dict(environment)
    overrides = sorted(name for name in snapshot
                       if name.startswith("LD_") or name == "GLIBC_TUNABLES")
    if overrides:
        raise ValueError("native ELF loader overrides are not allowed: " + ",".join(overrides))
    return snapshot


def owner_file(path, maximum):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("owner file must have an exact canonical absolute path")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                or info.st_uid not in (0, os.geteuid()) or not 0 < info.st_size <= maximum):
            raise ValueError("owner file must be protected, regular, bounded and unaliased")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def pinned(spec, maximum):
    exact(spec, ("path", "sha256"), "pinned file")
    codec.digest(spec["sha256"])
    with owner_file(spec["path"], maximum) as stream:
        raw = stream.read(maximum + 1)
        if len(raw) > maximum or checksum(raw) != spec["sha256"]:
            raise ValueError("independent owner file digest mismatch")
    return raw


def bounded(path, maximum):
    with owner_file(path, maximum) as stream:
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("producer input exceeds its bound")
        return raw


def publish(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sealed_executable(spec):
    """Hash the exact copied ELF and seal its bytes, not just its pathname."""
    exact(spec, ("path", "sha256"), "native executable")
    codec.digest(spec["sha256"])
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        raise NotConfigured("Linux sealed native executable handoff is unavailable")
    maximum = 512 * 1024**2
    with owner_file(spec["path"], maximum) as source:
        if not os.fstat(source.fileno()).st_mode & 0o111:
            raise ValueError("pinned native ELF host executable required")
        try:
            fd = os.memfd_create("hepta-cell-host", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        except (OSError, AttributeError) as error:
            raise NotConfigured("Linux sealed native executable handoff is unavailable") from error
        try:
            os.fchmod(fd, 0o700)
            size = 0
            while raw := source.read(min(1024**2, maximum + 1 - size)):
                size += len(raw)
                if size > maximum:
                    raise ValueError("native executable exceeds its bound")
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(fd, remaining)
                    if written == 0:
                        raise OSError("native executable snapshot write made no progress")
                    remaining = remaining[written:]
            try:
                fcntl.fcntl(fd, ADD_SEALS, EXECUTABLE_SEALS)
                if fcntl.fcntl(fd, GET_SEALS) & EXECUTABLE_SEALS != EXECUTABLE_SEALS:
                    raise OSError("native executable seal readback mismatch")
            except OSError as error:
                raise NotConfigured("immutable native executable seals are unavailable") from error
            os.lseek(fd, 0, os.SEEK_SET)
            if not 0 < os.fstat(fd).st_size <= maximum or os.read(fd, 4) != b"\x7fELF":
                raise ValueError("pinned native ELF host executable required")
            os.lseek(fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while raw := os.read(fd, 1024**2):
                digest.update(raw)
            if digest.hexdigest() != spec["sha256"]:
                raise ValueError("sealed native executable differs from independent owner pin")
            os.lseek(fd, 0, os.SEEK_SET)
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise


def authentication(value):
    profile = value.get("profile") if type(value) is dict else None
    if profile == "content-cache-v1":
        exact(value, ("profile",), "content authentication")
        return ["--authentication-profile", profile], {}
    fields = ("profile", "authorization", "signer_spki", "signer_key_id", "generation", "sequence",
              "network", "parameters", "key_not_before", "key_expires", "key_revoked_at")
    exact(value, fields, "PQ authentication")
    if profile != "cell-pq-v2":
        raise ValueError("explicit supported authentication profile required")
    for name in ("signer_key_id", "network", "parameters"):
        codec.digest(value[name])
    for name in ("generation", "sequence", "key_not_before", "key_expires"):
        if type(value[name]) is not int or not 0 <= value[name] < 2**64:
            raise ValueError("PQ owner integer: " + name)
    revoked = value["key_revoked_at"]
    if revoked is not None and (type(revoked) is not int or not 0 <= revoked < 2**64):
        raise ValueError("PQ owner revocation time")
    snapshots = {name: pinned(value[name], maximum) for name, maximum in
                 (("authorization", 3509), ("signer_spki", 1974))}
    result = ["--authentication-profile", profile]
    for name in ("signer_key_id", "generation", "sequence", "network", "parameters", "key_not_before", "key_expires"):
        result.extend(("--pq-" + name.replace("_", "-"), str(value[name])))
    if revoked is not None:
        result.extend(("--pq-key-revoked-at", str(revoked)))
    return result, snapshots


class Plan:
    def __init__(self, value, host, executable, execution_profile):
        self.value, self.host, self.executable = value, host, executable
        self.execution_profile = execution_profile
        self._auth_arguments, self._auth_snapshots = authentication(value["authentication"])
        self._prepared_auth = None
        self.sidecar = None

    @property
    def auth(self):
        if self._prepared_auth is None:
            raise ValueError("complete owner-pinned release is not prepared")
        return self._prepared_auth

    def publish_auth(self, output):
        info = output.stat(follow_symlinks=False)
        if (not output.is_absolute() or output.resolve(strict=True) != output
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o777 != 0o700):
            raise ValueError("this run requires its canonical private 0700 output directory")
        result = list(self._auth_arguments)
        for name, filename in (("authorization", "owner-pq-authorization.cpr2"),
                               ("signer_spki", "owner-pq-signer.spki")):
            if name in self._auth_snapshots:
                path = output / filename
                publish(path, self._auth_snapshots[name])
                result.extend(("--pq-" + name.replace("_", "-"), str(path)))
        return result

    def close(self):
        self.executable.close()

    def exec_owner(self):
        # Keep the independently measured image FD through the selected profile's exec. The unchanged
        # protected host is re-read against its original pin by the real daemon.
        environment = checked_environment(os.environ)
        if self.execution_profile == "protected-installed-elf-v1":
            import llm_cell_installed_executable as installed
            installed.require_subject()
            installed.verify_installed_path(self.value["executable"]["path"], self.executable)
        os.chdir(self.value["workspace"])
        os.execve(self.executable.fileno(), [self.value["executable"]["path"],
            "--host-format", "cell-v2", "--host-config", self.value["host"]["path"],
            "--host-config-sha256", self.value["host"]["sha256"]], environment)


def load(path, digest, output, environment):
    if path is None or digest is None:
        raise NotConfigured("cell-host-v2 requires --handoff-config and its independent --handoff-config-sha256")
    environment = checked_environment(environment)
    missing = [name for name in REQUIRED_ENV if not environment.get(name)]
    if missing:
        raise NotConfigured("original Fleet/Agentd process environment missing: " + ",".join(missing))
    if os.execve not in os.supports_fd:
        raise NotConfigured("native executable FD handoff is unavailable on this platform")
    try:
        value = json.loads(pinned({"path": str(path), "sha256": digest}, 65_536), object_pairs_hook=unique)
        fields = ("schema", "host", "executable", "workspace", "generation", "loader_profile", "context", "authentication")
        schema = value.get("schema") if type(value) is dict else None
        if schema == SCHEMA:
            exact(value, fields, "handoff-v2")
            execution_profile = "sealed-elf-v1"
        elif schema == INSTALLED_SCHEMA:
            exact(value, (*fields, "execution_profile"), "handoff-v3")
            execution_profile = value["execution_profile"]
            if execution_profile != "protected-installed-elf-v1":
                raise ValueError("explicit protected-installed-elf-v1 execution profile required")
        else:
            raise ValueError("explicit supported handoff schema required")
        if type(value["generation"]) is not int or not 0 < value["generation"] < 2**64:
            raise ValueError("independent selected generation")
        codec.digest(value["loader_profile"])
        codec.context_bytes(value["context"])
        workspace = Path(value["workspace"])
        if not workspace.is_absolute() or workspace.resolve(strict=True) != workspace or not workspace.is_dir():
            raise ValueError("original canonical Agentd workspace required")
        host = json.loads(pinned(value["host"], 65_536), object_pairs_hook=unique)
        exact(host, ("schema", "owner", "sidecar", "dependency_closure", "dependency_closure_id", "operation_id"), "host-v2")
        if host["schema"] != HOST_SCHEMA or host["owner"].get("schema") != "hepta-smollm-cognitive-host-v1":
            raise ValueError("original complete host-v2 and nested owner-v1 required")
        codec.digest(host["dependency_closure_id"])
        operation = host["operation_id"]
        if type(operation) is not str or not 1 <= len(operation) <= 128 or any(not 33 <= ord(c) <= 126 for c in operation):
            raise ValueError("original operation identity")
        for name, destination in (("sidecar", output / "consumer-cell-sidecar.json"),
                                  ("dependency_closure", output / "consumer-release.tcd1")):
            exact(host[name], ("path", "sha256"), name)
            if host[name]["path"] != str(destination):
                raise ValueError("owner destination must match this exact initially absent run: " + name)
            codec.digest(host[name]["sha256"])
        worker = host["owner"]["worker"]
        for actual, expected in ((worker["materials"], output / "consumer-materials"),
                                 (worker["target_contract"]["path"], output / "consumer-parent/target-contract.json"),
                                 (worker["wrapped_adapter"]["path"], output / "consumer-parent/wrapped-adapter.json")):
            if actual != str(expected):
                raise ValueError("original host material path differs from this run")
        # Original qualifications and issuer configuration must already exist.
        # Reading them creates no grant; the Rust owner performs semantic replay.
        pinned(host["owner"]["descriptor"], 2 * 1024 * 1024)
        with owner_file(host["owner"]["final_use_authorizer_config"], 65_536):
            pass
        exact(value["executable"], ("path", "sha256"), "native executable")
        codec.digest(value["executable"]["sha256"])
        if execution_profile == "sealed-elf-v1":
            executable = sealed_executable(value["executable"])
        else:
            import llm_cell_installed_executable as installed
            try:
                executable = installed.prepare(value["executable"]["path"], value["executable"]["sha256"])
            except installed.ProfileUnavailable as error:
                raise NotConfigured(str(error)) from error
        try:
            return Plan(value, host, executable, execution_profile)
        except BaseException:
            executable.close()
            raise
    except FileNotFoundError as error:
        raise NotConfigured("original owner input is absent: " + str(error.filename)) from error


def prepare(plan, args, family, parent, members, release_file, release, producer, deadline):
    worker = plan.host["owner"]["worker"]
    context = plan.value["context"]
    if sorted(member["name"] for member in members) != list(NAMES) or parent["generation"] != plan.value["generation"]:
        raise ValueError("exact eleven-file roster and independently selected generation required")
    source_pins = {str(args.chain / relative): checksum(bounded(args.chain / relative, 2 * 1024**2)) for relative in SOURCES.values()}
    if worker["source_pins"] != source_pins or worker["script"] != str(args.chain / SOURCES["llm_neural_read_worker.py"]) or worker["python"] != str(args.python):
        raise ValueError("original worker executable/source pins differ from producer checkout")
    sources = {name: source_pins[str(args.chain / relative)] for name, relative in sorted(SOURCES.items())}
    parent_dir = Path(parent["directory"])
    contract_raw = bounded(parent_dir / "target-contract.json", 1024**2)
    wrapper = bounded(parent_dir / "wrapped-adapter.json", 1024**2)
    contract = json.loads(contract_raw, object_pairs_hook=unique)
    expected_context = dict(family=family["id"], base=contract["backbone"]["index_root"], parent=parent["file_sha256"],
                            tokenizer=contract["tokenizer"]["files_root"], layout=parent["contract"], runtime=sources["llm_neural_read_worker.py"])
    if context != expected_context:
        raise ValueError("independent Cell context differs from original producer material")
    for key, actual in (("contract_digest", parent["contract"]), ("adapter_digest", parent["adapter"]),
                        ("backbone_digest", context["base"]), ("tokenizer_digest", context["tokenizer"])):
        if worker[key] != actual:
            raise ValueError("original host semantic pin mismatch: " + key)
    if worker["target_contract"]["sha256"] != checksum(contract_raw) or worker["wrapped_adapter"]["sha256"] != checksum(wrapper):
        raise ValueError("original host adapter file pins differ")
    actions = [dict(action_id=key, completion=value) for key, value in sorted(worker["action_completions"].items())]
    profile = ["hepta-smollm-single-token-action-score-v1", sources, actions, parent["contract"], parent["adapter"],
               checksum(contract_raw), checksum(wrapper), context["base"], context["tokenizer"], 4]
    if len(actions) != 2 or checksum(canonical(profile)) != plan.value["loader_profile"]:
        raise ValueError("original exact loader execution profile mismatch")
    declared, files = [], []
    for index, member in enumerate(sorted(members, key=lambda member: member["name"])):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original release preparation deadline exhausted")
        path = args.output / f"source-cell-{index}.tcm1"
        subprocess.run([str(args.cell_bin), "manifest", "--store", str(producer), "--manifest", member["pack"]["manifest"],
                        "--output", str(path)], check=True, capture_output=True, timeout=remaining)
        raw = bounded(path, 16_384)
        packed = member["pack"]
        if len(raw) > 16_384 or checksum(b"trnm.cell-manifest.v1\0" + raw) != packed["manifest"]:
            raise ValueError("native TCM1 export differs from declared member")
        declared.append(dict(name=member["name"], manifest_id=packed["manifest"], payload_sha256=packed["payload_sha256"], size=packed["bytes"], tcm1_hex=raw.hex()))
        role = 4 if index == 0 else 1 if member["name"] == "base/model.safetensors" else 2 if member["name"] in NAMES[8:] else 6
        files.append(dict(path=member["name"], role=role, manifest=packed["manifest"], payload_sha256=packed["payload_sha256"],
                          payload_bytes=packed["bytes"], dependencies=list(range(1, 11)) if index == 0 else []))
    tcr = bounded(release_file, 1_048_576)
    if (tcr != codec.release_bytes(context, [member["manifest_id"] for member in declared])
            or checksum(b"trnm.cell-release-manifest.v1\0" + tcr) != release["release"]):
        raise ValueError("native TCR1 differs from exact declared context and membership")
    tcd = codec.encode(dict(context=context, selected_generation=plan.value["generation"], loader_profile=plan.value["loader_profile"], roots=[0], files=files))
    sidecar = dict(schema="hepta-smollm-controlled-cell-release-v1", scope="controlled-native-load-only",
        profile="smollm2-135m-f32-r4-dense-single-adapter-no-fallback-v1", operation_id=plan.host["operation_id"],
        generation=plan.value["generation"], family_id=family["id"], family_file_sha256=sources["model-family-smollm2-135m-v1.json"],
        model=family["reference"]["model"], revision=family["reference"]["revision"], artifact_sha256=parent["file_sha256"],
        adapter_digest=parent["adapter"], contract_digest=parent["contract"], backbone_digest=context["base"], tokenizer_digest=context["tokenizer"],
        execution_profile_sha256=plan.value["loader_profile"], sources=[dict(name=key, sha256=value) for key, value in sources.items()],
        actions=actions, tcr1_hex=tcr.hex(), tcr1_id=release["release"], members=declared)
    sidecar_raw = canonical(sidecar)
    if (len(sidecar_raw) > 65_536 or checksum(sidecar_raw) != plan.host["sidecar"]["sha256"]
            or checksum(tcd) != plan.host["dependency_closure"]["sha256"]
            or checksum(codec.DOMAIN + tcd) != plan.host["dependency_closure_id"]):
        raise ValueError("produced sidecar/TCD1 differs from independent owner pins")
    if time.monotonic() >= deadline:
        raise TimeoutError("original release preparation deadline exhausted after readback")
    auth = plan.publish_auth(args.output)
    path = args.output / "source-closure.tcd1"
    publish(path, tcd)
    if time.monotonic() >= deadline:
        raise TimeoutError("original release preparation deadline exhausted after protected publication")
    plan._prepared_auth = auth
    plan.sidecar = sidecar_raw
    return path
