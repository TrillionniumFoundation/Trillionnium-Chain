"""Narrow controlled byte closure for the existing eleven-material handoff.

This declaration is not selected CURRENT, a grant, or an I10 installation.
The Hepta consumer independently reconstructs the original TCM1/TCR1 bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from llm_parent_material import read_regular, runtime

SCHEMA = "hepta-smollm-controlled-cell-release-v1"
PROFILE = "smollm2-135m-f32-r4-dense-single-adapter-no-fallback-v1"
MAX_SIDECAR = 65_536
SOURCE_PATHS = (
    "formal/pon-nakamoto-v1/llm_adapter_contract.py",
    "scripts/llm_inherited_runtime.py", "scripts/llm_neural_read_worker.py",
    "scripts/llm_parent_material.py", "scripts/llm_runtime_pilot.py",
    "config/pon/model-family-smollm2-135m-v1.json",
)
ACTIONS = [dict(action_id="native-answer-no", completion="no"),
           dict(action_id="native-answer-yes", completion="yes")]
ROSTER = sorted(["adapter/artifact.safetensors", "adapter/target-contract.json", "adapter/wrapped-adapter.json"] +
    ["base/" + name for name in ("README.md", "config.json", "generation_config.json", "material-manifest.json",
        "model.safetensors", "special_tokens_map.json", "tokenizer.json", "tokenizer_config.json")])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_sidecar(args, family, parent, contract, members, release_file, release_id, producer):
    if sorted(m["name"] for m in members) != ROSTER:
        raise ValueError("controlled exact eleven role/path roster")
    if (type(parent["generation"]) is not int or not 1 <= parent["generation"] < 1 << 64
            or type(parent["operation_id"]) is not str or not 1 <= len(parent["operation_id"]) <= 128
            or not all(33 <= ord(c) <= 126 for c in parent["operation_id"])):
        raise ValueError("controlled original parent identity")
    sources = {Path(name).name: digest(read_regular(args.chain / name, 2 * 1024 * 1024)) for name in SOURCE_PATHS}
    sources = dict(sorted(sources.items()))
    parent_root = Path(parent["directory"])
    target = read_regular(parent_root / "target-contract.json", 2 * 1024 * 1024)
    wrapped = read_regular(parent_root / "wrapped-adapter.json", 2 * 1024 * 1024)
    release_wire = read_regular(release_file, 65_536)
    if digest(b"trnm.cell-release-manifest.v1\0" + release_wire) != release_id:
        raise ValueError("TCR1 domain identity")
    execution = ["hepta-smollm-single-token-action-score-v1", sources, ACTIONS,
        parent["contract"], parent["adapter"], digest(target), digest(wrapped),
        contract["backbone"]["index_root"], contract["tokenizer"]["files_root"], 4]
    sidecar = dict(schema=SCHEMA, scope="controlled-native-load-only", profile=PROFILE,
        operation_id=parent["operation_id"], generation=parent["generation"],
        family_id=family["id"], family_file_sha256=sources["model-family-smollm2-135m-v1.json"],
        model=family["reference"]["model"], revision=family["reference"]["revision"],
        artifact_sha256=parent["file_sha256"], adapter_digest=parent["adapter"],
        contract_digest=parent["contract"], backbone_digest=contract["backbone"]["index_root"],
        tokenizer_digest=contract["tokenizer"]["files_root"],
        execution_profile_sha256=digest(canonical(execution)),
        sources=[dict(name=k, sha256=v) for k, v in sources.items()], actions=ACTIONS,
        tcr1_hex=release_wire.hex(), tcr1_id=release_id, members=[])
    exported = args.output / "canonical-member-manifests"
    exported.mkdir(mode=0o700)
    for index, member in enumerate(sorted(members, key=lambda row: row["name"])):
        path = exported / f"{index}.tcm1"
        command = [str(args.cell_bin), "manifest", "--store", str(producer),
            "--manifest", member["pack"]["manifest"], "--output", str(path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (exported / f"{index}.log").write_text(result.stdout + result.stderr)
        result.check_returncode()
        if path.stat().st_size > 16_384:
            raise ValueError("controlled TCM1 bound")
        wire = read_regular(path, 16_384)
        if digest(b"trnm.cell-manifest.v1\0" + wire) != member["pack"]["manifest"]:
            raise ValueError("exported TCM1 domain identity")
        sidecar["members"].append(dict(name=member["name"], tcm1_hex=wire.hex(),
            manifest_id=member["pack"]["manifest"], payload_sha256=member["pack"]["payload_sha256"],
            size=member["pack"]["bytes"]))
    raw = canonical(sidecar)
    if len(raw) > MAX_SIDECAR or len(sidecar["members"]) != 11:
        raise ValueError("controlled closure bound/roster")
    path = args.output / "controlled-byte-closure-v1.json"
    write_new(path, raw)
    return dict(path=str(path), sha256=digest(raw), bytes=len(raw),
        commitment=digest(b"hepta.smollm.controlled-cell-release.v1\0" + len(raw).to_bytes(8, "big") + raw))


def git_identity(repo):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()
    if git("status", "--porcelain"):
        raise ValueError("controlled native source must be committed and clean")
    return dict(head=git("rev-parse", "HEAD"), tree=git("rev-parse", "HEAD^{tree}"))


def consume_controlled(args, consumer_parent, sidecar):
    """Run one fixed original-owner case; no result can qualify I10."""
    before = git_identity(args.hepta)
    out = args.output / "controlled-original-native"
    parent_raw = read_regular(consumer_parent, 2 * 1024 * 1024)
    parent = json.loads(parent_raw, object_pairs_hook=runtime.unique)
    native = dict(schema="hepta-smollm-neural-native-check-v1", python=str(args.python),
        chain=str(args.chain), materials=str(args.output / "consumer-materials"),
        parent=str(consumer_parent), parent_sha256=digest(parent_raw), output=str(out))
    config = dict(schema="hepta-smollm-controlled-cell-native-check-v1", native=native,
        sidecar=sidecar["path"], sidecar_sha256=sidecar["sha256"])
    path = args.output / "controlled-cell-native-v1.json"
    write_new(path, canonical(config))
    environment = dict(os.environ, CODEX_REPO_ROOT=str(args.hepta),
        CARGO_TARGET_DIR=str(args.hepta_target), PYTHONDONTWRITEBYTECODE="1",
        HEPTA_PN3_CELL_NATIVE_CONFIG=str(path))
    command = [str(args.just), "test", "--locked", "--offline", "-p", "codex-hepta-infer-worker-host",
        "--run-ignored", "only", "--test-threads", "1", "--no-capture", "-E",
        "test(=smollm_neural_read::tests::native::real_cell_release_original_signed_load_query_and_terminal_unload)"]
    started = time.monotonic()
    # Cargo is never killed by this harness. The original nextest case deadline,
    # startup/read/unload limits remain in their existing owners. This controlled
    # call (including compilation/validation) is separate from the 35s transfer.
    with (args.output / "controlled-native-command.log").open("xb") as log:
        result = subprocess.run(command, cwd=args.hepta, env=environment, stdout=log, stderr=subprocess.STDOUT)
    after = git_identity(args.hepta)
    if before != after or result.returncode != 0:
        raise RuntimeError("controlled original native source/test did not pass")
    readback_path = out / "controlled-cell-loaded-readback-v1.json"
    readback_raw = read_regular(readback_path, 65_536)
    readback = json.loads(readback_raw, object_pairs_hook=runtime.unique)
    fields = {"schema", "sidecar_sha256", "closure_commitment", "actual_ready_sha256", "actual_parameters_sha256",
        "actual_generation", "original_final_use_claims", "controlled_load_query_unload_observed",
        "product_artifact_installed", "ordinary_cognitive_context_qualified", "public_reward_eligible"}
    if (set(readback) != fields or readback["schema"] != "hepta-smollm-controlled-cell-loaded-readback-v1"
            or readback["sidecar_sha256"] != sidecar["sha256"]
            or readback["closure_commitment"] != sidecar["commitment"]
            or readback["actual_parameters_sha256"] != parent["file_sha256"]
            or type(readback["actual_generation"]) is not int or readback["actual_generation"] != parent["generation"]
            or type(readback["original_final_use_claims"]) is not int
            or readback["original_final_use_claims"] != 3
            or type(readback["actual_ready_sha256"]) is not str
            or len(readback["actual_ready_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in readback["actual_ready_sha256"])
            or readback["controlled_load_query_unload_observed"] is not True
            or any(readback[k] is not False for k in ("product_artifact_installed",
                "ordinary_cognitive_context_qualified", "public_reward_eligible"))):
        raise ValueError("controlled byte-closure readback mismatch")
    return dict(source=before, command=command, exit_code=result.returncode,
        elapsed_seconds=time.monotonic() - started, readback_sha256=digest(readback_raw),
        readback=readback, scope="CONTROLLED_LOAD_ONLY_NOT_I10_OR_INSTALLATION")


def _write_protected_new(path, raw):
    # Linux ordinary-host inputs, not a namespace/admission capability.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_ordinary_host_config_v2(args):
    """Export content/configuration only; the ordinary host rechecks all bytes.

    Reusing a controlled declaration's wire data transfers no native-test,
    selector, installation, grant or FinalUse authority. The original V1 host
    descriptor and all its independent owners are still required by the consumer.
    """
    inputs = {}
    for name, path, expected in (("content", args.sidecar, args.sidecar_sha256),
                                 ("host", args.host_config, args.host_config_sha256)):
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected)):
            raise ValueError("ordinary host requires canonical pinned inputs")
        raw = read_regular(path, MAX_SIDECAR)
        if digest(raw) != expected:
            raise ValueError("ordinary host input digest mismatch")
        inputs[name] = json.loads(raw, object_pairs_hook=runtime.unique)
    sidecar = inputs["content"]
    fields = set("schema scope profile operation_id generation family_id family_file_sha256 model revision "
        "artifact_sha256 adapter_digest contract_digest backbone_digest tokenizer_digest "
        "execution_profile_sha256 sources actions tcr1_hex tcr1_id members".split())
    if (type(sidecar) is not dict or set(sidecar) != fields or sidecar["schema"] != SCHEMA
            or sidecar["scope"] != "controlled-native-load-only" or sidecar["profile"] != PROFILE
            or type(sidecar["members"]) is not list
            or [m["name"] for m in sidecar["members"]] != ROSTER
            or inputs["host"].get("schema") != "hepta-smollm-cognitive-host-v1"):
        raise ValueError("ordinary content requires original bounded declarations")
    operation = sidecar["operation_id"]
    if type(operation) is not str or not 1 <= len(operation) <= 128 or not all(33 <= ord(c) <= 126 for c in operation):
        raise ValueError("ordinary content operation identity")
    sidecar = dict(sidecar, schema="hepta-smollm-ordinary-cell-content-v1",
                   scope="qualified-host-content-only")
    content = canonical(sidecar)
    if len(content) > MAX_SIDECAR:
        raise ValueError("ordinary content declaration bound")
    if not args.output.is_absolute() or args.output.parent.resolve(strict=True) != args.output.parent:
        raise ValueError("ordinary output requires a canonical parent")
    args.output.mkdir(mode=0o700)
    content_path = args.output / "ordinary-cell-content-v1.json"
    _write_protected_new(content_path, content)
    config = canonical(dict(schema="hepta-smollm-cognitive-cell-host-v2",
        host=dict(path=str(args.host_config), sha256=args.host_config_sha256),
        cell_content=dict(path=str(content_path), sha256=digest(content)), operation_id=operation))
    if len(config) > MAX_SIDECAR:
        raise ValueError("ordinary host configuration bound")
    config_path = args.output / "ordinary-cell-host-v2.json"
    _write_protected_new(config_path, config)
    return dict(path=str(config_path), sha256=digest(config), bytes=len(config),
                scope="configuration-and-content-only-no-qualification-or-installation")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export explicitly pinned ordinary Cell content configuration")
    parser.add_argument("command", choices=("prepare-ordinary-host-config-v2",
        "freeze-ordinary-action-catalog-v1", "prepare-ordinary-host-config-v3"))
    parser.add_argument("--sidecar", type=Path)
    parser.add_argument("--sidecar-sha256")
    parser.add_argument("--host-config", type=Path)
    parser.add_argument("--host-config-sha256")
    parser.add_argument("--catalog-input", type=Path)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--catalog-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze-ordinary-action-catalog-v1":
        if args.catalog_input is None or any(value is not None for value in
                (args.sidecar, args.sidecar_sha256, args.host_config, args.host_config_sha256, args.catalog, args.catalog_sha256)):
            parser.error("freeze accepts only catalogue input and output")
        from llm_ordinary_action_catalog import freeze_catalog
        result = freeze_catalog(args)
    else:
        if any(value is None for value in (args.sidecar, args.sidecar_sha256, args.host_config, args.host_config_sha256)):
            parser.error("pinned sidecar and host inputs are required")
        if args.command == "prepare-ordinary-host-config-v2":
            if any(value is not None for value in (args.catalog_input, args.catalog, args.catalog_sha256)):
                parser.error("V2 does not accept catalogue inputs")
            result = prepare_ordinary_host_config_v2(args)
        else:
            if args.catalog_input is not None or args.catalog is None or args.catalog_sha256 is None:
                parser.error("pinned preregistered catalogue is required")
            from llm_ordinary_action_catalog import prepare_ordinary_host_config_v3
            result = prepare_ordinary_host_config_v3(args)
    print(json.dumps(result, sort_keys=True))
