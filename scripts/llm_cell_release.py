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


def runtime_material_command(args):
    """Use the release owner's create-only output; grant no loader capability."""
    import llm_runtime_release as closure
    root = args.root
    output = args.output.absolute()
    if output.resolve().is_relative_to(root):
        raise ValueError("runtime declaration output must be outside its material root")
    if args.command == "declare-runtime-material":
        raw = closure.declare_runtime_release(root,
            read_regular(args.spec, closure.MAX_MANIFEST), args.spec_sha256, args.maximum_bytes)
        summary = dict(runtime_root=digest(closure.DOMAIN + len(raw).to_bytes(8, "big") + raw),
            scope="DECLARED_MATERIAL_AND_STATIC_ELF_CLOSURE_ONLY",
            runtime_execution_qualified=False, ordinary_installation_qualified=False,
            public_reward_eligible=False)
    else:
        context_raw = read_regular(args.context, closure.MAX_MANIFEST)
        if digest(context_raw) != args.context_sha256:
            raise ValueError("runtime context differs from its independent pin")
        summary = closure.verify_runtime_release(root,
            read_regular(args.manifest, closure.MAX_MANIFEST), args.runtime_root,
            closure.decode(context_raw), args.maximum_bytes)
        raw = canonical(summary)
    write_new(output, raw)
    return summary


def main():
    import argparse
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Read-only runtime material declarations; no I10 admission")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("declare-runtime-material", "verify-runtime-material"):
        command = commands.add_parser(name)
        for option in ("root", "output"):
            command.add_argument("--" + option, type=Path, required=True)
        command.add_argument("--maximum-bytes", type=int, required=True)
        if name == "declare-runtime-material":
            command.add_argument("--spec", type=Path, required=True)
            command.add_argument("--spec-sha256", required=True)
        else:
            command.add_argument("--manifest", type=Path, required=True)
            command.add_argument("--runtime-root", required=True)
            command.add_argument("--context", type=Path, required=True)
            command.add_argument("--context-sha256", required=True)
    print(json.dumps(runtime_material_command(parser.parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
