"""Reproduce the retained HEPLCP04 codec vector with exact original Rust inputs.

This isolated assembly shim is not a Hepta daemon or a signature verifier.
Use fresh --workspace and --output directories; cached Cargo dependencies are required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

SOURCE = "afd2c91b3b9ef75ab9a174e3af772ad322118f7a"
FIXTURE = "b873d6f0606100ec8a3246548009b6afda5aa9fbc55e2bd85a4c6fed7fd81a46"
INPUT = "evidence/hepta-real-native-adoption-20261108/chain-reader/adopt-v1/completed.bin"
INPUT_SHA = "49687e0ece90dceb6409978616700c0b32ec342631a1941994ae3b7a886a7496"
ASSETS = {
    "isolated-workspace.toml": ("Cargo.toml", "55c81c4442579fde9b0ec24df5bd6ec3207bb9396335e35379b1d3b5a63f8967"),
    "exporter-package.toml": ("exporter/Cargo.toml", "48df099731415f266126195f9d90165b8754ee7fa50b7e412826bd4b8e6defb3"),
    "isolated-Cargo.lock": ("Cargo.lock", "fe6962b19cb111e8c1d472b9f008aa6b42b56e5b56fc85e1afb58831bc5941d3"),
    "exporter.rs": ("exporter/src/main.rs", "b8eb3e03193345d195b62d7f41ff2608628ff445ca335f7c23e9e5a96d325665"),
}
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
def require(condition, message):
    if not condition:
        raise ValueError(message)
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hepta-source", "chain-source", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    hepta, chain = args.hepta_source.resolve(), args.chain_source.resolve()
    workspace, output = args.workspace.resolve(), args.output.resolve()
    require(not workspace.exists() and not output.exists() and workspace != output, "fresh directories required")
    require(not workspace.is_relative_to(output) and not output.is_relative_to(workspace), "separate output/workspace required")
    require(all(not p.is_relative_to(root) for p in (workspace, output) for root in (hepta, chain)), "use external directories")
    require(git(hepta, "rev-parse", "HEAD") == SOURCE, "wrong Hepta source")
    require(not git(hepta, "status", "--porcelain", "--untracked-files=all"), "Hepta checkout must be clean")
    evidence = chain / "evidence/heplcp04-interop-20261111"
    raw_manifest = (evidence / "SOURCE_MANIFEST.json").read_bytes()
    require(sha(raw_manifest) == "9c697cb58edcc19b3852a86b1ea49b92cface798c267168677ed819d4d2e1013", "manifest changed")
    manifest = json.loads(raw_manifest)
    require(manifest["hepta_source_commit"] == SOURCE and git(hepta, "rev-parse", "HEAD^{tree}") == manifest["source_tree"], "source tree mismatch")
    paths = git(hepta, "ls-tree", "-r", "--name-only", "HEAD", "--", "codex-rs/hepta-types",
                "codex-rs/hepta-learning-artifacts", "codex-rs/hepta-agentd/src/learning_iteration_checkpoint_codec.rs").splitlines()
    require(set(paths) == {r["source_path"] for r in manifest["files"]} and len(paths) == len(manifest["files"]), "incomplete source manifest")
    workspace.mkdir(mode=0o700); output.mkdir(mode=0o700)
    inputs, source_before = {}, {}
    def retain(destination, raw):
        path = workspace / destination
        require(not Path(destination).is_absolute() and ".." not in Path(destination).parts, "invalid destination")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        inputs[str(path)] = sha(raw)
    for row in manifest["files"]:
        source_path = hepta / row["source_path"]
        require(source_path.is_file() and not source_path.is_symlink(), "nonregular source")
        raw = source_path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"] and
                blob == row["git_blob"] == git(hepta, "rev-parse", "HEAD:" + row["source_path"]), "source bytes changed")
        source_before[str(source_path)] = sha(raw)
        retain(row["workspace_path"], raw)
    for name, (destination, digest) in ASSETS.items():
        raw = (evidence / name).read_bytes()
        require(sha(raw) == digest, "assembly asset changed: " + name)
        retain(destination, raw)
    original = (chain / INPUT).read_bytes()
    require(sha(original) == INPUT_SHA, "original input changed")
    retain("original-input.bin", original)
    overrides = {"CARGO_TARGET_DIR": str(workspace / "target"), "CARGO_NET_OFFLINE": "true"}
    env = dict(os.environ, **overrides)
    command = [shutil.which("cargo") or "cargo", "run", "--locked", "--offline", "--manifest-path",
               str(workspace / "Cargo.toml"), "-p", "heplcp04-interop-export", "--", str(workspace / "original-input.bin")]
    started = time.monotonic()
    with (output / "stdout.json").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
        result = subprocess.run(command, cwd=workspace, env=env, stdout=stdout, stderr=stderr, check=False)
    after = {path: sha(Path(path).read_bytes()) for path in inputs}
    source_after = {path: sha(Path(path).read_bytes()) for path in source_before}
    binary = workspace / "target/debug/heplcp04-interop-export"
    output_hash = sha((output / "stdout.json").read_bytes())
    record = dict(scope="isolated-original-codec-and-coordinator-only", command=command, cwd=str(workspace),
        explicit_environment=overrides, build_environment={k: env.get(k) for k in ("RUSTFLAGS", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_TARGET", "CARGO_ENCODED_RUSTFLAGS")},
        returncode=result.returncode, elapsed_seconds=time.monotonic() - started, source_commit=SOURCE,
        inputs_before=inputs, inputs_after=after, source_before=source_before, source_after=source_after,
        binary_sha256=sha(binary.read_bytes()) if binary.is_file() else None, stdout_sha256=output_hash,
        stderr_sha256=sha((output / "stderr.log").read_bytes()), matches_retained_fixture=output_hash == FIXTURE,
        ordinary_task_executed=False, hepta_final_use_accepted=False, qualification="HOLD_NO_GO")
    (output / "RESULT.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    require(result.returncode == 0 and inputs == after and source_before == source_after and output_hash == FIXTURE,
            "native replay failed, changed source, or differs from retained fixture; original logs retained")
if __name__ == "__main__":
    main()
