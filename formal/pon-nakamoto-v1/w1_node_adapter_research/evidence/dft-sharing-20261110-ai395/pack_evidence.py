#!/usr/bin/env python3
"""Retain terminal files losslessly with content deduplication and fixed Git inputs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile


BASE_INPUT_COMMIT = "9133a2218890cfca837df34e7d6b892cec780868"
INPUT_PREFIX = "formal/pon-nakamoto-v1/w1_node_adapter_research/fixtures/node-input-v1/"
DEFAULT_GROUPS = {
    "receiver-experiment": "measurements/dft-abba",
    "python-and-source-checks": "validation-code",
    "p3-checks-and-precommit-observations": "dft-validation",
    "baseline-build": "tools/baseline-validation",
    "candidate-build": "tools/candidate-validation",
}
OPTIONAL_SETUP = (
    "tools/control-plane-manifest-restoration.json", "tools/registry-archives.json",
    "tools/metadata-default.json", "tools/metadata-all-features.json",
    "tools/cargo-fetch.log", "tools/cargo-fetch-public.log", "tools/cargo-fetch-adapter.log",
)
REPRODUCTION = ("run_dft_abba.py", "analyze_abba.py", "pack_evidence.py", "verify_retained.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--scripts-dir", type=Path, default=Path(__file__).resolve().parent)
    p.add_argument("--group", action="append", metavar="LABEL=PATH",
                   help="override all five retained group paths explicitly; paths may be relative to root")
    args = p.parse_args()
    groups = {label: args.root / relative for label, relative in DEFAULT_GROUPS.items()}
    if args.group is not None:
        groups = {}
        for item in args.group:
            label, separator, relative = item.partition("=")
            require(separator == "=" and label in DEFAULT_GROUPS and label not in groups,
                    "each recognized group needs one explicit path")
            require(bool(relative), "empty group path")
            path = Path(relative)
            groups[label] = path if path.is_absolute() else args.root / path
        require(set(groups) == set(DEFAULT_GROUPS), "all five original retained groups are required")
    refs = {}
    for name in ("packet.bin", "statement.bin", "sha.proof.bin", "arith.proof.bin", "operator-plan.json"):
        path = INPUT_PREFIX + name
        key = BASE_INPUT_COMMIT + ":" + path
        data = subprocess.check_output(["git", "show", key], cwd=args.repo)
        blob = subprocess.check_output(["git", "rev-parse", key], cwd=args.repo, text=True).strip()
        refs[sha(data)] = {"commit": BASE_INPUT_COMMIT, "path": path,
                           "git_blob": blob, "bytes": len(data)}
    entries, objects, directories = {}, {}, []

    def retain(name, path):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode), "nonregular retained file: " + str(path))
        data = path.read_bytes()
        after = path.lstat()
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "retained file changed during read: " + str(path))
        digest = sha(data)
        row = {"bytes": len(data), "sha256": digest, "mode": stat.S_IMODE(info.st_mode)}
        if digest in refs:
            require(len(data) == refs[digest]["bytes"], "fixed-input length mismatch")
            row["fixed_git_input"] = refs[digest]
        else:
            row["object"] = "objects/" + digest
            objects[digest] = data
        require(name not in entries, "duplicate retained path")
        entries[name] = row

    for label, root in groups.items():
        require(root.is_dir() and not root.is_symlink(), "missing/nonregular retained group: " + label)
        for path in sorted(root.rglob("*")):
            name = label + "/" + str(path.relative_to(root))
            mode = path.lstat().st_mode
            require(not stat.S_ISLNK(mode), "retained symlink is unsupported: " + str(path))
            if stat.S_ISDIR(mode):
                directories.append(name)
            else:
                retain(name, path)
    optional_absent = []
    for relative in OPTIONAL_SETUP:
        path = args.root / relative
        if path.exists():
            retain("setup-and-reproduction/" + relative, path)
        else:
            optional_absent.append(relative)
    for name in REPRODUCTION:
        path = args.scripts_dir / name
        require(path.is_file(), "missing reproduction script: " + str(path))
        retain("setup-and-reproduction/measurements/" + name, path)
    used_refs = {row["fixed_git_input"]["git_blob"] for row in entries.values()
                 if "fixed_git_input" in row}
    index = {"schema": "trnm-w1-dft-retained-files-v1", "entries": entries,
             "directories": directories, "fixed_git_inputs_available": len(refs),
             "fixed_git_inputs_referenced": len(used_refs),
             "retained_groups": {label: str(path) for label, path in groups.items()},
             "optional_setup_files_absent": optional_absent,
             "scope": "all terminal files under the five declared experiment/check directories plus listed setup/reproduction files; build targets, dependency caches and ELF executables are excluded",
             "executable_originals_included": False,
             "execution_authenticated_by_archive": False}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    archive = args.output / "records.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for digest, data in sorted(objects.items()):
            item = tarfile.TarInfo("objects/" + digest)
            item.size, item.mode, item.mtime = len(data), 0o644, 0
            tar.addfile(item, io.BytesIO(data))
    result = {"schema": "trnm-w1-dft-evidence-summary-v1",
              "retained_files": len(entries), "unique_objects": len(objects),
              "archive_bytes": archive.stat().st_size, "archive_sha256": sha(archive.read_bytes()),
              "index_bytes": (args.output / "index.json").stat().st_size,
              "index_sha256": sha((args.output / "index.json").read_bytes()),
              "qualified_improvement": None, "end_to_end_benefit": "NOT_ESTABLISHED",
              "production_activation": False, "qualification": "HOLD_NO_GO"}
    (args.output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
