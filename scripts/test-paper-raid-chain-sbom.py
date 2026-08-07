#!/usr/bin/env python3
"""Offline tamper self-test for the Paper Raid Chain SBOM kernel (no Cargo)."""

from __future__ import annotations

import copy
import hashlib
import pathlib
import tempfile

from paper_raid_chain_sbom_lib import (
    EvidenceError,
    TARGETS,
    build_artifacts,
    canonical_json,
    verify_artifacts,
)


def write(path: pathlib.Path, value: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8") if isinstance(value, str) else value)


def expect_rejected(label: str, operation) -> None:
    try:
        operation()
    except EvidenceError:
        return
    raise AssertionError(f"tamper case was accepted: {label}")


def fixture(base: pathlib.Path):
    source = base / "source"
    workspace = source / "trillionnium"
    write(
        source / "rust-toolchain.toml",
        '[toolchain]\nchannel = "1.95.0"\nprofile = "minimal"\n',
    )
    package_ids: dict[str, str] = {}
    packages: list[dict] = []
    nodes: list[dict] = []
    dependency_id = "registry+https://github.com/rust-lang/crates.io-index#shared-dep@1.2.3"
    dependency_checksum = "d" * 64
    for target in TARGETS:
        package = target["package"]
        package_id = f"path+file://{workspace}/crates/{package}#0.1.0"
        package_ids[package] = package_id
        manifest = workspace / "crates" / package / "Cargo.toml"
        write(manifest, f'[package]\nname = "{package}"\nversion = "0.1.0"\n')
        targets = [
            {
                "kind": ["bin"],
                "name": target["binary"],
                "required-features": list(target["features"]),
                "src_path": str(manifest.parent / "src" / "main.rs"),
            }
        ]
        write(manifest.parent / "src" / "main.rs", "fn main() {}\n")
        if package == "trnm-consensus-app":
            write(manifest.parent / "build.rs", "fn main() {}\n")
            targets.append(
                {
                    "kind": ["custom-build"],
                    "name": "build-script-build",
                    "required-features": [],
                    "src_path": str(manifest.parent / "build.rs"),
                }
            )
        packages.append(
            {
                "checksum": None,
                "id": package_id,
                "manifest_path": str(manifest),
                "name": package,
                "source": None,
                "targets": targets,
                "version": "0.1.0",
            }
        )
        nodes.append(
            {
                "deps": [
                    {
                        "dep_kinds": [{"kind": None, "target": None}],
                        "name": "shared_dep",
                        "pkg": dependency_id,
                    }
                ],
                "features": list(target["features"]),
                "id": package_id,
            }
        )
    packages.append(
        {
            "checksum": dependency_checksum,
            "id": dependency_id,
            "manifest_path": "/cargo/registry/shared-dep-1.2.3/Cargo.toml",
            "name": "shared-dep",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "targets": [],
            "version": "1.2.3",
        }
    )
    nodes.append({"deps": [], "features": [], "id": dependency_id})
    lock_lines = ["version = 4", ""]
    for target in TARGETS:
        lock_lines.extend(
            [
                "[[package]]",
                f'name = "{target["package"]}"',
                'version = "0.1.0"',
                "",
            ]
        )
    lock_lines.extend(
        [
            "[[package]]",
            'name = "shared-dep"',
            'version = "1.2.3"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{dependency_checksum}"',
            "",
        ]
    )
    write(workspace / "Cargo.lock", "\n".join(lock_lines))
    metadata_path = base / "metadata.json"
    metadata = {
        "packages": packages,
        "resolve": {"nodes": nodes, "root": None},
        "target_directory": str(base / "ignored-target"),
        "version": 1,
        "workspace_members": list(package_ids.values()),
        "workspace_root": str(workspace),
    }
    write(metadata_path, canonical_json(metadata))

    lock_path = base / "components.lock.json"
    component_lock = {
        "components": [
            {
                "component_id": "canonical-chain",
                "cargo_lock_sha256": "",
                "live_binaries": [
                    {
                        key: target[key]
                        for key in ("artifact_id", "binary", "cargo_profile", "package")
                    }
                    for target in TARGETS
                ],
                "project_id": "trillionnium-chain",
                "revision": "a" * 40,
                "rust_toolchain_sha256": "",
                "source_tree": "b" * 40,
                "working_tree_dirty": False,
            }
        ],
        "schema": 1,
    }
    component_lock["components"][0]["cargo_lock_sha256"] = hashlib.sha256(
        (workspace / "Cargo.lock").read_bytes()
    ).hexdigest()
    component_lock["components"][0]["rust_toolchain_sha256"] = hashlib.sha256(
        (source / "rust-toolchain.toml").read_bytes()
    ).hexdigest()
    write(lock_path, canonical_json(component_lock))

    binaries_a: dict[str, pathlib.Path] = {}
    binaries_b: dict[str, pathlib.Path] = {}
    for target in TARGETS:
        name = target["binary"]
        binaries_a[name] = base / "build-a" / name
        binaries_b[name] = base / "build-b" / name
        content = f"synthetic deterministic binary:{name}\n".encode()
        write(binaries_a[name], content)
        write(binaries_b[name], content)

    script_root = pathlib.Path(__file__).resolve().parent
    tools = {
        "gate": script_root / "check-paper-raid-chain-sbom.sh",
        "generator": script_root / "generate-paper-raid-chain-sbom.py",
        "library": script_root / "paper_raid_chain_sbom_lib.py",
        "verifier": script_root / "verify-paper-raid-chain-sbom.py",
    }
    cargo_version_path = base / "cargo-version-verbose.txt"
    rustc_version_path = base / "rustc-version-verbose.txt"
    write(
        cargo_version_path,
        "cargo 1.95.0 (111111111 2026-01-01)\n"
        "release: 1.95.0\n"
        f"commit-hash: {'1' * 40}\n"
        "commit-date: 2026-01-01\n"
        "host: x86_64-unknown-linux-gnu\n",
    )
    write(
        rustc_version_path,
        "rustc 1.95.0 (222222222 2026-01-01)\n"
        "binary: rustc\n"
        f"commit-hash: {'2' * 40}\n"
        "commit-date: 2026-01-01\n"
        "host: x86_64-unknown-linux-gnu\n"
        "release: 1.95.0\n"
        "LLVM version: 21.1.0\n",
    )
    arguments = {
        "metadata_path": metadata_path,
        "source_root": source,
        "revision": "a" * 40,
        "source_tree": "b" * 40,
        "component_lock_path": lock_path,
        "cargo_version_path": cargo_version_path,
        "rustc_version_path": rustc_version_path,
        "binaries_a": binaries_a,
        "binaries_b": binaries_b,
        "tool_paths": tools,
    }
    return arguments, metadata, component_lock


def main() -> None:
    gate_text = (
        pathlib.Path(__file__).resolve().parent / "check-paper-raid-chain-sbom.sh"
    ).read_text(encoding="utf-8")
    archive_index = gate_text.index('git archive --format=tar "$revision"')
    symlink_index = gate_text.index('archive_symlink=$(find "$scratch/source"')
    first_cargo_index = gate_text.index('cargo --version --verbose')
    if not archive_index < symlink_index < first_cargo_index:
        raise AssertionError("archive symlink rejection must precede every Cargo invocation")
    for signal_guard in ("trap cleanup EXIT", "trap 'exit 130' INT", "trap 'exit 143' TERM"):
        if signal_guard not in gate_text:
            raise AssertionError(f"missing fail-stop signal guard: {signal_guard}")
    for publication_guard in (
        "evidence parent must be owned by the invoking uid and not group/world writable",
        "evidence staging identity changed before publication",
        "evidence artifact set differs",
        "os.O_NOFOLLOW | os.O_NONBLOCK",
        "renameat2(",
        "published evidence identity differs from staging",
        "A successful gate must also remove the build scratch before printing PASS",
    ):
        if publication_guard not in gate_text:
            raise AssertionError(
                f"missing atomic evidence publication guard: {publication_guard}"
            )
    with tempfile.TemporaryDirectory(prefix="trnm-chain-sbom-selftest-") as raw_base:
        base = pathlib.Path(raw_base)
        arguments, metadata, component_lock = fixture(base / "fixture-a")
        sbom, provenance = build_artifacts(**arguments)
        second_arguments, _, _ = fixture(base / "fixture-b")
        second_sbom, second_provenance = build_artifacts(**second_arguments)
        if canonical_json(sbom) != canonical_json(second_sbom):
            raise AssertionError("different extraction roots changed canonical SBOM bytes")
        if canonical_json(provenance) != canonical_json(second_provenance):
            raise AssertionError("different extraction roots changed canonical provenance bytes")
        combined_evidence = canonical_json(sbom) + canonical_json(provenance)
        for temporary_path in (base, arguments["source_root"], second_arguments["source_root"]):
            if str(temporary_path).encode("utf-8") in combined_evidence:
                raise AssertionError(
                    f"temporary extraction path leaked into evidence: {temporary_path}"
                )
        sbom_path = base / "candidate.cdx.json"
        provenance_path = base / "candidate.provenance.json"
        write(sbom_path, canonical_json(sbom))
        write(provenance_path, canonical_json(provenance))

        verify_arguments = dict(arguments)
        verify_arguments.update(sbom_path=sbom_path, provenance_path=provenance_path)
        verify_artifacts(**verify_arguments)

        missing_component = copy.deepcopy(sbom)
        missing_component["components"].pop()
        write(sbom_path, canonical_json(missing_component))
        expect_rejected("missing SBOM component", lambda: verify_artifacts(**verify_arguments))
        write(sbom_path, canonical_json(sbom))

        volatile = copy.deepcopy(sbom)
        volatile["metadata"]["timestamp"] = "1970-01-01T00:00:00Z"
        write(sbom_path, canonical_json(volatile))
        expect_rejected("fabricated timestamp", lambda: verify_artifacts(**verify_arguments))
        write(sbom_path, canonical_json(sbom))

        write(sbom_path, '{"bomFormat":"CycloneDX","bomFormat":"forged"}\n')
        expect_rejected("duplicate JSON key", lambda: verify_artifacts(**verify_arguments))
        write(sbom_path, canonical_json(sbom))

        metadata_path = arguments["metadata_path"]
        duplicate_metadata = copy.deepcopy(metadata)
        duplicate_metadata["packages"].append(copy.deepcopy(duplicate_metadata["packages"][0]))
        write(metadata_path, canonical_json(duplicate_metadata))
        expect_rejected("duplicate cargo package", lambda: verify_artifacts(**verify_arguments))
        write(metadata_path, canonical_json(metadata))

        missing_metadata = copy.deepcopy(metadata)
        missing_metadata["packages"].pop()
        write(metadata_path, canonical_json(missing_metadata))
        expect_rejected("dependency closure missing package", lambda: verify_artifacts(**verify_arguments))
        write(metadata_path, canonical_json(metadata))

        null_registry_checksum = copy.deepcopy(metadata)
        for package in null_registry_checksum["packages"]:
            if package.get("name") == "shared-dep":
                package["checksum"] = None
        write(metadata_path, canonical_json(null_registry_checksum))
        verify_artifacts(**verify_arguments)
        mismatched_registry_checksum = copy.deepcopy(metadata)
        for package in mismatched_registry_checksum["packages"]:
            if package.get("name") == "shared-dep":
                package["checksum"] = "e" * 64
        write(metadata_path, canonical_json(mismatched_registry_checksum))
        expect_rejected(
            "present cargo metadata checksum drift",
            lambda: verify_artifacts(**verify_arguments),
        )
        write(metadata_path, canonical_json(metadata))

        lock_path = arguments["source_root"] / "trillionnium" / "Cargo.lock"
        original_lock = lock_path.read_bytes()
        write(lock_path, original_lock.replace(b'\n[[package]]\nname = "shared-dep"', b'\n# removed\nname = "shared-dep"'))
        expect_rejected("Cargo.lock missing dependency", lambda: verify_artifacts(**verify_arguments))
        write(lock_path, original_lock)

        build_script = (
            arguments["source_root"]
            / "trillionnium/crates/trnm-consensus-app/build.rs"
        )
        original_build_script = build_script.read_bytes()
        write(build_script, b"fn main() { panic!(\"tampered\") }\n")
        expect_rejected("build script hash drift", lambda: verify_artifacts(**verify_arguments))
        write(build_script, original_build_script)

        cargo_version = arguments["cargo_version_path"]
        original_cargo_version = cargo_version.read_bytes()
        write(cargo_version, original_cargo_version.replace(b"release: 1.95.0", b"release: 1.94.0"))
        expect_rejected("Cargo toolchain evidence drift", lambda: verify_artifacts(**verify_arguments))
        write(cargo_version, original_cargo_version)

        binary_b = arguments["binaries_b"]["trnm-chain-cli"]
        original_binary = binary_b.read_bytes()
        write(binary_b, original_binary + b"tamper")
        expect_rejected("isolated binary mismatch", lambda: verify_artifacts(**verify_arguments))
        write(binary_b, original_binary)

        lock_fixture_path = arguments["component_lock_path"]
        duplicate_lock = copy.deepcopy(component_lock)
        duplicate_lock["components"][0]["live_binaries"].append(
            copy.deepcopy(duplicate_lock["components"][0]["live_binaries"][0])
        )
        write(lock_fixture_path, canonical_json(duplicate_lock))
        expect_rejected("duplicate Integration live binary", lambda: verify_artifacts(**verify_arguments))
        write(lock_fixture_path, canonical_json(component_lock))

        symlink = arguments["source_root"] / "forbidden-link"
        symlink.symlink_to("rust-toolchain.toml")
        expect_rejected("source symlink", lambda: verify_artifacts(**verify_arguments))
        symlink.unlink()

        verify_artifacts(**verify_arguments)
    print("Paper Raid Chain SBOM offline tamper self-test: PASS")


if __name__ == "__main__":
    main()
