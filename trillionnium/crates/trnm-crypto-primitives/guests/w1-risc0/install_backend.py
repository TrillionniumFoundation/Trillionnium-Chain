#!/usr/bin/env python3
"""Install only SHA-256-pinned public research tools into a new explicit path.

No shell installer, credentials, remote proving or consensus activation is used.
The compressed archives are hashed while streaming to limit temporary storage.
No downloaded program is executed until both archive digests have matched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile
import urllib.request


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > 2 * 1024**3:
            raise ValueError("official archive exceeds the explicit download cap")
        self.digest.update(data)
        return data


def download(url, expected, destination, compiler):
    files = 0
    extracted_bytes = 0
    with urllib.request.urlopen(url, timeout=120) as response:
        reader = HashingReader(response)
        with tarfile.open(fileobj=reader, mode="r|gz") as archive:
            for member in archive:
                parts = Path(member.name).parts
                if parts and parts[0] == ".":
                    parts = parts[1:]
                if compiler:
                    if parts and parts[0] not in ("bin", "lib"):
                        parts = parts[1:]
                    relative = Path(*parts) if parts else Path(".")
                    name = relative.as_posix()
                    selected = (
                        name == "bin/rustc"
                        or name.startswith("lib/librustc_driver-") and name.endswith(".so")
                        or name.startswith("lib/rustlib/riscv32im-risc0-zkvm-elf/lib/")
                        or name.startswith("lib/rustlib/x86_64-unknown-linux-gnu/lib/")
                        or name == "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
                        or name.startswith("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld")
                    )
                else:
                    relative = Path(member.name).name
                    selected = relative in ("r0vm", "cargo-risczero")
                    relative = Path(relative)
                if not selected:
                    continue
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("archive path escapes installation directory")
                output = destination / relative
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as source, output.open("xb") as target:
                        shutil.copyfileobj(source, target, 1024 * 1024)
                    output.chmod(member.mode & 0o777)
                    files += 1
                    extracted_bytes += member.size
                elif member.issym():
                    target = (output.parent / member.linkname).resolve()
                    if not target.is_relative_to(destination):
                        raise ValueError("archive link escapes installation directory")
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.symlink_to(member.linkname)
                elif member.islnk() and compiler:
                    link_parts = Path(member.linkname).parts
                    if link_parts and link_parts[0] == ".":
                        link_parts = link_parts[1:]
                    if link_parts and link_parts[0] not in ("bin", "lib"):
                        link_parts = link_parts[1:]
                    target = (destination / Path(*link_parts)).resolve()
                    if not target.is_relative_to(destination) or not target.is_file():
                        raise ValueError("missing or escaping official hard-link target")
                    output.parent.mkdir(parents=True, exist_ok=True)
                    os.link(target, output)
                else:
                    raise ValueError("unexpected selected archive member type")
        while reader.read(1024 * 1024):
            pass
        actual = reader.digest.hexdigest()
    if actual != expected:
        raise ValueError(f"archive SHA-256 mismatch: {actual} != {expected}")
    return {"url": url, "sha256": actual, "downloaded_bytes": reader.count,
            "extracted_files": files, "extracted_bytes": extracted_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("this exact research tool profile requires Linux x86_64")
    destination = args.dest.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / "backend-manifest.json").read_text())
    observations = []
    try:
        observations.append(download(
            "https://github.com/risc0/risc0/releases/download/v3.0.6/"
            "cargo-risczero-x86_64-unknown-linux-gnu.tgz",
            manifest["official_linux_tools_sha256"], destination / "tools", False))
        observations.append(download(
            "https://github.com/risc0/rust/releases/download/r0.1.97.0/"
            "rust-toolchain-x86_64-unknown-linux-gnu.tar.gz",
            manifest["official_linux_guest_compiler_archive_sha256"],
            destination / "guest-compiler", True))
        for executable in [destination / "tools/r0vm", destination / "tools/cargo-risczero",
                           destination / "guest-compiler/bin/rustc"]:
            if not executable.is_file():
                raise ValueError(f"missing required official executable: {executable}")
            executable.chmod(0o755)
    except BaseException:
        # This invocation owns the new directory. Never leave unverified tools.
        shutil.rmtree(destination)
        raise
    print(json.dumps({"schema": "pon-w1-pinned-tools-v1", "archives": observations,
                      "proof_generated": False}, indent=2))


if __name__ == "__main__":
    main()
