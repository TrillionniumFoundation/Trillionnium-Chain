"""Call only the actual frozen private Rust layout method in an isolated test crate."""
import hashlib
import os
from pathlib import Path
import tomllib

from hia.tests.native_support import unlinked_path
from hia.tests.test_da_cell_tensor_reader_framing import TENSOR, TENSOR_SHA
from hia.tests.test_da_chunk_inclusion_path import observed_artifact, tracked, git_blob, ROOT
from hia.tests.test_da_protocol_context import _run

FIXTURE = Path(__file__).with_name("rust_da_cell_tensor_reader_layout_fixture.rs")
LOCAL = "hia_da_tensor_layout_fixture.rs"
TEST = "cell::tensor::hia_da_tensor_layout_fixture::original_private_layout_observe"
MARKER = b"TRNM_DA_TENSOR_LAYOUT_EXACT_V1"
APPEND = b'\n#[cfg(test)]\n#[path = "'+LOCAL.encode()+b'"]\nmod hia_da_tensor_layout_fixture;\n'
MAX_CAPTURE = 4 << 20
MAX_PACKET = 192 << 20


def real_layout(directory, stream):
    if type(stream) is not bytes or not 0 < len(stream) <= MAX_PACKET:
        raise ValueError("Unexpected original synthetic input extent")
    if hashlib.sha256(TENSOR.read_bytes()).hexdigest()!=TENSOR_SHA:
        raise ValueError("Frozen Rust tensor source pin changed")
    cargo = os.environ.get("TRNM_HIA_CARGO","cargo")
    rustc = os.environ.get("TRNM_HIA_RUSTC","rustc")
    rust = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if _run([rustc,"--version"]).stdout.decode().split()[1]!=rust:
        raise ValueError("Original tensor witness requires pinned Rust")
    blobs=tracked()
    for rel,sha in blobs.items():
        original=unlinked_path(ROOT/rel).read_bytes()
        if git_blob(original)!=sha:
            raise ValueError("Tracked original dependency was replaced")
        dest=directory/rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open("xb") as f:
            f.write(original)
    rel=TENSOR.relative_to(ROOT)
    owner=directory/rel
    raw=owner.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=TENSOR_SHA or git_blob(raw)!=blobs[rel]:
        raise ValueError("Exact tensor owner was not copied")
    fixture=unlinked_path(FIXTURE).read_bytes()
    witness=owner.with_name(LOCAL)
    capture=directory/"tensor-layout-capture.bin"
    common=["--manifest-path",str(directory/"trillionnium/Cargo.toml"),"--locked","--offline",
            "--package","trnm-data-availability","--lib","--target-dir",str(directory/"target"),
            "--message-format=json"]
    env={**os.environ,"RUSTC":rustc,"CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    clean=observed_artifact(_run([cargo,"build",*common],env=env),directory,False)
    pure=clean.read_bytes()
    with witness.open("xb") as handle:
        handle.write(fixture)
    try:
        owner.write_bytes(raw+APPEND)
        if owner.read_bytes()!=raw+APPEND:
            raise ValueError("Not the exact frozen original plus test-only leaf")
        test=observed_artifact(_run([cargo,"test",*common,"--no-run"],env=env),directory,True)
        if MARKER not in test.read_bytes() or clean.read_bytes()!=pure:
            raise ValueError("No test-only original artifact, or non-test artifact changed")
        observed=_run([str(test),TEST,"--exact","--test-threads=1"],stream,timeout=55,
                      env={**env,"TRNM_DA_TENSOR_LAYOUT_CAPTURE":str(capture)})
        if observed.stderr or TEST.encode() not in observed.stdout or b"1 passed" not in observed.stdout:
            raise ValueError("Missing genuine private original execution")
        if owner.read_bytes()!=raw+APPEND or witness.read_bytes()!=fixture:
            raise ValueError("Private original test source changed during execution")
    finally:
        owner.write_bytes(raw)
        witness.unlink()
    clean.unlink()
    after=observed_artifact(_run([cargo,"build",*common],env=env),directory,False)
    if after.read_bytes()!=pure or MARKER in pure or witness.exists() or FIXTURE.read_bytes()!=fixture:
        raise ValueError("Restored production artifact differs or contains test witness")
    for rel,sha in blobs.items():
        physical=unlinked_path(ROOT/rel).read_bytes()
        if unlinked_path(directory/rel).read_bytes()!=physical or git_blob(physical)!=sha:
            raise ValueError("Frozen dependency changed between original observations")
    capture=unlinked_path(capture)
    if capture.stat().st_size>MAX_CAPTURE:
        raise ValueError("Original capture exceeded its fixed cap")
    data=capture.read_bytes()
    if not data.startswith(MARKER):
        raise ValueError("Missing authentic test-only original marker")
    return data[len(MARKER):],hashlib.sha256(pure).hexdigest()
