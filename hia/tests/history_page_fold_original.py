"""Pinned original exact private method with a narrow in-memory SQLite adapter."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tomllib

from hia.tests.cell_held_rows_original import run
from hia.tests.history_inline_record_original import RUST_ROOT, ROOT, ORIGINAL, SOURCES, PREFIX

REFERENCE=Path(__file__).with_name("rust_history_page_fold_reference.rs")
PACKAGE="trnm-held-history-page-reference"


def sha(data):
    return sha256(data).hexdigest()


def extract():
    sources={k:(RUST_ROOT/k).read_bytes() for k in SOURCES}
    if {k:sha(v) for k,v in sources.items()}!=SOURCES:
        raise ValueError("Exact frozen history source closure changed")
    history=sources[PREFIX+"store/history_page.rs"]
    store=sources[PREFIX+"store.rs"]
    error=sources[PREFIX+"error.rs"]
    ledger=sources[PREFIX+"consensus.rs"]

    def crop(raw,begin,end):
        a=raw.index(begin)
        return raw[a:raw.index(end,a)]

    def once(raw,pattern):
        r,=re.findall(pattern,raw,re.MULTILINE|re.DOTALL)
        return r

    method=once(history,rb"^    fn history_page_ancestors\(.*?^    }\n")
    query=once(method,rb'"WITH RECURSIVE ancestry\(id,parent,ordinal\) AS \(.*?ORDER BY a.ordinal"')
    assert method.count(query)==1
    held=crop(history,b"const ANCESTOR_BATCH",b"// Keep fixed-field SQL values inline")
    htypes=crop(history,b"struct InlineSqlBlob",b"#[cfg(test)]\ntype RawRecord")
    access=(crop(store,b"fn bytes32(",b"// Packet::encode/decode")
            +crop(store,b"struct FixedSqlBlob",b"fn canonical<")
            +crop(store,b"#[derive(Clone)]\nstruct Record {",b"// Private native output parts"))
    work=(crop(ledger,b"#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]",b"impl Ord for Work")
          +crop(ledger,b"impl Work {",b"    pub fn from_target(")+b"}\n")
    # Same actual local identities, cause and conversions. Peer/transport paths
    # aren't part of the method and aren't loaded into this isolated fixture.
    errors=(crop(error,b"use std::{error, fmt};",b"    /// A failed reconstruction/recovery")
            +crop(error,b"    fn caused_by(",b"impl From<serde_json::Error>"))
    lib=once(sources[PREFIX+"lib.rs"],rb"^pub\(crate\) fn ensure\(.*?^}\n")
    harness=REFERENCE.read_bytes()
    for token,value in [(b"    // EXACT_ORIGINAL_HISTORY_PAGE_ANCESTORS",method),
                        (b"// EXACT_ORIGINAL_RECURSIVE_SQL",query)]:
        if harness.count(token)!=1:
            raise ValueError("Missing unique exact original insertion point")
        harness=harness.replace(token,value)
    return {"frozen.rs":held+htypes+access+work+errors+lib,"main.rs":harness},dict(
        original=dict(hashes=SOURCES,method=sha(method),query=sha(query)),
        extracted={name:sha(value) for name,value in dict(held=held,htypes=htypes,access=access,
                   work=work,errors=errors,lib=lib,method=method,query=query).items()})


def original(where):
    git=["git","-C",ROOT]
    def check():
        if run([*git,"rev-parse","HEAD:trillionnium"]).decode().strip()!=ORIGINAL:
            raise ValueError("Wrong frozen project Rust tree")
        run([*git,"diff","--quiet","HEAD","--","trillionnium"])
        return extract()
    exact,pins=check()
    src=where/"src"
    src.mkdir()
    for name,raw in exact.items():
        (src/name).write_bytes(raw)
    (where/"Cargo.toml").write_text(f"""[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
rusqlite = {{ version = "=0.41.1", features = ["bundled", "fallible_uint", "hooks"] }}
""")
    base=tomllib.loads((RUST_ROOT/"Cargo.lock").read_text())["package"]
    closed={(x["name"],x["version"],x.get("source"),x.get("checksum")) for x in base}
    channel=tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc=os.environ.get("TRNM_HIA_RUSTC","rustc")
    cargo=os.environ.get("TRNM_HIA_CARGO","cargo")
    tools=[run([cmd,"--version"]).decode().strip() for cmd in (cargo,rustc)]
    if [s.split()[:2] for s in tools]!=[["cargo",channel],["rustc",channel]]:
        raise ValueError("Pinned original Rust compiler and Cargo required")
    target=where/"target"
    env={**os.environ,"RUSTC":rustc,"CARGO_TARGET_DIR":str(target),
         "CARGO_PROFILE_DEV_DEBUG":"0","CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"1"}
    run([cargo,"generate-lockfile","--offline"],cwd=where,env=env)
    lock=(where/"Cargo.lock").read_bytes()
    subset=tomllib.loads(lock.decode())["package"]
    exact_deps={(x["name"],x["version"],x.get("source"),x.get("checksum")) for x in subset if x["name"]!=PACKAGE}
    if not exact_deps or not exact_deps<=closed or any(not d[3] for d in exact_deps):
        raise ValueError("Tiny original SQLite graph is not workspace checksum-locked")
    [host]=[s.removeprefix("host: ") for s in run([rustc,"-vV"]).decode().splitlines() if s.startswith("host: ")]
    metadata=json.loads(run([cargo,"metadata","--locked","--offline","--format-version","1",
                             "--filter-platform",host],cwd=where,env=env))
    tree=run([cargo,"build","--offline","--locked","--message-format=json"],cwd=where,env=env,timeout=120)
    events=[json.loads(x) for x in tree.splitlines()]
    if events[-1]!={"reason":"build-finished","success":True}:
        raise ValueError("No successful pinned SQLite build")
    artifacts=[e for e in events if e["reason"]=="compiler-artifact"]
    active={x["id"] for x in metadata["packages"]}
    if {e["package_id"] for e in artifacts}!=active:
        raise ValueError("Actual SQLite active graph differs")
    [lib]=[x for x in artifacts if x["package_id"].endswith("rusqlite@0.41.1")]
    if lib["fresh"] or not {"bundled","fallible_uint","hooks"}<=set(lib["features"]):
        raise ValueError("Wrong actual original SQLite frontend features")
    [static]=[e for e in events if e["reason"]=="build-script-executed" and
              e["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [native]=static["linked_paths"]
    if (not native.startswith("native=") or static["linked_libs"]!=["static=sqlite3"]
            or not Path(native[7:]).resolve(strict=True).is_relative_to(target)):
        raise ValueError("Missing locked actual bundled SQLite static library")
    [binary]=[Path(x["executable"]) for x in artifacts if x.get("executable") and x["target"]["name"]==PACKAGE]
    assert binary.is_relative_to(target)
    inert=where/"inert"
    inert.mkdir()
    out=run([str(binary)],env={},cwd=inert,timeout=15)
    if any(inert.iterdir()) or check()!=(exact,pins) or (where/"Cargo.lock").read_bytes()!=lock or any(
        (src/name).read_bytes()!=value for name,value in exact.items()
    ):
        raise ValueError("Fixture modified source or wrote to its execution directory")
    return out,dict(pins=pins,compilers=tools,lock=sha(lock),active=sorted(a.rsplit("#",1)[-1] for a in active),
                    dependencies=sorted(exact_deps),rusqlite=lib["features"],sqlite_link=static["linked_libs"],
                    harness=sha(REFERENCE.read_bytes()),captured_sources={k:sha(v) for k,v in exact.items()},
                    bundled_sqlite=sha((Path(native[7:])/"libsqlite3.a").read_bytes()))
