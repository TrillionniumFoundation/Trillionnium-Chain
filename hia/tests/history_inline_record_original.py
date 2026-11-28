"""Use the complete unchanged method and the actual locked rusqlite/Node crates."""
from hashlib import sha256
import json
import os
from pathlib import Path
import tomllib

from hia.tests.test_cell_model_artifact import ROOT, RUST_ROOT, ORIGINAL, PINS, execute

REFERENCE = Path(__file__).with_name("rust_history_inline_record_reference.rs")
PREFIX = "crates/trnm-pon-node/src/"
SOURCES = {
    **PINS,
    PREFIX+"store/history_page.rs": "43c2f10765dd16c5f8b51ec9f667667866180b9963b10da7304095bea3ed3e16",
    PREFIX+"store.rs": "9d79fd3c37db4a664d0a01b89e943276e07d2800cc64cb4986a1452ccf8fb820",
    PREFIX+"consensus.rs": "dbbd44790428ae0aff32d7305e062a6fc09ca0add0e3c4c077deefd8bfec760d",
    PREFIX+"error.rs": "0f7952a02aca0dfc9d6da3f38e6a1883b7943ad5b9ab94cfef9b4036dd1395fc",
}


def extract():
    def part(name, first, last):
        raw = (RUST_ROOT/(PREFIX+name)).read_bytes()
        at = raw.index(first)
        return raw[at:raw.index(last,at)]
    # The exact original function, Row getter type, Record and ensure body.
    return (part("store/history_page.rs",b"struct InlineSqlBlob",b"#[cfg(test)]\ntype RawRecord")
            +part("store.rs",b"#[derive(Clone)]\nstruct Record {", b"// Private native output parts")
            +part("lib.rs",b"pub(crate) fn ensure(",b"pub fn digest("))


def original(directory, *, held_link=False):
    link_options = []
    if held_link:
        from hia.tests.history_inline_record_held_link import prepare
        driver_override, archive = prepare(directory)
        archive_before = archive.read_bytes()
        link_options = ["-L",f"native={directory}","-l","static=trnm_history_inline_record_fixture"]
    git = ["git","-C",ROOT]
    def check():
        if execute([*git,"rev-parse","HEAD:trillionnium"]).stdout.decode().strip()!=ORIGINAL:
            raise ValueError("Wrong original workspace tree")
        execute([*git,"diff","--quiet","HEAD","--","trillionnium"])
        for name,digest in SOURCES.items():
            if sha256((RUST_ROOT/name).read_bytes()).hexdigest()!=digest:
                raise ValueError(f"Wrong frozen source {name}")
    check()
    frozen = extract()
    (directory/"frozen_inline_record.rs").write_bytes(frozen)
    probe = directory/"reference.rs"
    driver = REFERENCE.read_bytes()
    submitted = driver_override if held_link else driver
    probe.write_bytes(submitted)
    request = os.environ.get("TRNM_HIA_RUSTC","rustc")
    pinned = tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([request,"--version"]).stdout
    sysroot = Path(execute([request,"--print","sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc,cargo = sysroot/"bin/rustc",sysroot/"bin/cargo"
    if version.decode().split()[1]!=pinned or execute([rustc,"--version"]).stdout!=version:
        raise ValueError("Wrong original Rust version")
    target = directory/"cargo-target"
    env={**os.environ,"RUSTC":str(rustc),"CARGO_BUILD_JOBS":"1",
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    out=execute([cargo,"build","--locked","--offline","--no-default-features","--lib","-p","trnm-pon-node",
                 "--manifest-path",RUST_ROOT/"Cargo.toml","--target-dir",target,
                 "--message-format=json"],env=env,timeout=360).stdout
    rows=[json.loads(line) for line in out.splitlines()]
    if rows[-1]!={"reason":"build-finished","success":True}:
        raise ValueError("No successful original locked build")
    artifacts=[]
    for name in ("trnm_pon_node","rusqlite"):
        [row]=[r for r in rows if r.get("reason")=="compiler-artifact" and r["target"]["name"]==name
               and "lib" in r["target"]["kind"]]
        if row["fresh"]:
            raise ValueError("Expected actual private original build")
        if name=="trnm_pon_node":
            if row["features"] or Path(row["target"]["src_path"])!=RUST_ROOT/(PREFIX+"lib.rs"):
                raise ValueError("Wrong original Node library")
        elif not(row["package_id"].endswith("rusqlite@0.41.1")
                 and {"bundled","fallible_uint","hooks"}<=set(row["features"])):
            raise ValueError("Wrong original locked rusqlite library/features")
        [rlib]=[Path(p) for p in row["filenames"] if p.endswith(".rlib")]
        if not rlib.resolve(strict=True).is_relative_to(target):
            raise ValueError("Cargo artifact outside private build target")
        artifacts.extend(["--extern",f"{name}={rlib}"])
    [sqlite]=[r for r in rows if r.get("reason")=="build-script-executed"
              and r["package_id"].endswith("libsqlite3-sys@0.39.1")]
    [link]=sqlite["linked_paths"]
    if not link.startswith("native=") or sqlite["linked_libs"]!=["static=sqlite3"]:
        raise ValueError("Missing original bundled SQLite static library")
    if not Path(link[7:]).resolve(strict=True).is_relative_to(target):
        raise ValueError("SQLite path outside private build target")
    binary=directory/"original-inline-record"
    execute([rustc,"--edition=2021",probe,*artifacts,*link_options,"-L",link,"-L",f"dependency={target/'debug/deps'}",
             "-o",binary],env=env,timeout=90)
    if held_link:
        from hia.tests.history_inline_record_held_link import verify_linked
        verify_linked(binary, archive, archive_before)
    actual=execute([binary])
    check()
    if (actual.stderr or extract()!=frozen or REFERENCE.read_bytes()!=driver
            or probe.read_bytes()!=submitted
            or (held_link and archive.read_bytes()!=archive_before)):
        raise ValueError("Frozen original changed during execution")
    return actual.stdout
