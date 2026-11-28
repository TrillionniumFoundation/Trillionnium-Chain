"""Compile inert source-pinned Cell execute, without the Node or work owner."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from hia.tests.cell_training_coordinate_original import PINS as TRAIN_PINS

ROOT=Path(__file__).resolve().parents[2]
NODE=ROOT/"trillionnium/crates/trnm-pon-node/src"
WIRE=ROOT/"trillionnium/crates/trnm-protocol/src/pon_wire.rs"
HARNESS=Path(__file__).with_name("rust_cell_held_rows_reference.rs")
PINS={**TRAIN_PINS,WIRE:"ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b"}
PKG="trnm-cell-held-rows-reference"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def exactly(pattern,src):
    [value]=re.findall(pattern,src,re.MULTILINE|re.DOTALL)
    return value


def execute_source(harness=None):
    sources={p:p.read_bytes() for p in PINS}
    if {p:sha(b) for p,b in sources.items()}!=PINS:
        raise ValueError("Frozen Cell execution source/root lock changed")
    owner=sources[NODE/"cell_native_v1.rs"]
    lib=sources[NODE/"lib.rs"]
    src=sources[NODE/"cell_native_v1/source.rs"]
    wire=sources[WIRE]
    def end(start,raw):
        return exactly(rb"^"+start+rb"\([^\n]*.*?^\}\n",raw)
    constants=b"".join(exactly(rb"^pub const "+k+rb":[^\n]+\n",owner) for k in
        (b"PROFILE",b"MODEL_SCHEMA",b"STATE_SCHEMA",b"ADMISSION_SCHEMA",b"INPUT_PROFILE",
         b"OPTIMIZER_SCHEMA",b"DIM",b"CLASSES",b"MAX_BATCH",b"PRODUCT_BOUND",b"LOGIT_BOUND"))
    types=b"".join(exactly(rb"^type "+k+rb"[^\n]+\n",owner) for k in (b"Matrix",b"BoolMatrix"))
    for k in (b"Model",b"Optimizer",b"CellState",b"SourceSnippet",b"TrainableMask",b"Training",b"Policy",b"OwnerAdmission"):
        types+=exactly(rb"^#\[derive[^\n]+\n#\[serde\(deny_unknown_fields\)\]\npub struct "+k+rb" \{.*?^\}\n",owner)
    for k in (b"Action",b"Sampler"):
        types+=exactly(rb"^#\[derive[^\n]+\n(?:#\[serde\(rename_all[^\n]+\n)?pub enum "+k+rb" \{.*?^\}\n",owner)
    types+=b"".join(exactly(rb"^#\[derive\(Debug\)\]\nstruct "+k+rb" \{.*?^\}\n",owner)
                     for k in (b"Stage",b"Execution"))
    checked=b"".join(end(name,owner) for name in
         (b"fn check_json",b"fn identity",b"fn matrix",b"fn validate_model",b"pub fn model_artifact",b"fn validate_state"))
    checked+=exactly(rb"^pub fn canonical<T: Serialize>\(.*?^\}\n",owner)
    checked+=end(rb"pub\(crate\) fn ensure",lib)+end(b"pub fn digest",lib)+end(b"pub fn hash",wire)
    constants+=exactly(rb"^pub type Hash = [^\n]+\n",wire)
    prepared=exactly(rb"^pub\(super\) struct PreparedInputs \{.*?^\}\n",src)
    if harness is None:
        harness=HARNESS.read_bytes()
    marker=b"// EXACT_OWNER_DECLARATIONS"
    if harness.count(marker)!=1:
        raise ValueError("Missing unique authority-free fixture insertion point")
    return {"main.rs":harness.replace(marker,constants+types+checked),
            "execution.rs":sources[NODE/"cell_native_v1/execution.rs"],
            "source.rs":b"use super::Stage;\n"+prepared}


def run(argv, *, data=None, env=None, timeout=15, cwd=None):
    return subprocess.run(argv,cwd=cwd,input=data,env=env,timeout=timeout,check=True,capture_output=True).stdout


def locked_original(directory,stream,*,harness=None,link=None):
    """Optional private fixture linkage, never used by the existing dual runners."""
    sources=execute_source(harness)
    src=directory/"src"
    src.mkdir()
    for name,data in sources.items():
        (src/name).write_bytes(data)
    (directory/"Cargo.toml").write_text(f"""[package]
name = "{PKG}"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
serde = {{ version = "=1.0.229", features = ["derive"] }}
serde_json = "=1.0.149"
hex = "=0.4.3"
sha2 = "=0.10.9"
""")
    locked=tomllib.loads((ROOT/"trillionnium/Cargo.lock").read_text())["package"]
    allowed={(x["name"],x["version"],x.get("source"),x.get("checksum")) for x in locked}
    rustc=os.environ.get("TRNM_HIA_RUSTC","rustc")
    cargo=os.environ.get("TRNM_HIA_CARGO","cargo")
    pin=tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    tools=[run([cmd,"--version"]).decode().strip() for cmd in (cargo,rustc)]
    if [t.split()[:2] for t in tools]!=[["cargo",pin],["rustc",pin]]:
        raise ValueError("Frozen Cell execute requires both pinned Rust tools")
    # Only this tiny source-only projection builds, not any Node/workspace crate.
    target=directory/"target"
    env={**os.environ,"RUSTC":rustc,"CARGO_TARGET_DIR":str(target),
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0","CARGO_BUILD_JOBS":"2"}
    run([cargo,"generate-lockfile","--offline"],cwd=directory,env=env)
    lock=(directory/"Cargo.lock").read_bytes()
    selected=tomllib.loads(lock.decode())["package"]
    graph={(x["name"],x["version"],x.get("source"),x.get("checksum"))
           for x in selected if x["name"]!=PKG}
    if not graph or not graph<=allowed or any(not x[3] for x in graph):
        raise ValueError("Original tiny dependency graph not wholly checksum-locked to workspace")
    command=[cargo,"build" if link is None else "rustc","--offline","--locked","--message-format=json"]
    if link is not None:
        search,verify=link
        command.extend(["--","-L",f"native={search}","-l","static=trnm_held_train_fixture"])
    result=run(command,cwd=directory,env=env,timeout=90)
    events=list(map(json.loads,result.splitlines()))
    if events[-1]!={"reason":"build-finished","success":True}:
        raise ValueError("Original tiny Cargo build did not succeed")
    artifacts=[e for e in events if e.get("reason")=="compiler-artifact"]
    host=[line.removeprefix("host: ") for line in run([rustc,"-vV"]).decode().splitlines()
          if line.startswith("host: ")]
    if len(host)!=1:
        raise ValueError("Original compile target not uniquely reported")
    target_graph=json.loads(run([cargo,"metadata","--offline","--locked","--format-version","1",
                                 "--filter-platform",host[0]],cwd=directory,env=env))
    active={pkg["id"].rsplit("#",1)[-1] for pkg in target_graph["packages"] if pkg["name"]!=PKG}
    exact={f"{a}@{b}" for a,b,_,_ in graph}
    emitted={e["package_id"].rsplit("#",1)[-1] for e in artifacts if e["package_id"]!=target_graph["resolve"]["root"]}
    if not active<=exact or active!=emitted:
        raise ValueError(f"Actual target-locked Cargo graph differs: missing={sorted(active-emitted)}, extra={sorted(emitted-active)}")
    [exe]=[Path(a["executable"]) for a in artifacts if a.get("executable") and a["target"]["name"]==PKG]
    if not exe.is_relative_to(target):
        raise ValueError("Original witness outside its private target")
    if link is not None:
        verify(exe)
    inert=directory/"inert"
    inert.mkdir()
    out=run([str(exe)],data=stream,env={},cwd=inert,timeout=30)
    if link is not None:
        verify(exe)
    if list(inert.iterdir()) or execute_source(harness)!=sources or (directory/"Cargo.lock").read_bytes()!=lock or any(
        (src/n).read_bytes()!=b for n,b in sources.items()):
        raise ValueError("Original execute source was not immutable or fixture attempted IO")
    return out,dict(compilers=tools,source={n:sha(b) for n,b in sources.items()},locked=sorted(graph),
                    active_target=host[0],inactive_lock_entries=sorted(exact-active),
                    projected_lock=sha(lock),frozen_execution=sha(sources["execution.rs"]))
