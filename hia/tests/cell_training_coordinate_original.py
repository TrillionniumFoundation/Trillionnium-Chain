"""Compile the exact private Cell train function with its frozen types/helpers."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from hia.tests.test_worker_audit_jsonl_row import locked_dependencies

ROOT=Path(__file__).resolve().parents[2]
NODE=ROOT/"trillionnium/crates/trnm-pon-node/src"
HARNESS=Path(__file__).with_name("rust_cell_training_coordinate_reference.rs")
PACKAGE="trnm-cell-training-coordinate-reference"
PINS={
    NODE/"cell_native_v1.rs":"d807c924d7e9657d4126d9092d32585427fccba8144133066deb3ea7db54fe26",
    NODE/"cell_native_v1/execution.rs":"cbe589c07dfe2fef0c900676e74300946ae00e424359d43f11002989db5eb20d",
    NODE/"cell_native_v1/source.rs":"8c27cdadece9f1f9c26bd20869a74318bb7490aea436e6dc0140684c20cf6c3e",
    NODE/"lib.rs":"baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    ROOT/"trillionnium/Cargo.lock":"86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e",
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def extract():
    files={p:p.read_bytes() for p in PINS}
    if {p:sha(b) for p,b in files.items()}!=PINS:
        raise ValueError("Frozen Cell coordinate source changed")
    owner=files[NODE/"cell_native_v1.rs"]
    exe=files[NODE/"cell_native_v1/execution.rs"]
    lib=files[NODE/"lib.rs"]
    def one(pattern,src):
        [hit]=re.findall(pattern,src,re.MULTILINE|re.DOTALL)
        return hit
    def region(fn,src):
        return one(rb"^"+fn+rb"\([^\n]*.*?^\}\n",src)
    constants=b"".join(one(rb"^pub const "+k+rb":[^\n]+\n",owner) for k in
                       (b"MODEL_SCHEMA",b"OPTIMIZER_SCHEMA",b"DIM",b"MAX_BATCH",b"PRODUCT_BOUND",b"LOGIT_BOUND"))
    types=b"".join(one(rb"^type "+k+rb"[^\n]+\n",owner) for k in (b"Matrix",b"BoolMatrix"))
    for k in (b"Model",b"Optimizer",b"TrainableMask",b"Training"):
        types+=one(rb"^#\[derive[^\n]+\n#\[serde\(deny_unknown_fields\)\]\npub struct "+k+rb" \{.*?^\}\n",owner)
    types+=one(rb"^#\[derive\(Debug\)\]\nstruct Stage \{.*?^\}\n",owner)
    helpers=exe[exe.index(b"#[derive(Clone, Debug, Serialize)]"):exe.index(b"fn sample(")]
    train=region(b"fn train",exe)
    if not train.endswith(b"    Ok((updated, Some(moment), summary, stages))\n}\n"):
        raise ValueError("Incomplete original training function")
    original=constants+types+helpers+region(rb"pub\(crate\) fn ensure",lib)+train
    raw=HARNESS.read_bytes()
    if raw.count(b"// EXACT_ORIGINAL_TRAIN")!=1:
        raise ValueError("Training oracle has no unique original source marker")
    return raw.replace(b"// EXACT_ORIGINAL_TRAIN",original),sha(train)


def run(argv, *, data=None, env=None, timeout=15):
    return subprocess.run(argv,input=data,env=env,timeout=timeout,check=True,capture_output=True).stdout


def reference(directory,stream):
    source, train=extract()
    deps=locked_dependencies()
    (directory/"src").mkdir()
    f=directory/"src/main.rs"
    f.write_bytes(source)
    (directory/"Cargo.toml").write_text(f"""[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2021"

[dependencies]
serde = {{version = "={deps['serde']['version']}", features = ["derive"]}}
serde_json = "={deps['serde_json']['version']}"
""")
    root={"name":PACKAGE,"version":"0.0.0","dependencies":["serde","serde_json"]}
    rows=["version = 4",""]
    for name,pkg in sorted({**deps,PACKAGE:root}.items()):
        rows+=["[[package]]"]+[f"{k} = {json.dumps(pkg[k])}" for k in ("name","version","source","checksum") if k in pkg]
        if pkg.get("dependencies"):
            edges=[edge.split()[0] for edge in pkg["dependencies"]]
            assert set(edges)<=deps.keys()
            rows+=["dependencies = [",*(f" {json.dumps(edge)}," for edge in edges),"]"]
        rows.append("")
    lock="\n".join(rows).encode()
    (directory/"Cargo.lock").write_bytes(lock)
    rustc=os.environ.get("TRNM_HIA_RUSTC","rustc")
    cargo=os.environ.get("TRNM_HIA_CARGO","cargo")
    pin=tomllib.loads((ROOT/"rust-toolchain.toml").read_text())["toolchain"]["channel"]
    tools=[run([cmd,"--version"]).decode().strip() for cmd in (cargo,rustc)]
    if [t.split()[:2] for t in tools]!=[["cargo",pin],["rustc",pin]]:
        raise ValueError("Frozen Cell qualification requires both pinned Rust tools")
    target=directory/"target"
    env={**os.environ,"RUSTC":rustc,"CARGO_TARGET_DIR":str(target),"CARGO_BUILD_JOBS":"2",
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0"}
    args=[cargo,"build","--locked","--offline","--message-format=json","--manifest-path",str(directory/"Cargo.toml")]
    events=list(map(json.loads,run(args,env=env,timeout=180).splitlines()))
    if events[-1]!={"reason":"build-finished","success":True}:
        raise ValueError("No locked Rust build")
    artifacts=[a for a in events if a.get("reason")=="compiler-artifact"]
    observed={a["package_id"].rsplit("#",1)[-1] for a in artifacts}
    if not {f"{k}@{v['version']}" for k,v in deps.items()}<=observed:
        raise ValueError("Original locked serde graph incomplete")
    [exe]=[Path(a["executable"]) for a in artifacts if a.get("executable") and a["target"]["name"]==PACKAGE]
    if not exe.is_relative_to(target):
        raise ValueError("Original witness outside private build")
    output=run([str(exe)],data=stream,timeout=45)
    if (directory/"Cargo.lock").read_bytes()!=lock or extract()!=(source,train) or f.read_bytes()!=source:
        raise ValueError("Exact original source or lock changed")
    return output,{"original_train_sha256":train,"assembled_source_sha256":sha(source),
                   "projected_lock_sha256":sha(lock),"tools":tools,"packages":sorted(deps)}
