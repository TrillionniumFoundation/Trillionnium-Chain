#!/usr/bin/env python3
"""Explicit isolated W1 original-deadline lifecycle. Never reuses an operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PRIOR = Path("/home/qian-qi/work/chain-w1-postwin-runtime-20261107-recovery")
C3 = "abab79dac0cb89eb2753d3f579119ac135650eb5"
CPUS = [8, 9, 10, 11, 20, 21, 22, 23]
BUDGET_NS = 120_000_000_000
MEMORY = 8 * 1024**3
SELECTOR = "store::async_w1_generation_v2::tests::heavy::funded_fresh_full_w1_generation_timeout_then_refund_and_reorg"
COLD_SELECTOR = "store::async_w1_generation_v2::tests::heavy::funded_w1_owner_cancellation_cold_reconcile"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pin(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "regular absolute file required")
    h = hashlib.sha256()
    with path.open("rb") as f:
        before = os.fstat(f.fileno())
        for b in iter(lambda:f.read(1024*1024), b""):
            h.update(b)
        after = os.fstat(f.fileno())
    require((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            == (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), "file changed while hashing")
    return {"path":str(path),"bytes":after.st_size,"sha256":h.hexdigest()}

def write(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, sort_keys=True, indent=2, allow_nan=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def git(args, *argv):
    return subprocess.run(["/usr/bin/git","--no-optional-locks","-C",str(args.repo),*argv],
        check=True,capture_output=True,env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C",
        "GIT_OPTIONAL_LOCKS":"0"}).stdout

def source(args):
    require(args.repo.is_absolute() and args.repo.resolve()==args.repo,"canonical repo required")
    require(git(args,"rev-parse","HEAD").decode().strip()==args.expected_commit,"source HEAD changed")
    require(git(args,"status","--porcelain=v1","--untracked-files=all")==b"","source must be clean")
    return {"commit":args.expected_commit,"tree":git(args,"rev-parse","HEAD^{tree}").decode().strip()}

def qualify(args):
    src=source(args)
    q=args.root/"qualification"
    q.mkdir(exist_ok=False)
    env=os.environ.copy()
    toolchain=Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
    env.update(CARGO_TARGET_DIR=str(args.target_dir),PYTHONDONTWRITEBYTECODE="1",
        RUSTUP_TOOLCHAIN="1.95.0",RUSTUP_AUTO_INSTALL="0",
        RUSTC=str(toolchain/"rustc"),RUSTDOC=str(toolchain/"rustdoc"),RUSTFMT=str(toolchain/"rustfmt"))
    require((toolchain/"rustc").resolve()==toolchain/"rustc","canonical real compiler required")
    commands=[
      ("metadata",["cargo","metadata","--offline","--locked","--manifest-path","trillionnium/Cargo.toml","--format-version=1"]),
      ("owner",["cargo","test","--offline","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","async_w1_generation_v2::tests","--","--nocapture"]),
      ("m12",["cargo","test","--offline","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-service-settlement","--lib","native_generation_budget_v2","--","--nocapture"]),
      ("artifact",["cargo","test","--offline","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","--no-run","--message-format=json"]),
      ("clippy",["cargo","clippy","--offline","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","-p","trnm-service-settlement","--all-targets","--","-D","warnings"]),
      ("fmt",["cargo","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"]),
      ("python",["/usr/bin/python3.12","-B","-m","unittest","discover","-s","scripts","-p","test_w1_owner_cancellation_v1.py","-v"]),
    ]
    rows=[]
    for label,argv in commands:
        so=q/(label+".stdout")
        se=q/(label+".stderr")
        with so.open("xb") as out,se.open("xb") as err:
            result=subprocess.run(argv,cwd=args.repo,env=env,stdout=out,stderr=err,check=False)
        row={"label":label,"argv":argv,"exit":result.returncode,"stdout":pin(so),"stderr":pin(se)}
        rows.append(row)
        write(q/(label+".json"),row)
        require(result.returncode==0,"qualification failed: "+label)
    records=[json.loads(x) for x in (q/"artifact.stdout").read_text().splitlines() if x.startswith("{")]
    selected=[x for x in records if x.get("reason")=="compiler-artifact"
        and x.get("executable")==str(args.owner_binary) and x.get("profile",{}).get("test") is True]
    require(len(selected)==1,"exact owner test artifact not discovered")
    require(source(args)==src,"source changed during qualification")
    write(q/"manifest.json",{"schema":"TRNM-W1-TIMEOUT-OWNER-QUALIFICATION1","source":src,
       "source_clean_before":True,"source_clean_after":True,"commands":rows,"owner_binary":pin(args.owner_binary),\
       "qualification_complete":True,
       "cargo_artifact":selected[0],"cargo_target":str(args.target_dir),"fresh_cargo_target":False,
       "independent_reproducible_build_established":False,"fixed_guest_compilation_performed":False,
       "build_environment":{k:env[k] for k in ("CARGO_TARGET_DIR","RUSTUP_TOOLCHAIN","RUSTC","RUSTDOC","RUSTFMT")},
       "sqlite_io_budget_established_by_this_trial":False,
       "requires_separate_owned_io_domain_controls":True})
    print(json.dumps({"qualified":True,"manifest":pin(q/"manifest.json")}),flush=True)


def probe_runner(args, src):
    """An intentional unknown stage verifies source and launches no proof."""
    require(args.runner_binary is not None and args.runner_build_log is not None,
        "explicit current-checkout runner and Cargo artifact log required")
    rows=[]
    for line in args.runner_build_log.read_text().splitlines():
        if line.startswith("{"):
            value=json.loads(line)
            if value.get("reason")=="compiler-artifact" and value.get("executable")==str(args.runner_binary):
                rows.append(value)
    require(len(rows)>=1 and rows[-1].get("profile",{}).get("test") is False,
        "actual selected runner build artifact required")
    artifact=rows[-1]
    require(Path(artifact["manifest_path"]).resolve().is_relative_to(args.repo.resolve())
        and Path(artifact["target"]["src_path"]).resolve().is_relative_to(args.repo.resolve()),
        "runner build artifact names another checkout")
    unused=args.root/"source-binding-probe-does-not-create-checkpoint"
    require(not unused.exists(),"source-only probe path must be absent")
    argv=[str(args.runner_binary),"--r0vm",str(PRIOR/"fixed-backend-01/r0vm"),"source-binding-probe",str(unused)]
    before=pin(args.runner_binary)
    so=args.root/"runner-source-probe.stdout"
    se=args.root/"runner-source-probe.stderr"
    with so.open("xb") as out,se.open("xb") as err:
        result=subprocess.run(argv,cwd=args.repo,stdout=out,stderr=err,timeout=60,check=False,
           env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"})
    parsed=[]
    for line in so.read_text().splitlines():
        if line.startswith("{"):
            row=json.loads(line)
            if row.get("stage")=="RAW_COMMITTED_SOURCE_VERIFIED":
                parsed.append(row)
    observed={"schema":"TRNM-W1-RUNNER-SOURCE-PROBE1","argv":argv,"exit":result.returncode,
       "stdout":pin(so),"stderr":pin(se),"runner":before,"source":src,
       "raw_source_identity_records":parsed,"checkpoint_path_created":unused.exists(),
       "proof_launched":False,"source_probe_stage_intentionally_unknown":True,
       "cargo_artifact":artifact,"cargo_artifact_log":pin(args.runner_build_log)}
    write(args.root/"runner-source-probe.json",observed)
    require(result.returncode==1 and se.read_text().strip()=="Error: unknown stage"
        and len(parsed)==1 and not unused.exists() and before==pin(args.runner_binary),
        "runner did not reach the exact source-only unknown-stage boundary")
    identity=parsed[0]["identity"]
    require(identity["tested_commit"]==src["commit"] and identity["tested_tree"]==src["tree"],
        "runner is bound to another checkout/commit; no funded operation may start")
    return pin(args.root/"runner-source-probe.json")

def qualified_native(args, src):
    require(args.native_qualification is not None, "explicit current-source native/verifier qualification required")
    manifest_pin=pin(args.native_qualification)
    q=json.loads(args.native_qualification.read_text())
    require(q["schema"]=="TRNM-W1-EXACT-NATIVE-QUALIFICATION1" and q["source"]==src
        and q["repo"]==str(args.repo) and q["qualification_complete"] is True
        and q["source_clean_before"] is True and q["source_clean_after"] is True
        and all(row["passed"] is True and row["exit"]==0 for row in q["commands"]),
        "current source native/verifier qualification failed")
    selected={}
    require(set(q["binaries"])=={"native_winner","verifier"},"exact native/verifier roles required")
    for role,entry in q["binaries"].items():
        observed=pin(entry["file"]["path"])
        require(observed==entry["file"],"qualified native/verifier binary changed: "+role)
        artifact=entry["cargo_artifact"]
        require(artifact["reason"]=="compiler-artifact" and artifact["executable"]==observed["path"]
            and artifact["profile"]["test"] is False
            and Path(artifact["manifest_path"]).resolve().is_relative_to(args.repo)
            and Path(artifact["target"]["src_path"]).resolve().is_relative_to(args.repo),
            "native/verifier Cargo artifact names another source: "+role)
        log=Path(entry["build_log"]["path"])
        require(pin(log)==entry["build_log"],"native/verifier original Cargo log changed")
        rows=[json.loads(x) for x in log.read_text().splitlines() if x.startswith("{")]
        require([x for x in rows if x.get("reason")=="compiler-artifact"
                 and x.get("executable")==observed["path"]]==[artifact],
                "native/verifier exact emitted Cargo artifact absent")
        selected[role]=observed
    return selected,manifest_pin

def prepare(args):
    src=source(args)
    q=json.loads((args.root/"qualification/manifest.json").read_text())
    require(q["source"]==src and q["owner_binary"]==pin(args.owner_binary)\
        and q.get("qualification_complete") is True,"qualified owner changed or incomplete")
    runner_probe=probe_runner(args,src)
    native_roles,native_qualification=qualified_native(args,src)
    old_path=PRIOR/"owner-cancel-launch-plans-02/config.json"
    c=json.loads(old_path.read_text())
    for name in ("original_deadline_ns","original_boot_id","original_deadline_declaration",
                 "launch_observation","clean_build_qualification"):
        c.pop(name,None)
    tracked={p.decode() for p in git(args,"ls-files","-z").split(b"\0") if p}
    names=set(c["source_files"])|{p for p in tracked if p.startswith("scripts/") and p.endswith(".py")}
    names|={p for p in tracked if p.startswith("trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2")
                                      and p.endswith(".rs")}
    require(names<=tracked,"source selection not tracked")
    c["source_files"]={name:pin(args.repo/name)["sha256"] for name in sorted(names)}
    c.update(repo=str(args.repo),expected_commit=src["commit"],expected_tree=src["tree"],
       out=str(args.root/"run"),target_root=str(args.root/"target-state"),
       research_node_path=str(args.root/"research-node"),reserve_nonce=1,
       target_instance="w1-timeout-"+args.root.name,cpus=CPUS,
       owner_test_binary_sha256=pin(args.owner_binary)["sha256"],
       owner_build_qualification=pin(args.root/"qualification/manifest.json"))
    for key,name in (("runtime","w1_owned_generation_runtime_v2.py"),
                     ("target","w1_generation_target_v2.py"),("owner_cancel_runtime","w1_owner_cancellation_v1.py")):
        c[key]=pin(args.repo/"scripts"/name)
    c["native_winner"]=native_roles["native_winner"]
    c["runner"]=pin(args.runner_binary)
    c["runner_source_probe"]=runner_probe
    c["runner_build_log"]=pin(args.runner_build_log)
    c["verifier"]=native_roles["verifier"]
    c["native_verifier_build_qualification"]=native_qualification
    unchanged=["formal/pon-nakamoto-v1/w1_zkvm","formal/pon-nakamoto-v1/w1_v2_verifier",
        "trillionnium/crates/trnm-crypto-primitives","trillionnium/crates/trnm-protocol",
        "trillionnium/Cargo.lock","trillionnium/Cargo.toml"]
    require(git(args,"diff","--name-only",C3,"HEAD","--",*unchanged)==b"",
            "retained native/backend source prefix changed")
    c["binary_reuse_provenance"]={"source_commit":src["commit"],
        "native_verifier_built_for_current_checkout":True,"reused_roles":[],
        "fresh_cargo_target":False,"independent_cleanroom_build":False,
        "native_verifier_qualification":native_qualification,
        "raw_source_prefixes_unchanged":unchanged,
        "new_owner_binary_is_separately_qualified":True,
        "runner_build_checkout_and_source_probe":src,
        "native_manifest":pin(PRIOR/"clean-exact-native-verifier-abab79dac0cb-02/manifest.json"),
        "backend_manifest":pin(PRIOR/"backend-validation/exact-source-abab79dac0cb-02/manifest.json"),
        "guest_compilation_performed":False,"r0vm_fixed_upstream_version":"3.0.3"}
    operation=hashlib.sha256((str(args.root)+src["commit"]).encode()+os.urandom(32)).hexdigest()
    c["provider_operation"]=operation
    c["owner_cancellation"]={"schema":"TRNM-W1-OWNER-TIMEOUT-PLAN1","authority":"development-owner-0",
       "trigger":"original-deadline-after-live-first-prove-r0vm",
       "reason_sha256":hashlib.sha256(("owner-veto-after-actual-original-deadline:"+operation).encode()).hexdigest(),
       "native_task_action":"cancel-reserved"}
    c["resource_cap"]={"cpu_ns":8*BUDGET_NS,"gpu_ns":2*BUDGET_NS,
        "memory_peak_upper_bound_bytes":MEMORY,"receipt_bytes":16*1024**2}
    c["sample_kind"]="one independent original-deadline research operation; no complete proof or deployment performance claim"
    for key in ("out","target_root","research_node_path"):
        require(not Path(c[key]).exists(),"new destination required: "+key)
    for key in ("python","guest","r0vm","material","expected_artifacts","header_template"):
        require(pin(c[key]["path"])["sha256"]==c[key]["sha256"],"retained pinned material changed: "+key)
    plan={"schema":"TRNM-W1-OWNER-TIMEOUT-LAUNCH-PLAN1","source":src,
        "operation":operation,"maximum_original_budget_ns":BUDGET_NS,
        "deadline_selected":False,"winner_or_proof_started":False,"config_without_clock":c,
        "owner_binary":pin(args.owner_binary),"driver":pin(Path(__file__).resolve()),
        "configuration_template":pin(old_path),"research_only":True,
        "all_historical_descendants_wait_reap_qualified":False,"gpu_accounting":"UNKNOWN"}
    write(args.root/"plan.json",plan)
    print(json.dumps({"plan":pin(args.root/"plan.json"),"operation":operation,"source":src}),flush=True)

def identity():
    membership=Path("/proc/self/cgroup").read_text()
    require(membership.startswith("0::/") and "/hepta-runtime-job-" in membership
        and membership.strip().endswith(".service"),"original isolated Hepta owner job required")
    group=Path("/sys/fs/cgroup")/membership.strip()[3:].lstrip("/")
    quota,period=(group/"cpu.max").read_text().split()
    memory=(group/"memory.max").read_text().strip()
    affinity=sorted(os.sched_getaffinity(0))
    require(int(quota)==8*int(period) and int(memory)==MEMORY and affinity==CPUS,
            "actual predeclared 8CPU/8GiB/affinity allocation required")
    return {"pid":os.getpid(),"boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "proc_stat":Path("/proc/self/stat").read_text(),"cgroup":str(group),
        "cpu_max":quota+" "+period,"memory_max_bytes":int(memory),"affinity":affinity,
        "observed_monotonic_ns":time.monotonic_ns()}

def launch(args):
    require(args.plan_sha256 is not None and pin(args.root/"plan.json")["sha256"]==args.plan_sha256,
            "explicit exact plan digest required")
    p=json.loads((args.root/"plan.json").read_text())
    require(p["schema"]=="TRNM-W1-OWNER-TIMEOUT-LAUNCH-PLAN1"
        and p["source"]==source(args) and p["maximum_original_budget_ns"]==BUDGET_NS
        and not p["deadline_selected"] and not p["winner_or_proof_started"],"unstarted original plan required")
    require(pin(args.owner_binary)==p["owner_binary"] and pin(Path(__file__).resolve())==p["driver"],
            "owner or launch driver changed")
    c=p["config_without_clock"]
    require(pin(args.runner_binary)==c["runner"],"selected qualified runner changed")
    for key in ("out","target_root","research_node_path"):
        require(not Path(c[key]).exists(),"original operation already has effects: "+key)
    for name,digest in c["source_files"].items():
        require(pin(args.repo/name)["sha256"]==digest,"source changed: "+name)
    os.umask(0o077)
    os.sched_setaffinity(0,set(CPUS))
    who=identity()
    selected=time.monotonic_ns()
    deadline=selected+BUDGET_NS
    c.update(original_boot_id=who["boot_id"],original_deadline_ns=deadline,
        launch_observation=who,original_deadline_declaration={
          "schema":"TRNM-W1-OWNER-TIMEOUT-ORIGINAL-DEADLINE1",
          "selected_monotonic_ns":selected,"original_deadline_ns":deadline,
          "original_boot_id":who["boot_id"],"plan_sha256":args.plan_sha256,
          "operation":p["operation"],"deadline_can_be_renewed":False})
    write(args.root/"config.json",c)
    argv=[str(args.owner_binary),SELECTOR,"--exact","--ignored","--test-threads=1","--nocapture"]
    env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1",
         "RAYON_NUM_THREADS":"4","TRNM_W1_FUNDED_CONFIG":str(args.root/"config.json")}
    write(args.root/"launch-declaration.json",{"schema":"TRNM-W1-OWNER-TIMEOUT-LAUNCH1",
        "source":p["source"],"plan":pin(args.root/"plan.json"),"config":pin(args.root/"config.json"),
        "owner_binary":p["owner_binary"],"driver":p["driver"],"argv":argv,"env":env,
        "selected_monotonic_ns":selected,"original_deadline_ns":deadline,"original_identity":who,
        "all_historical_wait_reap_qualified":False,"gpu_accounting":"UNKNOWN",
        "proof_deadline_can_be_extended":False,"public_chain_transactions_sent":False})
    print(json.dumps({"launch_intent_recorded":True,"operation":p["operation"],
       "original_deadline_ns":deadline,"source":p["source"]}),flush=True)
    require(time.monotonic_ns()<deadline,"original deadline exhausted before launch")
    os.execve(argv[0],argv,env)

def cold(args):
    p=json.loads((args.root/"plan.json").read_text())
    require(p["source"]==source(args) and pin(args.owner_binary)==p["owner_binary"],"original source/owner required")
    require(args.cold_out is not None and args.cold_out.is_absolute() and not args.cold_out.exists(),"new cold output required")
    argv=[str(args.owner_binary),COLD_SELECTOR,"--exact","--ignored","--test-threads=1","--nocapture"]
    env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1",
         "TRNM_W1_FUNDED_CONFIG":str(args.root/"config.json"),"TRNM_W1_CANCEL_RECONCILE_OUT":str(args.cold_out)}
    write(args.root/"cold-launch-intent.json",{"schema":"TRNM-W1-OWNER-TIMEOUT-COLD-LAUNCH1",
        "source":source(args),"argv":argv,"env":env,"config":pin(args.root/"config.json"),
        "owner_binary":pin(args.owner_binary),"deadline_renewed":False,"new_generation_dispatches":0,
        "native_transaction_submissions":0})
    os.execve(argv[0],argv,env)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("qualify","prepare","launch","cold"))
    p.add_argument("--repo",type=Path,required=True)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--expected-commit",required=True)
    p.add_argument("--owner-binary",type=Path,required=True)
    p.add_argument("--target-dir",type=Path,required=True)
    p.add_argument("--plan-sha256")
    p.add_argument("--runner-binary",type=Path)
    p.add_argument("--runner-build-log",type=Path)
    p.add_argument("--native-qualification",type=Path)
    p.add_argument("--cold-out",type=Path)
    args=p.parse_args()
    require(args.root.is_absolute() and args.root.is_dir(),"new external experiment root required")
    globals()[args.mode](args)
if __name__=="__main__":
    main()
