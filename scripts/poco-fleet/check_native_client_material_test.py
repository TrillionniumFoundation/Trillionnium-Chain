#!/usr/bin/env python3
"""Real Rust author/loader parity for the isolated native client profile."""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import check_run_material as material
import check_validator_deployments as deployment
import check_validator_deployments_test as fixture


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--material-builder",required=True,type=pathlib.Path)
    parser.add_argument("--validator-binary",required=True,type=pathlib.Path)
    args=parser.parse_args()
    builder=fixture.exact_executable(args.material_builder,"material-builder")
    binary=fixture.exact_executable(args.validator_binary,"validator")
    with tempfile.TemporaryDirectory(prefix="trnm-native-material-") as temporary:
        root=pathlib.Path(temporary)
        coordinator,deployments,ids=fixture.prepare(root,builder,binary,7,native_client=True)
        selected,report=fixture.verify_representative(binary,coordinator,deployments,ids)
        fixture.verify_signed_report(root,binary,coordinator,deployments,selected,report)
        for validator in ids:
            fixture.run([str(binary),"verify-config",str(deployments/validator),str(deployments/validator/f"public/configs/{validator}.json")])
        keys=root/"native-client-keys-7"
        assert keys.is_dir() and keys.parent==root
        for path in deployments.rglob("*"):
            assert path.name not in {"operator.key","client.key","workload.corpus","workload-policy.json"}
        for path in coordinator.rglob("*"):
            assert path.name not in {"operator.key","client.key"}
        manifest=json.loads((coordinator/"manifest.json").read_text())
        assert material.application_public_paths_v1(manifest)==("public/native-client-profile.json",)
        native_ref=next(row for row in manifest["public_files"] if row["path"]=="public/native-client-profile.json")
        assert native_ref["sha256"]==hashlib.sha256((keys/"native-client-profile.json").read_bytes()).hexdigest()
        # Exact retry of material generation cannot silently replace campaign keys.
        occupied=subprocess.run([str(builder),"native-client-profile","trnm-poco-g3-lan",str(keys)],capture_output=True,text=True)
        assert occupied.returncode != 0
        negatives=1
        for name,mutate in [
            ("mixed",lambda m:m["public_files"].append({"path":"public/workload.corpus","sha256":"11"*32,"bytes":1})),
            ("duplicate",lambda m:m["public_files"].append(dict(native_ref))),
            ("missing",lambda m:m["public_files"].remove(next(row for row in m["public_files"] if row["path"]=="public/native-client-profile.json"))),
        ]:
            mutant=json.loads(json.dumps(manifest));mutate(mutant)
            try:material.application_public_paths_v1(mutant)
            except material.MaterialError:negatives+=1
            else:raise AssertionError(f"accepted {name} application inventory")
        for name,mutate in [
            ("zero-cadence",lambda p:p.update(block_cadence_ms=0)),
            ("duplicate-signer",lambda p:p["signers"].append(dict(p["signers"][0]))),
            ("production",lambda p:p.update(production_activation=True)),
            ("unknown",lambda p:p.update(undeclared_authority=True)),
        ]:
            copy=root/f"coordinator-{name}";shutil.copytree(coordinator,copy)
            path=copy/"public/native-client-profile.json";profile=json.loads(path.read_text());mutate(profile)
            encoded=json.dumps(profile,separators=(",",":"),ensure_ascii=False).encode();path.write_bytes(encoded)
            pinned=json.loads((copy/"manifest.json").read_text())
            row=next(v for v in pinned["public_files"] if v["path"]=="public/native-client-profile.json")
            row.update(sha256=hashlib.sha256(encoded).hexdigest(),bytes=len(encoded))
            (copy/"manifest.json").write_text(json.dumps(pinned,indent=2,sort_keys=True)+"\n")
            rejected=subprocess.run([sys.executable,str(material.HERE/"check_run_material.py"),str(copy),"--validators","7"],capture_output=True,text=True)
            assert rejected.returncode != 0, f"accepted readdressed profile {name}"
            negatives+=1
        mutated=root/"wrong-profile-deployment";shutil.copytree(deployments,mutated)
        selected_profile=mutated/selected/"public/native-client-profile.json"
        selected_profile.write_bytes(selected_profile.read_bytes()+b" ")
        rejected=subprocess.run([sys.executable,str(deployment.HERE/"check_validator_deployments.py"),str(coordinator),str(mutated),"--validators","7"],capture_output=True,text=True)
        assert rejected.returncode != 0;negatives+=1
        print(f"native_client_material=passed real_rust_author=true validators_loaded=7 observer_loaded=true negatives={negatives} campaign_keys_not_deployed=true legacy_profile_unchanged=true runtime_started=false production_activation=false")

if __name__=="__main__":main()
