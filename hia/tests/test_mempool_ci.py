"""New typed-mempool CI envelope controls; fixtures do not claim a real CI run."""
from __future__ import annotations
import json,os,socket,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from hia.tools import qualify_mempool_ci as ci

class MempoolCIPackageTests(unittest.TestCase):
    def test_failed_run_preserves_complete_binary_isolated_source_and_special_metadata(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-package-test-") as directory:
            root=Path(directory);complete=root/"hia-mempool-typed-complete"
            original=complete/"original";(original/"isolated-crate/src").mkdir(parents=True)
            (original/"original-tests").write_bytes(b"complete-independent-original-binary")
            (original/"isolated-crate/src/lib.rs").write_bytes(b"exact-original-source")
            (complete/"failure.json").write_text('{"status":"FAIL"}\n')
            os.mkfifo(complete/"never-open-this-fifo")
            (complete/"metadata-link").symlink_to("/outside-target-never-read")
            sock=socket.socket(socket.AF_UNIX);sock.bind(str(complete/"metadata-socket"))
            try:
                synthetic={"TRNM_EXPECTED_SOURCE_SHA":"a"*40,"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1"}
                with patch.dict(os.environ,synthetic):result=ci.pack(root)
            finally:sock.close()
            record=ci.read(root/"hia-mempool-typed-artifact/package-manifest.json")
            self.assertTrue(result["qualification_status_not_changed_by_packaging"])
            self.assertIn("ABSENT_OR_FAILED",record["binding_status"])
            self.assertIn("complete/original/original-tests",record["entries"])
            self.assertIn("complete/original/isolated-crate/src/lib.rs",record["entries"])
            self.assertEqual(record["entries"]["complete/never-open-this-fifo"]["type"],"fifo")
            self.assertEqual(record["metadata_only"],["complete/metadata-socket"])
            with tarfile.open(root/"hia-mempool-typed-artifact/complete-evidence.tar.xz","r:xz") as archive:
                self.assertEqual(archive.extractfile("complete/original/original-tests").read(),
                                 b"complete-independent-original-binary")
                self.assertEqual(archive.getmember("complete/metadata-link").linkname,
                                 "/outside-target-never-read")

    def test_pack_refuses_cross_run_binding(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-lineage-test-") as directory:
            root=Path(directory);observed=root/"hia-mempool-typed-observations";observed.mkdir()
            (observed/"binding.json").write_text(json.dumps({"schema":ci.SCHEMA,
                "lineage":{"git_head":"a"*40,"run_id":"124","attempt":1}}))
            synthetic={"TRNM_EXPECTED_SOURCE_SHA":"a"*40,"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1"}
            with patch.dict(os.environ,synthetic):
                with self.assertRaisesRegex(ValueError,"lineage"):ci.pack(root)

    def test_pack_refuses_aliased_evidence_root(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-alias-test-") as directory:
            root=Path(directory);outside=root/"outside";outside.mkdir()
            (root/"hia-mempool-typed-complete").symlink_to(outside,target_is_directory=True)
            synthetic={"TRNM_EXPECTED_SOURCE_SHA":"a"*40,"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1"}
            with patch.dict(os.environ,synthetic):
                with self.assertRaisesRegex(ValueError,"Aliased"):ci.pack(root)

    def test_unknown_source_observation_refuses_before_component_reader(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-early-refusal-") as directory:
            synthetic={"TRNM_EXPECTED_SOURCE_SHA":"a"*40,"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1"}
            with patch.dict(os.environ,synthetic),patch.object(ci.transfer,"source_pair",side_effect=ValueError("source fence")):
                with self.assertRaisesRegex(ValueError,"source fence"):ci.bind(Path(directory))


    def test_pack_rejects_nonpassing_same_run_binding_and_retains_manifest(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-failed-binding-") as directory:
            root=Path(directory);observed=root/"hia-mempool-typed-observations";observed.mkdir()
            synthetic={"TRNM_EXPECTED_SOURCE_SHA":"a"*40,"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1"}
            with patch.dict(os.environ,synthetic):
                (observed/"binding.json").write_text(json.dumps({"schema":ci.SCHEMA,
                    "lineage":ci.base.lineage(),"stage":ci.STAGE,"status":"FAIL"}))
                with self.assertRaisesRegex(ValueError,"not a successful"):ci.pack(root)
            record=ci.read(root/"hia-mempool-typed-artifact/package-manifest.json")
            self.assertEqual(record["packing_status"],"FAIL")
            self.assertEqual(record["qualification_status"],"NOT_BOUND")
            self.assertTrue(record["partial_archive"])

    def test_archive_reopen_refuses_changed_missing_duplicate_and_trailing_payloads(self):
        import hashlib,io,lzma
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-ci-archive-controls-") as directory:
            root=Path(directory);expected=b"complete native bytes"
            entries={"actual.raw":{"type":"regular","mode":0o600,"bytes":len(expected),
                "sha256":hashlib.sha256(expected).hexdigest()}}
            def make(name,rows):
                path=root/name
                with tarfile.open(path,"x:xz") as archive:
                    for member_name,payload in rows:
                        member=tarfile.TarInfo(member_name);member.size=len(payload);member.mode=0o600
                        archive.addfile(member,io.BytesIO(payload))
                return path
            valid=make("valid.tar.xz",[("actual.raw",expected)])
            ci.verify_archive(valid,entries,[])
            variants=[
                make("changed.tar.xz",[("actual.raw",b"x"+expected[1:])]),
                make("missing.tar.xz",[]),
                make("duplicate.tar.xz",[("actual.raw",expected),("actual.raw",expected)]),
                make("extra.tar.xz",[("actual.raw",expected),("extra.raw",b"x")])]
            trailing=root/"trailing.tar.xz";trailing.write_bytes(valid.read_bytes()+lzma.compress(b"extra"));variants.append(trailing)
            truncated=root/"truncated.tar.xz";truncated.write_bytes(valid.read_bytes()[:-3]);variants.append(truncated)
            for path in variants:
                with self.subTest(variant=path.name),self.assertRaises((ValueError,lzma.LZMAError)):ci.verify_archive(path,entries,[])

    def test_archive_cannot_rebind_modified_or_added_evidence(self):
        import copy,hashlib
        row={"type":"regular","mode":0o600,"bytes":3,"sha256":hashlib.sha256(b"raw").hexdigest()}
        entries={"complete/native/stdout.raw":row}
        value={"evidence_files":{"complete/native/stdout.raw":{k:row[k] for k in ("bytes","sha256")}},
            "special_evidence_metadata":{}}
        ci.check_bound_archive(value,entries)
        for variant in ("changed","missing","added","special"):
            altered=copy.deepcopy(entries)
            if variant=="changed":altered["complete/native/stdout.raw"]["sha256"]="0"*64
            elif variant=="missing":altered.clear()
            elif variant=="added":altered["complete/native/extra.raw"]=copy.deepcopy(row)
            else:altered["complete/link"]={"type":"symlink","mode":0o777,"bytes":0,"linkname":"elsewhere"}
            with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,"Bound"):
                ci.check_bound_archive(value,altered)

class MempoolCIWitnessTests(unittest.TestCase):
    """Small binding fixtures are not native qualification or a real CI run."""
    def make_witnesses(self,root):
        import copy
        complete=root/"complete";public_directory=root/"public"
        complete.mkdir();public_directory.mkdir()
        paths=sorted({name for _,names in ci.WITNESS_SPECS.values() for name in names})
        files={}
        for index,name in enumerate(paths):
            path=complete/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(("baseline-"+str(index)).encode());files[name]=ci.identity(path)
        baseline={"schema":"explicit-binding-test-only","source_set_sha256":"a"*64,
            "status":"FIXTURE_NOT_QUALIFICATION","files":files,"unchanged_field":"original"}
        (complete/"report.json").write_text(json.dumps(baseline))
        public={"baseline_qualification_report":ci.identity(complete/"report.json"),
            "baseline_source_set_sha256":baseline["source_set_sha256"],"baseline_file_count":len(files),
            "witness_control_count":8,"witness_controls":[]}
        for name,(error,changed) in ci.WITNESS_SPECS.items():
            directory=public_directory/name;directory.mkdir()
            expected=copy.deepcopy(baseline)
            row={"name":name,"status":"PASS","expected_error":error,"observed_error":error+": fixture refusal",
                "actual_runtime_executed":False,"changed_files":{}}
            for relative in changed:
                path=directory/"overlay"/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((name+":"+relative).encode())
                after=ci.identity(path);row["changed_files"][relative]={"before":files[relative],"after":after}
                expected["files"][relative]=after
            (directory/"mutated-summary.json").write_text(json.dumps(expected))
            row["mutated_summary"]=ci.identity(directory/"mutated-summary.json")
            (directory/"receipt.json").write_text(json.dumps(row));public["witness_controls"].append(row)
        return complete,public_directory,public

    def test_exact_eight_witness_transitions_bind_to_complete_baseline(self):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-witness-binding-") as directory:
            complete,public_directory,public=self.make_witnesses(Path(directory))
            self.assertEqual(ci.witness_reports(public_directory,complete,public),8)

    def test_witness_binding_rejects_self_consistent_summary_or_overlay_drift(self):
        variants=("missing-witness","duplicate-witness","reordered-witness","wrong-count","bool-count",
            "changed-baseline","changed-source-set","wrong-baseline-count","wrong-error","wrong-observed-error",
            "runtime-claim","missing-transition","extra-transition","foreign-before","unchanged-transition",
            "overlay-byte-drift","missing-overlay","extra-overlay","aliased-overlay",
            "changed-summary-scope","missing-summary-file","foreign-summary-identity","receipt-drift")
        for variant in variants:
            with self.subTest(variant=variant),tempfile.TemporaryDirectory(prefix="trnm-mempool-witness-negative-") as directory:
                complete,public_directory,public=self.make_witnesses(Path(directory))
                row=public["witness_controls"][0];case=public_directory/row["name"]
                relative=next(iter(row["changed_files"]));path=case/"overlay"/relative
                if variant=="missing-witness":public["witness_controls"].pop()
                elif variant=="duplicate-witness":public["witness_controls"][-1]=row
                elif variant=="reordered-witness":public["witness_controls"].reverse()
                elif variant=="wrong-count":public["witness_control_count"]=7
                elif variant=="bool-count":public["witness_control_count"]=True
                elif variant=="changed-baseline":(complete/"report.json").write_bytes((complete/"report.json").read_bytes()+b" ")
                elif variant=="changed-source-set":public["baseline_source_set_sha256"]="b"*64
                elif variant=="wrong-baseline-count":public["baseline_file_count"]+=1
                elif variant=="wrong-error":row["expected_error"]="unrelated error"
                elif variant=="wrong-observed-error":row["observed_error"]="unrelated error"
                elif variant=="runtime-claim":row["actual_runtime_executed"]=True
                elif variant=="missing-transition":row["changed_files"].pop(relative)
                elif variant=="extra-transition":row["changed_files"]["unexpected"]=row["changed_files"][relative]
                elif variant=="foreign-before":row["changed_files"][relative]["before"]={"bytes":1,"sha256":"0"*64}
                elif variant=="unchanged-transition":row["changed_files"][relative]["after"]=row["changed_files"][relative]["before"]
                elif variant=="overlay-byte-drift":path.write_bytes(path.read_bytes()+b"changed")
                elif variant=="missing-overlay":path.unlink()
                elif variant=="extra-overlay":(case/"overlay/extra.raw").write_bytes(b"added")
                elif variant=="aliased-overlay":path.unlink();path.symlink_to(complete/relative)
                elif variant in ("changed-summary-scope","missing-summary-file"):
                    summary=ci.read(case/"mutated-summary.json")
                    if variant=="changed-summary-scope":summary["unchanged_field"]="silently rewritten"
                    else:summary["files"].pop(relative)
                    (case/"mutated-summary.json").write_text(json.dumps(summary))
                    row["mutated_summary"]=ci.identity(case/"mutated-summary.json")
                elif variant=="foreign-summary-identity":row["mutated_summary"]={"bytes":1,"sha256":"0"*64}
                (case/"receipt.json").write_text(json.dumps(row))
                if variant=="receipt-drift":(case/"receipt.json").write_text("{}")
                with self.assertRaises((ValueError,OSError,KeyError,TypeError)):
                    ci.witness_reports(public_directory,complete,public)

class MempoolPreflightBoundaryTests(unittest.TestCase):
    def test_real_detached_checkout_requires_explicit_audit_and_keeps_project_boundaries(self):
        import shutil,subprocess
        from hia.platform.mempool_typed.contract import preflight
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-preflight-boundary-") as temporary:
            base=Path(temporary);root=base/"source";root.mkdir()
            names=["PROJECT_ID","PROJECT_BOUNDARY.json","config/portability-inventory-v1.json",
                   "trillionnium/Cargo.toml","scripts/project-preflight.sh","scripts/ci/project_boundary.py"]
            inventory=json.loads((ci.ROOT/"config/portability-inventory-v1.json").read_bytes())
            names.extend("trillionnium/crates/"+row["package"]+"/Cargo.toml" for row in inventory["packages"])
            for name in names:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ci.ROOT/name,target)
            def git(*arguments):
                return subprocess.run(["git","-C",str(root),*arguments],capture_output=True,check=True)
            git("init","--quiet","--initial-branch=feature/chain-preflight-fixture")
            origin="https://github.com/TrillionniumFoundation/Trillionnium-Chain"
            git("remote","add","origin",origin);git("add","--",".")
            git("-c","user.name=HIA boundary fixture","-c","user.email=fixture@example.invalid",
                "commit","--quiet","-m","Exact repository boundary metadata fixture")
            def observe(name,audit=False,rejected=None):
                directory=base/name;directory.mkdir()
                if rejected is None:
                    result=preflight(root,directory,audit=audit)
                    self.assertEqual(result["mode"],"--audit" if audit else "--dev")
                    self.assertEqual(result["exit_code"],0)
                    self.assertEqual((directory/"preflight.stderr").read_bytes(),b"")
                    return
                with self.assertRaisesRegex(ValueError,"Project preflight failed"):
                    preflight(root,directory,audit=audit)
                self.assertIn(rejected.encode(),(directory/"preflight.stderr").read_bytes())
            observe("development")
            git("switch","--detach","HEAD")
            self.assertEqual(git("branch","--show-current").stdout,b"")
            observe("detached-default",rejected="not an allowed development branch")
            observe("detached-audit",audit=True)
            git("remote","set-url","origin","https://github.com/foreign/other.git")
            observe("foreign-origin",audit=True,rejected="origin mismatch")
            git("remote","set-url","origin",origin)
            boundary=root/"PROJECT_BOUNDARY.json";original=boundary.read_bytes()
            altered=json.loads(original);altered["consensus"]["production_consensus_activation"]=True
            boundary.write_text(json.dumps(altered))
            observe("activation-changed",audit=True,rejected="activation changed")
            boundary.write_bytes(original)
            self.assertEqual(git("status","--porcelain").stdout,b"")

    def test_public_readback_rejects_audit_mode_without_opening_evidence(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-preflight-readback-") as temporary:
            absent=Path(temporary)/"must-not-be-opened"
            result=subprocess.run([sys.executable,"-B","-m","hia.platform.mempool_typed.qualify",
                "--verify",str(absent),"--audit"],cwd=ci.ROOT,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b"Readback does not execute a compiler or preflight",result.stderr)
            self.assertEqual(result.stdout,b"")
            self.assertFalse(absent.exists())

if __name__=="__main__":unittest.main()
