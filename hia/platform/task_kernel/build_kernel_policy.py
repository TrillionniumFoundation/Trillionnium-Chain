"""Build the native store trust, committed context and authorization policy."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build as PinnedBuild, INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_boundary import SourceBuild
from hia.platform.task_kernel.build_provider import identity, need

HERE = Path(__file__).resolve().parent


class KernelPolicyBuild(SourceBuild):
    def run(self):
        self.report.update(schema="trnm.hia.task-kernel.kernel-policy-build.v1",
                           scope="Candidate store trust, committed context and authorization policy")
        self.write()
        try:
            need(__debug__, "Optimized Python builder refused")
            self.stage("preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            self.pinned = PinnedBuild(self.output / "pinned-native")
            sys.path.insert(0, str(self.pinned.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            self.assemble = assemble_program
            for relative in PINNED_INPUTS:
                self.capture(ROOT / "hia" / relative)
            for path in [Path(__file__), HERE / "build_boundary.py", HERE / "build_provider.py",
                         HERE / "kernel_policy_includes.json", HERE / "qualification/kernel_policy_original.rs",
                         HERE / "qualification/type_layout.json", HERE / "qualification/kernel_policy_observer.py",
                         HERE / "qualification/kernel_policy_hook.rs",
                         HERE / "qualification/borsh_fixture.py",
                         ROOT / "scripts/project-preflight.sh", ROOT / "scripts/ci/project_boundary.py"]:
                self.capture(path)
            for name in ("types.rs", "store.rs", "codec.rs", "error.rs"):
                self.capture(ROOT / "trillionnium/crates/trnm-task-kernel/src" / name)
            self.capture(self.pinned.compiler_path)
            declaration = json.loads((HERE / "kernel_policy_includes.json").read_text())
            need(declaration["schema"] == "trnm.hia.task-kernel-policy-includes.v1", "Unknown includes schema")
            deps = [ROOT / p for p in dict.fromkeys(declaration["functions"].values())]
            raw, closure = self.compose(ROOT / declaration["source"], deps)
            actual = {name: str(Path(row["source"]).relative_to(ROOT)) for name, row in closure.items()
                      if str(Path(row["source"]).relative_to(ROOT)) != declaration["source"]}
            need(actual == declaration["functions"], "Kernel policy canonical include closure differs")
            (self.output / "kernel-policy.hepta").write_bytes(raw)
            native = self.pinned.stage(self.pinned.compiler, raw, "compile-kernel-policy")
            need(native.startswith(b"\x7fELF\x02\x01"), "Expected actual ELF64LE compiler output")
            (self.output / "kernel-policy.o").write_bytes(native)
            self.stage("link-kernel-policy", ["ld", "-shared", "-z", "defs", "-z", "noexecstack", "--build-id=none",
                                          self.output / "kernel-policy.o", "-lc", "-o", self.output / "kernel-policy.so"])
            (self.output / "native-compiler").write_bytes(self.pinned.compiler)
            self.fence()
            self.report.update(status="PASS", finalized=True, source_before=self.sources,
                               source_after={p: identity(p) for p in self.sources}, function_sources=closure,
                               native_stages=self.pinned.stages,
                               artifacts={name: identity(self.output / name) for name in
                                          ("kernel-policy.hepta", "kernel-policy.o", "kernel-policy.so", "native-compiler")},
                               full_task_kernel_owner_qualified=False,
                               wire_accepted=False, global_state_authority=False, production_activation=False)
            self.write()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error), source_before=self.sources)
            if hasattr(self, "pinned"):
                self.report["native_stages"] = self.pinned.stages
            self.write()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = KernelPolicyBuild(args.output).run()
    print(json.dumps({"status": result["status"], "functions": len(result["function_sources"]),
                      "report": str(args.output / "build.json")}))
