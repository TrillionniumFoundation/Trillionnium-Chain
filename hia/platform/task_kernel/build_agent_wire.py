"""Build the native candidate AgentTransaction constructor, decoder and getters."""
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


class AgentWireBuild(SourceBuild):
    def run(self):
        self.report.update(schema="trnm.hia.task-kernel.agent-wire-build.v1",
                           scope="Candidate AgentTransaction constructor, decoder and three getters")
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
                         HERE / "agent_wire_includes.json", HERE / "qualification/agent_wire_original.rs",
                         HERE / "qualification/type_layout.json", HERE / "qualification/agent_wire_observer.py",
                         ROOT / "scripts/project-preflight.sh", ROOT / "scripts/ci/project_boundary.py"]:
                self.capture(path)
            for name in ("types.rs", "agent_transaction_wire_v1.rs", "codec.rs", "error.rs"):
                self.capture(ROOT / "trillionnium/crates/trnm-task-kernel/src" / name)
            self.capture(self.pinned.compiler_path)
            declaration = json.loads((HERE / "agent_wire_includes.json").read_text())
            need(declaration["schema"] == "trnm.hia.task-agent-wire-includes.v1", "Unknown includes schema")
            deps = [ROOT / p for p in dict.fromkeys(declaration["functions"].values())]
            raw, closure = self.compose(ROOT / declaration["source"], deps)
            actual = {name: str(Path(row["source"]).relative_to(ROOT)) for name, row in closure.items()
                      if str(Path(row["source"]).relative_to(ROOT)) != declaration["source"]}
            need(actual == declaration["functions"], "Agent wire canonical include closure differs")
            (self.output / "agent-wire.hepta").write_bytes(raw)
            native = self.pinned.stage(self.pinned.compiler, raw, "compile-agent-wire")
            need(native.startswith(b"\x7fELF\x02\x01"), "Expected actual ELF64LE compiler output")
            (self.output / "agent-wire.o").write_bytes(native)
            self.stage("link-agent-wire", ["ld", "-shared", "-z", "defs", "-z", "noexecstack", "--build-id=none",
                                          self.output / "agent-wire.o", "-lc", "-o", self.output / "agent-wire.so"])
            (self.output / "native-compiler").write_bytes(self.pinned.compiler)
            self.fence()
            self.report.update(status="PASS", finalized=True, source_before=self.sources,
                               source_after={p: identity(p) for p in self.sources}, function_sources=closure,
                               native_stages=self.pinned.stages,
                               artifacts={name: identity(self.output / name) for name in
                                          ("agent-wire.hepta", "agent-wire.o", "agent-wire.so", "native-compiler")},
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
    result = AgentWireBuild(args.output).run()
    print(json.dumps({"status": result["status"], "functions": len(result["function_sources"]),
                      "report": str(args.output / "build.json")}))
