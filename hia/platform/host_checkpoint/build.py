"""Source-bound native build of the fresh Host checkpoint owner.

The build compiles complete checked-in HIA sources and executes the HIA ELF
emitter. This Python driver neither emits ISA nor supplies runtime I/O results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

HIA = Path(__file__).resolve().parents[2]
ROOT = HIA.parent
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build as PinnedBuild
from hia.platform.build import inspect_executable, new_output, sha256, write_json

HERE = Path(__file__).resolve().parent
INPUTS = (
    'hia/platform/host_checkpoint/owner_policy.hepta',
    'hia/platform/host_checkpoint/linux_emitter.hepta',
    'hia/platform/host_checkpoint/fixture_entry.hepta',
    'hia/platform/host_checkpoint/build.py',
    'hia/platform/host_checkpoint/qualify.py',
    'hia/platform/host_checkpoint/qualify_production.py',
    'hia/platform/host_checkpoint/original_cases.py',
    'hia/platform/host_checkpoint/rust_reference.rs',
    'hia/platform/host_checkpoint/rust_oracle.py',
    'hia/platform/host_checkpoint/abi.json',
    'hia/platform/host_checkpoint/README.md',
    'hia/tests/test_host_checkpoint.py',
    'hia/tests/test_host_production.py',
    'hia/qualification/host-production-trace-parser-development.json',
    'hia/platform/transport_request/rust_oracle.py',
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent_relative_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/error.rs',
    'scripts/ci/public_host_ci_observation.py',
    'scripts/ci/public_fixture_host_lease.py',
    'scripts/ci/run_from_zero_host.py',
    'scripts/ci/verify_ci_source.py',
)


def source_manifest() -> dict:
    if not __debug__:
        raise RuntimeError('Host source validation requires normal Python execution')
    rows = {}
    for relative in INPUTS:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError('Missing, symlinked or noncanonical Host source: ' + relative)
        data = path.read_bytes()
        rows[relative] = {'bytes': len(data), 'sha256': sha256(data)}
    return rows


def compose_fixture(canonical: bytes, fixture: bytes) -> tuple[bytes, dict]:
    pattern = rb'^fn ([A-Za-z_][A-Za-z_0-9]*)\('
    functions = list(re.finditer(pattern, canonical, re.MULTILINE))
    entries = list(re.finditer(pattern, fixture, re.MULTILINE))
    if (len(functions) < 2 or functions[0].group(1) != b'f0'
            or functions[1].group(1) != b'host_entry'
            or any(not row.group(1).startswith(b'host_') for row in functions[1:])
            or len(entries) != 1 or entries[0].group(1) != b'f0'
            or not fixture.startswith(b'hia-asm.v1 hepta.hia.program.v8 ')
            or not fixture.endswith(b'\n')):
        raise ValueError('Unexpected Host owner/fixture function inventory')
    helpers = canonical[functions[1].start():]
    combined = fixture + helpers
    return combined, {
        'method': 'explicit fixture f0 and byte-identical production helper functions',
        'canonical_sha256': sha256(canonical), 'fixture_sha256': sha256(fixture),
        'helpers_sha256': sha256(helpers), 'helpers_bytes': len(helpers),
        'combined_sha256': sha256(combined), 'combined_bytes': len(combined),
    }


class Build(PinnedBuild):
    def __init__(self, output: Path):
        if not __debug__:
            raise RuntimeError('Host native qualification refuses optimized Python')
        super().__init__(output)
        self.host_manifest = source_manifest()
        self.host_sources = {}
        for name in ('owner_policy.hepta', 'linux_emitter.hepta', 'fixture_entry.hepta'):
            data = (HERE / name).read_bytes()
            if sha256(data) != self.host_manifest['hia/platform/host_checkpoint/' + name]['sha256']:
                raise ValueError('Host source changed during capture')
            self.host_sources[name] = data
        self.check_pin()

    @property
    def source_inputs(self) -> dict:
        return {**{'hia/' + key: value for key, value in self.manifest.items()},
                **self.host_manifest}

    def check_pin(self) -> None:
        super().check_pin()
        if hasattr(self, 'host_manifest') and source_manifest() != self.host_manifest:
            raise ValueError('Host owner or complete original comparison source changed')

    def core_check(self, data: bytes) -> dict:
        sys.path.insert(0, str(self.toolchain))
        from hepta import hia_agent_assembly
        if self.toolchain not in Path(hia_agent_assembly.__file__).resolve().parents:
            raise ValueError('Core verifier must be from the pinned checkout')
        document = hia_agent_assembly.assemble_program(data).as_dict()
        return {'status': 'CORE_ACCEPTED', 'source_sha256': sha256(data),
                'functions': len(document['functions']),
                'emitted_isa_semantics_proven': False}

    def pack(self, policy: bytes, label: str) -> tuple[bytes, dict]:
        image = self.stage(self.emitter, policy, label)
        profile = inspect_executable(image)
        if not 0 < len(policy) <= 524288 or not image.endswith(policy):
            raise ValueError('HIA emitter did not retain the exact complete native policy')
        return image, {'sha256': sha256(image), 'bytes': len(image),
                       'adapter_prefix_bytes': len(image) - len(policy), **profile}

    def build(self) -> dict:
        canonical = self.host_sources['owner_policy.hepta']
        emitter_source = self.host_sources['linux_emitter.hepta']
        fixture, composition = compose_fixture(canonical, self.host_sources['fixture_entry.hepta'])
        core = {'owner': self.core_check(canonical), 'emitter': self.core_check(emitter_source),
                'fixture': self.core_check(fixture)}
        self.policy = self.stage(self.compiler, canonical, 'compile-host-owner')
        self.emitter = self.stage(self.compiler, emitter_source, 'compile-host-emitter')
        emitter_profile = inspect_executable(self.emitter)
        self.executable, production_profile = self.pack(self.policy, 'emit-host-owner')
        self.fixture_policy = self.stage(self.compiler, fixture, 'compile-host-fixture')
        self.fixture_executable, fixture_profile = self.pack(self.fixture_policy, 'emit-host-fixture')
        for name, data in (('owner.elf', self.executable), ('fixture.elf', self.fixture_executable),
                           ('policy.flat.bin', self.policy), ('fixture-policy.flat.bin', self.fixture_policy),
                           ('emitter.elf', self.emitter), ('fixture-composed.hepta', fixture)):
            (self.output / name).write_bytes(data)
        self.check_pin()
        result = {'schema': 'trnm.hia.fresh-host-build.v2', 'status': 'PASS',
                  'source_inputs': self.source_inputs, 'toolchain': self.lock,
                  'compiler_sha256': sha256(self.compiler),
                  'compiler_qualification_binding': self.binding,
                  'core_checks': core, 'stages': self.stages,
                  'policy': {'sha256': sha256(self.policy), 'bytes': len(self.policy)},
                  'executable': production_profile, 'fixture_executable': fixture_profile,
                  'emitter': {'sha256': sha256(self.emitter), 'bytes': len(self.emitter), **emitter_profile},
                  'fixture_composition': composition,
                  'runtime_host_language_or_dynamic_loader': False,
                  'adapter_is_hia_emitted_isa_data': True,
                  'independent_syscall_trace_qualified_by_build': False,
                  'whole_node_or_original_service_budget_qualified': False,
                  'recovered_old_candidate_source': False}
        write_json(self.output / 'build.json', result)
        return result


def main() -> int:
    if not __debug__:
        raise RuntimeError('Host build refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    build = Build(output / 'build')
    result = build.build()
    print(json.dumps({'status': result['status'], 'executable': result['executable'],
                      'report': str(build.output / 'build.json')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
