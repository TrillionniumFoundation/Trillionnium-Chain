"""Build the native aggregate Host resource owner from checked-in HIA only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build as PinnedBuild
from hia.platform.build import inspect_executable, new_output, sha256, write_json
from hia.platform.host_checkpoint.build import INPUTS as HOST_INPUTS

HERE = Path(__file__).resolve().parent
PREFIX = 'hia/platform/host_resource/'
INPUTS = tuple(dict.fromkeys((
    PREFIX + 'resource_policy.hepta', PREFIX + 'fixture_entry.hepta',
    PREFIX + 'build.py', PREFIX + 'README.md', PREFIX + 'abi.json',
    PREFIX + 'cases.py', PREFIX + 'native_io.py', PREFIX + 'qualify.py',
    PREFIX + 'rust_reference.rs', PREFIX + 'rust_oracle.py',
    PREFIX + 'test_integrity.py',
    'hia/platform/transport_request/rust_oracle.py',
    'hia/platform/host_checkpoint/owner_policy.hepta',
    'hia/platform/host_checkpoint/linux_emitter.hepta',
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent_relative_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/main.rs',
    'trillionnium/crates/trnm-pon-node/src/error.rs',
    *HOST_INPUTS,
    PREFIX + 'qualify_production.py', PREFIX + 'test_production.py',
    'scripts/ci/run_history_native.py',
    'scripts/ci/check_required_native_test.py',
    'scripts/ci/replay_pinned_native.py',
    'config/systemd/trnmponpublic.slice',
)))
HOST_SOURCE_SHA256 = '474aa5ce229c23723fe1f8bdcf7047c3e1bd3f2b95ed24f1a4c183702e86f3be'
HOST_EMITTER_SHA256 = '1f8911ee0d044d0df2f19c4986c49baffd580864c4c91982b413aae32a59572d'


def source_manifest() -> dict:
    if not __debug__:
        raise RuntimeError('Host resource validation refuses optimized Python')
    rows = {}
    for relative in INPUTS:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError('Noncanonical or missing resource source: ' + relative)
        raw = path.read_bytes()
        rows[relative] = {'bytes': len(raw), 'sha256': sha256(raw)}
    return rows


def compose(wrapper: bytes, host: bytes, fixture: bytes) -> tuple[bytes, bytes, dict]:
    pattern = rb'^fn ([A-Za-z_][A-Za-z_0-9]*)\('
    hosts = list(re.finditer(pattern, host, re.MULTILINE))
    resources = list(re.finditer(pattern, wrapper, re.MULTILINE))
    entries = list(re.finditer(pattern, fixture, re.MULTILINE))
    if (sha256(host) != HOST_SOURCE_SHA256 or len(hosts) < 2
            or hosts[0].group(1) != b'f0' or hosts[1].group(1) != b'host_entry'
            or any(not m.group(1).startswith(b'host_') for m in hosts[1:])
            or len(resources) < 2 or resources[0].group(1) != b'f0'
            or resources[1].group(1) != b'resource_entry'
            or any(not m.group(1).startswith(b'resource_') for m in resources[1:])
            or len(entries) != 1 or entries[0].group(1) != b'f0'
            or any(not raw.endswith(b'\n') for raw in (host, wrapper, fixture))):
        raise ValueError('Host/resource function or pinned source boundary changed')
    helpers = host[hosts[1].start():]
    production = wrapper + helpers
    private_fixture = fixture + wrapper[resources[1].start():] + helpers
    return production, private_fixture, {
        'method': 'new HIA resource owner plus byte-identical frozen Host helpers',
        'host_source_sha256': sha256(host), 'host_helpers_sha256': sha256(helpers),
        'host_helpers_bytes': len(helpers), 'resource_source_sha256': sha256(wrapper),
        'production_source_sha256': sha256(production),
        'fixture_source_sha256': sha256(private_fixture),
        'fixture_reuses_all_production_helpers': True,
    }


class Build(PinnedBuild):
    def __init__(self, output: Path):
        if not __debug__:
            raise RuntimeError('Host resource build refuses optimized Python')
        super().__init__(output)
        self.resource_manifest = source_manifest()
        self.check_pin()

    @property
    def source_inputs(self) -> dict:
        return {**{'hia/' + k: v for k, v in self.manifest.items()}, **self.resource_manifest}

    def check_pin(self):
        super().check_pin()
        if hasattr(self, 'resource_manifest') and source_manifest() != self.resource_manifest:
            raise ValueError('Resource owner or complete comparison source changed')

    def core_check(self, data: bytes) -> dict:
        sys.path.insert(0, str(self.toolchain))
        from hepta import hia_agent_assembly
        if self.toolchain not in Path(hia_agent_assembly.__file__).resolve().parents:
            raise ValueError('Resource Core verifier must be the pinned toolchain')
        program = hia_agent_assembly.assemble_program(data).as_dict()
        return {'status': 'CORE_ACCEPTED', 'sha256': sha256(data),
                'functions': len(program['functions']), 'literal_isa_effects_proven': False}

    def pack(self, policy: bytes, label: str) -> tuple[bytes, dict]:
        image = self.stage(self.emitter, policy, label)
        profile = inspect_executable(image)
        if not 0 < len(policy) <= 524288 or not image.endswith(policy):
            raise ValueError('Resource image does not retain its complete native policy')
        return image, {'sha256': sha256(image), 'bytes': len(image),
                       'adapter_prefix_bytes': len(image) - len(policy), **profile}

    def build(self) -> dict:
        self.check_pin()
        wrapper = (HERE / 'resource_policy.hepta').read_bytes()
        host = (ROOT / 'hia/platform/host_checkpoint/owner_policy.hepta').read_bytes()
        fixture_entry = (HERE / 'fixture_entry.hepta').read_bytes()
        emitter = (ROOT / 'hia/platform/host_checkpoint/linux_emitter.hepta').read_bytes()
        if sha256(emitter) != HOST_EMITTER_SHA256:
            raise ValueError('Reviewed read-only Host syscall adapter changed')
        production, fixture, composition = compose(wrapper, host, fixture_entry)
        core = {'production': self.core_check(production),
                'fixture': self.core_check(fixture), 'emitter': self.core_check(emitter)}
        policy = self.stage(self.compiler, production, 'compile-resource-owner')
        self.emitter = self.stage(self.compiler, emitter, 'compile-resource-emitter')
        emitter_profile = inspect_executable(self.emitter)
        self.executable, production_profile = self.pack(policy, 'emit-resource-owner')
        fixture_policy = self.stage(self.compiler, fixture, 'compile-resource-fixture')
        self.fixture_executable, fixture_profile = self.pack(fixture_policy, 'emit-resource-fixture')
        for name, raw in (('owner.elf', self.executable), ('fixture.elf', self.fixture_executable),
                ('policy.flat.bin', policy), ('fixture-policy.flat.bin', fixture_policy),
                ('owner-composed.hepta', production), ('fixture-composed.hepta', fixture),
                ('emitter.elf', self.emitter)):
            (self.output / name).write_bytes(raw)
        self.check_pin()
        result = {'schema': 'trnm.hia.host-resource-build.v1', 'status': 'PASS',
            'source_inputs': self.source_inputs, 'toolchain': self.lock,
            'compiler_sha256': sha256(self.compiler),
            'compiler_qualification_binding': self.binding,
            'core_checks': core, 'stages': self.stages, 'composition': composition,
            'executable': production_profile, 'fixture_executable': fixture_profile,
            'emitter': {'sha256': sha256(self.emitter), **emitter_profile},
            'policy': {'bytes': len(policy), 'sha256': sha256(policy)},
            'runtime_host_supplied_counters': False,
            'runtime_host_language_or_dynamic_loader': False,
            'production_fixed_parent_positive_qualified': False,
            'thread_cpu_account_or_wait4_owner_implemented': False,
            'whole_node_or_service_budget_qualified': False}
        write_json(self.output / 'build.json', result)
        return result


def main() -> int:
    if not __debug__:
        raise RuntimeError('Resource build refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = new_output(args.output)
    build = Build(output / 'build')
    result = build.build()
    print(json.dumps({'status': result['status'], 'report': str(build.output / 'build.json'),
                      'executable': result['executable']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
