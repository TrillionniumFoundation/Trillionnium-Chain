"""Source-bound build of the private HIA continuity and typed staging owner.

Every machine instruction is emitted by the pinned HIA native compiler or the
literal HIA Linux adapter. The only hosted link action concatenates the emitted
prefix and the four exact independently compiled native images.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

from hia.platform.build import Build as PinnedBuild, inspect_executable, sha256
from hia.platform.typed_store.build import file_identity, original_manifest, owned_functions, describe_core
from hia.tools.toolchain import compose_source

HIA = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TYPED = HIA / 'platform/typed_store'

def need(condition, message):
    if not condition:
        raise ValueError(message)

class Build:
    def __init__(self, output: Path, repository: Path):
        if not __debug__:
            raise RuntimeError('Optimized qualification is not supported')
        output.mkdir(mode=0o700)
        self.output = output
        self.repository = repository.resolve(strict=True)
        need(HIA.resolve() == self.repository / 'hia', 'Builder repository differs')
        self.pinned = PinnedBuild(output / 'pinned-native')
        self.inputs, self.paths = {}, {}
        for directory in (HERE, TYPED):
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.suffix in {'.py', '.rs', '.json', '.hepta', '.md'}:
                    self.capture(path)
        for relative in ('platform/build.py', 'tools/toolchain.py', 'components.json',
                'platform/transport_request/rust_oracle.py', 'tests/test_state_root.py',
                'tests/native_support.py', 'toolchain.lock.json', 'qualification/compiler-binding.json'):
            self.capture(HIA / relative)
        self.original = original_manifest(self.repository)
        configuration = json.loads(self.inputs['hia/platform/continuity_store/source-inputs.json'])
        need(configuration['schema'] == 'trnm.hia.continuity-installed-inputs.v1', 'Unknown installed input schema')
        for name in configuration['files']:
            need(isinstance(name, str) and name.startswith('config/pon/') and '..' not in Path(name).parts,
                'Installed configuration path leaves exact original source')
            self.capture(self.repository / name)
        self.declarations = {}
        for prefix, directory, schema in (
                ('platform/typed_store/', TYPED, 'trnm.hia.typed-stage-includes.v1'),
                ('platform/continuity_store/', HERE, 'trnm.hia.continuity-store-includes.v1')):
            includes = json.loads((directory / 'includes.json').read_bytes())
            need(set(includes) == {'schema', 'includes'} and includes['schema'] == schema,
                'Unknown private dependency schema')
            for name, rows in includes['includes'].items():
                need(Path(name).name == name and name.endswith('.hepta'), 'Invalid private component name')
                self.declarations[prefix + name] = rows
        sys.path.insert(0, str(self.pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.assemble = assemble_program
        self.admitted = {}
        self.composed, self.core = {}, {}
        for name, path in (
                ('primary', 'platform/continuity_store/primary_policy.hepta'),
                ('root', 'platform/typed_store/root_finalize.hepta'),
                ('continuity', 'platform/continuity_store/continuity_policy.hepta'),
                ('context', 'platform/continuity_store/context.hepta')):
            combined, _ = self.admit(path, ())
            self.composed[name] = combined
            self.core[name] = describe_core(self.assemble(combined).as_dict())
            need(self.core[name]['functions'] <= 128 and self.core[name]['ops'] <= 8192,
                'Native compiler profile exceeded')
        self.emitter_source = self.inputs['hia/platform/continuity_store/linux_continuity_emitter.hepta']
        self.core['emitter'] = describe_core(self.assemble(self.emitter_source).as_dict())
        self.manifest = {name: {'bytes': len(raw), 'sha256': sha256(raw)}
            for name, raw in sorted(self.inputs.items())}
        self.check_sources()

    def capture(self, path: Path, admitted: bytes | None = None):
        need(not path.is_symlink() and path.is_file(), 'Missing or symlinked source: ' + str(path))
        name = path.relative_to(self.repository).as_posix()
        raw = path.read_bytes()
        need(admitted is None or raw == admitted, 'Source changed during admission: ' + name)
        need(name not in self.inputs or self.inputs[name] == raw, 'Inconsistent source capture: ' + name)
        self.inputs[name], self.paths[name] = raw, path
        return raw

    def admit(self, relative: str, ancestry: tuple):
        need(relative not in ancestry and '..' not in Path(relative).parts, 'Cyclic or escaping include')
        if relative in self.admitted:
            return self.admitted[relative]
        path = HIA / relative
        if relative.startswith('src/'):
            combined, captures = compose_source(path)
            for capture, raw in captures:
                self.capture(capture, raw)
            own = owned_functions(path.read_bytes())
        else:
            need(relative in self.declarations, 'Undeclared private HIA dependency: ' + relative)
            raw = self.capture(path)
            own = owned_functions(raw)
            blocks, names = [raw.rstrip() + b'\n'], set(own)
            rows = self.declarations[relative]
            need(isinstance(rows, list), 'Includes must be an explicit list')
            for row in rows:
                need(isinstance(row, dict) and set(row) == {'source', 'functions'}
                    and isinstance(row['functions'], list) and bool(row['functions']), 'Malformed HIA include')
                dependency = row['source']
                need(isinstance(dependency, str) and not Path(dependency).is_absolute(), 'Invalid dependency')
                _, available = self.admit(dependency, (*ancestry, relative))
                for function in row['functions']:
                    need(isinstance(function, str) and function in available and function not in names,
                        'Unknown or duplicate HIA function: ' + str(function))
                    names.add(function)
                    blocks.append(available[function].rstrip() + b'\n')
            combined = b''.join(blocks)
        checked = self.assemble(combined).as_dict()
        need(set(own) <= {function['name'] for function in checked['functions']}, 'Function boundaries differ')
        self.admitted[relative] = combined, own
        return combined, own

    def check_sources(self):
        self.pinned.check_pin()
        for name, raw in self.inputs.items():
            path = self.paths[name]
            need(not path.is_symlink() and path.read_bytes() == raw, 'Continuity source changed: ' + name)
        need(original_manifest(self.repository) == self.original, 'Original source changed')
        from hia.platform.continuity_store.rust_oracle import complete_source_manifest
        need(complete_source_manifest(self.repository) == self.manifest,
            'Complete current source closure differs from captured native inputs')

    def build(self):
        self.check_sources()
        images = {}
        for name in ('primary', 'root', 'continuity', 'context'):
            images[name] = self.pinned.stage(self.pinned.compiler, self.composed[name], 'compile-' + name)
            need(0 < len(images[name]) <= 1048576, 'Compiled image extent exceeds pinned profile')
            (self.output / (name + '.flat')).write_bytes(images[name])
            (self.output / (name + '-composed.hepta')).write_bytes(self.composed[name])
        emitter = self.pinned.stage(self.pinned.compiler, self.emitter_source, 'compile-emitter')
        inspect_executable(emitter)
        payload = struct.pack('<4Q', *(len(images[name]) for name in images))
        prefix = self.pinned.stage(emitter, payload, 'emit-elf-prefix')
        need(176 <= len(prefix) <= 4096, 'Unexpected emitted ELF prefix extent')
        executable = prefix + b''.join(images.values())
        elf = inspect_executable(executable)
        (self.output / 'emitter.elf').write_bytes(emitter)
        (self.output / 'elf-prefix.raw').write_bytes(prefix)
        (self.output / 'continuity-stage.elf').write_bytes(executable)
        self.check_sources()
        receipt = {'schema': 'trnm.hia.continuity-staging-build.v1', 'status': 'PASS',
            'source_inputs': self.manifest, 'original_sources': self.original,
            'source_inputs_stable': True, 'core': self.core,
            'source_set_sha256': sha256(json.dumps(self.manifest, sort_keys=True, separators=(',', ':')).encode()),
            'toolchain': self.pinned.lock, 'compiler_sha256': sha256(self.pinned.compiler),
            'compiler_qualification_binding': self.pinned.binding, 'stages': self.pinned.stages,
            'images': {name: {'bytes': len(raw), 'sha256': sha256(raw)} for name, raw in images.items()},
            'emitter': {'bytes': len(emitter), 'sha256': sha256(emitter)},
            'elf_prefix': {'bytes': len(prefix), 'sha256': sha256(prefix)},
            'executable': {'bytes': len(executable), 'sha256': sha256(executable), **elf},
            'hosted_link_action': 'concatenate exact native-emitted prefix and four native-compiled images',
            'runtime_host_proxy': False, 'interpreter_or_rust_fallback': False,
            'literal_isa_is_a_separate_trusted_boundary': True,
            'namespace_commit_ack_authority': False, 'complete_node': False}
        (self.output / 'build.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        self.executable = executable
        return executable, receipt
