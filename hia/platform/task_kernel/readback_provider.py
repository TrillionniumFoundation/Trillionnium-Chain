"""Independent source, native-object, link and differential provider readback.

This reader executes no compiler, C probe, provider or HIA fallback. It checks
the retained actual streams, complete paired observations, ELF symbols and
relocations, and the dynamic native witness data against its observed input.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tomllib

COMPILER = '87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54'
FENCE = 'trnm-hia-task-kernel-sqlite-3.54.1-hia-provider-x86_64-v2'
ORACLE_FENCE = 'trnm-hia-task-kernel-sqlite-3.54.1-c-oracle-x86_64-v1'
EXPORTS = set('trnm_task_provider trnm_task_provider_new trnm_task_provider_enter trnm_task_provider_leave trnm_task_provider_reset trnm_task_provider_free'.split())
IMPORTS = set('''__errno_location calloc clock_gettime close free fsync getpid link lstat malloc memchr memcpy mkdir open
pthread_mutex_destroy pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock read sqlite3_bind_blob64
sqlite3_bind_double sqlite3_bind_int64 sqlite3_bind_null sqlite3_bind_parameter_count sqlite3_bind_text64
sqlite3_busy_timeout sqlite3_changes64 sqlite3_close sqlite3_close_v2 sqlite3_column_blob sqlite3_column_bytes
sqlite3_column_count sqlite3_column_double sqlite3_column_int64 sqlite3_column_name sqlite3_column_text
sqlite3_column_type sqlite3_compileoption_get sqlite3_db_handle sqlite3_errcode sqlite3_errmsg sqlite3_error_offset
sqlite3_errstr sqlite3_extended_errcode sqlite3_finalize sqlite3_libversion_number sqlite3_open_v2
sqlite3_prepare_v3 sqlite3_sourceid sqlite3_step sqlite3_threadsafe stat strerror strlen
trnm_io_witness_compileoption trnm_io_witness_layout trnm_io_witness_source_id trnm_io_witness_version unlink'''.split())
WITNESS = {'trnm_io_witness_layout': (0, 27), 'trnm_io_witness_compileoption': (32, 28),
           'trnm_io_witness_version': (64, 6), 'trnm_io_witness_source_id': (80, 8)}
LAYOUT = [8, 4, 2, 8, 8, 168, 152, 120, 8, 0, 8, 24, 64, 24, 8, 0, 96, 8, 24]
ABI = {'pointer_bytes': 8, 'size_t_bytes': 8, 'int_bytes': 4, 'long_bytes': 8,
       'ssize_t_bytes': 8, 'mode_t_bytes': 4, 'mutex_bytes': 40, 'mutex_alignment': 8,
       'owner_bytes': 48, 'owner_lock_offset': 8, 'stat_bytes': 144, 'stat_mode_offset': 24,
       'stat_mode_bytes': 4, 'stat_size_offset': 48, 'stat_size_bytes': 8, 'timespec_bytes': 16,
       'timespec_seconds_offset': 0, 'timespec_nanoseconds_offset': 8, 'clock_realtime': 0}
SOURCE_PATHS = (
    'PROJECT_BOUNDARY.json', 'PROJECT_ID', 'config/portability-inventory-v1.json',
    'hia/platform/README.md', 'hia/platform/abi.json', 'hia/platform/build.py',
    'hia/platform/linux_adapter_emitter.hepta', 'hia/platform/probe_policy.hepta',
    'hia/platform/task_kernel/build_provider.py', 'hia/platform/task_kernel/build_witness.py',
    'hia/platform/task_kernel/provider_abi.json', 'hia/platform/task_kernel/provider_native.hepta',
    'hia/platform/task_kernel/qualification/provider_abi_probe.c',
    'hia/platform/task_kernel/witness_emitter.hepta', 'hia/platform/task_kernel/readback_provider.py',
    'hia/qualification/compiler-binding.json', 'hia/qualification/compiler-cold-full.json.xz',
    'hia/qualification/compiler-cold.json', 'hia/tests/test_platform_cleanup.py',
    'hia/toolchain.lock.json', 'hia/tools/qualify_platform.py', 'hia/tools/toolchain.py',
    'scripts/ci/project_boundary.py', 'scripts/project-preflight.sh', 'trillionnium/Cargo.toml',
    'trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c',
)
WITNESS_ARTIFACTS = {'emitter-compiled.hepta', 'emitter-input.bin', 'emitter-output.bin',
    'observed-identity.json', 'probe.o', 'probe.so', 'witness-emitter.o', 'witness-emitter.so',
    'witness.o', 'witness.so'}
PROVIDER_ARTIFACTS = {'observed-identity.json', 'provider-abi-probe', 'provider-abi.json',
    'provider-emitter-input.bin', 'provider-emitter-output.bin', 'provider-emitter.hepta',
    'provider-emitter.o', 'provider-emitter.so', 'provider.o', 'provider.so', 'sqlite.o', 'witness.o',
    'native-witness/build.json'} | {'native-witness/' + name for name in WITNESS_ARTIFACTS}


def require(yes, message):
    if not yes:
        raise ValueError(message)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def elf_object(raw):
    require(len(raw) >= 64 and raw[:16] == b'\x7fELF\x02\x01\x01' + bytes(9), 'Expected ELF64LE object')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    require(h[1:4] == (1, 62, 1) and h[4:6] == (0, 0) and h[11] == 64 and
            h[6] + 64 * h[12] == len(raw) and h[13] < h[12], 'Native object header differs')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, h[6] + 64 * i) for i in range(h[12])]
    for s in sections:
        require(s[4] <= len(raw) and s[5] <= len(raw) - s[4], 'ELF section extent exceeds object')
        require(s[2] & 1 == 0, 'Provider/witness object has writable static state')
    shstr = sections[h[13]]; names = raw[shstr[4]:shstr[4] + shstr[5]]
    def string(table, index):
        require(index < len(table) and b'\0' in table[index:], 'Unterminated ELF string')
        return table[index:table.index(b'\0', index)].decode('ascii')
    by_name = {string(names, s[0]): s for s in sections}
    require('.text' in by_name and '.note.GNU-stack' in by_name and by_name['.text'][1:3] == (1, 6) and
            by_name['.note.GNU-stack'][2] == 0, 'Native code or stack permissions differ')
    text_section = by_name['.text']; text = raw[text_section[4]:text_section[4] + text_section[5]]
    exported, imported, symbols, functions = {}, set(), [], {}
    symbol_table = by_name['.symtab']
    require(symbol_table[1] == 2 and symbol_table[9] == 24 and symbol_table[6] < len(sections), 'ELF symbol table differs')
    strings = sections[symbol_table[6]]; table = raw[strings[4]:strings[4] + strings[5]]
    for pos in range(symbol_table[4], symbol_table[4] + symbol_table[5], 24):
        name, info, other, section, offset, size = struct.unpack_from('<IBBHQQ', raw, pos)
        name = string(table, name); symbols.append(name)
        if section and info & 15 == 2:
            require(section == 1 and offset + size <= len(text), 'Native function extent differs')
            require(name not in functions, 'Duplicate native function symbol');functions[name] = (offset, size)
        if info >> 4 in (1, 2):
            if section:
                require(section == 1 and info & 15 == 2 and offset + size <= len(text), 'Export is not a bounded text function')
                require(name not in exported, 'Duplicate ELF public symbol');exported[name] = (offset, size)
            else:
                imported.add(name)
    relocations = []
    for s in sections:
        if s[1] not in (4, 9): continue
        require(s[1] == 4 and s[9] == 24, 'Unexpected native relocation format')
        for pos in range(s[4], s[4] + s[5], 24):
            offset, info, addend = struct.unpack_from('<QQq', raw, pos)
            require(info & 0xffffffff == 4 and addend == -4 and 0 < offset <= len(text) - 4 and
                    text[offset - 1:offset + 4] == b'\xe8' + bytes(4) and info >> 32 < len(symbols),
                    'Relocation is not an exact SysV PLT32 call')
            relocations.append((offset, symbols[info >> 32]))
    return {'exports': exported, 'imports': imported, 'relocations': relocations,
            'text': text, 'sections': by_name, 'functions': functions}


def linked_native_bytes(raw, provider, witness):
    """Bind the actual DSO's code and every call target to both native objects."""
    require(raw[:7] == b'\x7fELF\x02\x01\x01', 'Final provider image is not ELF64LE')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    require(h[1:4] == (3, 62, 1) and h[11] == 64, 'Final provider image is not x86_64 ET_DYN')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, h[6] + 64 * index) for index in range(h[12])]
    def string(table, index):
        require(index < len(table) and b'\0' in table[index:], 'Invalid linked symbol name')
        return table[index:table.index(b'\0', index)].decode('ascii')
    tables, functions = {}, {}
    for index, section in enumerate(sections):
        if section[1] not in (2, 11):continue
        require(section[9] == 24 and section[6] < len(sections), 'Invalid linked symbol table')
        strings = sections[section[6]];table = raw[strings[4]:strings[4] + strings[5]];entries = []
        for pos in range(section[4], section[4] + section[5], 24):
            name, info, other, shndx, address, size = struct.unpack_from('<IBBHQQ', raw, pos)
            name = string(table, name);entries.append(name)
            if shndx and info & 15 == 2 and name in set(provider['functions']) | set(WITNESS):
                value = (address, size)
                require(name not in functions or functions[name] == value, 'Ambiguous linked native function')
                functions[name] = value
        tables[index] = entries
    def extract(address, length):
        matches = [section for section in sections if section[1] == 1 and section[2] & 4 and
                   section[3] <= address and address + length <= section[3] + section[5]]
        require(len(matches) == 1, 'Native linked code is outside exact executable section')
        section = matches[0];offset = section[4] + address - section[3]
        require(offset + length <= len(raw), 'Linked code extends beyond image')
        return raw[offset:offset + length]
    jumps = {}
    for section in sections:
        if section[1] != 4:continue
        require(section[9] == 24 and section[6] in tables, 'Linked relocation table differs')
        for pos in range(section[4], section[4] + section[5], 24):
            address, info, addend = struct.unpack_from('<QQq', raw, pos)
            if info & 0xffffffff == 7:
                require(info >> 32 < len(tables[section[6]]), 'Invalid linked PLT symbol')
                jumps[address] = tables[section[6]][info >> 32]
    require(set(provider['functions']) | set(WITNESS) <= set(functions),
            'Final provider image is missing native lifecycle/helper functions')
    for name, (start, size) in provider['functions'].items():
        address, actual_size = functions[name]
        require(actual_size == size, 'Final provider function is not the HIA implementation: ' + name)
        expected = bytearray(provider['text'][start:start + size]);actual = bytearray(extract(address, size))
        for offset, target in provider['relocations']:
            if not start <= offset < start + size:continue
            relative = offset - start
            target_address = address + relative + 4 + struct.unpack_from('<i', actual, relative)[0]
            if target in functions and target_address == functions[target][0]:
                pass
            else:
                stub = extract(target_address, 16)
                skip = 4 if stub.startswith(b'\xf3\x0f\x1e\xfa') else 0
                require(stub[skip:skip + 2] == b'\xff\x25', 'Native foreign call does not target an admitted PLT slot')
                got = target_address + skip + 6 + struct.unpack_from('<i', stub, skip + 2)[0]
                require(jumps.get(got) == target, 'Native provider call was retargeted: ' + target)
            actual[relative:relative + 4] = expected[relative:relative + 4]
        require(actual == expected, 'Final linked native provider instructions differ: ' + name)
    witness_start = functions['trnm_io_witness_layout'][0]
    for name, (offset, size) in WITNESS.items():
        require(functions[name] == (witness_start + offset, size), 'Final witness function address/size differs')
    require(extract(witness_start, len(witness['text'])) == witness['text'],
            'Final provider image contains a foreign C witness or changed native metadata')


def constant_provider_emission(source):
    """Read the canonical provider emitter's literal writes independently.

    This is restricted source inspection, not a compiler or runtime fallback.
    Unknown helpers, computed writes or changing emission control require an
    explicit reader update; a producer's self-reported ELF is never sufficient.
    """
    matches = re.findall(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)', source)
    functions = {}
    for item in re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)', source):
        functions[item[1].decode()] = item[0].decode()
    require(len(functions) == len(matches) == 25 and 'f0' in functions, 'Canonical provider emitter function roster differs')
    calls = re.findall(r'\{"function":"([A-Za-z_][A-Za-z_0-9]*)"\}', functions['f0'])
    chunks = [name for name in calls if name.startswith('emit_')]
    require(len(chunks) == len(set(chunks)) and set(chunks) == set(functions) - {'f0', 'hp_emit_word', 'hp_emit_read'},
            'Provider emitter omits or substitutes a literal emission helper')
    def writes(body, entry=False):
        values, result = {}, []
        for line in body.splitlines():
            const = re.search(r'(v\d+):(u64|u32|u8) = const\(\) \{"value":(\d+)\}', line)
            if const:
                values[const[1]] = int(const[3]);continue
            cast = re.search(r'(v\d+):usize = int.cast\((v\d+)\) \{"mode":"wrap"\}', line)
            if cast and cast[2] in values:
                values[cast[1]] = values[cast[2]];continue
            word = re.search(r'call\([^,]+,(v\d+),(v\d+)\) \{"function":"hp_emit_word"\}', line)
            if word:
                require(word[1] in values and word[2] in values, 'Provider emission is no longer a reviewed literal write')
                result.append((values[word[1]], struct.pack('<Q', values[word[2]])));continue
            byte = re.search(r'_ = buffer.store\([^,]+,(v\d+),(v\d+)\)', line)
            if byte:
                require(byte[1] in values and byte[2] in values and values[byte[2]] <= 255,
                        'Provider literal byte write differs')
                result.append((values[byte[1]], bytes((values[byte[2]],))));continue
            if not entry:
                require(line.startswith(('fn ', 'block ', 'end')) or re.fullmatch(r'  ret\(v\d+\)', line),
                        'Provider emission helper contains unreviewed control or operation')
        return result
    header = writes(functions['f0'], True)
    require(len(header) == 1 and header[0][0] == 0, 'Provider emitter size declaration differs')
    size = struct.unpack('<Q', header[0][1])[0]
    require(64 <= size <= 65528, 'Provider emitter ELF extent differs')
    output = bytearray(size + 8);touched = bytearray(size + 8)
    for offset, payload in header + [item for name in chunks for item in writes(functions[name])]:
        require(offset <= len(output) and len(payload) <= len(output) - offset, 'Provider literal emission overruns output')
        output[offset:offset + len(payload)] = payload;touched[offset:offset + len(payload)] = b'\1' * len(payload)
    require(all(touched), 'Provider emitter leaves uninitialized ELF bytes')
    return bytes(output)


def canonical_reads(read):
    def checked(path, expected=None):
        path = Path(path).absolute()
        require(path.resolve() == path and all(not parent.is_symlink() for parent in path.parents),
                'Symlinked or noncanonical provider evidence path')
        return read(path, expected)
    return checked


def check_provider(read, directory, repo):
    read = canonical_reads(read)
    directory, repo = Path(directory).absolute(), Path(repo).absolute()
    require(Path(__file__).absolute() == repo / 'hia/platform/task_kernel/readback_provider.py',
            'Reader must be the canonical current provider reader')
    def load(path): return json.loads(read(path))
    def passed(path):
        value = load(path)
        require(value.get('status') == 'PASS' and value.get('finalized') is True, 'Incomplete provider evidence')
        if 'source_before' in value:
            require(value['source_before'] == value['source_after'], 'Provider source fence differs')
            for name, expected in value['source_before'].items():read(name, expected)
        return value
    def streams(base, rows):
        names = []
        for row in rows:
            name = row['name'];require(name not in names and row.get('completed') is True and
                    row.get('exit_code', row.get('exit')) == 0, 'Failed/duplicate provider stage')
            names.append(name)
            for stream in ('stdin', 'stdout', 'stderr'):read(base / (name + '.' + stream + '.raw'))
        return names
    def compile_native(base, canonical, compiled_name, object_name, rows, stage):
        require(len(rows) == 1 and rows[0]['stage'] == stage, 'Native provider compiler roster differs')
        receipt = rows[0]; work = base / 'pinned-native' / stage
        require(load(work / 'receipt.json') == receipt and receipt['exit_code'] == 0 and
                not receipt['timed_out'] and receipt['stderr_hex'] == '' and
                receipt['wall_limit_seconds'] == 30 and receipt['cleanup_limit_seconds'] == 3 and
                receipt['executable_sha256'] == COMPILER, 'Native provider compiler execution differs')
        source = b'hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n' + read(canonical).split(b'\n', 1)[1]
        require(read(base / compiled_name) == read(work / 'stdin.raw') == source and
                identity(source) == {'bytes': receipt['input_bytes'], 'sha256': receipt['input_sha256']},
                'Native provider compiler source bytes differ')
        actual = read(work / 'stdout.raw')
        require(actual == read(base / object_name) and identity(actual) ==
                {'bytes': receipt['output_bytes'], 'sha256': receipt['output_sha256']} and
                read(work / 'stderr.raw') == b'', 'Native provider compiler output bytes differ')
        profile = elf_object(actual)
        require(profile['exports'] == {'f0': (0, 78)} and not profile['imports'],
                'Native HIA emitter object has a substituted foreign ABI')
    build = passed(directory / 'build.json')
    require(build['schema'] == 'trnm.hia.task-kernel.sqlite-provider.v2' and build['fence'] == FENCE and
            build['qualification_only_original_oracle'] is False, 'Legacy C oracle cannot be a production provider')
    members = tomllib.loads(read(repo / 'trillionnium/Cargo.toml').decode())['workspace']['members']
    expected_sources = {str(repo / name) for name in SOURCE_PATHS}
    expected_sources.update(str(repo / 'trillionnium' / member / 'Cargo.toml') for member in members)
    dependencies = [Path(path).parent for path in build['source_before']
                    if path.endswith('/libsqlite3-sys-0.39.1/Cargo.toml')]
    require(len(dependencies) == 1, 'Ambiguous original SQLite dependency source')
    dependency = dependencies[0]
    expected_sources.update(str(dependency / name) for name in ('Cargo.toml', 'build.rs', 'sqlite3/sqlite3.c', 'sqlite3/sqlite3.h'))
    require(set(build['source_before']) == expected_sources, 'Provider canonical source namespace is missing or substituted')
    claims = build['claims']
    require(claims['project_provider_runtime_hia'] is True and claims['project_witness_runtime_hia'] is True and
            claims['original_project_c_linked'] is False and claims['third_party_sqlite_c_linked'] is True and
            claims['pure_hia_sqlite'] is False and claims['whole_chain_native'] is False, 'Provider runtime boundary claim differs')
    require(set(build['artifacts']) == PROVIDER_ARTIFACTS, 'Production provider artifact roster differs')
    for name, expected in build['artifacts'].items():read(directory / name, expected)
    native = build['native_provider']; read(native['compiler']['path'], native['compiler'])
    require(native['compiler']['sha256'] == COMPILER and native['emission_status'] == 0 and
            native['source_from_original_c_object'] is False, 'Provider is not from the pinned native HIA emitter')
    compile_native(directory, repo / 'hia/platform/task_kernel/provider_native.hepta', 'provider-emitter.hepta',
                   'provider-emitter.o', native['compiler_stages'], 'compile-provider-emitter')
    require(read(directory / 'provider-emitter-input.bin', native['input']) == b'TKPROV01', 'Provider emitter request differs')
    emitted = read(directory / 'provider-emitter-output.bin', native['output'])
    obj = read(directory / 'provider.o', native['object'])
    require(emitted == struct.pack('<Q', len(obj)) + obj, 'Provider object differs from actual HIA emission')
    require(emitted == constant_provider_emission(read(repo / 'hia/platform/task_kernel/provider_native.hepta')),
            'Provider ELF differs from canonical HIA literal emission despite rehashed manifests')
    parsed = elf_object(obj)
    require(set(parsed['exports']) == EXPORTS and parsed['imports'] == IMPORTS and
            set(native['exports']) == EXPORTS and set(native['imports']) == IMPORTS and
            set(name for _, name in parsed['relocations']) >= IMPORTS, 'Provider native ELF ABI differs')
    require(load(directory / 'provider-abi.json') == load(directory / 'observe-provider-abi.stdout.raw') == ABI ==
            build['native_provider_abi'], 'Actual platform ABI probe differs from native owner layout')
    stages = {row['name']: row for row in build['stages']}
    require(streams(directory, build['stages']) == ['preflight', 'compiler-version', 'compiler-target', 'compile-sqlite',
            'compile-provider-abi-probe', 'observe-provider-abi', 'link-provider-emitter', 'provider-native-exports',
            'provider-native-imports', 'link', 'symbols'], 'Production provider stage roster includes foreign implementation')
    compiler = build['compiler'];read(compiler['path'], compiler)
    expected_link = [compiler['path'], '-shared', '-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections',
                     *[str(directory / (name + '.o')) for name in ('sqlite', 'witness', 'provider')],
                     '-lm', '-ldl', '-lpthread', '-o', str(directory / 'provider.so')]
    require(stages['link']['argv'] == expected_link, 'Production provider link includes a C provider or probe')
    require(stages['compile-sqlite']['argv'][-4:] == ['-c',
            next(path for path in build['source_before'] if path.endswith('/sqlite3/sqlite3.c')),
            '-o', str(directory / 'sqlite.o')], 'Only the exact external SQLite C object may enter the production link')
    require(not any(path.endswith('/provider.c') for path in build['source_before']), 'Original C entered production source graph')
    # Verify the dynamically emitted ABI witness without importing its builder.
    witness_dir = directory / 'native-witness'
    require(build['native_witness_build'] == str(witness_dir / 'build.json'), 'Witness build provenance points elsewhere')
    witness = passed(witness_dir / 'build.json')
    witness_sources = expected_sources - {str(repo / 'hia/platform/task_kernel' / name) for name in
        ('provider_abi.json', 'provider_native.hepta', 'qualification/provider_abi_probe.c', 'readback_provider.py')}
    require(set(witness['source_before']) == witness_sources,
            'Native witness canonical source namespace is missing or substituted')
    require(set(witness['artifacts']) == WITNESS_ARTIFACTS, 'Native witness artifact roster differs')
    require(witness['probe_linked_into_final_object'] is False and witness['native_witness_runtime_c_dependencies'] is False,
            'Original C witness entered runtime')
    for name, expected in witness['artifacts'].items():read(witness_dir / name, expected)
    compile_native(witness_dir, repo / 'hia/platform/task_kernel/witness_emitter.hepta', 'emitter-compiled.hepta',
                   'witness-emitter.o', witness['native_compiler_stages'], 'compile-witness-emitter')
    require(streams(witness_dir, witness['stages']) == ['preflight', 'probe-compiler-version', 'probe-compiler-target',
            'compile-probe', 'link-probe', 'link-witness-emitter', 'link-witness', 'witness-symbols', 'witness-undefined'],
            'Witness stage roster differs')
    require(read(witness_dir / 'witness-undefined.stdout.raw') == b'', 'Witness runtime has external symbols')
    request = read(witness_dir / 'emitter-input.bin', witness['emitter_input'])
    require(len(request) >= 193 and request[:8] == b'TWIT0001', 'Witness input framing differs')
    version, count, source_len, options_len = struct.unpack_from('<4Q', request, 8)
    layout = list(struct.unpack_from('<19Q', request, 40))
    require(version == 3054001 and layout == LAYOUT and len(request) == 193 + options_len + source_len,
            'Witness input layout or complete extent differs')
    options = request[192:192 + options_len]
    source_id = request[192 + options_len:]
    require(options.endswith(b'\0') and source_id.endswith(b'\0') and len(options[:-1].split(b'\0')) == count,
            'Witness metadata has invalid string count')
    observation = {'layout': layout, 'version': version, 'options': [v.decode('ascii') for v in options[:-1].split(b'\0')],
                   'source_id': source_id[:-1].decode('ascii')}
    require(load(witness_dir / 'observed-identity.json') == witness['observed_identity'] == witness['native_identity'] == observation,
            'Native witness input differs from independent current C probe observation')
    witness_obj = read(witness_dir / 'witness.o')
    require(read(directory / 'witness.o') == witness_obj and read(witness_dir / 'emitter-output.bin') ==
            struct.pack('<Q', len(witness_obj)) + witness_obj, 'Runtime witness is not the actual HIA emission')
    viewed = elf_object(witness_obj)
    require(viewed['exports'] == WITNESS and not viewed['imports'] and not viewed['relocations'],
            'Native witness ABI has foreign code dependencies')
    text = viewed['text']
    require(len(text) == 249 + 8 * count + options_len + source_len and
            list(struct.unpack_from('<19Q', text, 96)) == layout, 'Native witness readonly data layout differs')
    base = 248 + 8 * count
    require(text[base:base + options_len] == options and text[base + options_len:] == source_id,
            'Witness readonly strings differ from actual probe input')
    offset = 0
    for index, value in enumerate(options[:-1].split(b'\0')):
        require(struct.unpack_from('<Q', text, 248 + index * 8)[0] == 8 * count + offset,
                'Witness option pointer table differs')
        offset += len(value) + 1
    require(struct.unpack_from('<I', text, 34)[0] == count and struct.unpack_from('<I', text, 65)[0] == version and
            struct.unpack_from('<i', text, 83)[0] == 161 + 8 * count + options_len,
            'Witness dynamic code operands differ')
    code = bytearray(text[:96])
    for start in (34, 65, 83):code[start:start + 4] = bytes(4)
    expected_code = bytes.fromhex('83ff13730e89ff488d0552000000488b04f8c348c7c0ffffffffc30000000000'
        '81ff00000000731189ff488d05c7000000488b14f84801d0c331c0c300000000'
        'b800000000c300000000000000000000488d0500000000c30000000000000000')
    require(bytes(code) == expected_code, 'Native witness function instruction sequence differs')
    observed = load(directory / 'observed-identity.json')
    require(observed['runtime_version'] == observed['witness_version'] == version and
            observed['runtime_source_id'] == observed['witness_source_id'] == observation['source_id'] and
            observed['runtime_options'] == observed['witness_options'] == observation['options'] and
            observed['c_layout'] == layout and observed['runtime_threadsafe'] == 1,
            'Final linked SQLite image differs from native witness')
    linked_native_bytes(read(directory / 'provider.so'), parsed, viewed)
    return {'six_public_provider_entries': True, 'operations': 29, 'native_compiler_source_output_bound': True,
            'provider_imports': len(IMPORTS), 'native_witness_exports': 4,
            'native_witness_foreign_symbols': 0, 'project_c_in_production_link': False,
            'third_party_sqlite_c_retained': True}


def check_qualification(read, directory, provider):
    read = canonical_reads(read)
    directory, provider = Path(directory).absolute(), Path(provider).absolute()
    def load(path):return json.loads(read(path))
    report = load(directory / 'report.json')
    require(report['status'] == 'PASS' and report['finalized'] is True and
            report['source_before'] == report['source_after'], 'Provider qualification incomplete')
    for path, expected in report['source_before'].items():read(path, expected)
    require(report['native_build'] == str(provider / 'build.json') and
            report['original_build'] == str(directory / 'original/build.json'), 'Provider comparison image selection differs')
    oracle = load(directory / 'original/build.json')
    require(oracle['fence'] == ORACLE_FENCE and oracle['qualification_only_original_oracle'] is True and
            oracle['status'] == 'PASS' and oracle['finalized'], 'Original C comparison image is not separately fenced')
    require(oracle['source_before'] == oracle['source_after'], 'Original C oracle source fence differs')
    for path, expected in oracle['source_before'].items():read(path, expected)
    require(set(oracle['artifacts']) == {'sqlite.o', 'witness.o', 'provider.o', 'provider.so', 'observed-identity.json'},
            'Original C oracle artifact roster differs')
    for name, expected in oracle['artifacts'].items():read(directory / 'original' / name, expected)
    require(read(directory / 'original/sqlite.o') == read(provider / 'sqlite.o'), 'Original/native external SQLite code differs')
    repo = Path(__file__).absolute().parents[3]
    source = str(repo / 'hia/platform/task_kernel/provider.c')
    task = repo / 'hia/platform/task_kernel'; q = task / 'qualification'
    production = load(provider / 'build.json')
    qualification_sources = set(production['source_before']) | {str(provider / name) for name in production['artifacts']}
    qualification_sources.update(str(task / name) for name in ('qualify_provider_native.py', 'provider.c',
        'qualification/native_provider_observer.py', 'qualification/provider_fault_observer.c',
        'qualification/fd_observer.c', 'qualification/read_observer.c',
        'qualification/native_witness_observer.py', 'qualification/provider_controls.py'))
    qualification_sources.update((str(provider / 'build.json'), production['compiler']['path']))
    require(set(report['source_before']) == qualification_sources,
            'Provider qualification canonical source namespace is missing or substituted')
    require(oracle['compiler'] == production['compiler'], 'Original/native C dependency compiler differs')
    cc = oracle['compiler']['path'];read(cc, oracle['compiler'])
    dependencies = [Path(path).parent for path in oracle['source_before']
                    if path.endswith('/libsqlite3-sys-0.39.1/Cargo.toml')]
    require(len(dependencies) == 1, 'Original dependency source is ambiguous');dependency = dependencies[0]
    members = tomllib.loads(read(repo / 'trillionnium/Cargo.toml').decode())['workspace']['members']
    original_sources = {str(repo / path) for path in ('scripts/project-preflight.sh', 'scripts/ci/project_boundary.py',
        'PROJECT_BOUNDARY.json', 'PROJECT_ID', 'config/portability-inventory-v1.json', 'trillionnium/Cargo.toml',
        'hia/platform/task_kernel/build_provider.py', 'hia/platform/task_kernel/provider_abi.json',
        'hia/platform/task_kernel/provider.c', 'trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c')}
    original_sources.update(str(repo / 'trillionnium' / member / 'Cargo.toml') for member in members)
    original_sources.update(str(dependency / name) for name in ('Cargo.toml', 'build.rs', 'sqlite3/sqlite3.c', 'sqlite3/sqlite3.h'))
    require(set(oracle['source_before']) == original_sources, 'Original C oracle canonical source namespace differs')
    tree = ast.parse(read(task / 'build_provider.py'))
    definitions = {node.targets[0].id: node.value for node in tree.body
                   if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    flags = ast.literal_eval(definitions['FLAGS'])
    original = directory / 'original'
    common_c = [cc, '-std=c11', '-O0', '-fPIC', '-fno-common', '-fno-strict-aliasing',
                '-ffunction-sections', '-fdata-sections', '-I', str(dependency / 'sqlite3'), *['-D' + flag for flag in flags]]
    oracle_stages = [
        ('preflight', ['bash', str(repo / 'scripts/project-preflight.sh'), '--audit']),
        ('compiler-version', [cc, '--version']), ('compiler-target', [cc, '-dumpmachine']),
        ('compile-sqlite', [*common_c, '-c', str(dependency / 'sqlite3/sqlite3.c'), '-o', str(original / 'sqlite.o')]),
        ('compile-witness', [*common_c, '-DTRNM_SQLITE_AMALGAMATION="' + str(dependency / 'sqlite3/sqlite3.c') + '"',
                            '-c', str(repo / 'trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c'), '-o', str(original / 'witness.o')]),
        ('compile-provider', [*common_c, '-Wall', '-Wextra', '-Werror', '-c', source, '-o', str(original / 'provider.o')]),
        ('link', [cc, '-shared', '-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections',
                  *[str(original / (name + '.o')) for name in ('sqlite', 'witness', 'provider')],
                  '-lm', '-ldl', '-lpthread', '-o', str(original / 'provider.so')]),
        ('symbols', ['nm', '--defined-only', str(original / 'provider.so')]),
    ]
    require([(row['name'], row['argv']) for row in oracle['stages']] == oracle_stages,
            'Original C provider actual compile/link graph differs')
    for row in oracle['stages']:
        require(row['completed'] and row['exit'] == 0, 'Original C build stage failed')
        for stream in ('stdin', 'stdout', 'stderr'):read(original / (row['name'] + '.' + stream + '.raw'))
    def c_symbols(raw):
        require(raw[:7] == b'\x7fELF\x02\x01\x01', 'Original C artifact is not ELF64LE')
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
        require(header[1:4] == (1, 62, 1) and header[11] == 64, 'Original C artifact is not x86_64 ET_REL')
        sections = [struct.unpack_from('<IIQQQQIIQQ', raw, header[6] + 64 * index) for index in range(header[12])]
        files, functions = set(), set()
        for section in sections:
            if section[1] != 2:continue
            require(section[9] == 24 and section[6] < len(sections), 'Invalid original C symbol table')
            names = sections[section[6]]; strings = raw[names[4]:names[4] + names[5]]
            for pos in range(section[4], section[4] + section[5], 24):
                name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', raw, pos)
                require(name < len(strings) and b'\0' in strings[name:], 'Invalid original C symbol name')
                name = strings[name:strings.index(b'\0', name)].decode('ascii')
                if info & 15 == 4:files.add(name)
                if info & 15 == 2 and shndx:
                    require(shndx < len(sections) and sections[shndx][2] & 4 and size and
                            value + size <= sections[shndx][5], 'Original C function extent differs')
                    functions.add(name)
        return files, functions
    files, functions = c_symbols(read(original / 'provider.o'))
    require(files == {'provider.c'} and functions == EXPORTS | {'contains', 'retain', 'release', 'rd', 'wr', 'scalar', 'bytes', 'text'},
            'Original comparison provider object is not the complete C translation unit')
    files, functions = c_symbols(read(original / 'witness.o'))
    require('unix_layout_witness.c' in files and set(WITNESS) <= functions,
            'Original comparison witness is not the C probe translation unit')
    require(read(directory / 'original-source-git.stdout.raw') == read(source, report['original_source']),
            'C comparison is not the retained exact original source')
    left = load(directory / 'original-observations/observation.json')
    right = load(directory / 'native-observations/observation.json')
    require(left['status'] == right['status'] == 'PASS' and left['finalized'] and right['finalized'] and
            len(left['calls']) == len(right['calls']) == 1182, 'Complete original/native call roster differs')
    for observation, image in ((left, original / 'provider.so'), (right, provider / 'provider.so')):
        require(observation['library'] == str(image) and observation['library_sha256'] == identity(read(image))['sha256'],
                'Observed original/native library identity differs')
        token = 1000
        for row in observation['calls']:
            raw = bytes.fromhex(row['actual_response_hex']);normalized = bytearray(raw)
            result = row['normalized']['return'];capacity = row['capacity']
            require((result <= capacity and len(raw) == result) or (result > capacity and not raw),
                    'Observed response extent differs from actual return/capacity')
            if len(raw) >= 24 and row['op'] in (2, 5, 17):
                capability = struct.unpack_from('<Q', raw, 8)[0]
                if capability not in (0, (1 << 64) - 1):
                    token += 1;struct.pack_into('<Q', normalized, 8, token)
            if len(raw) >= 24 and row['op'] in (22, 23):
                struct.pack_into('<Q', normalized, 8, 0)
                if row['op'] == 22:struct.pack_into('<Q', normalized, 16, 0)
            require(normalized.hex() == row['normalized']['response_hex'],
                    'Provider normalization concealed an actual return value')
    require(len({item['name'] for item in left['calls']}) == 1182, 'Duplicate provider comparison case')
    for a, b in zip(left['calls'], right['calls']):
        require(all(a[key] == b[key] for key in ('name', 'op', 'capacity', 'normalized')),
                'Observed provider return/value differs: ' + a['name'])
    for key in ('operation_coverage', 'resource_checks', 'concurrent'):
        require(left[key] == right[key], 'Observed provider state/ownership differs: ' + key)
    require(left['operation_coverage'] == list(range(1, 30)) and len(left['concurrent']) == 64,
            'Missing operation or concurrent owner observation')
    expected = [(name, index) for name, count in (('open', 110), ('prepare', 31), ('column', 1), ('invalid-path-flags', 1))
                for index in range(count)]
    require([(row['scenario'], row['index']) for row in report['allocation_cases']] == expected,
            'Allocation failure ordinal roster differs')
    for name, index in expected:
        suffix = '-allocation-' + name + '-' + str(index) + '.stdout.raw'
        a = load(directory / ('original' + suffix));b = load(directory / ('native' + suffix))
        require(a == b and a['status'] == 'PASS' and a['actual_failure_hit'] is True and
                a['live_allocations'] == a['sqlite_memory'] == 0, 'Actual allocation failure/cleanup differs')
        if name == 'column':require(a['code'] == 7 and a['return'] == 24, 'Actual SQLite NOMEM was lost')
    for name in ('new-calloc', 'new-mutex', 'close-eintr', 'close-eio'):
        a = load(directory / ('original-fault-' + name + '-baseline.stdout.raw'))
        b = load(directory / ('native-fault-' + name + '-baseline.stdout.raw'))
        require(a == b and a['status'] == 'PASS', 'Constructor/consumed close differs')
        require(a.get('null') is True if name.startswith('new-') else
                a.get('actual_close_calls') == 1 and a.get('consumed') is True, 'Missing actual constructor/close failure')
    for label in ('original', 'native'):
        fd = read(directory / (label + '-real-descriptor-controls.stdout.raw'))
        rd = read(directory / (label + '-real-read-controls.stdout.raw'))
        require(json.loads(fd.splitlines()[-1]) == {'status': 'PASS', 'cases': 8} and
                json.loads(rd.splitlines()[-1]) == {'status': 'PASS', 'cases': 13, 'real_signal_interruptions': 1},
                'Actual descriptor/read/signal observations differ')
        fd_rows = [json.loads(line) for line in fd.splitlines()]
        rd_rows = [json.loads(line) for line in rd.splitlines()]
        require([row['case'] for row in fd_rows if 'case' in row] == [
                'capacity-no-side-effect', 'cross-context-capability', 'forged-and-repeated-descriptors',
                'path-allocation-null-no-open', 'retention-allocation-null-closes-real-fd',
                'reset-real-mixed-resources', 'owner-drop-closes-real-fd', 'descriptor-zero-owned'],
                'Missing actual descriptor lifecycle observation')
        require([row['case'] for row in rd_rows if 'case' in row] == [
                'capacity-before-read', 'first-five', 'next-seven', 'short-read', 'eof', 'zero-length',
                'cross-context', 'foreign-descriptor', 'already-closed', 'actual-directory-error',
                'actual-fifo-eintr', 'actual-pipe-short-read', 'descriptor-zero'],
                'Missing actual read/EINTR observation')
        interrupted = next(row for row in rd_rows if row.get('case') == 'actual-fifo-eintr')
        require(interrupted['return'] == 24 and struct.unpack_from('<Q', bytes.fromhex(interrupted['actual_output']))[0] == 4,
                'Actual EINTR errno differs')
    witness = load(directory / 'witness-controls/report.json')
    negative = load(directory / 'provider-controls/report.json')
    require(witness['status'] == 'PASS' and witness['finalized'] and witness['controls_count'] == len(witness['controls']) == 123 and
            negative['status'] == 'PASS' and negative['finalized'] and negative['negative_controls'] == 8,
            'Witness or build refusal roster differs')
    names = []
    for row in report['stages']:
        name = row['name'];require(name not in names and row['completed'] and row['exit_code'] == 0,
                                  'Provider qualification stage failed or duplicated');names.append(name)
        for stream in ('stdin', 'stdout', 'stderr'):read(directory / (name + '.' + stream + '.raw'))
    require(len(names) == 320 and len(report['emitter_controls']) == 12 and
            report['actual_original_native_pairs'] == 1182 and report['actual_allocation_failure_pairs'] == 143,
            'Complete qualification stage/control roster differs')
    expected_stages = [
        ('original-source-git', ['git', 'show', 'HEAD:hia/platform/task_kernel/provider.c']),
        ('build-original-oracle', [sys.executable, str(task / 'build_provider.py'), '--dependency', str(dependency),
                                  '--output', str(original), '--original-oracle']),
    ]
    for label, image in (('original', original), ('native', provider)):
        expected_stages.append((label + '-29-operations', [sys.executable, str(q / 'native_provider_observer.py'),
            '--library', str(image / 'provider.so'), '--output', str(directory / (label + '-observations'))]))
    expected_artifacts = set()
    for label, image in (('original', original), ('native', provider)):
        work = directory / (label + '-faults');objects = [str(image / (name + '.o')) for name in ('provider', 'sqlite', 'witness')]
        common = [cc, '-std=c11', '-O0', '-fPIC', '-Wall', '-Wextra', '-Werror']
        wraps = ['-Wl,--wrap=' + name for name in ('malloc', 'calloc', 'realloc', 'free', 'close', 'pthread_mutex_init',
                                                  'pthread_mutex_destroy', 'sqlite3_finalize', 'sqlite3_close_v2')]
        expected_stages.append((label + '-compile-fault-observer', [*common, '-I', str(dependency / 'sqlite3'),
            str(q / 'provider_fault_observer.c'), *objects, *wraps, '-ldl', '-lm', '-lpthread', '-o', str(work / 'fault-observer')]))
        for name in ('new-calloc', 'new-mutex', 'open', 'prepare', 'column', 'invalid-path-flags', 'close-eintr', 'close-eio'):
            expected_stages.append((label + '-fault-' + name + '-baseline', [str(work / 'fault-observer'), name, '-1', str(work / 'target')]))
        wraps = ['-Wl,--wrap=' + name for name in ('malloc', 'calloc', 'open', 'close', 'read', 'sqlite3_finalize', 'sqlite3_close_v2')]
        expected_stages.extend([
            (label + '-compile-fd-observer', [*common, str(q / 'fd_observer.c'), *objects, *wraps,
                                            '-ldl', '-lm', '-lpthread', '-o', str(work / 'fd-observer')]),
            (label + '-compile-fd-wrapper', [*common, '-DTRNM_OBSERVER_NO_MAIN', '-c', str(q / 'fd_observer.c'), '-o', str(work / 'fd-wrapper.o')]),
            (label + '-compile-read-observer', [*common, str(q / 'read_observer.c'), str(work / 'fd-wrapper.o'), *objects, *wraps,
                                              '-ldl', '-lm', '-lpthread', '-o', str(work / 'read-observer')]),
            (label + '-real-descriptor-controls', [str(work / 'fd-observer'), str(work / 'fd-target')]),
            (label + '-real-read-controls', [str(work / 'read-observer'), str(work)]),
        ])
        expected_artifacts.update(label + '-faults/' + name for name in ('fault-observer', 'fd-observer', 'fd-wrapper.o', 'read-observer'))
    for name, index in expected:
        for label in ('original', 'native'):
            work = directory / (label + '-faults')
            expected_stages.append((label + '-allocation-' + name + '-' + str(index),
                                    [str(work / 'fault-observer'), name, str(index), str(work / 'target')]))
    expected_stages.extend([
        ('native-witness-controls', [sys.executable, str(q / 'native_witness_observer.py'), '--build', str(provider / 'native-witness'),
                                     '--output', str(directory / 'witness-controls')]),
        ('provider-negative-controls', [sys.executable, str(q / 'provider_controls.py'), str(provider), str(directory / 'provider-controls')]),
    ])
    require([(row['name'], row['argv']) for row in report['stages']] == expected_stages and
            all(row['cwd'] == str(repo) for row in report['stages']), 'Actual provider qualification stage/argv graph differs')
    require(set(report['observer_artifacts']) == expected_artifacts, 'Observed qualification binary roster differs')
    for name, value in report['observer_artifacts'].items():read(directory / name, value)
    require([row['actual_status'] for row in report['emitter_controls']] == [100] * 5 + [101] * 5 + [0] * 2 and
            len(report['pairs']) == 1182 and all(row['equal'] is True for row in report['pairs']),
            'Native emitter refusal or exact pair roster differs')
    return {'actual_original_native_pairs': 1182, 'actual_allocation_failure_pairs': 143,
            'constructor_failure_pairs': 2, 'close_error_pairs': 2, 'concurrent_provider_calls': 256,
            'witness_controls': 123, 'build_refusal_controls': 8}


class Reader:
    def __init__(self):self.checked = {}
    def read(self, path, expected=None):
        path = Path(path).absolute();before = path.lstat()
        require(path.resolve() == path and all(not parent.is_symlink() for parent in path.parents),
                'Symlinked or noncanonical provider evidence path')
        require(stat.S_ISREG(before.st_mode), 'Regular independent readback input required')
        raw = path.read_bytes();after = path.lstat()
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(stamp(before) == stamp(after), 'Provider evidence changed while reading')
        actual = identity(raw)
        if expected is not None:require(actual == {key: expected[key] for key in ('bytes', 'sha256')}, 'Provider content differs: ' + str(path))
        require(str(path) not in self.checked or self.checked[str(path)] == actual, 'Provider evidence changed between reads')
        self.checked[str(path)] = actual;return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider', type=Path, required=True)
    parser.add_argument('--qualification', type=Path)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args();output = args.output.absolute()
    require(Path(__file__).absolute() == args.repo.resolve() / 'hia/platform/task_kernel/readback_provider.py',
            'Reader must be the canonical current provider reader')
    require(output.resolve() == output and not output.exists() and args.provider.resolve() not in output.parents and
            (args.qualification is None or args.qualification.resolve() not in output.parents) and
            args.repo.resolve() not in output.parents, 'Fresh independent readback output outside inputs required')
    output.mkdir(parents=True, mode=0o700)
    reader = Reader();report = {'schema': 'trnm.hia.task-provider.independent-readback.v1', 'status': 'FAIL', 'finalized': False}
    try:
        reader.read(Path(__file__).resolve())
        report['build'] = check_provider(reader.read, args.provider, args.repo)
        if args.qualification is not None:
            report['qualification'] = check_qualification(reader.read, args.qualification, args.provider)
        for path, expected in list(reader.checked.items()):reader.read(path, expected)
        report.update(status='PASS', finalized=True, checked_files=reader.checked,
                      provider_build=str(args.provider.absolute() / 'build.json'),
                      qualification_report=None if args.qualification is None else str(args.qualification.absolute() / 'report.json'))
    except BaseException as error:
        report['failure'] = repr(error);raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'PASS', 'checked_files': len(reader.checked),
                      'complete_provider_qualification': args.qualification is not None}))


if __name__ == '__main__':main()
