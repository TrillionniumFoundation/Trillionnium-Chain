"""Read-only lexical inventory; unknown include expressions block closure readiness."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import signal
signal.alarm(120)

ROOT = pathlib.Path('/tmp/hepta-chain-6523704f97df-real-crate-attempt-1')
SOURCE = ROOT / 'source'
HEAD = '1bd4a71c6efaa6921237fd4612d37cb7ef0e4645'
ENV = dict(os.environ, GIT_NO_LAZY_FETCH='1')


def git(*args):
    result = subprocess.run(['git', *args], cwd=SOURCE, env=ENV,
                            capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return result.stdout


RAW = re.compile(r'(br|cr|r)(#*)"')
PREFIX = re.compile(r'(?:b|c)?"')
CHAR = re.compile(r"(?:b)?'(?:[^'\\\r\n]|\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.))'")
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def tokens(text):
    out = []
    pos = 0
    while pos < len(text):
        start = pos
        if text[pos].isspace():
            pos += 1
            continue
        if text.startswith('//', pos):
            end = text.find('\n', pos + 2)
            pos = len(text) if end < 0 else end + 1
            continue
        if text.startswith('/*', pos):
            depth = 1
            pos += 2
            while depth and pos < len(text):
                if text.startswith('/*', pos):
                    depth += 1
                    pos += 2
                elif text.startswith('*/', pos):
                    depth -= 1
                    pos += 2
                else:
                    pos += 1
            if depth:
                raise ValueError('unterminated comment')
            continue
        raw = RAW.match(text, pos)
        if raw:
            close = '"' + raw[2]
            body = pos + len(raw[0])
            end = text.find(close, body)
            if end < 0:
                raise ValueError('unterminated raw string')
            pos = end + len(close)
            out.append(('str' if raw[1] == 'r' else 'other_string',
                        text[body:end], start, pos))
            continue
        prefix = PREFIX.match(text, pos)
        if prefix:
            pos += len(prefix[0])
            while pos < len(text):
                if text[pos] == '\\':
                    pos += 2
                elif text[pos] == '"':
                    pos += 1
                    break
                else:
                    pos += 1
            else:
                raise ValueError('unterminated string')
            kind = 'quoted' if prefix[0] == '"' else 'other_string'
            out.append((kind, text[start:pos], start, pos))
            continue
        char = CHAR.match(text, pos)
        if char:
            pos += len(char[0])
            out.append(('char', char[0], start, pos))
            continue
        identifier = IDENTIFIER.match(text, pos)
        if identifier:
            pos += len(identifier[0])
            out.append(('id', identifier[0], start, pos))
            continue
        pos += 1
        out.append((text[start], text[start], start, pos))
    return out


def literal(token):
    if token[0] == 'str':
        return token[1]
    if token[0] != 'quoted':
        raise ValueError('path requires a Rust string literal')
    # All path literals are ASCII. Unknown Rust escapes are explicit refusals.
    return json.loads(token[1])


PAIRS = {'(': ')', '[': ']', '{': '}'}


def end_of_group(ts, start):
    stack = [PAIRS[ts[start][0]]]
    pos = start + 1
    while pos < len(ts):
        kind = ts[pos][0]
        if kind in PAIRS:
            stack.append(PAIRS[kind])
        elif kind in PAIRS.values():
            if kind != stack.pop():
                raise ValueError('mismatched macro delimiter')
            if not stack:
                return pos
        pos += 1
    raise ValueError('unterminated macro delimiter')


def expression(ts, pos, manifest):
    if pos >= len(ts):
        raise ValueError('empty expression')
    if ts[pos][0] in ('str', 'quoted'):
        return literal(ts[pos]), pos + 1
    if ts[pos][0] != 'id' or pos + 2 >= len(ts) or ts[pos + 1][0] != '!':
        raise ValueError('non-literal or unsupported expression')
    name = ts[pos][1]
    opening = pos + 2
    if ts[opening][0] not in PAIRS:
        raise ValueError('expected macro delimiter')
    end = end_of_group(ts, opening)
    cursor = opening + 1
    values = []
    while cursor < end:
        value, cursor = expression(ts, cursor, manifest)
        values.append(value)
        if cursor != end:
            if ts[cursor][0] != ',':
                raise ValueError('expected argument separator')
            cursor += 1
    if name == 'concat':
        value = ''.join(values)
    elif name == 'env' and values == ['CARGO_MANIFEST_DIR']:
        if manifest is None:
            raise ValueError('no nearest Cargo.toml for manifest environment')
        value = str(SOURCE / manifest)
    else:
        raise ValueError('unsupported path macro ' + name + '(' + repr(values) + ')')
    return value, end + 1


def main():
    assert git('rev-parse', 'HEAD').decode().strip() == HEAD
    blobs = {}
    for item in git('ls-tree', '-r', '-z', HEAD + ':trillionnium').split(b'\0'):
        if not item:
            continue
        attr, path = item.split(b'\t', 1)
        mode, kind, sha = attr.decode().split()
        assert kind == 'blob'
        blobs['trillionnium/' + path.decode()] = sha
    assert len(blobs) == 1718
    all_pins = {}
    occurrences = []
    unresolved = []
    lexer_failures = []
    for path, blob in sorted(blobs.items()):
        raw = (SOURCE / path).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob
        all_pins[path] = hashlib.sha256(raw).hexdigest()
        if not path.endswith('.rs'):
            continue
        if len(all_pins) % 200 == 0:
            print(json.dumps({'verified_subtree_files': len(all_pins)}), flush=True)
        text = raw.decode('utf8')
        try:
            ts = tokens(text)
        except (ValueError, IndexError) as error:
            lexer_failures.append({'source': path, 'error': str(error)})
            continue
        nearest = pathlib.PurePosixPath(path).parent
        manifest = None
        while str(nearest) != '.':
            if str(nearest / 'Cargo.toml') in blobs:
                manifest = str(nearest)
                break
            nearest = nearest.parent
        for i, token in enumerate(ts):
            if token[0] != 'id' or token[1] not in ('include_bytes', 'include_str', 'include'):
                continue
            if i + 2 >= len(ts) or ts[i + 1][0] != '!':
                continue
            record = {'source': path, 'source_blob': blob, 'macro': token[1],
                      'line': text.count('\n', 0, token[2]) + 1,
                      'cargo_manifest_dir': manifest}
            try:
                opening = i + 2
                if ts[opening][0] not in PAIRS:
                    raise ValueError('missing macro delimiter')
                end = end_of_group(ts, opening)
                record['expression'] = text[ts[opening][3]:ts[end][2]]
                value, cursor = expression(ts, opening + 1, manifest)
                if cursor < end and ts[cursor][0] == ',':
                    cursor += 1
                if cursor != end:
                    raise ValueError('extra include arguments')
                physical = pathlib.Path(value)
                if not physical.is_absolute():
                    physical = SOURCE / pathlib.PurePosixPath(path).parent / physical
                normalized = pathlib.Path(os.path.normpath(physical))
                record['target'] = str(normalized.relative_to(SOURCE))
                record['exists'] = normalized.is_file() and not normalized.is_symlink()
                if record['exists']:
                    data = normalized.read_bytes()
                    record['size'] = len(data)
                    record['sha256'] = hashlib.sha256(data).hexdigest()
                occurrences.append(record)
            except (ValueError, IndexError) as error:
                record['error'] = str(error)
                unresolved.append(record)
    targets = sorted({r['target'] for r in occurrences})
    missing = sorted({r['target'] for r in occurrences if not r['exists']})
    result = {'schema': 'chain-full-rust-include-closure-inventory-v1', 'head': HEAD,
              'whole_tree': 'f00edac77554e3ff3a649cd6159b25d1c193ac13',
              'rust_subtree': '6b348e35c55a324630aeeb5e2f7727e3a5b1905b',
              'rust_subtree_blob_count': len(blobs),
              'rust_source_file_count': sum(p.endswith('.rs') for p in blobs),
              'verified_source_sha256': all_pins,
              'resolved_occurrences': occurrences, 'unique_targets': targets,
              'missing_targets': missing, 'unresolved_expressions': unresolved,
              'lexer_failures': lexer_failures,
              'closure_ready': not missing and not unresolved and not lexer_failures,
              'cfg_branches_filtered': False, 'cargo_or_test_invoked': False,
              'scope': 'all Rust files in complete fixed trillionnium subtree; lexical include expressions only'}
    dest = ROOT / 'FULL_INCLUDE_CLOSURE_SCAN_LINEAR.json'
    with dest.open('x') as out:
        json.dump(result, out, sort_keys=True, indent=2)
    print(json.dumps({k: v for k, v in result.items() if k not in
                      ('verified_source_sha256', 'resolved_occurrences', 'unique_targets')}))
    print(json.dumps({'path': str(dest), 'size': dest.stat().st_size,
                      'sha256': hashlib.sha256(dest.read_bytes()).hexdigest(),
                      'resolved_occurrences': len(occurrences), 'unique_targets': len(targets)}))


if __name__ == '__main__':
    main()
