#!/usr/bin/env python3
"""Apply the exact two-query resource change to the frozen native owner."""
import hashlib
from pathlib import Path
import sys

path = Path('trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs')
raw = path.read_bytes()
blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
if blob != '16773890b8a5f7f714f0900a8d6eccc1b1f9ad34':
    raise SystemExit(f'SOURCE_BLOB_MISMATCH:{blob}')
text = raw.decode()
old_block = '"SELECT parent,height,chainwork,CASE WHEN typeof(packet)=\'blob\' THEN substr(packet,1,1048577) ELSE packet END AS packet,state_root FROM blocks WHERE id=?"'
old_parent = '"SELECT height,chainwork FROM blocks WHERE id=?"'
for old, new in [(old_block, 'NATIVE_BLOCK_SQL'), (old_parent, 'NATIVE_PARENT_SQL')]:
    if text.count(old) != 1:
        raise SystemExit('QUERY_OCCURRENCE_MISMATCH')
    text = text.replace(old, new)
anchor = 'const MAX_RECORD_BYTES: usize = 16 * 1024;\n'
constants = '''
// The original fixed-width checks still reject a one-byte sentinel. Restrict
// owned Rust payload copies before those checks, without coercing SQL types or
// changing packet bytes, field order, error identity, ancestry or work checks.
// SQLite page reads/allocations and full history traversal are not bounded here.
const NATIVE_BLOCK_SQL: &str = "SELECT
 CASE WHEN typeof(parent)='blob' THEN substr(parent,1,33) ELSE parent END AS parent,
 height,
 CASE WHEN typeof(chainwork)='blob' THEN substr(chainwork,1,65) ELSE chainwork END AS chainwork,
 CASE WHEN typeof(packet)='blob' THEN substr(packet,1,1048577) ELSE packet END AS packet,
 CASE WHEN typeof(state_root)='blob' THEN substr(state_root,1,33) ELSE state_root END AS state_root
 FROM blocks WHERE id=?";
const NATIVE_PARENT_SQL: &str = "SELECT height,
 CASE WHEN typeof(chainwork)='blob' THEN substr(chainwork,1,65) ELSE chainwork END AS chainwork
 FROM blocks WHERE id=?";
'''
if text.count(anchor) != 1:
    raise SystemExit('CONSTANT_ANCHOR_MISMATCH')
text = text.replace(anchor, anchor + constants)
text += '\n#[cfg(test)]\nmod native_fixed_blob_tests;\n'
target = path.parent / 'native_authenticated' / 'native_fixed_blob_tests.rs'
# A submodule declared from native_authenticated.rs resolves in its matching
# directory; explicitly use the existing store directory instead.
text = text.replace('#[cfg(test)]\nmod native_fixed_blob_tests;\n', '#[cfg(test)]\n#[path = "native_fixed_blob_tests.rs"]\nmod native_fixed_blob_tests;\n')
target = path.with_name('native_fixed_blob_tests.rs')
if target.exists():
    raise SystemExit('TEST_TARGET_EXISTS')
payload = Path(sys.argv[1]).read_bytes()
if payload.count(b'#[test]') != 4:
    raise SystemExit('TEST_COUNT_MISMATCH')
path.write_text(text)
target.write_bytes(payload)
print('Applied two SQL projections and four additive native tests; no stored verdict or rule changes.')
