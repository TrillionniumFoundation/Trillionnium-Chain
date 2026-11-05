"""Independent mathematical GSC2 vectors; no node, account, or profile authority."""
import hashlib
import json
import struct


def h(tag, *parts):
    tag = tag.encode('ascii')
    data = b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
    return hashlib.sha256(data + b''.join(struct.pack('<I', len(p)) + p for p in parts)).digest()


def sparse_root(leaves, empty_tag, branch_tag):
    """Bottom-up integer-path reconstruction, independent of sorted recursion."""
    empty = [None] * 257
    empty[256] = h(empty_tag)
    for depth in range(255, -1, -1):
        empty[depth] = h(branch_tag, empty[depth + 1], empty[depth + 1])
    level = {}
    for path, value in leaves:
        index = int.from_bytes(path, 'big')
        if index in level:
            raise ValueError('duplicate sparse path')
        level[index] = value
    for depth in range(255, -1, -1):
        level = {parent: h(branch_tag, level.get(2 * parent, empty[depth + 1]),
                          level.get(2 * parent + 1, empty[depth + 1]))
                 for parent in {index >> 1 for index in level}}
    return level.get(0, empty[0])


def archive(accounts):
    return sparse_root([(h('account-archive-key-v1', owner),
                         h('account-archive-leaf-v1', owner, struct.pack('<Q', balance), struct.pack('<Q', nonce)))
                        for owner, balance, nonce in accounts],
                       'account-archive-empty-v1', 'account-archive-branch-v1')


def state_root(state):
    return sparse_root([(h('state-key', key.encode()),
                         h('state-leaf', key.encode(), json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()))
                        for key, value in state.items()], 'state-empty', 'state-node')


def encode(value):
    result = (b'GSC2' + bytes.fromhex(value['network']) + bytes.fromhex(value['parameters'])
              + bytes.fromhex(value['account_root'])
              + struct.pack('<QQQ', value['account_count'], value['account_balance'], value['maximum_permanent_accounts'])
              + bytes.fromhex(value['working_root'])
              + struct.pack('<QQQQQ', value['working_count'], value['maximum_working_keys'], value['escrow_balance'], value['reward_balance'], value['issued']))
    assert len(result) == 196
    return result


codec = dict(network='01'*32, parameters='02'*32, account_root='03'*32, account_count=4,
             account_balance=6, maximum_permanent_accounts=1000000, working_root='04'*32,
             working_count=3, maximum_working_keys=65536, escrow_balance=7, reward_balance=11, issued=24)
accounts = [(bytes(32), 0, 7), (bytes([255])*32, 17, 9)]
working = {'meta:issued': 17}
account_root = archive(accounts)
assert account_root == archive(accounts[::-1])
assert account_root != archive(accounts[1:])
assert account_root != archive([(accounts[0][0], 0, 8), accounts[1]])
semantic = dict(network=bytes(range(32)).hex(), parameters=bytes(range(32,64)).hex(),
                account_root=account_root.hex(), account_count=2, account_balance=17,
                maximum_permanent_accounts=1000000, working_root=state_root(working).hex(),
                working_count=1, maximum_working_keys=65536, escrow_balance=0, reward_balance=0, issued=17)
full = dict(working)
for owner, balance, nonce in accounts:
    full['account:' + owner.hex()] = {'balance': balance, 'nonce': nonce}
maximum = (1 << 64) - 1
max_accounts = [(bytes([170])*32, maximum, maximum)]
max_working = {'meta:issued': maximum}
max_case = dict(network='ff'*32, parameters='00'*32, account_root=archive(max_accounts).hex(), account_count=1, account_balance=maximum, maximum_permanent_accounts=1000000, working_root=state_root(max_working).hex(), working_count=1, maximum_working_keys=65536, escrow_balance=0, reward_balance=0, issued=maximum)
vectors = []
for name, value in [('codec_only_existing_fixture', codec), ('two_accounts_zero_balance_nonce_full_relation', semantic), ('maximum_u64_balance_and_nonce', max_case)]:
    raw = encode(value)
    vectors.append(dict(name=name, fields=value, encoded_hex=raw.hex(), encoded_bytes=len(raw),
                        id=h('native-permanent-account-state-v2', raw).hex()))
assert vectors[0]['id'] == 'ba20a82c4d08b745d8606f8ed273d9743fd9c60bf1d848c19cf6dbe240dd7179'
mutations = []
base_id = vectors[1]['id']
for field in semantic:
    changed = dict(semantic)
    if isinstance(changed[field], str):
        raw_field = bytearray.fromhex(changed[field]); raw_field[0] ^= 1; changed[field] = raw_field.hex()
    else:
        changed[field] += 1
    changed_id = h('native-permanent-account-state-v2', encode(changed)).hex()
    assert changed_id != base_id
    mutations.append(dict(field=field, mutated_fields=changed, id=changed_id))
assert h('permanent-account-growth-commitment-v2', encode(semantic)).hex() != base_id
result = dict(field_binding_mutations=mutations, wrong_domain_id=h('permanent-account-growth-commitment-v2', encode(semantic)).hex(), scope='Independent Python mathematical encoding and sparse-hash vectors; no native execution, admission, valid-config or bounded-validation claim',
              algorithm='SHA256 domain/length framing, little-endian u64 fields, MSB sparse paths built bottom-up',
              fields_offset=dict(magic=0,network=4,parameters=36,account_root=68,account_count=100,account_balance=108,maximum_permanent_accounts=116,
                                 working_root=124,working_count=156,maximum_working_keys=164,escrow_balance=172,reward_balance=180,issued=188),
              vectors=vectors, semantic_accounts=[dict(owner=o.hex(),balance=b,nonce=n) for o,b,n in accounts],
              semantic_working=working, semantic_legacy_full_state_root=state_root(full).hex())
if __name__ == '__main__':
    print(json.dumps(result, indent=2, sort_keys=True))
