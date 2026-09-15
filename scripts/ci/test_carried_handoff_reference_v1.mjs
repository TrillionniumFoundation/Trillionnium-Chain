#!/usr/bin/env node
// Independent byte/signature reference for the existing carried-set corpus.
// Uses public deterministic TEST keys only. This does not run Rust journals,
// prove PoP for new members, bootstrap trust, or activate a live epoch.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const corpus = JSON.parse(fs.readFileSync(fileURLToPath(new URL(
  '../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json', import.meta.url)), 'utf8'));
const pkcs8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const spki = Buffer.from('302a300506032b6570032100', 'hex');
const hash = data => crypto.createHash('sha256').update(data).digest();
function uint(n, width) {
  n = BigInt(n);
  assert(n >= 0n && n < (1n << BigInt(width * 8)));
  const result = Buffer.alloc(width);
  for (let i = width - 1; i >= 0; --i) { result[i] = Number(n & 255n); n >>= 8n; }
  return result;
}
function raw(value) {
  assert.equal(typeof value, 'string');
  assert(/^(?:[0-9a-f]{2})*$/.test(value));
  return Buffer.from(value, 'hex');
}
function framed(domain, bytes) {
  const prefix = Buffer.from('trnm.cev0.hash.v0');
  const d = Buffer.from(domain);
  return hash(Buffer.concat([uint(prefix.length, 4), prefix, uint(d.length, 4), d, uint(bytes.length, 4), bytes]));
}
class Reader {
  constructor(bytes) { this.bytes = bytes; this.at = 0; }
  take(n) { assert(Number.isSafeInteger(n) && n >= 0 && n <= this.bytes.length - this.at); const b = this.bytes.subarray(this.at, this.at + n); this.at += n; return b; }
  u(n) { const b = this.take(n); let value = 0n; for (const byte of b) value = (value << 8n) | BigInt(byte); return value; }
  blob(width, maximum) { const length = Number(this.u(width)); assert(length <= maximum); return this.take(length); }
  done() { assert.equal(this.at, this.bytes.length); }
}
function descriptor(bytes) {
  const r = new Reader(bytes); assert.equal(r.u(2), 0n);
  const d = { genesis: r.take(32), chain: r.blob(2, 128), oldEpoch: r.u(8), newEpoch: r.u(8), oldVersion: r.u(4), newVersion: r.u(4), oldSet: r.take(32), newSet: r.take(32), oldParams: r.take(32), newParams: r.take(32), checkpointHeight: r.u(8), checkpoint: r.take(32), state: r.take(32), commitment: r.take(32), terminalHeight: r.u(8), terminal: r.take(32), qc: r.take(32), terminalView: r.u(8), activation: r.u(8), initialView: r.u(8) };
  r.done(); assert.equal(d.newEpoch, d.oldEpoch + 1n); assert.equal(d.initialView, 1n); return d;
}
function signingRoot(d, digest, role) {
  assert(role === 'old' || role === 'new'); const old = role === 'old';
  return framed('trnm.poco-bft.handoff-vote.v0', Buffer.concat([
    uint(0, 2), d.genesis, uint(d.chain.length, 2), d.chain,
    uint(old ? d.oldVersion : d.newVersion, 4), uint(old ? d.oldEpoch : d.newEpoch, 8),
    old ? d.oldSet : d.newSet, uint(old ? d.terminalView : d.initialView, 8),
    uint(old ? 3 : 4, 1), digest,
  ]));
}
function validatorSet(bytes) {
  const r = new Reader(bytes); assert.equal(r.u(2), 0n);
  r.take(32); r.blob(2, 128); r.u(4); r.u(8); r.take(32);
  const count = Number(r.u(4)); assert(count > 0 && count <= 100);
  const result = [];
  for (let i = 0; i < count; ++i) {
    const id = r.blob(4, 128); const key = r.take(32); const weight = r.u(8);
    assert(weight > 0n); if (i) assert(Buffer.compare(result[i-1].id, id) < 0);
    result.push({id, key, weight});
  }
  r.done(); return result;
}
function shares(reader) {
  const count = Number(reader.u(4)); assert(count > 0 && count <= 100); const out = [];
  for (let i = 0; i < count; ++i) {
    const id = reader.blob(4, 128); if (i) assert(Buffer.compare(out[i-1].id, id) < 0);
    out.push({id, signature: reader.take(64)});
  }
  return out;
}
function certificate(bytes, descriptorBytes) {
  const r = new Reader(bytes); assert.equal(r.u(2), 0n); assert.deepEqual(r.take(descriptorBytes.length), descriptorBytes);
  const old = shares(r); const fresh = shares(r); r.done(); return {old, fresh};
}
function context(name) {
  const c = corpus[name]; const bytes = raw(c.handoff.descriptor_cev0_hex); const d = descriptor(bytes);
  const id = framed('trnm.poco-bft.handoff-descriptor.v0', bytes);
  assert.equal(id.toString('hex'), c.handoff.descriptor_id_hex);
  const oldSet = validatorSet(raw(c.preheader.old_validator_set_cev0_hex));
  const newSet = validatorSet(raw(c.preheader.new_validator_set_cev0_hex));
  assert.deepEqual(oldSet, newSet, 'this reference supports complete carries only');
  assert.deepEqual(framed('trnm.poco-bft.validator-set.v0', raw(c.preheader.old_validator_set_cev0_hex)), d.oldSet);
  assert.deepEqual(framed('trnm.poco-bft.validator-set.v0', raw(c.preheader.new_validator_set_cev0_hex)), d.newSet);
  const cert = certificate(raw(c.handoff.certificate_cev0_hex), bytes);
  return {c, bytes, d, id, oldSet, newSet, cert};
}
function verifyRole(set, list, root) {
  let weight = 0n; let previous;
  for (const share of list) {
    if (previous) assert(Buffer.compare(previous, share.id) < 0);
    previous = share.id;
    const member = set.find(v => v.id.equals(share.id)); assert(member);
    assert(crypto.verify(null, root, {key: Buffer.concat([spki, member.key]), format: 'der', type: 'spki'}, share.signature));
    weight += member.weight;
  }
  const total = set.reduce((n, v) => n + v.weight, 0n); assert(weight >= (2n * total) / 3n + 1n);
}
for (const name of ['positive', 'authenticated_fallback']) {
  test(`${name}: exact carried-set keys, role signatures and certificate bytes`, () => {
    const x = context(name); const encoded = [uint(0, 2), x.bytes];
    for (const [role, list] of [['old', x.cert.old], ['new', x.cert.fresh]]) {
      const root = signingRoot(x.d, x.id, role); verifyRole(x.oldSet, list, root); encoded.push(uint(list.length, 4));
      for (const share of list) {
        const seed = hash(Buffer.from(`trnm.poco-bft.checkpoint-finality.private-fixture.v0:${share.id.toString('utf8')}`));
        const key = crypto.createPrivateKey({key: Buffer.concat([pkcs8, seed]), format: 'der', type: 'pkcs8'});
        const derived = crypto.createPublicKey(key).export({format:'der', type:'spki'}).subarray(-32);
        assert.deepEqual(derived, x.oldSet.find(v => v.id.equals(share.id)).key);
        const signature = crypto.sign(null, root, key); assert.deepEqual(signature, share.signature);
        encoded.push(uint(share.id.length, 4), share.id, signature);
      }
    }
    const bytes = Buffer.concat(encoded); assert.equal(bytes.toString('hex'), x.c.handoff.certificate_cev0_hex);
    assert.equal(framed('trnm.poco-bft.handoff-certificate.v0', bytes).toString('hex'), x.c.handoff.certificate_id_hex);
  });
}
test('old signatures never authenticate the new role', () => {
  const x = context('positive'); assert.throws(() => verifyRole(x.newSet, x.cert.old, signingRoot(x.d, x.id, 'new')));
});
test('descriptor, epoch and domain substitutions reject', () => {
  const x = context('positive');
  for (const change of [d => ({...d, newEpoch: d.newEpoch + 1n}), d => ({...d, chain: Buffer.from('other-chain')})]) {
    assert.throws(() => verifyRole(x.newSet, x.cert.fresh, signingRoot(change(x.d), x.id, 'new')));
  }
  const digest = Buffer.from(x.id); digest[0] ^= 1;
  assert.throws(() => verifyRole(x.newSet, x.cert.fresh, signingRoot(x.d, digest, 'new')));
  assert.throws(() => verifyRole(x.newSet, x.cert.fresh, framed('not-the-handoff-domain', x.bytes)));
});
test('duplicate, insufficient, unknown and corrupt signature shares reject', () => {
  const x = context('positive'); const root = signingRoot(x.d, x.id, 'new');
  for (const list of [[x.cert.fresh[0], x.cert.fresh[0]], x.cert.fresh.slice(0, 2),
    [{id: Buffer.from('unknown-validator'), signature: x.cert.fresh[0].signature}]]) assert.throws(() => verifyRole(x.newSet, list, root));
  const signature = Buffer.from(x.cert.fresh[0].signature); signature[0] ^= 1;
  assert.throws(() => verifyRole(x.newSet, [{...x.cert.fresh[0], signature}, ...x.cert.fresh.slice(1)], root));
});
test('every truncated descriptor and trailing byte reject', () => {
  const x = context('positive'); for (let n=0; n < x.bytes.length; ++n) assert.throws(() => descriptor(x.bytes.subarray(0,n)));
  assert.throws(() => descriptor(Buffer.concat([x.bytes, Buffer.from([0])])));
});
test('every truncated certificate and trailing byte reject', () => {
  const x = context('positive'); const bytes = raw(x.c.handoff.certificate_cev0_hex);
  for (let n=0; n < bytes.length; ++n) assert.throws(() => certificate(bytes.subarray(0,n), x.bytes));
  assert.throws(() => certificate(Buffer.concat([bytes, Buffer.from([0])]), x.bytes));
});
test('strict fixture hex and integer bounds reject normalization', () => {
  for (const s of ['0', 'AA', ' 00', '00\n', 'zz']) assert.throws(() => raw(s));
  assert.throws(() => uint(-1,8)); assert.throws(() => uint(1n<<64n,8));
  assert.equal(uint((1n<<64n)-1n,8).toString('hex'), 'ffffffffffffffff');
});
