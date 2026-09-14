#!/usr/bin/env node
// Bounded independent byte/signature regression. This does not execute Rust,
// drive a native host, authenticate a local COMMITTED row or activate an epoch.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { test } from "node:test";
import {
  decodeCommitment, decodeFinality, decodeHeader, decodeParameters,
  decodeValidatorSet, validateFinality,
} from "./check_poco_bft_v0_joint_handoff_schema.mjs";

const path = new URL("../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json", import.meta.url);
function fixture(profile = "positive") {
  const row = JSON.parse(fs.readFileSync(path, "utf8"))[profile];
  delete row.handoff;
  delete row.bound_authority;
  const raw = (section, name) => Buffer.from(row[section][name], "hex");
  const parameters = decodeParameters(raw("preheader", "old_parameters_cev0_hex"));
  return {
    raw: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
    parameters,
    set: decodeValidatorSet(raw("preheader", "old_validator_set_cev0_hex"), parameters),
    commitment: decodeCommitment(raw("preheader", "commitment_cev0_hex")),
    header: decodeHeader(raw("checkpoint", "header_cev0_hex"), parameters),
    parent: decodeHeader(raw("preheader", "checkpoint_parent_header_cev0_hex"), parameters),
  };
}

function verify(f, raw = f.raw, expected = f.header, parent = f.parent) {
  const proof = decodeFinality(raw, f.parameters);
  assert.deepEqual(proof.finalizedBlock.header.raw, expected.raw, "exact checkpoint header");
  assert.deepEqual(proof.finalizedBlock.header.parentId, parent.id, "authenticated parent");
  validateFinality(proof, f.set, f.parameters, f.commitment, parent.timestamp);
  return proof;
}

function countActual(action) {
  let calls = 0;
  const original = crypto.verify;
  crypto.verify = (...args) => { calls += 1; return original(...args); };
  try { action(); return calls; } finally { crypto.verify = original; }
}

for (const profile of ["positive", "authenticated_fallback"]) {
  test(`${profile}: verifies two seals with no joint handoff certificate`, () => {
    const f = fixture(profile);
    const proof = verify(f);
    assert.equal(proof.finalizedBlock.header.kind, 1);
    assert.equal(proof.child.header.kind, 2);
    assert.equal(proof.grandchild.header.kind, 3);
  });

  test(`${profile}: real Ed25519 calls include all three proposer signatures`, () => {
    const f = fixture(profile);
    const proof = decodeFinality(f.raw, f.parameters);
    const sharesOnly = [proof.finalizedBlock, proof.child, proof.grandchild]
      .reduce((sum, block) => sum + block.justifyQc.signatures.length + block.certifyingQc.signatures.length, 0);
    const calls = countActual(() => verify(f));
    assert.equal(calls, sharesOnly + 3);
    assert.notEqual(calls, sharesOnly, "regression witness for the previous Rust undercount");
    console.log(`${profile}: certificate_shares=${sharesOnly} proposer_signatures=3 actual_verifications=${calls}`);
  });
}

test("each corrupt proposal signature rejects without changing input", () => {
  const f = fixture();
  const proof = decodeFinality(f.raw, f.parameters);
  const unchanged = Buffer.from(f.raw);
  for (const block of [proof.finalizedBlock, proof.child, proof.grandchild]) {
    const at = f.raw.indexOf(block.proposerSignature);
    assert.ok(at >= 0);
    assert.equal(f.raw.indexOf(block.proposerSignature, at + 1), -1);
    const corrupt = Buffer.from(f.raw);
    corrupt[at] ^= 1;
    assert.throws(() => verify(f, corrupt));
    assert.deepEqual(f.raw, unchanged);
  }
});

test("wrong checkpoint or authenticated parent is never inferred from the proof", () => {
  const f = fixture();
  const other = fixture("authenticated_fallback");
  assert.throws(() => verify(f, f.raw, other.header));
  assert.throws(() => verify(f, f.raw, f.header, other.parent));
});

test("truncation and trailing bytes have no permissive decoder fallback", () => {
  const f = fixture();
  for (const end of [0, 1, Math.floor(f.raw.length / 2), f.raw.length - 1]) {
    assert.throws(() => verify(f, f.raw.subarray(0, end)));
  }
  assert.throws(() => verify(f, Buffer.concat([f.raw, Buffer.from([0])])));
});
