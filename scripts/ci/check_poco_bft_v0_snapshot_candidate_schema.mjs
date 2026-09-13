#!/usr/bin/env node

// Independent, standard-library-only B2-G generator/gate. It neither invokes
// Rust nor treats the caller-supplied transcript as authenticated state.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCHEMA_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/schema/snapshot-candidate-kernel-v0.json");
const VECTOR_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/vectors/snapshot-candidate-kernel-v0.json");
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const POP_DOMAIN = "trnm.poco-bft.validator-key-pop.v0";
const PARAMETERS_DOMAIN = "trnm.poco-bft.parameters.v0";
const MAX_U128 = (1n << 128n) - 1n;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_SNAPSHOT_CANDIDATES = 100;
const MAX_SNAPSHOT_CONTRIBUTIONS = 10_000;
const MAX_SNAPSHOT_RELATION_ID_BYTES = 128;
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const stats = {
  popObjects: 0,
  popPrefixes: 0,
  signatureChecks: 0,
  positiveCases: 0,
  permutationCases: 0,
  calculationCases: 0,
  fallbackCases: 0,
  popNegativeCases: 0,
  authorizationOutputs: 0,
};

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function clone(value) {
  return structuredClone(value);
}

function hex(buffer) {
  return Buffer.from(buffer).toString("hex");
}

function fromHex(value, label) {
  invariant(typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value), `${label}: non-canonical hex`);
  const decoded = Buffer.from(value, "hex");
  invariant(hex(decoded) === value, `${label}: hex round-trip drift`);
  return decoded;
}

function isBoundedHexBytes(value, minimum, maximum) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) return false;
  const length = value.length / 2;
  return length >= minimum && length <= maximum;
}

function compareCanonicalHex(left, right) {
  return left === right ? 0 : left < right ? -1 : 1;
}

function asciiHex(value) {
  return Buffer.from(value, "ascii").toString("hex");
}

function bigint(value, label = "integer") {
  invariant(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), `${label}: non-canonical unsigned decimal`);
  return BigInt(value);
}

function checked(value, label) {
  if (value < 0n || value > MAX_U128) throw new ArithmeticError(label);
  return value;
}

function add(left, right, label) {
  return checked(left + right, label);
}

function mul(left, right, label) {
  return checked(left * right, label);
}

class ArithmeticError extends Error {}

function uint(value, width) {
  let remaining = typeof value === "bigint" ? value : BigInt(value);
  invariant(remaining >= 0n && remaining < (1n << BigInt(width * 8)), `u${width * 8} overflow`);
  const result = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function bytes(value) {
  return Buffer.concat([uint(value.length, 4), value]);
}

function consensusString(value) {
  return Buffer.concat([uint(value.length, 2), value]);
}

function frame(value) {
  return Buffer.concat([uint(value.length, 4), value]);
}

function digest(domain, encoded) {
  return crypto.createHash("sha256").update(Buffer.concat([
    frame(HASH_PREFIX),
    frame(Buffer.from(domain, "ascii")),
    frame(encoded),
  ])).digest();
}

function sha(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest();
}

function privateKeyFor(label) {
  const seed = sha(`trnm.poco-bft.snapshot-candidate.private-fixture.v0:${label}`);
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function publicKeyRaw(privateKey) {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  invariant(der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX), "unexpected Ed25519 SPKI prefix");
  return Buffer.from(der.subarray(SPKI_PREFIX.length));
}

function publicKeyObject(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function popSigningPreimage(fields) {
  const chain = Buffer.from(fields.chain_id_ascii, "ascii");
  const validator = fromHex(fields.validator_id_hex, "PoP validator_id");
  return Buffer.concat([
    uint(fields.schema_version, 2),
    fromHex(fields.genesis_hash_hex, "PoP genesis_hash"),
    consensusString(chain),
    uint(fields.target_epoch, 8),
    bytes(validator),
    fromHex(fields.public_key_hex, "PoP public_key"),
    uint(fields.registration_nonce, 8),
  ]);
}

function makePopFixture(id, validatorId, context, nonce) {
  const privateKey = privateKeyFor(id);
  const publicKey = publicKeyRaw(privateKey);
  const fields = {
    schema_version: 0,
    genesis_hash_hex: context.genesis_hash_hex,
    chain_id_ascii: context.chain_id_ascii,
    target_epoch: context.target_epoch,
    validator_id_hex: hex(validatorId),
    public_key_hex: hex(publicKey),
    registration_nonce: String(nonce),
  };
  const signing = popSigningPreimage(fields);
  const root = digest(POP_DOMAIN, signing);
  const signature = crypto.sign(null, root, privateKey);
  return {
    id,
    ...fields,
    signing_preimage_cev0_hex: hex(signing),
    signing_root_hex: hex(root),
    signature_hex: hex(signature),
    cev0_hex: hex(Buffer.concat([signing, signature])),
  };
}

class DecodeError extends Error {
  constructor(code, offset) {
    super(`${code}@${offset}`);
    this.code = code;
    this.offset = offset;
  }
}

class Cursor {
  constructor(raw) { this.raw = raw; this.position = 0; }
  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || this.position + length > this.raw.length) {
      throw new DecodeError("unexpected_end", this.position);
    }
    const value = this.raw.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }
  integer(width) {
    let value = 0n;
    for (const byte of this.take(width)) value = (value << 8n) | BigInt(byte);
    return value;
  }
}

function decodePopExact(raw) {
  const cursor = new Cursor(raw);
  const schemaOffset = cursor.position;
  const schemaVersion = Number(cursor.integer(2));
  if (schemaVersion !== 0) throw new DecodeError("invalid_schema_version", schemaOffset);
  const genesisOffset = cursor.position;
  const genesisHash = Buffer.from(cursor.take(32));
  if (genesisHash.equals(Buffer.alloc(32))) throw new DecodeError("zero_genesis_hash", genesisOffset);
  const chainOffset = cursor.position;
  const chainLength = Number(cursor.integer(2));
  if (chainLength < 1 || chainLength > 128) throw new DecodeError("invalid_chain_id", chainOffset);
  const chainId = Buffer.from(cursor.take(chainLength));
  const validFirst = (byte) => (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39);
  const validTail = (byte) => validFirst(byte) || byte === 0x2e || byte === 0x5f || byte === 0x3a || byte === 0x2d;
  if (!validFirst(chainId[0]) || ![...chainId.subarray(1)].every(validTail)) throw new DecodeError("invalid_chain_id", chainOffset);
  const targetEpoch = cursor.integer(8);
  const validatorOffset = cursor.position;
  const validatorLength = Number(cursor.integer(4));
  if (validatorLength === 0) throw new DecodeError("empty_validator_id", validatorOffset);
  if (validatorLength > 128) throw new DecodeError("validator_id_too_long", validatorOffset);
  const validatorId = Buffer.from(cursor.take(validatorLength));
  const publicKeyOffset = cursor.position;
  const publicKey = Buffer.from(cursor.take(32));
  if (publicKey.equals(Buffer.alloc(32))) throw new DecodeError("zero_public_key", publicKeyOffset);
  const registrationNonce = cursor.integer(8);
  const signature = Buffer.from(cursor.take(64));
  if (cursor.position !== raw.length) throw new DecodeError("trailing_bytes", cursor.position);
  const fields = {
    schema_version: schemaVersion,
    genesis_hash_hex: hex(genesisHash),
    chain_id_ascii: chainId.toString("ascii"),
    target_epoch: targetEpoch.toString(),
    validator_id_hex: hex(validatorId),
    public_key_hex: hex(publicKey),
    registration_nonce: registrationNonce.toString(),
  };
  return { fields, signature, signing: raw.subarray(0, raw.length - 64) };
}

function verifyPopFixture(fixture) {
  const raw = fromHex(fixture.cev0_hex, fixture.id);
  const decoded = decodePopExact(raw);
  assert.deepEqual(decoded.fields, {
    schema_version: fixture.schema_version,
    genesis_hash_hex: fixture.genesis_hash_hex,
    chain_id_ascii: fixture.chain_id_ascii,
    target_epoch: fixture.target_epoch,
    validator_id_hex: fixture.validator_id_hex,
    public_key_hex: fixture.public_key_hex,
    registration_nonce: fixture.registration_nonce,
  });
  assert.equal(hex(decoded.signing), fixture.signing_preimage_cev0_hex);
  const root = digest(POP_DOMAIN, decoded.signing);
  assert.equal(hex(root), fixture.signing_root_hex);
  assert.equal(hex(decoded.signature), fixture.signature_hex);
  assert.equal(crypto.verify(null, root, publicKeyObject(fromHex(fixture.public_key_hex, "public key")), decoded.signature), true);
  stats.signatureChecks += 1;
  for (let length = 0; length < raw.length; length += 1) {
    assert.throws(() => decodePopExact(raw.subarray(0, length)), (error) => error instanceof DecodeError && error.code === "unexpected_end");
    stats.popPrefixes += 1;
  }
  assert.throws(() => decodePopExact(Buffer.concat([raw, Buffer.from([0])])), (error) => error instanceof DecodeError && error.code === "trailing_bytes");
  stats.popObjects += 1;
}

function baseParameters(overrides = {}) {
  return {
    schema_version: 0,
    protocol_version: 0,
    production_activation: true,
    epoch_length_blocks: "10000",
    rollout_phase: 3,
    max_chain_id_bytes: 128,
    max_validator_id_bytes: 128,
    scale_ppm: "1000000",
    maturity_epochs: "2",
    max_certificate_age_epochs: "20",
    decay_step_ppm_per_epoch: "50000",
    per_certificate_unit_cap: "2000",
    per_consumer_provider_epoch_unit_cap: "2500",
    per_task_provider_epoch_unit_cap: "3000",
    per_provider_epoch_unit_cap: "3500",
    units_per_power: "100",
    bond_atomic_units_per_power: "100",
    min_validator_power: "1",
    max_validator_power: "100",
    min_validators: 4,
    max_validators: 4,
    max_total_voting_power: "400",
    max_validator_share_ppm: "333000",
    capped_weight_alpha_ppm: "250000",
    full_weight_alpha_ppm: "1000000",
    ...overrides,
  };
}

function fallbackName(code) {
  return ["none", "malformed_snapshot_input", "arithmetic_failure", "too_few_eligible_validators", "invalid_validator_identity_or_key", "validator_weight_out_of_bounds", "invalid_total_voting_power", "concentration_constraint_violated", "invalid_committed_parameters", "invalid_upgrade_or_activation"][code];
}

function recordReason(state, code) {
  if (code > 0 && (state.reason === 0 || code < state.reason)) state.reason = code;
}

function capAggregate(transcript, parameters, candidateIds, state) {
  const ordered = [...transcript.contributions].sort((a, b) => compareCanonicalHex(a.certificate_id_hex, b.certificate_id_hex));
  const groups = new Map();
  let previous = null;
  for (const item of ordered) {
    const taskLength = fromHex(item.task_id_hex, "task_id").length;
    const consumerLength = fromHex(item.consumer_id_hex, "consumer_id").length;
    if (item.certificate_id_hex === "00".repeat(32) || item.certificate_id_hex === previous || taskLength < 1 || taskLength > 128 || consumerLength < 1 || consumerLength > 128) recordReason(state, 1);
    previous = item.certificate_id_hex;
    if (!item.eligible) continue;
    const units = bigint(item.consumed_units, "consumed_units");
    if (units === 0n || !candidateIds.has(item.provider_validator_id_hex)) { recordReason(state, 1); continue; }
    try {
      const snapshot = bigint(transcript.snapshot_epoch, "snapshot_epoch");
      if (bigint(item.finalized_epoch, "finalized_epoch") > snapshot) { recordReason(state, 1); continue; }
      const matureAt = add(bigint(item.finalized_epoch), bigint(parameters.maturity_epochs), "maturity epoch");
      if (snapshot < matureAt) continue;
      const age = snapshot - matureAt;
      if (age >= bigint(parameters.max_certificate_age_epochs)) continue;
      const product = mul(age, bigint(parameters.decay_step_ppm_per_epoch), "decay product");
      const scale = bigint(parameters.scale_ppm);
      const decay = product >= scale ? 0n : scale - product;
      const capped = units < bigint(parameters.per_certificate_unit_cap) ? units : bigint(parameters.per_certificate_unit_cap);
      const decayed = mul(capped, decay, "scaled contribution") / scale;
      const key = `${item.provider_validator_id_hex}:${item.task_id_hex}:${item.consumer_id_hex}`;
      groups.set(key, add(groups.get(key) ?? 0n, decayed, "consumer aggregate"));
    } catch (error) {
      if (!(error instanceof ArithmeticError)) throw error;
      recordReason(state, 2);
    }
  }
  return groups;
}

function providerUnits(provider, groups, parameters, state) {
  const taskTotals = new Map();
  let consumerHits = 0;
  for (const [key, total] of groups) {
    const [entryProvider, task] = key.split(":");
    if (entryProvider !== provider) continue;
    const cap = bigint(parameters.per_consumer_provider_epoch_unit_cap);
    const value = total > cap ? cap : total;
    if (total > cap) consumerHits += 1;
    try { taskTotals.set(task, add(taskTotals.get(task) ?? 0n, value, "task aggregate")); }
    catch (error) { if (!(error instanceof ArithmeticError)) throw error; recordReason(state, 2); }
  }
  let providerTotal = 0n;
  let taskHits = 0;
  for (const total of [...taskTotals.entries()].sort(([a], [b]) => compareCanonicalHex(a, b)).map(([, value]) => value)) {
    const cap = bigint(parameters.per_task_provider_epoch_unit_cap);
    const value = total > cap ? cap : total;
    if (total > cap) taskHits += 1;
    try { providerTotal = add(providerTotal, value, "provider aggregate"); }
    catch (error) { if (!(error instanceof ArithmeticError)) throw error; recordReason(state, 2); }
  }
  const providerCap = bigint(parameters.per_provider_epoch_unit_cap);
  return { units: providerTotal > providerCap ? providerCap : providerTotal, consumerHits, taskHits, providerHit: providerTotal > providerCap };
}

function verifyCandidate(candidate, oldSet, context, popById, state) {
  if (!candidate.registration_valid || candidate.consensus_key_hex === "00".repeat(32)) recordReason(state, 4);
  const old = oldSet.validators.find((entry) => entry.validator_id_hex === candidate.validator_id_hex);
  const unchanged = old?.consensus_key_hex === candidate.consensus_key_hex;
  const requiresProof = !unchanged;
  if (!old && candidate.previous_registration_nonce !== null) recordReason(state, 4);
  if (old && !unchanged && candidate.previous_registration_nonce === null) recordReason(state, 4);
  if (requiresProof && candidate.proof_fixture_id === null) recordReason(state, 4);
  if (candidate.proof_fixture_id !== null) {
    const fixture = popById.get(candidate.proof_fixture_id);
    if (!fixture) { recordReason(state, 4); return; }
    try {
      const decoded = decodePopExact(fromHex(fixture.cev0_hex, fixture.id));
      const fields = decoded.fields;
      const scoped = fields.genesis_hash_hex === context.genesis_hash_hex &&
        fields.chain_id_ascii === context.chain_id_ascii &&
        fields.target_epoch === context.target_epoch &&
        fields.validator_id_hex === candidate.validator_id_hex &&
        fields.public_key_hex === candidate.consensus_key_hex;
      const root = digest(POP_DOMAIN, decoded.signing);
      const validSignature = crypto.verify(null, root, publicKeyObject(fromHex(fields.public_key_hex, "PoP key")), decoded.signature);
      stats.signatureChecks += 1;
      if (!scoped || !validSignature) recordReason(state, 4);
      if (candidate.previous_registration_nonce !== null && bigint(fields.registration_nonce) <= bigint(candidate.previous_registration_nonce)) recordReason(state, 4);
    } catch { recordReason(state, 4); }
  }
}

function validateEffective(validators, parameters, state) {
  if (validators.length < parameters.min_validators) recordReason(state, 3);
  if (validators.length > parameters.max_validators) recordReason(state, 8);
  let total = 0n;
  let maximum = 0n;
  for (const validator of validators) {
    if (fromHex(validator.validator_id_hex, "effective validator ID").length > parameters.max_validator_id_bytes) recordReason(state, 8);
    const weight = bigint(validator.effective_weight);
    if (weight < bigint(parameters.min_validator_power) || weight > bigint(parameters.max_validator_power) || weight > MAX_U64) recordReason(state, 5);
    try { total = add(total, weight, "total voting power"); }
    catch (error) { if (!(error instanceof ArithmeticError)) throw error; recordReason(state, 2); }
    if (weight > maximum) maximum = weight;
  }
  if (total === 0n || total > bigint(parameters.max_total_voting_power)) recordReason(state, 6);
  try {
    if (mul(maximum, 3n, "triple maximum") >= total ||
        mul(maximum, bigint(parameters.scale_ppm), "scaled maximum") > mul(total, bigint(parameters.max_validator_share_ppm), "allowed share")) recordReason(state, 7);
  } catch (error) { if (!(error instanceof ArithmeticError)) throw error; recordReason(state, 2); }
}

function computeCase(record, oldSet, oldParameters, popById, context) {
  const parameters = record.candidate_parameters;
  const transcript = record.transcript;
  const state = { reason: 0 };
  if (transcript.candidates.length > MAX_SNAPSHOT_CANDIDATES || transcript.contributions.length > MAX_SNAPSHOT_CONTRIBUTIONS) {
    return outcome(state, 1, [], null, oldSet.validators, "old");
  }
  if (transcript.contributions.some((contribution) =>
    !isBoundedHexBytes(contribution.task_id_hex, 1, MAX_SNAPSHOT_RELATION_ID_BYTES) ||
    !isBoundedHexBytes(contribution.consumer_id_hex, 1, MAX_SNAPSHOT_RELATION_ID_BYTES))) {
    return outcome(state, 1, [], null, oldSet.validators, "old");
  }
  if (transcript.snapshot_epoch !== oldSet.epoch || transcript.snapshot_height !== transcript.committed_snapshot_cutoff) recordReason(state, 1);
  if (parameters.epoch_length_blocks !== oldParameters.epoch_length_blocks || parameters.schema_version !== 0 || parameters.protocol_version !== 0) recordReason(state, 8);
  if (!parameters.production_activation && parameters.rollout_phase !== 0) recordReason(state, 9);
  if (Buffer.byteLength(context.chain_id_ascii, "ascii") > parameters.max_chain_id_bytes) recordReason(state, 8);

  const candidates = [...transcript.candidates].sort((left, right) => compareCanonicalHex(left.validator_id_hex, right.validator_id_hex));
  let previousId = null;
  const keys = new Set();
  for (const candidate of candidates) {
    const idLength = fromHex(candidate.validator_id_hex, "candidate ID").length;
    if (idLength < 1 || idLength > parameters.max_validator_id_bytes || candidate.validator_id_hex === previousId || keys.has(candidate.consensus_key_hex)) recordReason(state, 4);
    previousId = candidate.validator_id_hex;
    keys.add(candidate.consensus_key_hex);
    verifyCandidate(candidate, oldSet, context, popById, state);
  }
  const candidateIds = new Set(candidates.map((entry) => entry.validator_id_hex));
  const aggregates = capAggregate(transcript, parameters, candidateIds, state);
  const diagnostics = candidates.map((candidate) => {
    const capped = providerUnits(candidate.validator_id_hex, aggregates, parameters, state);
    const poco = capped.units / bigint(parameters.units_per_power);
    const bond = bigint(candidate.active_slashable_bond) / bigint(parameters.bond_atomic_units_per_power);
    const raw = [poco, bond, bigint(parameters.max_validator_power)].reduce((a, b) => a < b ? a : b);
    return {
      validator_id_hex: candidate.validator_id_hex,
      consensus_key_hex: candidate.consensus_key_hex,
      decayed_units: capped.units.toString(),
      poco_capacity: poco.toString(),
      bond_capacity: bond.toString(),
      raw_power: raw.toString(),
      selected: false,
      rollout_weight: null,
      consumer_cap_hits: capped.consumerHits,
      task_cap_hits: capped.taskHits,
      provider_cap_hit: capped.providerHit,
      jailed: candidate.jailed,
    };
  });
  const eligible = diagnostics.filter((entry) => !entry.jailed && bigint(entry.raw_power) >= bigint(parameters.min_validator_power));
  eligible.sort((left, right) => {
    const power = bigint(right.raw_power) - bigint(left.raw_power);
    return power === 0n ? compareCanonicalHex(left.validator_id_hex, right.validator_id_hex) : power > 0n ? 1 : -1;
  });
  const selected = eligible.slice(0, parameters.max_validators);
  if (selected.length < parameters.min_validators) recordReason(state, 3);
  const selectedIds = new Set(selected.map((entry) => entry.validator_id_hex));
  for (const entry of diagnostics) {
    entry.selected = selectedIds.has(entry.validator_id_hex);
    if (!entry.selected || parameters.rollout_phase === 0) continue;
    if (parameters.rollout_phase === 1) entry.rollout_weight = "1";
    else if (parameters.rollout_phase === 2) entry.rollout_weight = (1n + mul(bigint(parameters.capped_weight_alpha_ppm), bigint(entry.raw_power) - 1n, "rollout weight") / bigint(parameters.scale_ppm)).toString();
    else entry.rollout_weight = entry.raw_power;
  }
  let computedSet = null;
  if (parameters.rollout_phase !== 0) {
    computedSet = diagnostics.filter((entry) => entry.selected).map((entry) => ({
      validator_id_hex: entry.validator_id_hex,
      consensus_key_hex: entry.consensus_key_hex,
      effective_weight: entry.rollout_weight,
    })).sort((a, b) => compareCanonicalHex(a.validator_id_hex, b.validator_id_hex));
  }
  if (parameters.rollout_phase === 0) validateEffective(oldSet.validators, parameters, state);
  else if (computedSet !== null) validateEffective(computedSet, parameters, state);
  if (state.reason !== 0) return outcome(state, state.reason, [], null, oldSet.validators, "old");
  const effective = parameters.rollout_phase === 0 ? oldSet.validators : computedSet;
  return outcome(state, 0, diagnostics.map(({ jailed, ...entry }) => entry), computedSet, effective, record.parameters_profile);
}

function outcome(_state, reason, diagnostics, computedSet, effectiveSet, parameterProfile) {
  return {
    fallback_used: reason !== 0,
    fallback_reason_code: reason,
    fallback_reason: fallbackName(reason),
    computed_candidates: diagnostics,
    computed_candidate_validator_set: computedSet,
    effective_validator_set: effectiveSet.map((entry) => ({
      validator_id_hex: entry.validator_id_hex,
      consensus_key_hex: entry.consensus_key_hex,
      effective_weight: entry.effective_weight,
    })),
    effective_parameters_profile: parameterProfile,
    authorization_outputs: 0,
  };
}

function candidateFromPop(fixture, rawPower) {
  return {
    validator_id_hex: fixture.validator_id_hex,
    consensus_key_hex: fixture.public_key_hex,
    active_slashable_bond: String(rawPower * 100),
    jailed: false,
    registration_valid: true,
    previous_registration_nonce: null,
    proof_fixture_id: fixture.id,
  };
}

function contributionFor(fixture, units, index, finalizedEpoch = "8") {
  return {
    certificate_id_hex: hex(sha(`trnm-b2-g:certificate:${index}`)),
    provider_validator_id_hex: fixture.validator_id_hex,
    task_id_hex: asciiHex(`task-${index}`),
    consumer_id_hex: asciiHex(`consumer-${index}`),
    finalized_epoch: finalizedEpoch,
    consumed_units: String(units),
    eligible: true,
  };
}

function fullCase(id, profile, candidates, contributions, transcriptOverrides = {}) {
  return {
    id,
    parameters_profile: profile.id,
    candidate_parameters: clone(profile.parameters),
    transcript: {
      snapshot_epoch: "10",
      snapshot_height: "900",
      committed_snapshot_cutoff: "900",
      candidates: clone(candidates),
      contributions: clone(contributions),
      ...transcriptOverrides,
    },
  };
}

function calculationResult(record) {
  const state = { reason: 0 };
  const candidateIds = new Set([record.candidate.validator_id_hex]);
  const transcript = {
    snapshot_epoch: record.snapshot_epoch,
    contributions: record.contributions,
  };
  const groups = capAggregate(transcript, record.parameters, candidateIds, state);
  const capped = providerUnits(record.candidate.validator_id_hex, groups, record.parameters, state);
  const poco = capped.units / bigint(record.parameters.units_per_power);
  const bond = bigint(record.candidate.active_slashable_bond) / bigint(record.parameters.bond_atomic_units_per_power);
  const raw = [poco, bond, bigint(record.parameters.max_validator_power)].reduce((a, b) => a < b ? a : b);
  return {
    fallback_reason_code: state.reason,
    decayed_units: capped.units.toString(),
    poco_capacity: poco.toString(),
    bond_capacity: bond.toString(),
    raw_power: raw.toString(),
    consumer_cap_hits: capped.consumerHits,
    task_cap_hits: capped.taskHits,
    provider_cap_hit: capped.providerHit,
  };
}

function buildManifest() {
  const context = {
    genesis_hash_hex: hex(sha("trnm-b2-g:genesis")),
    chain_id_ascii: "trnm-b2g-candidate-0",
    snapshot_epoch: "10",
    target_epoch: "11",
    snapshot_height: "900",
  };
  const fixtures = ["a", "b", "c", "d", "e", "f"].map((suffix, index) =>
    makePopFixture(`validator-${suffix}`, Buffer.from(`validator-${suffix}`, "ascii"), context, 101 + index));
  fixtures.push(makePopFixture("id-length-1", Buffer.from([0x61]), context, 201));
  fixtures.push(makePopFixture("id-length-128", Buffer.alloc(128, 0x78), context, 202));
  fixtures.push(makePopFixture("id-all-zero-byte", Buffer.from([0]), context, 203));
  const popById = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  const oldParameters = baseParameters({ production_activation: false, rollout_phase: 0 });
  const oldSet = {
    genesis_hash_hex: context.genesis_hash_hex,
    chain_id_ascii: context.chain_id_ascii,
    protocol_version: 0,
    epoch: "10",
    validators: ["a", "b", "c", "d"].map((suffix) => ({
      validator_id_hex: asciiHex(`old-validator-${suffix}`),
      consensus_key_hex: hex(publicKeyRaw(privateKeyFor(`old-validator-${suffix}`))),
      effective_weight: "2",
    })),
  };
  const profiles = [
    { id: "shadow", parameters: baseParameters({ production_activation: false, rollout_phase: 0 }) },
    { id: "eligibility_only", parameters: baseParameters({ rollout_phase: 1 }) },
    { id: "capped_weight", parameters: baseParameters({ rollout_phase: 2 }) },
    { id: "full_weight", parameters: baseParameters({ rollout_phase: 3 }) },
    { id: "arithmetic_overflow", parameters: baseParameters({ per_certificate_unit_cap: MAX_U128.toString(), per_consumer_provider_epoch_unit_cap: MAX_U128.toString(), per_task_provider_epoch_unit_cap: MAX_U128.toString(), per_provider_epoch_unit_cap: MAX_U128.toString() }) },
    { id: "weight_out_of_bounds", parameters: baseParameters({ rollout_phase: 1, min_validator_power: "2" }) },
    { id: "total_power_tight_shadow", parameters: baseParameters({ production_activation: false, rollout_phase: 0, max_total_voting_power: "4" }) },
    { id: "concentration", parameters: baseParameters({ per_certificate_unit_cap: "20000", per_consumer_provider_epoch_unit_cap: "20000", per_task_provider_epoch_unit_cap: "20000", per_provider_epoch_unit_cap: "20000" }) },
    { id: "epoch_length_mismatch", parameters: baseParameters({ production_activation: false, rollout_phase: 0, epoch_length_blocks: "10001" }) },
    { id: "unauthorized_activation", parameters: baseParameters({ production_activation: false, rollout_phase: 1 }) },
  ];
  const profileById = new Map(profiles.map((profile) => [profile.id, profile]));
  const rawPowers = [12, 11, 10, 9, 8, 7];
  const baseCandidates = fixtures.slice(0, 6).map((fixture, index) => candidateFromPop(fixture, rawPowers[index]));
  const baseContributions = fixtures.slice(0, 6).map((fixture, index) => contributionFor(fixture, rawPowers[index] * 100, index));

  const cases = [];
  for (const id of ["shadow", "eligibility_only", "capped_weight", "full_weight"]) {
    cases.push(fullCase(id, profileById.get(id), baseCandidates, baseContributions));
  }
  const permutation = fullCase("candidate_and_contribution_reverse", profileById.get("full_weight"), [...baseCandidates].reverse(), [...baseContributions].reverse());

  const fallbackCases = [];
  const duplicate = [...baseContributions, clone(baseContributions[0])];
  fallbackCases.push(fullCase("reason_1_malformed_duplicate_certificate", profileById.get("full_weight"), baseCandidates, duplicate));
  const futureContribution = clone(baseContributions); futureContribution[0].finalized_epoch = "11";
  fallbackCases.push(fullCase("reason_1_future_finalized_epoch", profileById.get("full_weight"), baseCandidates, futureContribution));
  const emptyTask = clone(baseContributions); emptyTask[0].task_id_hex = "";
  fallbackCases.push(fullCase("reason_1_empty_task_id_preclone", profileById.get("full_weight"), baseCandidates, emptyTask));
  const longConsumer = clone(baseContributions); longConsumer[0].consumer_id_hex = "63".repeat(129);
  fallbackCases.push(fullCase("reason_1_consumer_id_length_129_preclone", profileById.get("full_weight"), baseCandidates, longConsumer));
  const overflowContributions = [
    { ...contributionFor(fixtures[0], MAX_U128, 80), consumed_units: MAX_U128.toString(), task_id_hex: asciiHex("overflow"), consumer_id_hex: asciiHex("same") },
    { ...contributionFor(fixtures[0], MAX_U128, 81), consumed_units: MAX_U128.toString(), task_id_hex: asciiHex("overflow"), consumer_id_hex: asciiHex("same") },
    ...baseContributions.slice(1),
  ];
  fallbackCases.push(fullCase("reason_2_checked_u128_overflow", profileById.get("arithmetic_overflow"), baseCandidates, overflowContributions));
  fallbackCases.push(fullCase("reason_3_too_few_eligible", profileById.get("full_weight"), baseCandidates.slice(0, 3), baseContributions.slice(0, 3)));
  const missingProof = clone(baseCandidates); missingProof[0].proof_fixture_id = null;
  fallbackCases.push(fullCase("reason_4_missing_required_pop", profileById.get("full_weight"), missingProof, baseContributions));
  fallbackCases.push(fullCase("reason_5_eligibility_weight_below_minimum", profileById.get("weight_out_of_bounds"), baseCandidates, baseContributions));
  fallbackCases.push(fullCase("reason_6_shadow_total_power_cap", profileById.get("total_power_tight_shadow"), baseCandidates, baseContributions));
  const skewCandidates = fixtures.slice(0, 4).map((fixture, index) => candidateFromPop(fixture, [100, 1, 1, 1][index]));
  const skewContributions = fixtures.slice(0, 4).map((fixture, index) => contributionFor(fixture, [10000, 100, 100, 100][index], 90 + index));
  fallbackCases.push(fullCase("reason_7_concentration", profileById.get("concentration"), skewCandidates, skewContributions));
  fallbackCases.push(fullCase("reason_8_epoch_length_mismatch", profileById.get("epoch_length_mismatch"), baseCandidates, baseContributions));
  fallbackCases.push(fullCase("reason_9_nonproduction_activation", profileById.get("unauthorized_activation"), baseCandidates, baseContributions));
  const multiOneCandidates = clone(missingProof);
  fallbackCases.push(fullCase("lowest_reason_1_over_4_8", profileById.get("epoch_length_mismatch"), multiOneCandidates, duplicate, { snapshot_height: "901" }));
  fallbackCases.push(fullCase("lowest_reason_2_over_3", profileById.get("arithmetic_overflow"), baseCandidates.slice(0, 3), overflowContributions.slice(0, 2)));

  const calculationParameters = baseParameters();
  const calcCandidate = clone(baseCandidates[0]);
  const calculationCases = [
    { id: "maturity_immature", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 1000, 200, "9")] },
    { id: "maturity_age_zero", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 1000, 201, "8")] },
    { id: "decay_age_nineteen", snapshot_epoch: "29", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 1000, 202, "8")] },
    { id: "expiry_age_twenty", snapshot_epoch: "30", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 1000, 203, "8")] },
    { id: "per_certificate_cap", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 3000, 204, "8")] },
    { id: "consumer_provider_cap", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [contributionFor(fixtures[0], 2000, 205, "8"), { ...contributionFor(fixtures[0], 2000, 206, "8"), task_id_hex: asciiHex("task-205"), consumer_id_hex: asciiHex("consumer-205") }] },
    { id: "task_provider_cap", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [0, 1].map((index) => ({ ...contributionFor(fixtures[0], 2000, 207 + index, "8"), task_id_hex: asciiHex("task-cap"), consumer_id_hex: asciiHex(`consumer-${index}`) })) },
    { id: "provider_cap", snapshot_epoch: "10", parameters: calculationParameters, candidate: calcCandidate, contributions: [0, 1].map((index) => ({ ...contributionFor(fixtures[0], 3000, 209 + index, "8"), task_id_hex: asciiHex(`provider-task-${index}`), consumer_id_hex: asciiHex(`provider-consumer-${index}`) })) },
    { id: "bond_ceiling", snapshot_epoch: "10", parameters: calculationParameters, candidate: { ...calcCandidate, active_slashable_bond: "650" }, contributions: [contributionFor(fixtures[0], 2000, 211, "8")] },
  ];

  const negativePop = buildPopNegatives(fixtures[0], fixtures[1], context);
  for (const record of [...cases, permutation, ...fallbackCases]) record.expected = computeCase(record, oldSet, oldParameters, popById, context);
  for (const record of calculationCases) record.expected = calculationResult(record);
  return {
    schema: "trnm_poco_bft_snapshot_candidate_kernel_vectors_v0",
    schema_version: 0,
    scope: "B2-G deterministic candidate/fallback computation over unauthenticated normalized inputs",
    logical_schema: "../schema/snapshot-candidate-kernel-v0.json",
    fixture_secret_policy: "Deterministic fixture seeds exist only in the independent Node gate; the committed vector contains no private seed or private key.",
    authorization_outputs: 0,
    hard_bounds: { max_snapshot_candidates: MAX_SNAPSHOT_CANDIDATES, max_snapshot_contributions: MAX_SNAPSHOT_CONTRIBUTIONS, id_bytes_min: 1, id_bytes_max: 128 },
    pop_contract: { domain: POP_DOMAIN, hash_prefix_ascii: HASH_PREFIX.toString("ascii"), signing_preimage_fields: 7, exact_object_fields: 8, signature_in_signing_preimage: false },
    context,
    old_parameters: oldParameters,
    old_active_validator_set: oldSet,
    parameter_profiles: profiles,
    pop_fixtures: fixtures,
    base_candidates: baseCandidates,
    base_contributions: baseContributions,
    positive_cases: cases,
    permutation_cases: [permutation],
    calculation_boundary_cases: calculationCases,
    fallback_cases: fallbackCases,
    pop_negative_cases: negativePop,
    hard_bound_cases: [
      { id: "candidate_count_101", expected_reason: 1, expected_diagnostics: 0 },
      { id: "contribution_count_10001", expected_reason: 1, expected_diagnostics: 0 },
    ],
    honest_boundary: [
      "Only the seven-field PoP signing preimage, eight-field exact PoP object, frozen domain, and strict Ed25519 signatures are cryptographically checked.",
      "All candidate, contribution, eligibility, registration, bond, jail, cutoff, old-set, and parameter facts are caller-supplied and unauthenticated.",
      "The kernel is not exact-transcript-bound and has no aggregate CEV0 or digest domain. Inputs may be permuted and are internally sorted; duplicates fail closed.",
      "Every fallback clears non-authoritative diagnostics and atomically carries the old set and old parameters. Shadow success has no computed candidate validator set and carries old membership/weights under candidate parameters.",
      "Success is inert deterministic outcome evidence, never JMT/runtime/checkpoint provenance, an anchor, handoff, activation, validator-set authority, or epoch transition.",
    ],
  };
}

function encodePopWithSignature(fields, signature) {
  return Buffer.concat([popSigningPreimage(fields), signature]);
}

function buildPopNegatives(base, other, context) {
  const baseSignature = fromHex(base.signature_hex, "base signature");
  const mutations = [
    ["wrong_genesis_scope", { genesis_hash_hex: hex(sha("foreign genesis")) }, "valid", "invalid_scope"],
    ["wrong_chain_scope", { chain_id_ascii: "foreign-chain" }, "valid", "invalid_scope"],
    ["wrong_epoch_scope", { target_epoch: "12" }, "valid", "invalid_scope"],
    ["wrong_validator_scope", { validator_id_hex: asciiHex("foreign-validator") }, "valid", "invalid_scope"],
    ["wrong_key_scope", { public_key_hex: other.public_key_hex }, "valid", "invalid_scope"],
    ["wrong_nonce_signature", { registration_nonce: "999" }, "valid", "invalid_signature"],
  ];
  const result = mutations.map(([id, override, decode, verification]) => {
    const fields = { ...base, ...override };
    return { id, cev0_hex: hex(encodePopWithSignature(fields, baseSignature)), expected_decode: decode, expected_verification: verification, expected_kernel_reason: 4 };
  });
  for (const [id, chainId] of [
    ["invalid_chain_first_uppercase", "Avalid"],
    ["invalid_chain_first_punctuation", "!valid"],
    ["invalid_chain_tail_slash", "valid/"],
  ]) {
    const fields = { ...base, chain_id_ascii: chainId };
    result.push({
      id,
      cev0_hex: hex(encodePopWithSignature(fields, baseSignature)),
      expected_decode: "invalid_chain_id",
      expected_error_byte_offset: 34,
      expected_verification: "not_reached",
      expected_kernel_reason: 4,
    });
  }
  const wrongDomainRoot = digest("trnm.poco-bft.validator-key-pop.v1", fromHex(base.signing_preimage_cev0_hex, "signing preimage"));
  const wrongDomainSignature = crypto.sign(null, wrongDomainRoot, privateKeyFor(base.id));
  result.push({ id: "wrong_domain_signature", cev0_hex: hex(encodePopWithSignature(base, wrongDomainSignature)), expected_decode: "valid", expected_verification: "invalid_signature", expected_kernel_reason: 4 });
  const corrupted = Buffer.from(baseSignature); corrupted[0] ^= 1;
  result.push({ id: "corrupt_signature", cev0_hex: hex(encodePopWithSignature(base, corrupted)), expected_decode: "valid", expected_verification: "invalid_signature", expected_kernel_reason: 4 });
  const tooLongFields = { ...base, validator_id_hex: "78".repeat(129) };
  result.push({ id: "validator_id_length_129", cev0_hex: hex(encodePopWithSignature(tooLongFields, baseSignature)), expected_decode: "validator_id_too_long", expected_verification: "not_reached", expected_kernel_reason: 4 });
  result.push({ id: "missing_required_pop", cev0_hex: null, expected_decode: "not_present", expected_verification: "not_reached", expected_kernel_reason: 4 });
  result.push({ id: "stale_registration_nonce", cev0_hex: base.cev0_hex, previous_registration_nonce: base.registration_nonce, expected_decode: "valid", expected_verification: "valid_signature_but_stale_nonce", expected_kernel_reason: 4 });
  return result;
}

function assertInertOutcome(actual, label) {
  assert.equal(actual.authorization_outputs, 0, `${label}: authorization output drift`);
  stats.authorizationOutputs += actual.authorization_outputs;
  if (actual.fallback_used) {
    assert.equal(actual.fallback_reason_code > 0, true, `${label}: fallback lacks reason`);
    assert.deepEqual(actual.computed_candidates, [], `${label}: fallback leaked diagnostics`);
    assert.equal(actual.computed_candidate_validator_set, null, `${label}: fallback leaked computed set`);
    assert.equal(actual.effective_parameters_profile, "old", `${label}: fallback did not carry old parameters`);
  } else {
    assert.equal(actual.fallback_reason_code, 0, `${label}: success has fallback reason`);
  }
}

function verifyPopNegative(record, base, context) {
  assert.equal(record.expected_kernel_reason, 4, `${record.id}: PoP negative reason drift`);
  if (record.cev0_hex === null) {
    assert.equal(record.expected_decode, "not_present", `${record.id}: missing proof contract drift`);
    stats.popNegativeCases += 1;
    return;
  }
  let decoded;
  try {
    decoded = decodePopExact(fromHex(record.cev0_hex, record.id));
  } catch (error) {
    assert.equal(error instanceof DecodeError, true, `${record.id}: unexpected decoder failure`);
    assert.equal(error.code, record.expected_decode, `${record.id}: decoder code drift`);
    if (record.expected_error_byte_offset !== undefined) assert.equal(error.offset, record.expected_error_byte_offset, `${record.id}: decoder offset drift`);
    stats.popNegativeCases += 1;
    return;
  }
  assert.equal(record.expected_decode, "valid", `${record.id}: unexpectedly decoded`);
  const root = digest(POP_DOMAIN, decoded.signing);
  const signatureValid = crypto.verify(
    null,
    root,
    publicKeyObject(fromHex(decoded.fields.public_key_hex, `${record.id} public key`)),
    decoded.signature,
  );
  stats.signatureChecks += 1;
  const scopeValid = decoded.fields.genesis_hash_hex === context.genesis_hash_hex &&
    decoded.fields.chain_id_ascii === context.chain_id_ascii &&
    decoded.fields.target_epoch === context.target_epoch &&
    decoded.fields.validator_id_hex === base.validator_id_hex &&
    decoded.fields.public_key_hex === base.public_key_hex;
  if (record.expected_verification === "invalid_scope") assert.equal(scopeValid, false, `${record.id}: scope mutation ineffective`);
  else if (record.expected_verification === "invalid_signature") assert.equal(signatureValid, false, `${record.id}: invalid signature accepted`);
  else if (record.expected_verification === "valid_signature_but_stale_nonce") {
    assert.equal(scopeValid, true, `${record.id}: stale nonce scope drift`);
    assert.equal(signatureValid, true, `${record.id}: stale nonce fixture signature drift`);
    assert.equal(bigint(decoded.fields.registration_nonce) <= bigint(record.previous_registration_nonce), true, `${record.id}: nonce is not stale`);
  } else throw new Error(`${record.id}: unknown PoP verification expectation`);
  stats.popNegativeCases += 1;
}

function validateSchema(schema) {
  assert.equal(schema.schema, "trnm_poco_bft_snapshot_candidate_kernel_v0");
  assert.equal(schema.schema_version, 0);
  assert.deepEqual(schema.public_types, [
    "ValidatorKeyProofOfPossessionV0",
    "UnauthenticatedSnapshotContributionV0",
    "UnauthenticatedSnapshotCandidateV0",
    "UnauthenticatedCandidateSelectionTranscriptV0",
    "CandidateComputationV0",
    "CandidateSelectionKernelV0",
  ]);
  assert.equal(schema.validator_key_proof_of_possession_v0.digest_domain, POP_DOMAIN);
  assert.equal(schema.validator_key_proof_of_possession_v0.signing_preimage_field_order.length, 7);
  assert.equal(schema.validator_key_proof_of_possession_v0.exact_object_suffix.index, 8);
  assert.equal(schema.unauthenticated_candidate_selection_transcript_v0.canonical_cev0, false);
  assert.equal(schema.unauthenticated_candidate_selection_transcript_v0.digest_domain, null);
  assert.equal(schema.candidate_selection_kernel_v0.authorization_outputs, 0);
  assert.equal(schema.hard_bounds.max_snapshot_candidates, MAX_SNAPSHOT_CANDIDATES);
  assert.equal(schema.hard_bounds.max_snapshot_contributions, MAX_SNAPSHOT_CONTRIBUTIONS);
  assert.deepEqual(schema.fallback_reasons.map((entry) => entry.code), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

function validateManifest(vector) {
  assert.equal(vector.schema, "trnm_poco_bft_snapshot_candidate_kernel_vectors_v0");
  assert.equal(vector.schema_version, 0);
  assert.equal(vector.authorization_outputs, 0);
  assert.deepEqual(vector.hard_bounds, {
    max_snapshot_candidates: MAX_SNAPSHOT_CANDIDATES,
    max_snapshot_contributions: MAX_SNAPSHOT_CONTRIBUTIONS,
    id_bytes_min: 1,
    id_bytes_max: 128,
  });
  assert.equal(vector.pop_contract.domain, POP_DOMAIN);
  assert.equal(vector.pop_contract.signing_preimage_fields, 7);
  assert.equal(vector.pop_contract.exact_object_fields, 8);
  assert.equal(vector.pop_contract.signature_in_signing_preimage, false);
  const serialized = JSON.stringify(vector);
  assert.equal(serialized.includes('"private_key":'), false, "vector contains private-key material");
  assert.equal(serialized.includes('"private_seed":'), false, "vector contains private-seed material");

  for (const fixture of vector.pop_fixtures) verifyPopFixture(fixture);
  const oneByte = vector.pop_fixtures.find((fixture) => fixture.id === "id-length-1");
  const maximum = vector.pop_fixtures.find((fixture) => fixture.id === "id-length-128");
  const allZero = vector.pop_fixtures.find((fixture) => fixture.id === "id-all-zero-byte");
  assert.equal(fromHex(oneByte.validator_id_hex, "one-byte ID").length, 1);
  assert.equal(fromHex(maximum.validator_id_hex, "maximum ID").length, 128);
  assert.equal(allZero.validator_id_hex, "00", "all-zero nonempty opaque ID fixture missing");
  assert.equal(decodePopExact(fromHex(allZero.cev0_hex, allZero.id)).fields.validator_id_hex, "00");

  const popById = new Map(vector.pop_fixtures.map((fixture) => [fixture.id, fixture]));
  const run = (record, category) => {
    assert.equal(record.candidate_parameters !== undefined, true, `${record.id}: candidate parameters missing`);
    const actual = computeCase(record, vector.old_active_validator_set, vector.old_parameters, popById, vector.context);
    assert.deepEqual(actual, record.expected, `${record.id}: ${category} outcome drift`);
    assertInertOutcome(actual, record.id);
    stats[category] += 1;
    return actual;
  };
  const positives = new Map();
  for (const record of vector.positive_cases) positives.set(record.id, run(record, "positiveCases"));
  const shadow = positives.get("shadow");
  assert.equal(shadow.computed_candidate_validator_set, null, "shadow minted a candidate set");
  assert.deepEqual(shadow.effective_validator_set, vector.old_active_validator_set.validators, "shadow did not carry old membership/weights");
  for (const record of vector.permutation_cases) {
    const actual = run(record, "permutationCases");
    assert.deepEqual(actual, positives.get("full_weight"), `${record.id}: permutation changed result`);
  }
  for (const record of vector.fallback_cases) {
    const actual = run(record, "fallbackCases");
    assert.equal(actual.fallback_used, true, `${record.id}: expected fallback`);
    assert.deepEqual(actual.effective_validator_set, vector.old_active_validator_set.validators, `${record.id}: fallback old-set carry drift`);
  }
  assert.deepEqual([...new Set(vector.fallback_cases.map((record) => record.expected.fallback_reason_code))].sort(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);

  for (const record of vector.calculation_boundary_cases) {
    assert.deepEqual(calculationResult(record), record.expected, `${record.id}: calculation boundary drift`);
    stats.calculationCases += 1;
  }
  const base = vector.pop_fixtures.find((fixture) => fixture.id === "validator-a");
  for (const record of vector.pop_negative_cases) verifyPopNegative(record, base, vector.context);

  const baseCase = clone(vector.positive_cases.find((record) => record.id === "full_weight"));
  const candidateBound = clone(baseCase);
  candidateBound.transcript.candidates = Array.from({ length: MAX_SNAPSHOT_CANDIDATES + 1 }, () => clone(vector.base_candidates[0]));
  const candidateOutcome = computeCase(candidateBound, vector.old_active_validator_set, vector.old_parameters, popById, vector.context);
  assert.equal(candidateOutcome.fallback_reason_code, 1);
  assert.deepEqual(candidateOutcome.computed_candidates, []);
  assert.equal(candidateOutcome.computed_candidate_validator_set, null);
  const contributionBound = clone(baseCase);
  contributionBound.transcript.contributions = Array.from({ length: MAX_SNAPSHOT_CONTRIBUTIONS + 1 }, () => clone(vector.base_contributions[0]));
  const contributionOutcome = computeCase(contributionBound, vector.old_active_validator_set, vector.old_parameters, popById, vector.context);
  assert.equal(contributionOutcome.fallback_reason_code, 1);
  assert.deepEqual(contributionOutcome.computed_candidates, []);
  assert.equal(contributionOutcome.computed_candidate_validator_set, null);
  assert.equal(stats.authorizationOutputs, 0, "gate observed an authorization output");
}

function main() {
  if (process.argv.includes("--emit-vector")) {
    process.stdout.write(`${JSON.stringify(buildManifest(), null, 2)}\n`);
    return;
  }
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  const vector = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
  validateSchema(schema);
  validateManifest(vector);
  process.stdout.write(`snapshot candidate gate ok: pop=${stats.popObjects}, prefixes=${stats.popPrefixes}, signatures=${stats.signatureChecks}, positive=${stats.positiveCases}, permutations=${stats.permutationCases}, calculations=${stats.calculationCases}, fallbacks=${stats.fallbackCases}, pop_negatives=${stats.popNegativeCases}, authorization_outputs=${stats.authorizationOutputs}\n`);
}

export {
  POP_DOMAIN,
  bytes,
  computeCase,
  decodePopExact,
  digest,
  fallbackName,
  fromHex,
  hex,
  publicKeyObject,
  uint,
};

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
