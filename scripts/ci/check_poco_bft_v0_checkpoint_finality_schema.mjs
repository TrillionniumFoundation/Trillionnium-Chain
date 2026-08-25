#!/usr/bin/env node

// Independent B2-E checkpoint/two-seal CEV0 and semantic gate.
// Standard-library only. The output is deliberately inert: successful checks
// cannot construct an EpochAnchorQC, authorize a handoff signature, or prove
// snapshot/runtime provenance.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "../..");
const SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-checkpoint-finality-v0.json",
);
const BASE_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-v0.json",
);
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/checkpoint-two-seal-kernel-v0.json",
);
const PARAMETERS_VECTOR_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/parameters-v0.json",
);
const COMMON_PROTO_PATH = path.join(REPO_ROOT, "proto/trnm/poco/bft/v0/common.proto");
const LIGHT_PROTO_PATH = path.join(
  REPO_ROOT,
  "proto/trnm/poco/bft/v0/light_client.proto",
);

const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const DOMAIN_PARAMETERS = "trnm.poco-bft.parameters.v0";
const DOMAIN_VALIDATOR_SET = "trnm.poco-bft.validator-set.v0";
const DOMAIN_BLOCK = "trnm.poco-bft.block.v0";
const DOMAIN_VOTE = "trnm.poco-bft.vote.v0";
const DOMAIN_QC = "trnm.poco-bft.qc.v0";
const DOMAIN_TIMEOUT = "trnm.poco-bft.timeout.v0";
const DOMAIN_TC = "trnm.poco-bft.tc.v0";
const DOMAIN_PROPOSAL = "trnm.poco-bft.proposal.v0";
const DOMAIN_FINALITY = "trnm.poco-bft.finality-proof.v0";
const DOMAIN_EPOCH_COMMITMENT = "trnm.poco-bft.epoch-commitment.v0";
const EMPTY_PAYLOAD_ROOT = Buffer.from(
  "0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2",
  "hex",
);
const EMPTY_RECEIPTS_ROOT = Buffer.from(
  "b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156",
  "hex",
);
const EMPTY_EVIDENCE_ROOT = Buffer.from(
  "df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047",
  "hex",
);
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

class KernelError extends Error {
  constructor(code, offset, message, layer = "decoder") {
    super(`${code} at byte ${offset}: ${message}`);
    this.name = "KernelError";
    this.code = code;
    this.offset = offset;
    this.layer = layer;
  }
}

function fail(code, offset, message, layer = "decoder") {
  throw new KernelError(code, offset, message, layer);
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, "utf8"));
}

function cloneBuffer(value) {
  return Buffer.from(value);
}

function u(value, width) {
  let remaining = typeof value === "bigint" ? value : BigInt(value);
  const maximum = 1n << BigInt(width * 8);
  if (remaining < 0n || remaining >= maximum) {
    fail("source_vector_drift", 0, `${value} does not fit u${width * 8}`, "gate");
  }
  const result = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function bytes(value) {
  return Buffer.concat([u(value.length, 4), value]);
}

function consensusString(value) {
  return Buffer.concat([u(value.length, 2), value]);
}

function list(values, encode) {
  return Buffer.concat([u(values.length, 4), ...values.map(encode)]);
}

function frame(value) {
  return Buffer.concat([u(value.length, 4), value]);
}

function optional(value, encode) {
  return value === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), encode(value)]);
}

function digest(domain, encoded) {
  return crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        frame(HASH_PREFIX),
        frame(Buffer.from(domain, "ascii")),
        frame(encoded),
      ]),
    )
    .digest();
}

function labelHash(label) {
  return crypto.createHash("sha256").update(`b2-e:${label}`, "utf8").digest();
}

function fixtureSeed(id) {
  return crypto
    .createHash("sha256")
    .update(`trnm.poco-bft.checkpoint-finality.private-fixture.v0:${id}`, "utf8")
    .digest();
}

function privateKeyFromSeed(seed) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyRaw(privateKey) {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  if (
    der.length !== SPKI_PREFIX.length + 32 ||
    !der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)
  ) {
    fail("source_vector_drift", 0, "unexpected Ed25519 SPKI encoding", "gate");
  }
  return der.subarray(SPKI_PREFIX.length);
}

function publicKeyObject(raw) {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function sign(privateKey, root) {
  const signature = crypto.sign(null, root, privateKey);
  if (signature.length !== 64) {
    fail("source_vector_drift", 0, "Ed25519 signature is not 64 bytes", "gate");
  }
  return signature;
}

function verify(publicKey, root, signature) {
  return signature.length === 64 && crypto.verify(null, root, publicKeyObject(publicKey), signature);
}

class Cursor {
  constructor(raw) {
    this.raw = raw;
    this.position = 0;
  }

  offset() {
    return this.position;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || this.position + length > this.raw.length) {
      fail("unexpected_eof", this.position, `need ${length} bytes`);
    }
    const result = this.raw.subarray(this.position, this.position + length);
    this.position += length;
    return result;
  }

  uint(width) {
    const raw = this.take(width);
    let result = 0n;
    for (const octet of raw) result = (result << 8n) | BigInt(octet);
    return result;
  }

  u8() {
    return Number(this.uint(1));
  }

  u16() {
    return Number(this.uint(2));
  }

  u32() {
    return Number(this.uint(4));
  }

  u64() {
    return this.uint(8);
  }

  u128() {
    return this.uint(16);
  }

  fixed(length) {
    return this.take(length);
  }

  bytes(maximum = 128) {
    const lengthOffset = this.offset();
    const length = this.u32();
    if (length === 0 || length > maximum) {
      fail("length_limit_exceeded", lengthOffset, `byte string length ${length}`);
    }
    return this.take(length);
  }

  consensusString(maximum = 128) {
    const lengthOffset = this.offset();
    const length = this.u16();
    if (length === 0 || length > maximum) {
      fail("invalid_consensus_string", lengthOffset, `consensus string length ${length}`);
    }
    const raw = this.take(length);
    for (let index = 0; index < raw.length; index += 1) {
      const octet = raw[index];
      const lower = octet >= 0x61 && octet <= 0x7a;
      const digit = octet >= 0x30 && octet <= 0x39;
      const punctuation = octet === 0x2e || octet === 0x5f || octet === 0x3a || octet === 0x2d;
      if (!(lower || digit || (index > 0 && punctuation))) {
        fail("invalid_consensus_string", lengthOffset, "non-canonical consensus string byte");
      }
    }
    return raw;
  }

  count(maximum = 100) {
    const offset = this.offset();
    const count = this.u32();
    if (count > maximum) fail("count_limit_exceeded", offset, `count ${count}`);
    return count;
  }

  finish() {
    if (this.position !== this.raw.length) {
      fail("trailing_bytes", this.position, `${this.raw.length - this.position} trailing bytes`);
    }
  }
}

const PARAMETER_LAYOUT = [
  ["schema_version", "u16"],
  ["protocol_version", "u32"],
  ["production_activation", "bool"],
  ["max_chain_id_bytes", "u16"],
  ["max_validator_id_bytes", "u16"],
  ["max_block_bytes", "u32"],
  ["max_consensus_message_bytes", "u32"],
  ["min_validators", "u32"],
  ["max_validators", "u32"],
  ["quorum_numerator", "u32"],
  ["quorum_denominator", "u32"],
  ["quorum_addend", "u32"],
  ["finality_certified_chain_length", "u8"],
  ["max_total_voting_power", "u64"],
  ["max_block_time_step_ms", "u64"],
  ["leader_schedule", "leader"],
  ["require_full_payload_before_vote", "bool"],
  ["base_timeout_ms", "u64"],
  ["timeout_multiplier_numerator", "u32"],
  ["timeout_multiplier_denominator", "u32"],
  ["timeout_max_ms", "u64"],
  ["epoch_length_blocks", "u64"],
  ["epoch_seal_blocks", "u8"],
  ["snapshot_lead_blocks", "u64"],
  ["joint_handoff_old_quorum", "bool"],
  ["joint_handoff_new_quorum", "bool"],
  ["upgrade_notice_epochs", "u64"],
  ["max_protocol_version_jump", "u32"],
  ["scale_ppm", "u64"],
  ["maturity_epochs", "u64"],
  ["max_certificate_age_epochs", "u64"],
  ["decay_step_ppm_per_epoch", "u64"],
  ["per_certificate_unit_cap", "u128"],
  ["per_consumer_provider_epoch_unit_cap", "u128"],
  ["per_task_provider_epoch_unit_cap", "u128"],
  ["per_provider_epoch_unit_cap", "u128"],
  ["units_per_power", "u128"],
  ["bond_atomic_units_per_power", "u128"],
  ["min_validator_power", "u64"],
  ["max_validator_power", "u64"],
  ["max_validator_share_ppm", "u64"],
  ["capped_weight_alpha_ppm", "u64"],
  ["full_weight_alpha_ppm", "u64"],
  ["rollout_phase", "rollout"],
  ["minimum_shadow_epochs", "u64"],
  ["minimum_eligibility_only_epochs", "u64"],
  ["minimum_capped_weight_epochs", "u64"],
  ["automatic_promotion", "bool"],
  ["evidence_window_epochs", "u64"],
  ["unbonding_delay_epochs", "u64"],
  ["jail_duration_epochs", "u64"],
  ["trusting_period_epochs", "u64"],
  ["require_trusting_period_less_than_evidence", "bool"],
  ["require_evidence_window_le_unbonding_delay", "bool"],
];

function encodeParameterValue(type, value) {
  if (type === "bool") return u(value ? 1 : 0, 1);
  if (type === "leader" || type === "rollout") return u(value, 1);
  return u(value, Number(type.slice(1)) / 8);
}

function encodeParameters(fields) {
  return Buffer.concat(PARAMETER_LAYOUT.map(([name, type]) => encodeParameterValue(type, fields[name])));
}

function parseParameters(cursor) {
  const start = cursor.offset();
  const fields = {};
  const offsets = {};
  for (const [name, type] of PARAMETER_LAYOUT) {
    offsets[name] = cursor.offset();
    if (type === "u8") fields[name] = cursor.u8();
    else if (type === "u16") fields[name] = cursor.u16();
    else if (type === "u32") fields[name] = cursor.u32();
    else if (type === "u64") fields[name] = cursor.u64();
    else if (type === "u128") fields[name] = cursor.u128();
    else {
      const value = cursor.u8();
      if (type === "bool") {
        if (value > 1) fail("invalid_boolean", offsets[name], `${name} is not 0/1`);
        fields[name] = value === 1;
      } else if (type === "leader") {
        if (value !== 0) fail("invalid_leader_schedule", offsets[name], "unknown leader schedule");
        fields[name] = value;
      } else {
        if (value > 3) fail("invalid_rollout_phase", offsets[name], "unknown rollout phase");
        fields[name] = value;
      }
    }
  }
  const raw = cursor.raw.subarray(start, cursor.offset());
  validateParameters(fields, offsets);
  return { fields, offsets, raw, hash: digest(DOMAIN_PARAMETERS, raw) };
}

function decodeParametersExact(raw) {
  const cursor = new Cursor(raw);
  const result = parseParameters(cursor);
  cursor.finish();
  if (raw.length !== 341) fail("invalid_consensus_parameters", 0, "parameter preimage is not 341 bytes");
  return result;
}

function invalidParameters(offsets, field, message) {
  fail("invalid_consensus_parameters", offsets[field] ?? 0, message);
}

function validateParameters(p, o) {
  if (p.schema_version !== 0) fail("invalid_schema_version", o.schema_version, "parameters schema");
  if (p.protocol_version !== 0) fail("invalid_protocol_version", o.protocol_version, "parameters protocol");
  if (p.max_chain_id_bytes === 0 || p.max_chain_id_bytes > 128) invalidParameters(o, "max_chain_id_bytes", "chain ID bound");
  if (p.max_validator_id_bytes === 0 || p.max_validator_id_bytes > 128) invalidParameters(o, "max_validator_id_bytes", "validator ID bound");
  if (p.max_block_bytes === 0 || p.max_block_bytes > p.max_consensus_message_bytes) invalidParameters(o, "max_block_bytes", "message bounds");
  if (p.min_validators < 4) invalidParameters(o, "min_validators", "minimum validator bound");
  if (p.min_validators > p.max_validators || p.max_validators > 100) invalidParameters(o, "max_validators", "maximum validator bound");
  if (p.quorum_numerator !== 2 || p.quorum_denominator !== 3 || p.quorum_addend !== 1) invalidParameters(o, "quorum_numerator", "quorum formula");
  if (p.finality_certified_chain_length !== 3) invalidParameters(o, "finality_certified_chain_length", "finality length");
  if (!p.require_full_payload_before_vote) invalidParameters(o, "require_full_payload_before_vote", "full payload required");
  if (p.timeout_multiplier_denominator === 0 || p.timeout_multiplier_numerator <= p.timeout_multiplier_denominator) invalidParameters(o, "timeout_multiplier_numerator", "timeout multiplier");
  if (p.base_timeout_ms > p.timeout_max_ms) invalidParameters(o, "base_timeout_ms", "timeout maximum");
  if (p.epoch_seal_blocks !== 2) invalidParameters(o, "epoch_seal_blocks", "exactly two seals required");
  if (p.snapshot_lead_blocks === 0n) invalidParameters(o, "snapshot_lead_blocks", "snapshot lead positive");
  if (p.snapshot_lead_blocks < BigInt(p.finality_certified_chain_length)) {
    invalidParameters(
      o,
      "snapshot_lead_blocks",
      "snapshot lead must cover the finality-certified chain length",
    );
  }
  if (p.epoch_length_blocks <= p.snapshot_lead_blocks + 2n) invalidParameters(o, "epoch_length_blocks", "epoch geometry");
  if (!p.joint_handoff_old_quorum || !p.joint_handoff_new_quorum) invalidParameters(o, "joint_handoff_old_quorum", "both handoff roles required");
  if (p.upgrade_notice_epochs < 1n || p.max_protocol_version_jump !== 1) invalidParameters(o, "upgrade_notice_epochs", "upgrade bounds");
  if (p.scale_ppm === 0n) invalidParameters(o, "scale_ppm", "ppm scale");
  if (p.per_certificate_unit_cap === 0n ||
      p.per_certificate_unit_cap > p.per_consumer_provider_epoch_unit_cap ||
      p.per_consumer_provider_epoch_unit_cap > p.per_task_provider_epoch_unit_cap ||
      p.per_task_provider_epoch_unit_cap > p.per_provider_epoch_unit_cap) {
    invalidParameters(o, "per_certificate_unit_cap", "unit caps");
  }
  if (p.units_per_power === 0n || p.bond_atomic_units_per_power === 0n) invalidParameters(o, "units_per_power", "power divisors");
  if (p.min_validator_power === 0n || p.min_validator_power > p.max_validator_power) invalidParameters(o, "min_validator_power", "power bounds");
  if (p.max_validator_share_ppm === 0n || p.max_validator_share_ppm * 3n >= p.scale_ppm) invalidParameters(o, "max_validator_share_ppm", "share cap");
  if (p.capped_weight_alpha_ppm > p.scale_ppm || p.full_weight_alpha_ppm !== p.scale_ppm) invalidParameters(o, "capped_weight_alpha_ppm", "alpha bounds");
  if (BigInt(p.min_validators) * p.min_validator_power > p.max_total_voting_power) invalidParameters(o, "max_total_voting_power", "minimum candidate power");
  if (p.automatic_promotion) invalidParameters(o, "automatic_promotion", "automatic promotion forbidden");
  if (!(p.trusting_period_epochs < p.evidence_window_epochs && p.evidence_window_epochs <= p.unbonding_delay_epochs)) invalidParameters(o, "trusting_period_epochs", "weak-subjectivity bounds");
  if (!p.require_trusting_period_less_than_evidence || !p.require_evidence_window_le_unbonding_delay) invalidParameters(o, "require_trusting_period_less_than_evidence", "relationship flags");
}

function parseValidatorSet(cursor, parameters) {
  const start = cursor.offset();
  const schemaOffset = cursor.offset();
  const schema = cursor.u16();
  if (schema !== 0) fail("invalid_schema_version", schemaOffset, "validator set schema");
  const genesisOffset = cursor.offset();
  const genesis = cloneBuffer(cursor.fixed(32));
  if (genesis.equals(Buffer.alloc(32))) fail("zero_genesis_hash", genesisOffset, "zero validator-set genesis");
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  const protocolOffset = cursor.offset();
  const protocol = cursor.u32();
  if (protocol !== 0) fail("invalid_protocol_version", protocolOffset, "validator set protocol");
  const epoch = cursor.u64();
  const parametersHash = cloneBuffer(cursor.fixed(32));
  const count = cursor.count(parameters.fields.max_validators);
  const validators = [];
  let previous = null;
  const keySet = new Set();
  let totalPower = 0n;
  for (let index = 0; index < count; index += 1) {
    const idOffset = cursor.offset();
    const id = cloneBuffer(cursor.bytes(parameters.fields.max_validator_id_bytes));
    const publicKeyOffset = cursor.offset();
    const publicKey = cloneBuffer(cursor.fixed(32));
    const power = cursor.u64();
    if (publicKey.equals(Buffer.alloc(32))) {
      fail("zero_public_key", idOffset, "zero validator consensus key");
    }
    if (power === 0n || power < parameters.fields.min_validator_power || power > parameters.fields.max_validator_power) {
      fail("context_mismatch", idOffset, "validator power outside active bounds");
    }
    if (previous !== null && Buffer.compare(previous, id) >= 0) {
      fail(Buffer.compare(previous, id) === 0 ? "duplicate_validator_id" : "noncanonical_validator_order", idOffset, "validator order");
    }
    const keyHex = publicKey.toString("hex");
    if (keySet.has(keyHex)) fail("duplicate_public_key", idOffset, "duplicate validator key");
    keySet.add(keyHex);
    previous = id;
    totalPower += power;
    validators.push({ id, publicKey, power, idOffset, publicKeyOffset });
  }
  if (validators.length < parameters.fields.min_validators) fail("context_mismatch", start, "too few validators");
  if (totalPower === 0n || totalPower > parameters.fields.max_total_voting_power) fail("context_mismatch", start, "invalid total power");
  for (const validator of validators) {
    if (validator.power * parameters.fields.scale_ppm > totalPower * parameters.fields.max_validator_share_ppm) {
      fail("context_mismatch", start, "validator concentration exceeds active bound");
    }
  }
  if (!parametersHash.equals(parameters.hash)) fail("context_mismatch", start, "validator set parameter hash mismatch");
  const raw = cursor.raw.subarray(start, cursor.offset());
  const setHash = digest(DOMAIN_VALIDATOR_SET, raw);
  const byId = new Map(validators.map((validator) => [validator.id.toString("hex"), validator]));
  return {
    schema,
    genesis,
    chain,
    protocol,
    epoch,
    parametersHash,
    validators,
    totalPower,
    quorumPower: (2n * totalPower) / 3n + 1n,
    byId,
    raw,
    hash: setHash,
  };
}

function decodeValidatorSetExact(raw, parameters) {
  const cursor = new Cursor(raw);
  const result = parseValidatorSet(cursor, parameters);
  cursor.finish();
  return result;
}

function encodeValidatorSet(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis,
    consensusString(value.chain),
    u(0, 4),
    u(value.epoch, 8),
    value.parametersHash,
    list(value.validators, (validator) =>
      Buffer.concat([bytes(validator.id), validator.publicKey, u(validator.power, 8)]),
    ),
  ]);
}

function parseHeader(cursor, parameters) {
  const start = cursor.offset();
  const offsets = { object: start, schema: cursor.offset() };
  const schema = cursor.u16();
  if (schema !== 0) fail("invalid_schema_version", offsets.schema, "block header schema");
  const genesis = cloneBuffer(cursor.fixed(32));
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  offsets.protocol = cursor.offset();
  const protocol = cursor.u32();
  if (protocol !== 0) fail("invalid_protocol_version", offsets.protocol, "block header protocol");
  const epoch = cursor.u64();
  const view = cursor.u64();
  const height = cursor.u64();
  offsets.kind = cursor.offset();
  const kind = cursor.u8();
  if (kind > 4) fail("invalid_block_kind", offsets.kind, "unknown block kind");
  const parentId = cloneBuffer(cursor.fixed(32));
  offsets.proposer = cursor.offset();
  const proposerId = cloneBuffer(cursor.bytes(parameters.fields.max_validator_id_bytes));
  const setHash = cloneBuffer(cursor.fixed(32));
  const parametersHash = cloneBuffer(cursor.fixed(32));
  const payloadRoot = cloneBuffer(cursor.fixed(32));
  const stateRoot = cloneBuffer(cursor.fixed(32));
  const receiptsRoot = cloneBuffer(cursor.fixed(32));
  const evidenceRoot = cloneBuffer(cursor.fixed(32));
  offsets.timestamp = cursor.offset();
  const timestamp = cursor.u64();
  offsets.nextTag = cursor.offset();
  const nextTag = cursor.u8();
  if (nextTag > 1) fail("invalid_optional_tag", offsets.nextTag, "next commitment tag");
  const nextCommitment = nextTag === 1 ? cloneBuffer(cursor.fixed(32)) : null;
  if (view === 0n || height === 0n) fail("invalid_block_header", start, "zero view/height");
  if ((kind === 0 || kind === 4) !== (nextCommitment === null)) {
    fail("invalid_block_header", offsets.nextTag, "block-kind commitment presence mismatch");
  }
  const raw = cursor.raw.subarray(start, cursor.offset());
  return {
    schema,
    genesis,
    chain,
    protocol,
    epoch,
    view,
    height,
    kind,
    parentId,
    proposerId,
    setHash,
    parametersHash,
    payloadRoot,
    stateRoot,
    receiptsRoot,
    evidenceRoot,
    timestamp,
    nextCommitment,
    raw,
    id: digest(DOMAIN_BLOCK, raw),
    offsets,
  };
}

function encodeHeader(header) {
  return Buffer.concat([
    u(0, 2),
    header.genesis,
    consensusString(header.chain),
    u(0, 4),
    u(header.epoch, 8),
    u(header.view, 8),
    u(header.height, 8),
    u(header.kind, 1),
    header.parentId,
    bytes(header.proposerId),
    header.setHash,
    header.parametersHash,
    header.payloadRoot,
    header.stateRoot,
    header.receiptsRoot,
    header.evidenceRoot,
    u(header.timestamp, 8),
    optional(header.nextCommitment, (value) => value),
  ]);
}

function commonContext(scope, view, kind) {
  return Buffer.concat([
    u(0, 2),
    scope.genesis,
    consensusString(scope.chain),
    u(0, 4),
    u(scope.epoch, 8),
    scope.setHash,
    u(view, 8),
    u(kind, 1),
  ]);
}

function voteRoot(scope, view, height, blockId) {
  return digest(
    DOMAIN_VOTE,
    Buffer.concat([commonContext(scope, view, 1), u(height, 8), blockId]),
  );
}

function proposalRoot(header, justifyDigest, tcDigest = null) {
  return digest(
    DOMAIN_PROPOSAL,
    Buffer.concat([
      commonContext(
        { genesis: header.genesis, chain: header.chain, epoch: header.epoch, setHash: header.setHash },
        header.view,
        0,
      ),
      u(header.height, 8),
      header.id,
      justifyDigest,
      optional(tcDigest, (value) => value),
      Buffer.from([0]),
    ]),
  );
}

function parseQc(cursor, parameters) {
  const start = cursor.offset();
  const schemaOffset = cursor.offset();
  const schema = cursor.u16();
  if (schema !== 0) fail("invalid_schema_version", schemaOffset, "QC schema");
  const genesis = cloneBuffer(cursor.fixed(32));
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  const protocolOffset = cursor.offset();
  const protocol = cursor.u32();
  if (protocol !== 0) fail("invalid_protocol_version", protocolOffset, "QC protocol");
  const epoch = cursor.u64();
  const setHash = cloneBuffer(cursor.fixed(32));
  const viewOffset = cursor.offset();
  const view = cursor.u64();
  if (view === 0n) fail("unauthorized_synthetic_qc", viewOffset, "ordinary QC view zero");
  const height = cursor.u64();
  const blockId = cloneBuffer(cursor.fixed(32));
  const count = cursor.count(100);
  const signatures = [];
  let previous = null;
  for (let index = 0; index < count; index += 1) {
    const idOffset = cursor.offset();
    const validatorId = cloneBuffer(cursor.bytes(parameters.fields.max_validator_id_bytes));
    if (previous !== null && Buffer.compare(previous, validatorId) >= 0) {
      fail(Buffer.compare(previous, validatorId) === 0 ? "duplicate_signer" : "noncanonical_signer_order", idOffset, "QC signer order");
    }
    previous = validatorId;
    const signatureOffset = cursor.offset();
    signatures.push({
      validatorId,
      signature: cloneBuffer(cursor.fixed(64)),
      offset: idOffset,
      signatureOffset,
    });
  }
  if (signatures.length === 0) fail("unauthorized_synthetic_qc", start, "ordinary QC is empty");
  const raw = cursor.raw.subarray(start, cursor.offset());
  return {
    genesis,
    chain,
    protocol,
    epoch,
    setHash,
    view,
    height,
    blockId,
    signatures,
    raw,
    id: digest(DOMAIN_QC, raw),
    offset: start,
  };
}

function encodeQc(qc) {
  return Buffer.concat([
    u(0, 2),
    qc.genesis,
    consensusString(qc.chain),
    u(0, 4),
    u(qc.epoch, 8),
    qc.setHash,
    u(qc.view, 8),
    u(qc.height, 8),
    qc.blockId,
    list(qc.signatures, (share) => Buffer.concat([bytes(share.validatorId), share.signature])),
  ]);
}

function validateQc(qc, activeSet) {
  if (
    !qc.genesis.equals(activeSet.genesis) ||
    !qc.chain.equals(activeSet.chain) ||
    qc.protocol !== activeSet.protocol ||
    qc.epoch !== activeSet.epoch ||
    !qc.setHash.equals(activeSet.hash)
  ) {
    fail("context_mismatch", qc.offset, "QC scope differs from active set", "semantic");
  }
  const root = voteRoot(
    { genesis: qc.genesis, chain: qc.chain, epoch: qc.epoch, setHash: qc.setHash },
    qc.view,
    qc.height,
    qc.blockId,
  );
  let signedPower = 0n;
  for (const share of qc.signatures) {
    const validator = activeSet.byId.get(share.validatorId.toString("hex"));
    if (validator === undefined) fail("unknown_signer", share.offset, "unknown QC signer");
    if (!verify(validator.publicKey, root, share.signature)) {
      fail("invalid_signature", share.offset, "invalid QC signature", "crypto");
    }
    signedPower += validator.power;
  }
  if (signedPower < activeSet.quorumPower) {
    fail("insufficient_quorum", qc.offset, "QC signer power below quorum", "semantic");
  }
}

function parseHighQcSummary(cursor) {
  return {
    digest: cloneBuffer(cursor.fixed(32)),
    epoch: cursor.u64(),
    view: cursor.u64(),
    height: cursor.u64(),
    blockId: cloneBuffer(cursor.fixed(32)),
  };
}

function encodeHighQcSummary(summary) {
  return Buffer.concat([
    summary.digest,
    u(summary.epoch, 8),
    u(summary.view, 8),
    u(summary.height, 8),
    summary.blockId,
  ]);
}

function timeoutRoot(tc, summary) {
  return digest(
    DOMAIN_TIMEOUT,
    Buffer.concat([
      commonContext(
        { genesis: tc.genesis, chain: tc.chain, epoch: tc.epoch, setHash: tc.setHash },
        tc.timedOutView,
        2,
      ),
      encodeHighQcSummary(summary),
    ]),
  );
}

function parseTc(cursor, parameters) {
  const start = cursor.offset();
  const schemaOffset = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", schemaOffset, "TC schema");
  const genesis = cloneBuffer(cursor.fixed(32));
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  const protocolOffset = cursor.offset();
  const protocol = cursor.u32();
  if (protocol !== 0) fail("invalid_protocol_version", protocolOffset, "TC protocol");
  const epoch = cursor.u64();
  const setHash = cloneBuffer(cursor.fixed(32));
  const timedOutView = cursor.u64();
  const entryCount = cursor.count(100);
  const entries = [];
  let previous = null;
  for (let index = 0; index < entryCount; index += 1) {
    const offset = cursor.offset();
    const validatorId = cloneBuffer(cursor.bytes(parameters.fields.max_validator_id_bytes));
    if (previous !== null && Buffer.compare(previous, validatorId) >= 0) {
      fail(Buffer.compare(previous, validatorId) === 0 ? "duplicate_signer" : "noncanonical_signer_order", offset, "TC signer order");
    }
    previous = validatorId;
    entries.push({ validatorId, summary: parseHighQcSummary(cursor), signature: cloneBuffer(cursor.fixed(64)), offset });
  }
  const referenceCount = cursor.count(100);
  const references = [];
  for (let index = 0; index < referenceCount; index += 1) references.push(parseQc(cursor, parameters));
  const selectedDigest = cloneBuffer(cursor.fixed(32));
  const raw = cursor.raw.subarray(start, cursor.offset());
  return { genesis, chain, protocol, epoch, setHash, timedOutView, entries, references, selectedDigest, raw, id: digest(DOMAIN_TC, raw), offset: start };
}

function validateTc(tc, activeSet) {
  if (!tc.genesis.equals(activeSet.genesis) || !tc.chain.equals(activeSet.chain) || tc.epoch !== activeSet.epoch || !tc.setHash.equals(activeSet.hash)) {
    fail("context_mismatch", tc.offset, "TC scope", "semantic");
  }
  if (tc.entries.length === 0) fail("invalid_referenced_qc", tc.offset, "empty TC", "semantic");
  const byDigest = new Map();
  const byEpochView = new Map();
  const byBlock = new Map();
  let previousDigest = null;
  for (const reference of tc.references) {
    validateQc(reference, activeSet);
    if (reference.view > tc.timedOutView) {
      fail("future_reference_view", reference.offset, "QC reference is ahead of timed-out view", "semantic");
    }
    const key = reference.id.toString("hex");
    if (previousDigest !== null && previousDigest >= key) fail("invalid_referenced_qc", reference.offset, "reference order", "semantic");
    previousDigest = key;
    const epochView = `${reference.epoch}:${reference.view}`;
    const heightBlock = `${reference.height}:${reference.blockId.toString("hex")}`;
    const previousCoordinate = byEpochView.get(epochView);
    if (previousCoordinate !== undefined && previousCoordinate !== heightBlock) {
      fail("conflicting_same_view_qc", reference.offset, "same view binds different QC coordinates", "semantic");
    }
    byEpochView.set(epochView, heightBlock);
    const block = reference.blockId.toString("hex");
    const coordinate = `${reference.epoch}:${reference.view}:${reference.height}`;
    const previousBlockCoordinate = byBlock.get(block);
    if (previousBlockCoordinate !== undefined && previousBlockCoordinate !== coordinate) {
      fail("same_block_different_coordinates", reference.offset, "same block binds different QC coordinates", "semantic");
    }
    byBlock.set(block, coordinate);
    byDigest.set(key, reference);
  }
  let power = 0n;
  const named = new Set();
  for (const entry of tc.entries) {
    const validator = activeSet.byId.get(entry.validatorId.toString("hex"));
    if (validator === undefined) fail("unknown_signer", entry.offset, "unknown TC signer");
    const reference = byDigest.get(entry.summary.digest.toString("hex"));
    if (reference === undefined || reference.epoch !== entry.summary.epoch || reference.view !== entry.summary.view || reference.height !== entry.summary.height || !reference.blockId.equals(entry.summary.blockId)) {
      fail("invalid_referenced_qc", entry.offset, "TC summary mismatch", "semantic");
    }
    if (reference.view > tc.timedOutView) fail("future_reference_view", entry.offset, "future QC reference", "semantic");
    if (!verify(validator.publicKey, timeoutRoot(tc, entry.summary), entry.signature)) fail("invalid_signature", entry.offset, "invalid timeout signature", "crypto");
    named.add(entry.summary.digest.toString("hex"));
    power += validator.power;
  }
  if (power < activeSet.quorumPower) fail("insufficient_quorum", tc.offset, "TC quorum", "semantic");
  if (named.size !== byDigest.size || [...named].some((key) => !byDigest.has(key))) fail("invalid_referenced_qc", tc.offset, "TC reference set mismatch", "semantic");
  const selected = [...tc.references].sort((left, right) => {
    if (left.view !== right.view) return left.view < right.view ? -1 : 1;
    const block = Buffer.compare(left.blockId, right.blockId);
    return block !== 0 ? block : Buffer.compare(left.id, right.id);
  }).at(-1);
  if (selected === undefined || !selected.id.equals(tc.selectedDigest)) fail("invalid_referenced_qc", tc.offset, "TC selected digest", "semantic");
}

function parseCertifiedHeader(cursor, parameters) {
  const start = cursor.offset();
  const header = parseHeader(cursor, parameters);
  const justifyQc = parseQc(cursor, parameters);
  const tcTagOffset = cursor.offset();
  const tcTag = cursor.u8();
  if (tcTag > 1) fail("invalid_optional_tag", tcTagOffset, "TC tag");
  const timeoutCertificate = tcTag === 1 ? parseTc(cursor, parameters) : null;
  const anchorTagOffset = cursor.offset();
  const anchorTag = cursor.u8();
  if (anchorTag > 1) fail("invalid_optional_tag", anchorTagOffset, "anchor tag");
  if (anchorTag === 1) {
    fail("invalid_finality_proof", anchorTagOffset, "old checkpoint chain cannot carry an epoch anchor", "semantic");
  }
  const proposerSignatureOffset = cursor.offset();
  const proposerSignature = cloneBuffer(cursor.fixed(64));
  const certifyingQc = parseQc(cursor, parameters);
  const raw = cursor.raw.subarray(start, cursor.offset());
  return { header, justifyQc, timeoutCertificate, proposerSignature, proposerSignatureOffset, certifyingQc, raw, offset: start };
}

function encodeCertifiedHeader(value) {
  return Buffer.concat([
    value.header.raw ?? encodeHeader(value.header),
    value.justifyQc.raw ?? encodeQc(value.justifyQc),
    optional(value.timeoutCertificate, (tc) => tc.raw),
    Buffer.from([0]),
    value.proposerSignature,
    value.certifyingQc.raw ?? encodeQc(value.certifyingQc),
  ]);
}

function parseFinalityProof(cursor, parameters) {
  const start = cursor.offset();
  const schemaOffset = cursor.offset();
  const schema = cursor.u16();
  if (schema !== 0) fail("invalid_schema_version", schemaOffset, "finality proof schema");
  const genesis = cloneBuffer(cursor.fixed(32));
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  const protocolOffset = cursor.offset();
  const protocol = cursor.u32();
  if (protocol !== 0) fail("invalid_protocol_version", protocolOffset, "finality proof protocol");
  const epoch = cursor.u64();
  const setHash = cloneBuffer(cursor.fixed(32));
  const parametersHash = cloneBuffer(cursor.fixed(32));
  const finalizedBlock = parseCertifiedHeader(cursor, parameters);
  const child = parseCertifiedHeader(cursor, parameters);
  const grandchild = parseCertifiedHeader(cursor, parameters);
  const raw = cursor.raw.subarray(start, cursor.offset());
  return { genesis, chain, protocol, epoch, setHash, parametersHash, finalizedBlock, child, grandchild, raw, id: digest(DOMAIN_FINALITY, raw), offset: start };
}

function decodeFinalityProofExact(raw, parameters) {
  const cursor = new Cursor(raw);
  const result = parseFinalityProof(cursor, parameters);
  cursor.finish();
  return result;
}

function encodeFinalityProof(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis,
    consensusString(value.chain),
    u(0, 4),
    u(value.epoch, 8),
    value.setHash,
    value.parametersHash,
    value.finalizedBlock.raw ?? encodeCertifiedHeader(value.finalizedBlock),
    value.child.raw ?? encodeCertifiedHeader(value.child),
    value.grandchild.raw ?? encodeCertifiedHeader(value.grandchild),
  ]);
}

function parseNextEpochCommitment(cursor, parameters) {
  const start = cursor.offset();
  const schemaOffset = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", schemaOffset, "next-epoch commitment schema");
  const genesisOffset = cursor.offset();
  const genesis = cloneBuffer(cursor.fixed(32));
  if (genesis.equals(Buffer.alloc(32))) fail("zero_genesis_hash", genesisOffset, "zero commitment genesis");
  const chain = cloneBuffer(cursor.consensusString(parameters.fields.max_chain_id_bytes));
  const oldEpoch = cursor.u64();
  const newEpoch = cursor.u64();
  const snapshotCutoffHeight = cursor.u64();
  const snapshotStateRoot = cloneBuffer(cursor.fixed(32));
  const newProtocolVersion = cursor.u32();
  const newValidatorSetHash = cloneBuffer(cursor.fixed(32));
  const newParametersHash = cloneBuffer(cursor.fixed(32));
  const rolloutOffset = cursor.offset();
  const rolloutPhase = cursor.u8();
  if (rolloutPhase > 3) fail("invalid_rollout_phase", rolloutOffset, "next rollout");
  const upgradeTagOffset = cursor.offset();
  const upgradeTag = cursor.u8();
  if (upgradeTag > 1) fail("invalid_optional_tag", upgradeTagOffset, "upgrade tag");
  const upgradeHashOffset = cursor.offset();
  const upgradePlanHash = upgradeTag === 1 ? cloneBuffer(cursor.fixed(32)) : null;
  if (upgradePlanHash !== null && upgradePlanHash.equals(Buffer.alloc(32))) {
    fail("invalid_next_epoch_commitment", upgradeHashOffset, "present upgrade hash is zero", "semantic");
  }
  const fallbackOffset = cursor.offset();
  const fallbackRaw = cursor.u8();
  if (fallbackRaw > 1) fail("invalid_boolean", fallbackOffset, "fallback bool");
  const fallbackReason = cursor.u16();
  const activationHeight = cursor.u64();
  if (newEpoch !== oldEpoch + 1n || snapshotStateRoot.equals(Buffer.alloc(32)) || newValidatorSetHash.equals(Buffer.alloc(32)) || newParametersHash.equals(Buffer.alloc(32)) || (fallbackRaw === 1) === (fallbackReason === 0) || fallbackReason > 9 || activationHeight === 0n) {
    fail("invalid_next_epoch_commitment", start, "invalid commitment shape", "semantic");
  }
  const raw = cursor.raw.subarray(start, cursor.offset());
  return { genesis, chain, oldEpoch, newEpoch, snapshotCutoffHeight, snapshotStateRoot, newProtocolVersion, newValidatorSetHash, newParametersHash, rolloutPhase, upgradePlanHash, fallbackUsed: fallbackRaw === 1, fallbackReason, activationHeight, raw, id: digest(DOMAIN_EPOCH_COMMITMENT, raw), offset: start };
}

function decodeNextEpochCommitmentExact(raw, parameters) {
  const cursor = new Cursor(raw);
  const result = parseNextEpochCommitment(cursor, parameters);
  cursor.finish();
  return result;
}

function encodeNextEpochCommitment(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis,
    consensusString(value.chain),
    u(value.oldEpoch, 8),
    u(value.newEpoch, 8),
    u(value.snapshotCutoffHeight, 8),
    value.snapshotStateRoot,
    u(value.newProtocolVersion, 4),
    value.newValidatorSetHash,
    value.newParametersHash,
    u(value.rolloutPhase, 1),
    optional(value.upgradePlanHash, (hash) => hash),
    u(value.fallbackUsed ? 1 : 0, 1),
    u(value.fallbackReason, 2),
    u(value.activationHeight, 8),
  ]);
}

function sameScope(left, right) {
  const rightSetHash = right.setHash ?? right.hash;
  return (
    left.genesis.equals(right.genesis) &&
    left.chain.equals(right.chain) &&
    left.protocol === right.protocol &&
    left.epoch === right.epoch &&
    left.setHash.equals(rightSetHash)
  );
}

function validateCertifiedRelations(certified, activeSet, parameters) {
  const header = certified.header;
  if (!sameScope(header, activeSet) || !header.parametersHash.equals(parameters.hash)) {
    fail("invalid_finality_proof", certified.offset, "certified header scope", "semantic");
  }
  if (!sameScope(certified.justifyQc, activeSet) || !sameScope(certified.certifyingQc, activeSet)) {
    fail("invalid_finality_proof", certified.offset, "certificate scope", "semantic");
  }
  if (certified.justifyQc.height + 1n !== header.height || !certified.justifyQc.blockId.equals(header.parentId)) {
    fail("invalid_finality_proof", certified.offset, "justify QC is not the direct parent", "semantic");
  }
  if (certified.certifyingQc.view !== header.view || certified.certifyingQc.height !== header.height || !certified.certifyingQc.blockId.equals(header.id)) {
    fail("invalid_finality_proof", certified.offset, "certifying QC does not authenticate header", "semantic");
  }
  if (certified.timeoutCertificate === null) {
    if (header.view !== certified.justifyQc.view + 1n) fail("invalid_finality_proof", certified.offset, "skipped view without TC", "semantic");
  } else {
    if (header.view === certified.justifyQc.view + 1n || certified.timeoutCertificate.timedOutView + 1n !== header.view || !certified.timeoutCertificate.selectedDigest.equals(certified.justifyQc.id)) {
      fail("invalid_finality_proof", certified.offset, "invalid proposal TC relation", "semantic");
    }
  }
  const leaderIndex = Number((header.view - 1n) % BigInt(activeSet.validators.length));
  if (!header.proposerId.equals(activeSet.validators[leaderIndex].id)) {
    fail("invalid_leader_schedule", header.offsets.proposer, "proposer is not scheduled leader", "semantic");
  }
}

function validateCheckpointKernel({
  parameters,
  activeSet,
  commitment,
  proof,
  authenticatedCheckpointParentTimestamp,
}) {
  if (!activeSet.parametersHash.equals(parameters.hash)) fail("context_mismatch", 0, "active parameter preimage", "semantic");
  if (
    !proof.genesis.equals(activeSet.genesis) ||
    !proof.chain.equals(activeSet.chain) ||
    proof.protocol !== activeSet.protocol ||
    proof.epoch !== activeSet.epoch ||
    !proof.setHash.equals(activeSet.hash) ||
    !proof.parametersHash.equals(parameters.hash)
  ) {
    fail("invalid_finality_proof", proof.offset, "outer finality scope", "semantic");
  }
  const checkpoint = proof.finalizedBlock;
  const seal1 = proof.child;
  const seal2 = proof.grandchild;
  for (const certified of [checkpoint, seal1, seal2]) validateCertifiedRelations(certified, activeSet, parameters);

  const epochEnd = (proof.epoch + 1n) * parameters.fields.epoch_length_blocks;
  const checkpointHeight = epochEnd - 2n;
  if (checkpoint.header.kind !== 1 || seal1.header.kind !== 2 || seal2.header.kind !== 3) {
    fail("invalid_checkpoint_two_seal", 0, "checkpoint/seal block kinds", "semantic");
  }
  if (checkpoint.header.height !== checkpointHeight || seal1.header.height !== checkpointHeight + 1n || seal2.header.height !== checkpointHeight + 2n) {
    fail("invalid_checkpoint_two_seal", 0, "checkpoint/seal geometry", "semantic");
  }
  if (!seal1.header.parentId.equals(checkpoint.header.id) || !seal2.header.parentId.equals(seal1.header.id)) {
    fail("invalid_finality_proof", 0, "checkpoint/seal parent chain", "semantic");
  }
  if (!seal1.justifyQc.id.equals(checkpoint.certifyingQc.id) || !seal2.justifyQc.id.equals(seal1.certifyingQc.id)) {
    fail("invalid_finality_proof", 0, "exact certifying-QC subset digest linkage", "semantic");
  }
  if (!(checkpoint.certifyingQc.view < seal1.certifyingQc.view && seal1.certifyingQc.view < seal2.certifyingQc.view)) {
    fail("invalid_finality_proof", 0, "certifying QC views", "semantic");
  }
  const timestampSteps = [
    [authenticatedCheckpointParentTimestamp, checkpoint.header],
    [checkpoint.header.timestamp, seal1.header],
    [seal1.header.timestamp, seal2.header],
  ];
  for (const [parentTimestamp, header] of timestampSteps) {
    if (
      header.timestamp <= parentTimestamp ||
      header.timestamp - parentTimestamp > parameters.fields.max_block_time_step_ms
    ) {
      fail("invalid_finality_proof", header.offsets.timestamp, "invalid authenticated timestamp step", "semantic");
    }
  }
  for (const seal of [seal1.header, seal2.header]) {
    if (!seal.payloadRoot.equals(EMPTY_PAYLOAD_ROOT) || !seal.receiptsRoot.equals(EMPTY_RECEIPTS_ROOT) || !seal.evidenceRoot.equals(EMPTY_EVIDENCE_ROOT)) {
      fail("invalid_checkpoint_two_seal", 0, "seal roots are not frozen empty roots", "semantic");
    }
    if (!seal.stateRoot.equals(checkpoint.header.stateRoot)) fail("invalid_checkpoint_two_seal", 0, "seal changes checkpoint state", "semantic");
  }
  if (checkpoint.header.nextCommitment === null || seal1.header.nextCommitment === null || seal2.header.nextCommitment === null || !checkpoint.header.nextCommitment.equals(commitment.id) || !seal1.header.nextCommitment.equals(commitment.id) || !seal2.header.nextCommitment.equals(commitment.id)) {
    fail("invalid_checkpoint_two_seal", 0, "next-epoch commitment binding", "semantic");
  }
  if (!commitment.genesis.equals(activeSet.genesis) || !commitment.chain.equals(activeSet.chain) || commitment.oldEpoch !== activeSet.epoch) {
    fail("invalid_checkpoint_two_seal", 0, "commitment old context", "semantic");
  }
  const expectedCutoff = checkpointHeight - parameters.fields.snapshot_lead_blocks;
  if (commitment.snapshotCutoffHeight !== expectedCutoff || commitment.activationHeight !== epochEnd + 1n) {
    fail("invalid_checkpoint_two_seal", 0, "commitment geometry", "semantic");
  }

  for (const certified of [checkpoint, seal1, seal2]) {
    validateQc(certified.justifyQc, activeSet);
    if (certified.timeoutCertificate !== null) validateTc(certified.timeoutCertificate, activeSet);
    const proposer = activeSet.byId.get(certified.header.proposerId.toString("hex"));
    const root = proposalRoot(certified.header, certified.justifyQc.id, certified.timeoutCertificate?.id ?? null);
    if (proposer === undefined || !verify(proposer.publicKey, root, certified.proposerSignature)) {
      fail("invalid_signature", certified.proposerSignatureOffset, "invalid proposer signature", "crypto");
    }
    validateQc(certified.certifyingQc, activeSet);
  }
  return Object.freeze({
    checkpointBlockId: cloneBuffer(checkpoint.header.id),
    checkpointStateRoot: cloneBuffer(checkpoint.header.stateRoot),
    terminalBlockId: cloneBuffer(seal2.header.id),
    terminalQcDigest: cloneBuffer(seal2.certifyingQc.id),
    nextEpochCommitmentDigest: cloneBuffer(commitment.id),
  });
}

function decodeAndValidateKernel(
  raw,
  parametersRaw,
  setRaw,
  commitmentRaw,
  authenticatedCheckpointParentTimestamp,
) {
  const parameters = decodeParametersExact(parametersRaw);
  const activeSet = decodeValidatorSetExact(setRaw, parameters);
  const commitment = decodeNextEpochCommitmentExact(commitmentRaw, parameters);
  const proof = decodeFinalityProofExact(raw, parameters);
  return validateCheckpointKernel({
    parameters,
    activeSet,
    commitment,
    proof,
    authenticatedCheckpointParentTimestamp,
  });
}

function makeValidator(id) {
  const privateKey = privateKeyFromSeed(fixtureSeed(id));
  return {
    id: Buffer.from(id, "ascii"),
    privateKey,
    publicKey: publicKeyRaw(privateKey),
    power: 1n,
  };
}

function makeQc(scope, validators, view, height, blockId, signerIds) {
  const root = voteRoot(scope, view, height, blockId);
  const signatures = signerIds.map((id) => {
    const validator = validators.find((candidate) => candidate.id.equals(Buffer.from(id, "ascii")));
    if (validator === undefined) fail("source_vector_drift", 0, `unknown fixture signer ${id}`, "gate");
    return { validatorId: validator.id, signature: sign(validator.privateKey, root) };
  });
  const value = { ...scope, view, height, blockId, signatures };
  value.raw = encodeQc(value);
  value.id = digest(DOMAIN_QC, value.raw);
  return value;
}

function makeHeader(fields) {
  const value = { ...fields };
  value.raw = encodeHeader(value);
  value.id = digest(DOMAIN_BLOCK, value.raw);
  return value;
}

function makeCertified(header, justifyQc, certifyingQc, validators, proposerOverride = null) {
  const proposerId = proposerOverride ?? header.proposerId;
  const proposer = validators.find((validator) => validator.id.equals(proposerId));
  if (proposer === undefined) fail("source_vector_drift", 0, "fixture proposer absent", "gate");
  const actualHeader = proposerId.equals(header.proposerId) ? header : makeHeader({ ...header, proposerId });
  const proposerSignature = sign(proposer.privateKey, proposalRoot(actualHeader, justifyQc.id));
  const value = { header: actualHeader, justifyQc, timeoutCertificate: null, proposerSignature, certifyingQc };
  value.raw = encodeCertifiedHeader(value);
  return value;
}

function baseParameterFields() {
  const reference = readJson(PARAMETERS_VECTOR_PATH);
  const decoded = decodeParametersExact(Buffer.from(reference.cev0_hex, "hex"));
  return { ...decoded.fields, epoch_length_blocks: 10n, snapshot_lead_blocks: 3n };
}

function buildFixture(options = {}) {
  const parameterFields = baseParameterFields();
  if (options.parameterMutation !== undefined) options.parameterMutation(parameterFields);
  const parameterRaw = encodeParameters(parameterFields);
  const parameters = decodeParametersExact(parameterRaw);
  const genesis = labelHash("genesis");
  const chain = Buffer.from("trnm-b2e-checkpoint-0", "ascii");
  const validators = ["validator-a", "validator-b", "validator-c", "validator-d"].map(makeValidator);
  const setValue = { genesis, chain, epoch: 0n, parametersHash: parameters.hash, validators };
  const setRaw = encodeValidatorSet(setValue);
  const activeSet = decodeValidatorSetExact(setRaw, parameters);
  const scope = { genesis, chain, protocol: 0, epoch: 0n, setHash: activeSet.hash };
  const commitmentValue = {
    genesis,
    chain,
    oldEpoch: 0n,
    newEpoch: 1n,
    snapshotCutoffHeight: options.wrongCutoff ? 6n : 5n,
    snapshotStateRoot: labelHash("snapshot-state-root"),
    newProtocolVersion: options.newProtocolVersion ?? 0,
    newValidatorSetHash: labelHash("new-validator-set"),
    newParametersHash: labelHash("new-consensus-parameters"),
    rolloutPhase: 0,
    upgradePlanHash: null,
    fallbackUsed: false,
    fallbackReason: 0,
    activationHeight: options.wrongActivation ? 12n : 11n,
  };
  const commitmentRaw = encodeNextEpochCommitment(commitmentValue);
  const commitment = decodeNextEpochCommitmentExact(commitmentRaw, parameters);
  const committedDigest = options.checkpointWrongCommitment ? labelHash("wrong-checkpoint-commitment") : commitment.id;
  const seal1Commitment = options.seal1WrongCommitment ? labelHash("wrong-seal1-commitment") : commitment.id;
  const seal2Commitment = options.seal2WrongCommitment ? labelHash("wrong-seal2-commitment") : commitment.id;
  const checkpointState = labelHash("checkpoint-state");
  const authenticatedCheckpointParentTimestamp = 500n;
  const checkpointTimestamp = options.parentToCheckpointHugeJump
    ? authenticatedCheckpointParentTimestamp + parameters.fields.max_block_time_step_ms + 1n
    : 1_000n;
  const seal1Timestamp = options.checkpointToSeal1HugeJump
    ? checkpointTimestamp + parameters.fields.max_block_time_step_ms + 1n
    : 2_000n;
  const seal2Timestamp = options.seal1ToSeal2HugeJump
    ? seal1Timestamp + parameters.fields.max_block_time_step_ms + 1n
    : (options.nonIncreasingTimestamp ? seal1Timestamp : 3_000n);
  const checkpointHeight = options.wrongCheckpointHeight ? 7n : 8n;
  const parentBlockId = labelHash("height-7-parent");
  const parentQc = makeQc(scope, validators, 2n, 7n, parentBlockId, ["validator-a", "validator-b", "validator-c"]);
  let checkpointHeader = makeHeader({
    ...scope,
    view: 3n,
    height: checkpointHeight,
    kind: options.wrongCheckpointKind ? 0 : 1,
    parentId: parentBlockId,
    proposerId: Buffer.from("validator-c", "ascii"),
    parametersHash: options.headerWrongParameters ? labelHash("wrong-old-parameters") : parameters.hash,
    payloadRoot: labelHash("checkpoint-payload-root"),
    stateRoot: checkpointState,
    receiptsRoot: labelHash("checkpoint-receipts-root"),
    evidenceRoot: labelHash("checkpoint-evidence-root"),
    timestamp: checkpointTimestamp,
    nextCommitment: committedDigest,
  });
  if (options.wrongCheckpointLeader) {
    checkpointHeader = makeHeader({ ...checkpointHeader, proposerId: Buffer.from("validator-b", "ascii") });
  }
  const q0Canonical = makeQc(scope, validators, 3n, checkpointHeader.height, checkpointHeader.id, ["validator-a", "validator-b", "validator-c"]);
  const q0Alternate = makeQc(scope, validators, 3n, checkpointHeader.height, checkpointHeader.id, ["validator-a", "validator-b", "validator-d"]);
  const q0 = options.alternateQ0Certifying ? q0Alternate : q0Canonical;
  const checkpointProposer = options.wrongCheckpointLeader ? Buffer.from("validator-b", "ascii") : null;
  const checkpointCertified = makeCertified(checkpointHeader, parentQc, q0, validators, checkpointProposer);

  const childJustify = options.alternateChildJustify
    ? q0Alternate
    : (options.alternateQ0Certifying ? q0Canonical : q0);
  let seal1Header = makeHeader({
    ...scope,
    view: 4n,
    height: options.wrongSeal1Height ? 10n : 9n,
    kind: options.wrongSeal1Kind ? 3 : 2,
    parentId: options.breakSeal1Parent ? labelHash("wrong-seal1-parent") : checkpointHeader.id,
    proposerId: Buffer.from("validator-d", "ascii"),
    parametersHash: parameters.hash,
    payloadRoot: options.nonemptySeal1Payload ? labelHash("nonempty-seal1-payload") : EMPTY_PAYLOAD_ROOT,
    stateRoot: options.seal1StateDrift ? labelHash("seal1-state-drift") : checkpointState,
    receiptsRoot: options.nonemptySeal1Receipts ? labelHash("nonempty-seal1-receipts") : EMPTY_RECEIPTS_ROOT,
    evidenceRoot: options.nonemptySeal1Evidence ? labelHash("nonempty-seal1-evidence") : EMPTY_EVIDENCE_ROOT,
    timestamp: seal1Timestamp,
    nextCommitment: seal1Commitment,
  });
  const q1 = makeQc(scope, validators, 4n, seal1Header.height, seal1Header.id, ["validator-b", "validator-c", "validator-d"]);
  const seal1Certified = makeCertified(seal1Header, childJustify, q1, validators);

  let seal2Header = makeHeader({
    ...scope,
    view: 5n,
    height: options.wrongSeal2Height ? 11n : 10n,
    kind: options.wrongSeal2Kind ? 2 : 3,
    parentId: options.breakSeal2Parent ? labelHash("wrong-seal2-parent") : seal1Header.id,
    proposerId: Buffer.from("validator-a", "ascii"),
    parametersHash: parameters.hash,
    payloadRoot: options.nonemptySeal2Payload ? labelHash("nonempty-seal2-payload") : EMPTY_PAYLOAD_ROOT,
    stateRoot: options.seal2StateDrift ? labelHash("seal2-state-drift") : checkpointState,
    receiptsRoot: options.nonemptySeal2Receipts ? labelHash("nonempty-seal2-receipts") : EMPTY_RECEIPTS_ROOT,
    evidenceRoot: options.nonemptySeal2Evidence ? labelHash("nonempty-seal2-evidence") : EMPTY_EVIDENCE_ROOT,
    timestamp: seal2Timestamp,
    nextCommitment: seal2Commitment,
  });
  let q2 = makeQc(scope, validators, 5n, seal2Header.height, seal2Header.id, ["validator-a", "validator-c", "validator-d"]);
  const seal2Certified = makeCertified(seal2Header, q1, q2, validators);

  if (options.invalidProposerSignature) {
    checkpointCertified.proposerSignature = Buffer.alloc(64, 0x42);
    checkpointCertified.raw = encodeCertifiedHeader(checkpointCertified);
  }
  if (options.invalidQcSignature) {
    checkpointCertified.justifyQc.signatures[0].signature = Buffer.alloc(64, 0x24);
    checkpointCertified.justifyQc.raw = encodeQc(checkpointCertified.justifyQc);
    checkpointCertified.justifyQc.id = digest(DOMAIN_QC, checkpointCertified.justifyQc.raw);
    checkpointCertified.raw = encodeCertifiedHeader(checkpointCertified);
  }
  const proofValue = {
    genesis: options.outerWrongGenesis ? labelHash("wrong-outer-genesis") : genesis,
    chain,
    protocol: 0,
    epoch: 0n,
    setHash: options.outerWrongSet ? labelHash("wrong-outer-set") : activeSet.hash,
    parametersHash: parameters.hash,
    finalizedBlock: checkpointCertified,
    child: seal1Certified,
    grandchild: seal2Certified,
  };
  const proofRaw = encodeFinalityProof(proofValue);
  return {
    parameterRaw,
    parameters,
    setRaw,
    activeSet,
    commitmentRaw,
    commitment,
    validators,
    parentQc,
    checkpointCertified,
    seal1Certified,
    seal2Certified,
    proofRaw,
    authenticatedCheckpointParentTimestamp,
  };
}

const SEMANTIC_CASES = [
  ["checkpoint_wrong_kind", { wrongCheckpointKind: true }, "invalid_block_header"],
  ["seal1_wrong_kind", { wrongSeal1Kind: true }, "invalid_checkpoint_two_seal"],
  ["seal2_wrong_kind", { wrongSeal2Kind: true }, "invalid_checkpoint_two_seal"],
  ["checkpoint_wrong_geometry", { wrongCheckpointHeight: true }, "invalid_finality_proof"],
  ["seal1_wrong_geometry", { wrongSeal1Height: true }, "invalid_finality_proof"],
  ["seal2_wrong_geometry", { wrongSeal2Height: true }, "invalid_finality_proof"],
  ["seal1_wrong_parent", { breakSeal1Parent: true }, "invalid_finality_proof"],
  ["seal2_wrong_parent", { breakSeal2Parent: true }, "invalid_finality_proof"],
  ["outer_scope_wrong_genesis", { outerWrongGenesis: true }, "invalid_finality_proof"],
  ["outer_scope_wrong_set", { outerWrongSet: true }, "invalid_finality_proof"],
  ["header_parameter_scope_mismatch", { headerWrongParameters: true }, "invalid_finality_proof"],
  ["seal1_state_drift", { seal1StateDrift: true }, "invalid_checkpoint_two_seal"],
  ["seal2_state_drift", { seal2StateDrift: true }, "invalid_checkpoint_two_seal"],
  ["seal1_nonempty_payload_root", { nonemptySeal1Payload: true }, "invalid_checkpoint_two_seal"],
  ["seal1_nonempty_receipts_root", { nonemptySeal1Receipts: true }, "invalid_checkpoint_two_seal"],
  ["seal1_nonempty_evidence_root", { nonemptySeal1Evidence: true }, "invalid_checkpoint_two_seal"],
  ["seal2_nonempty_payload_root", { nonemptySeal2Payload: true }, "invalid_checkpoint_two_seal"],
  ["seal2_nonempty_receipts_root", { nonemptySeal2Receipts: true }, "invalid_checkpoint_two_seal"],
  ["seal2_nonempty_evidence_root", { nonemptySeal2Evidence: true }, "invalid_checkpoint_two_seal"],
  ["checkpoint_commitment_mismatch", { checkpointWrongCommitment: true }, "invalid_checkpoint_two_seal"],
  ["seal1_commitment_mismatch", { seal1WrongCommitment: true }, "invalid_checkpoint_two_seal"],
  ["seal2_commitment_mismatch", { seal2WrongCommitment: true }, "invalid_checkpoint_two_seal"],
  ["snapshot_cutoff_geometry_mismatch", { wrongCutoff: true }, "invalid_checkpoint_two_seal"],
  ["activation_geometry_mismatch", { wrongActivation: true }, "invalid_checkpoint_two_seal"],
  ["wrong_scheduled_leader_with_valid_signature", { wrongCheckpointLeader: true }, "invalid_leader_schedule"],
  ["alternate_valid_qc_subset_in_child_justify", { alternateChildJustify: true }, "invalid_finality_proof"],
  ["alternate_valid_qc_subset_as_checkpoint_certifier", { alternateQ0Certifying: true }, "invalid_finality_proof"],
  ["nonincreasing_seal_timestamp", { nonIncreasingTimestamp: true }, "invalid_finality_proof"],
  ["parent_to_checkpoint_timestamp_step_exceeded", { parentToCheckpointHugeJump: true }, "invalid_finality_proof"],
  ["checkpoint_to_seal1_timestamp_step_exceeded", { checkpointToSeal1HugeJump: true }, "invalid_finality_proof"],
  ["seal1_to_seal2_timestamp_step_exceeded", { seal1ToSeal2HugeJump: true }, "invalid_finality_proof"],
  ["invalid_proposer_signature", { invalidProposerSignature: true }, "invalid_signature"],
  ["invalid_qc_signature", { invalidQcSignature: true }, "invalid_signature"],
];

function expectError(action, expectedCode, label, expectedOffset = undefined) {
  try {
    action();
  } catch (error) {
    if (!(error instanceof KernelError)) throw error;
    if (error.code !== expectedCode) {
      fail("source_vector_drift", 0, `${label}: expected ${expectedCode}, got ${error.code}`, "gate");
    }
    if (expectedOffset !== undefined && error.offset !== expectedOffset) {
      fail("source_vector_drift", 0, `${label}: expected offset ${expectedOffset}, got ${error.offset}`, "gate");
    }
    return error;
  }
  fail("source_vector_drift", 0, `${label}: mutation was accepted`, "gate");
}

function mutateParameterRaw(raw, field, encoded) {
  const decoded = decodeParametersExact(raw);
  const offset = decoded.offsets[field];
  const result = cloneBuffer(raw);
  encoded.copy(result, offset);
  return { raw: result, offset };
}

function buildParserBoundaries(valid) {
  const cases = [];
  const context = { parameters: valid.parameters, activeSet: valid.activeSet };
  const addRaw = (id, parser, raw, expected) => {
    const error = expectError(
      () => decodeById(parser, raw, context),
      expected,
      id,
    );
    cases.push({
      id,
      parser,
      raw_hex: raw.toString("hex"),
      expected_code: expected,
      expected_offset: error.offset,
    });
  };
  const add = (id, field, encoded, expected) => {
    const mutation = mutateParameterRaw(valid.parameterRaw, field, encoded);
    addRaw(id, "consensus_parameters", mutation.raw, expected);
  };
  add("parameters_schema_v1", "schema_version", u(1, 2), "invalid_schema_version");
  add("parameters_protocol_v1", "protocol_version", u(1, 4), "invalid_protocol_version");
  add("parameters_boolean_2", "production_activation", u(2, 1), "invalid_boolean");
  add("parameters_unknown_leader", "leader_schedule", u(1, 1), "invalid_leader_schedule");
  add("parameters_unknown_rollout", "rollout_phase", u(4, 1), "invalid_rollout_phase");
  add("parameters_min_validators_3", "min_validators", u(3, 4), "invalid_consensus_parameters");
  add("parameters_snapshot_lead_zero", "snapshot_lead_blocks", u(0, 8), "invalid_consensus_parameters");
  add(
    "parameters_snapshot_lead_two_below_finality",
    "snapshot_lead_blocks",
    u(2, 8),
    "invalid_consensus_parameters",
  );
  add("parameters_seal_count_one", "epoch_seal_blocks", u(1, 1), "invalid_consensus_parameters");
  add("parameters_finality_length_two", "finality_certified_chain_length", u(2, 1), "invalid_consensus_parameters");
  add("parameters_max_validators_101", "max_validators", u(101, 4), "invalid_consensus_parameters");

  const invalidChainSet = cloneBuffer(valid.setRaw);
  invalidChainSet[36] = 0x54;
  addRaw("validator_set_invalid_chain_grammar", "old_validator_set", invalidChainSet, "invalid_consensus_string");

  const zeroGenesisSet = cloneBuffer(valid.setRaw);
  zeroGenesisSet.fill(0, 2, 34);
  addRaw("validator_set_zero_genesis", "old_validator_set", zeroGenesisSet, "zero_genesis_hash");

  const zeroPublicKeySet = cloneBuffer(valid.setRaw);
  const firstValidator = valid.activeSet.validators[0];
  zeroPublicKeySet.fill(0, firstValidator.publicKeyOffset, firstValidator.publicKeyOffset + 32);
  addRaw("validator_set_zero_public_key", "old_validator_set", zeroPublicKeySet, "zero_public_key");

  const zeroGenesisCommitment = cloneBuffer(valid.commitmentRaw);
  zeroGenesisCommitment.fill(0, 2, 34);
  addRaw("next_epoch_commitment_zero_genesis", "next_epoch_commitment", zeroGenesisCommitment, "zero_genesis_hash");

  const presentZeroUpgrade = encodeNextEpochCommitment({
    ...valid.commitment,
    upgradePlanHash: Buffer.alloc(32),
  });
  addRaw("next_epoch_commitment_present_zero_upgrade", "next_epoch_commitment", presentZeroUpgrade, "invalid_next_epoch_commitment");

  const zeroViewQc = cloneBuffer(valid.parentQc.raw);
  const qcCursor = new Cursor(zeroViewQc);
  qcCursor.u16();
  qcCursor.fixed(32);
  qcCursor.consensusString(valid.parameters.fields.max_chain_id_bytes);
  qcCursor.u32();
  qcCursor.u64();
  qcCursor.fixed(32);
  const qcViewOffset = qcCursor.offset();
  u(0, 8).copy(zeroViewQc, qcViewOffset);
  addRaw("ordinary_qc_view_zero", "parent_qc", zeroViewQc, "unauthorized_synthetic_qc");
  return cases;
}

function objectRecord(raw, domain = null) {
  const record = { cev0_hex: raw.toString("hex"), cev0_length: raw.length };
  if (domain !== null) {
    record.domain_ascii = domain;
    record.digest_hex = digest(domain, raw).toString("hex");
  }
  return record;
}

function buildCorpus() {
  const valid = buildFixture();
  const protocolV1 = buildFixture({ newProtocolVersion: 1 });
  decodeAndValidateKernel(
    protocolV1.proofRaw,
    protocolV1.parameterRaw,
    protocolV1.setRaw,
    protocolV1.commitmentRaw,
    protocolV1.authenticatedCheckpointParentTimestamp,
  );
  const parsedProof = decodeFinalityProofExact(valid.proofRaw, valid.parameters);
  const signatureMutationOffsets = new Map([
    ["invalid_proposer_signature", parsedProof.finalizedBlock.proposerSignatureOffset],
    ["invalid_qc_signature", parsedProof.finalizedBlock.justifyQc.signatures[0].signatureOffset],
  ]);
  const semanticNegatives = SEMANTIC_CASES.map(([id, mutation, expectedCode]) => {
    const mutated = buildFixture(mutation);
    const error = expectError(
      () => decodeAndValidateKernel(
        mutated.proofRaw,
        mutated.parameterRaw,
        mutated.setRaw,
        mutated.commitmentRaw,
        mutated.authenticatedCheckpointParentTimestamp,
      ),
      expectedCode,
      id,
    );
    const record = {
      id,
      mutation: id,
      expected_code: expectedCode,
      expected_offset: error.offset,
    };
    const rawMutationOffset = signatureMutationOffsets.get(id);
    if (rawMutationOffset !== undefined) record.raw_mutation_offset = rawMutationOffset;
    return record;
  });
  const parserBoundaries = buildParserBoundaries(valid);
  const validObjects = {
    consensus_parameters: objectRecord(valid.parameterRaw, DOMAIN_PARAMETERS),
    old_validator_set: objectRecord(valid.setRaw, DOMAIN_VALIDATOR_SET),
    next_epoch_commitment: objectRecord(valid.commitmentRaw, DOMAIN_EPOCH_COMMITMENT),
    parent_qc: objectRecord(valid.parentQc.raw, DOMAIN_QC),
    checkpoint_certified_header: objectRecord(valid.checkpointCertified.raw),
    seal_1_certified_header: objectRecord(valid.seal1Certified.raw),
    seal_2_certified_header: objectRecord(valid.seal2Certified.raw),
    checkpoint_finality_proof: objectRecord(valid.proofRaw, DOMAIN_FINALITY),
  };
  const prefixObjects = Object.entries(validObjects).map(([id, record]) => ({ id, cev0_length: record.cev0_length }));
  return {
    schema: "trnm_poco_bft_checkpoint_two_seal_kernel_vectors_v0",
    schema_version: 0,
    scope: "B2-E exact ConsensusParametersV0 plus one inert old-set checkpoint/two-seal next-view finality kernel",
    cryptographic_validity_claimed: true,
    cryptographic_claim_scope: "deterministic Node.js Ed25519 fixture only",
    verifier_identity_attested: false,
    authorization_output: false,
    fixture: {
      chain_id_ascii: valid.activeSet.chain.toString("ascii"),
      genesis_hash_hex: valid.activeSet.genesis.toString("hex"),
      old_epoch: "0",
      epoch_length_blocks: "10",
      snapshot_lead_blocks: "3",
      checkpoint_height: "8",
      seal_1_height: "9",
      seal_2_height: "10",
      snapshot_cutoff_height: "5",
      activation_height: "11",
      authenticated_checkpoint_parent_timestamp_ms: valid.authenticatedCheckpointParentTimestamp.toString(),
      max_block_time_step_ms: valid.parameters.fields.max_block_time_step_ms.toString(),
      validator_total_power: valid.activeSet.totalPower.toString(),
      quorum_power: valid.activeSet.quorumPower.toString(),
      validators: valid.validators.map((validator) => ({
        validator_id_ascii: validator.id.toString("ascii"),
        public_key_hex: validator.publicKey.toString("hex"),
        voting_power: validator.power.toString(),
      })),
      frozen_empty_roots: {
        payload_root_hex: EMPTY_PAYLOAD_ROOT.toString("hex"),
        receipts_root_hex: EMPTY_RECEIPTS_ROOT.toString("hex"),
        evidence_root_hex: EMPTY_EVIDENCE_ROOT.toString("hex"),
      },
      checkpoint_block_id_hex: parsedProof.finalizedBlock.header.id.toString("hex"),
      seal_1_block_id_hex: parsedProof.child.header.id.toString("hex"),
      seal_2_block_id_hex: parsedProof.grandchild.header.id.toString("hex"),
      checkpoint_certifying_qc_digest_hex: parsedProof.finalizedBlock.certifyingQc.id.toString("hex"),
      terminal_qc_digest_hex: parsedProof.grandchild.certifyingQc.id.toString("hex"),
    },
    valid_objects: validObjects,
    valid_commitment_variants: {
      protocol_version_1_inert_commitment: {
        ...objectRecord(protocolV1.commitmentRaw, DOMAIN_EPOCH_COMMITMENT),
        expected_new_protocol_version: "1",
        checkpoint_kernel_result: "inert_accepted",
        transition_authorization: false,
      },
    },
    parser_campaigns: {
      all_noncomplete_prefixes: {
        expected_code: "unexpected_eof",
        objects: prefixObjects,
        case_count: prefixObjects.reduce((sum, item) => sum + item.cev0_length, 0),
      },
      trailing_byte: {
        expected_code: "trailing_bytes",
        objects: prefixObjects.map((item) => item.id),
        case_count: prefixObjects.length,
      },
    },
    parser_boundaries: parserBoundaries,
    semantic_negatives: semanticNegatives,
    real_ed25519_checks: {
      proposer_signatures: 3,
      qc_objects: 4,
      signatures_per_qc: 3,
      total_signature_verifications: 21,
      invalid_signature_cases: 2,
    },
    forbidden_entry_points: [
      "epoch_anchor_qc",
      "into_authorization",
      "handoff_signing_capability",
      "authorized_next_context",
      "authorize_epoch_transition",
    ],
    honest_boundary: [
      "The finalized commitment authenticates snapshot_state_root only as a committed claim, not as a proven cutoff-header state root.",
      "No cutoff ancestry, JMT/ICS23 state proof, snapshot candidate construction, new configuration authority, runtime identity/execution, receipt provenance, handoff signature capability, EpochAnchorQC, or epoch activation is produced.",
      "The valid corpus uses only next-view proposals and makes no B2-E TC semantic-coverage claim; B2-A remains the authoritative TC corpus.",
      "The inert capability records caller-verifier acceptance but does not attest verifier identity; the cryptographic claim in this corpus is limited to the deterministic Node.js Ed25519 fixture.",
      "B2 overall and wire_conformance remain open."
    ]
  };
}

function decodeById(id, raw, context) {
  if (id === "consensus_parameters") return decodeParametersExact(raw);
  if (id === "old_validator_set") return decodeValidatorSetExact(raw, context.parameters);
  if (id === "next_epoch_commitment") return decodeNextEpochCommitmentExact(raw, context.parameters);
  if (id === "parent_qc") {
    const cursor = new Cursor(raw);
    const qc = parseQc(cursor, context.parameters);
    cursor.finish();
    validateQc(qc, context.activeSet);
    return qc;
  }
  if (id.endsWith("certified_header")) {
    const cursor = new Cursor(raw);
    const certified = parseCertifiedHeader(cursor, context.parameters);
    cursor.finish();
    return certified;
  }
  if (id === "checkpoint_finality_proof") return decodeFinalityProofExact(raw, context.parameters);
  fail("source_vector_drift", 0, `unknown corpus object ${id}`, "gate");
}

function validateCorpus(corpus) {
  const parametersRaw = Buffer.from(corpus.valid_objects.consensus_parameters.cev0_hex, "hex");
  const parameters = decodeParametersExact(parametersRaw);
  const setRaw = Buffer.from(corpus.valid_objects.old_validator_set.cev0_hex, "hex");
  const activeSet = decodeValidatorSetExact(setRaw, parameters);
  const commitmentRaw = Buffer.from(corpus.valid_objects.next_epoch_commitment.cev0_hex, "hex");
  const commitment = decodeNextEpochCommitmentExact(commitmentRaw, parameters);
  const proofRaw = Buffer.from(corpus.valid_objects.checkpoint_finality_proof.cev0_hex, "hex");
  const proof = decodeFinalityProofExact(proofRaw, parameters);
  const capability = validateCheckpointKernel({
    parameters,
    activeSet,
    commitment,
    proof,
    authenticatedCheckpointParentTimestamp: BigInt(
      corpus.fixture.authenticated_checkpoint_parent_timestamp_ms,
    ),
  });
  if (Object.keys(capability).some((key) => key.includes("anchor") || key.includes("authoriz"))) {
    fail("source_vector_drift", 0, "inert capability leaks authorization", "gate");
  }
  for (const forbidden of corpus.forbidden_entry_points) {
    if (forbidden in capability) fail("source_vector_drift", 0, `forbidden entry point ${forbidden}`, "gate");
  }
  if (!encodeParameters(parameters.fields).equals(parametersRaw)) fail("source_vector_drift", 0, "parameters round-trip", "gate");
  if (!encodeValidatorSet(activeSet).equals(setRaw)) fail("source_vector_drift", 0, "validator set round-trip", "gate");
  if (!encodeNextEpochCommitment(commitment).equals(commitmentRaw)) fail("source_vector_drift", 0, "commitment round-trip", "gate");
  if (!encodeFinalityProof(proof).equals(proofRaw)) fail("source_vector_drift", 0, "finality proof round-trip", "gate");

  const protocolV1Record = corpus.valid_commitment_variants.protocol_version_1_inert_commitment;
  const protocolV1Raw = Buffer.from(protocolV1Record.cev0_hex, "hex");
  const protocolV1Commitment = decodeNextEpochCommitmentExact(protocolV1Raw, parameters);
  if (protocolV1Commitment.newProtocolVersion !== 1) {
    fail("source_vector_drift", 0, "protocol-v1 commitment version", "gate");
  }
  if (!encodeNextEpochCommitment(protocolV1Commitment).equals(protocolV1Raw)) {
    fail("source_vector_drift", 0, "protocol-v1 commitment round-trip", "gate");
  }

  const context = { parameters, activeSet };
  let prefixCount = 0;
  for (const item of corpus.parser_campaigns.all_noncomplete_prefixes.objects) {
    const raw = Buffer.from(corpus.valid_objects[item.id].cev0_hex, "hex");
    for (let length = 0; length < raw.length; length += 1) {
      expectError(() => decodeById(item.id, raw.subarray(0, length), context), "unexpected_eof", `${item.id} prefix ${length}`);
      prefixCount += 1;
    }
  }
  if (prefixCount !== corpus.parser_campaigns.all_noncomplete_prefixes.case_count) fail("source_vector_drift", 0, "prefix count", "gate");
  for (const id of corpus.parser_campaigns.trailing_byte.objects) {
    const raw = Buffer.from(corpus.valid_objects[id].cev0_hex, "hex");
    expectError(() => decodeById(id, Buffer.concat([raw, Buffer.from([0xa5])]), context), "trailing_bytes", `${id} trailing`);
  }
  for (const testCase of corpus.parser_boundaries) {
    expectError(
      () => decodeById(
        testCase.parser,
        Buffer.from(testCase.raw_hex, "hex"),
        context,
      ),
      testCase.expected_code,
      testCase.id,
      testCase.expected_offset,
    );
  }
  for (const [index, [id, mutation, expectedCode]] of SEMANTIC_CASES.entries()) {
    const mutated = buildFixture(mutation);
    expectError(
      () => decodeAndValidateKernel(
        mutated.proofRaw,
        mutated.parameterRaw,
        mutated.setRaw,
        mutated.commitmentRaw,
        mutated.authenticatedCheckpointParentTimestamp,
      ),
      expectedCode,
      id,
      corpus.semantic_negatives[index].expected_offset,
    );
  }
}

function messageFields(proto, messageName) {
  const match = new RegExp(`message\\s+${messageName}\\s*\\{([\\s\\S]*?)\\n\\}`, "m").exec(proto);
  if (match === null) fail("projection_drift", 0, `missing proto message ${messageName}`, "gate");
  const fields = [];
  for (const line of match[1].split("\n")) {
    const field = /^\s*(?:(repeated|optional|required)\s+)?([A-Za-z_][A-Za-z0-9_.<>]*)\s+([a-z_][a-z0-9_]*)\s*=\s*(\d+)\s*;/.exec(line);
    if (field !== null) {
      fields.push({
        name: field[3],
        number: Number(field[4]),
        type: field[2],
        cardinality: field[1] === "repeated" ? "repeated" : "singular",
      });
    }
  }
  return fields;
}

function extractRustDecodeCodes(source) {
  const marker = source.indexOf("pub const fn as_str");
  if (marker < 0) fail("schema_drift", 0, "Rust DecodeErrorCode::as_str is missing", "gate");
  const matchStart = source.indexOf("match self", marker);
  const opening = source.indexOf("{", matchStart);
  if (matchStart < 0 || opening < 0) fail("schema_drift", 0, "Rust DecodeErrorCode::as_str is malformed", "gate");
  let depth = 1;
  for (let index = opening + 1; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) {
      return [...source.slice(opening, index).matchAll(
        /Self::[A-Za-z0-9_]+\s*=>\s*"([a-z0-9_]+)"/g,
      )].map((item) => item[1]);
    }
  }
  fail("schema_drift", 0, "Rust DecodeErrorCode::as_str has no closing brace", "gate");
}

function extractBracedBody(source, marker, label) {
  const markerOffset = source.indexOf(marker);
  if (markerOffset < 0) fail("schema_drift", 0, `${label} is missing`, "gate");
  const opening = source.indexOf("{", markerOffset + marker.length);
  if (opening < 0) fail("schema_drift", 0, `${label} is malformed`, "gate");
  let depth = 1;
  for (let index = opening + 1; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(opening + 1, index);
  }
  fail("schema_drift", 0, `${label} has no closing brace`, "gate");
}

function validateRustDecoderTaxonomy(manifest, base) {
  const decoderPath = path.join(REPO_ROOT, manifest.decoder_error_taxonomy.rust_source);
  const decoderSource = fs.readFileSync(decoderPath, "utf8");
  const rustCodes = extractRustDecodeCodes(decoderSource);
  if (new Set(rustCodes).size !== rustCodes.length) {
    fail("schema_drift", 0, "Rust DecodeErrorCode::as_str contains duplicates", "gate");
  }
  const additions = manifest.decoder_error_taxonomy.new_codes;
  const expectedNodeLocalCodes = [
    "invalid_sign_intent_tag",
    "invalid_sign_intent",
    "invalid_handoff_sign_intent_role",
    "invalid_handoff_sign_intent",
  ];
  const nodeLocalCodes = (base.rust_decoder_error_exclusions ?? [])
    .filter((item) => item.scope === "node-local signer-intent endpoint only")
    .map((item) => item.code);
  const expectedCodes = [
    ...manifest.decoder_error_taxonomy.reused_codes,
    ...additions,
    ...nodeLocalCodes,
  ];
  if (JSON.stringify(nodeLocalCodes) !== JSON.stringify(expectedNodeLocalCodes)) {
    fail("schema_drift", 0, "node-local signer-intent taxonomy registration drift", "gate");
  }
  if (JSON.stringify(rustCodes) !== JSON.stringify(expectedCodes)) {
    fail("schema_drift", 0, "Rust decoder taxonomy differs from exact imported+B2-E manifest order", "gate");
  }
  for (const outcome of manifest.cryptographic_outcome_taxonomy.codes) {
    if (rustCodes.includes(outcome)) {
      fail("schema_drift", 0, `post-decode crypto outcome ${outcome} leaked into Rust DecodeErrorCode`, "gate");
    }
  }
  if (/DecodeResult\s*<\s*CheckpointTwoSealKernelV0\s*>/.test(decoderSource)) {
    fail("schema_drift", 0, "raw decoder can manufacture the inert checkpoint capability", "gate");
  }
}

function normalizedLogicalType(type) {
  if (typeof type === "string") return type;
  if (type?.kind === "optional") return `optional<${type.item}>`;
  return "invalid";
}

function validateRustCapabilitySurface(manifest) {
  const capability = manifest.semantic_capability;
  const source = fs.readFileSync(path.join(REPO_ROOT, capability.rust_source), "utf8");
  const structBody = extractBracedBody(source, `pub struct ${capability.name}`, capability.name);
  if (/\bpub(?:\([^)]*\))?\s+[A-Za-z_][A-Za-z0-9_]*\s*:/.test(structBody)) {
    fail("schema_drift", 0, `${capability.name} contains a public field`, "gate");
  }
  const implBody = extractBracedBody(source, `impl ${capability.name}`, `impl ${capability.name}`);
  for (const forbidden of capability.forbidden_entry_points) {
    const method = new RegExp(`\\bfn\\s+${forbidden}\\s*\\(`);
    if (method.test(implBody)) fail("schema_drift", 0, `forbidden capability method ${forbidden}`, "gate");
  }
}

function validateManifest(manifest) {
  if (
    manifest.schema !== "trnm_poco_bft_cev0_logical_schema_checkpoint_finality_v0" ||
    manifest.schema_version !== 0 ||
    manifest.scope !== "B2-E checkpoint/two-seal semantic kernel only" ||
    manifest.status !== "closed_for_listed_objects_and_inert_relations_only" ||
    manifest.authorization_output !== false ||
    manifest.cryptographic_validity_claimed !== true ||
    manifest.cryptographic_claim_scope !== "deterministic Node.js fixture plus the committed Rust StrictEd25519Verifier integration test only; the inert token does not attest verifier identity"
  ) {
    fail("schema_drift", 0, "B2-E manifest identity/boundary", "gate");
  }
  const expectedImports = [
    {
      path: "cev0-logical-schema-v0.json",
      reuse: ["CEV0 primitives", "ValidatorSetV0", "QuorumCertificateV0", "TimeoutCertificateV0"],
    },
    {
      path: "cev0-logical-schema-anchor-handoff-v0.json",
      reuse: ["BlockKindV0", "BlockHeaderV0", "EpochAnchorAuthorizationV0"],
    },
    {
      path: "cev0-logical-schema-epoch-commitment-v0.json",
      reuse: ["NextEpochCommitmentV0", "EpochGeometryV0 relations", "RolloutPhaseV0"],
    },
    {
      path: "cev0-logical-schema-block-body-v0.json",
      reuse: ["frozen empty payload root", "frozen empty receipts root", "frozen empty evidence root"],
    },
  ];
  if (JSON.stringify(manifest.imports) !== JSON.stringify(expectedImports)) {
    fail("schema_drift", 0, "B2-E import/reuse closure", "gate");
  }
  const expectedLimits = {
    max_chain_id_bytes: "128",
    max_validator_id_bytes: "128",
    max_certificate_signers: "100",
    consensus_parameters_cev0_bytes: "341",
    checkpoint_chain_headers: "3",
    max_timestamp_step_source: "ConsensusParametersV0.max_block_time_step_ms",
  };
  if (JSON.stringify(manifest.hard_limits) !== JSON.stringify(expectedLimits)) {
    fail("schema_drift", 0, "B2-E hard-limit contract", "gate");
  }
  const names = manifest.objects.map((object) => object.name);
  if (JSON.stringify(names) !== JSON.stringify(["ConsensusParametersV0", "CertifiedHeaderV0", "FinalityProofV0"])) {
    fail("schema_drift", 0, "B2-E object list/order", "gate");
  }
  const manifestParameterFields = manifest.objects[0].fields.map((field) => [field.name, normalizedLogicalType(field.type)]);
  const expectedParameterFields = PARAMETER_LAYOUT.map(([name, type]) => [
    name,
    type === "leader" ? "LeaderScheduleV0" : type === "rollout" ? "RolloutPhaseV0" : type,
  ]);
  if (JSON.stringify(manifestParameterFields) !== JSON.stringify(expectedParameterFields)) {
    fail("schema_drift", 0, "ConsensusParametersV0 field order/type", "gate");
  }
  const snapshotLeadField = manifest.objects[0].fields.find(
    (field) => field.name === "snapshot_lead_blocks",
  );
  if (
    snapshotLeadField?.min !== "1" ||
    snapshotLeadField?.minimum_from_field !== "finality_certified_chain_length"
  ) {
    fail(
      "schema_drift",
      0,
      "snapshot lead/finality cross-field constraint drift",
      "gate",
    );
  }
  const certifiedFields = manifest.objects[1].fields.map((field) => [field.name, normalizedLogicalType(field.type)]);
  const finalityFields = manifest.objects[2].fields.map((field) => [field.name, normalizedLogicalType(field.type)]);
  const expectedCertifiedFields = [
    ["header", "BlockHeaderV0"],
    ["justify_qc", "QuorumCertificateV0"],
    ["timeout_certificate", "optional<TimeoutCertificateV0>"],
    ["epoch_anchor_authorization", "optional<EpochAnchorAuthorizationV0>"],
    ["proposer_signature", "Signature64"],
    ["certifying_qc", "QuorumCertificateV0"],
  ];
  const expectedFinalityFields = [
    ["schema_version", "u16"],
    ["genesis_hash", "Hash32"],
    ["chain_id", "ConsensusString"],
    ["protocol_version", "u32"],
    ["epoch", "u64"],
    ["validator_set_hash", "Hash32"],
    ["consensus_parameters_hash", "Hash32"],
    ["finalized_block", "CertifiedHeaderV0"],
    ["child", "CertifiedHeaderV0"],
    ["grandchild", "CertifiedHeaderV0"],
  ];
  if (
    JSON.stringify(certifiedFields) !== JSON.stringify(expectedCertifiedFields) ||
    JSON.stringify(finalityFields) !== JSON.stringify(expectedFinalityFields)
  ) {
    fail("schema_drift", 0, "CertifiedHeaderV0/FinalityProofV0 field order/type", "gate");
  }
  const newCodes = manifest.decoder_error_taxonomy.new_codes;
  if (JSON.stringify(newCodes) !== JSON.stringify(["invalid_leader_schedule", "invalid_consensus_parameters", "invalid_finality_proof", "invalid_checkpoint_two_seal"])) {
    fail("schema_drift", 0, "B2-E stable error additions", "gate");
  }
  const decoderCodes = [
    ...manifest.decoder_error_taxonomy.reused_codes,
    ...manifest.decoder_error_taxonomy.new_codes,
  ];
  if (decoderCodes.includes("invalid_signature")) {
    fail("schema_drift", 0, "cryptographic outcome leaked into decoder taxonomy", "gate");
  }
  if (
    manifest.cryptographic_outcome_taxonomy.decoder_contract !== false ||
    JSON.stringify(manifest.cryptographic_outcome_taxonomy.codes) !== JSON.stringify(["invalid_signature"])
  ) {
    fail("schema_drift", 0, "post-decode cryptographic outcome taxonomy", "gate");
  }
  const expectedChecks = [
    "old ValidatorSetV0 is recomputed and validated against the complete old ConsensusParametersV0 preimage",
    "snapshot_lead_blocks is at least finality_certified_chain_length, which is exactly 3 in protocol v0",
    "checkpoint, seal-1, and seal-2 use one old chain/genesis/version/epoch/set/parameter scope",
    "checked outgoing geometry fixes checkpoint=epoch_end-2, seal-1=checkpoint+1, and seal-2=seal-1+1",
    "the three certified headers form a direct parent-linked and height-consecutive chain",
    "every proposer is the canonical scheduled leader for its actual view",
    "every proposal and ordinary QC signature is real Ed25519 over the exact domain-separated root",
    "child and grandchild bind the exact preceding certifying-QC digest, including signer-subset identity",
    "seal roots equal the frozen empty payload/receipt/evidence constants",
    "both seals preserve the checkpoint state root and repeat the checkpoint next-epoch commitment digest",
    "the checkpoint commits the exact supplied NextEpochCommitmentV0 digest",
    "snapshot cutoff and activation height follow the old committed parameter geometry",
    "authenticated parent to checkpoint, checkpoint to seal-1, and seal-1 to seal-2 timestamps are positive steps bounded by max_block_time_step_ms",
  ];
  if (
    !manifest.semantic_capability.inert ||
    manifest.semantic_capability.peer_decodable ||
    !manifest.semantic_capability.private_fields ||
    manifest.semantic_capability.verifier_identity_attested !== false ||
    JSON.stringify(manifest.semantic_capability.checks) !== JSON.stringify(expectedChecks)
  ) {
    fail("schema_drift", 0, "B2-E capability is not inert/private", "gate");
  }
  if (JSON.stringify(manifest.semantic_capability.forbidden_entry_points) !== JSON.stringify(buildCorpus().forbidden_entry_points)) {
    fail("schema_drift", 0, "forbidden entry-point list drift", "gate");
  }
  const expectedEntryPoints = [
    "decode_consensus_parameters_v0_exact",
    "decode_ordinary_certified_header_v0_exact",
    "decode_checkpoint_finality_proof_v0_exact",
  ];
  const strictTest = "trillionnium/crates/trnm-consensus-crypto/tests/checkpoint_two_seal_kernel_vectors.rs";
  if (
    JSON.stringify(manifest.rust_exact_decoder_entry_points) !== JSON.stringify(expectedEntryPoints) ||
    manifest.rust_strict_integration_test !== strictTest
  ) {
    fail("schema_drift", 0, "Rust closure artifact manifest", "gate");
  }
  const decoderSource = fs.readFileSync(path.join(REPO_ROOT, manifest.decoder_error_taxonomy.rust_source), "utf8");
  for (const entryPoint of expectedEntryPoints) {
    if (!new RegExp(`\\bpub\\s+fn\\s+${entryPoint}\\s*\\(`).test(decoderSource)) {
      fail("schema_drift", 0, `missing Rust exact decoder ${entryPoint}`, "gate");
    }
  }
  const strictSource = fs.readFileSync(path.join(REPO_ROOT, strictTest), "utf8");
  for (const marker of [
    "checkpoint-two-seal-kernel-v0.json",
    "StrictEd25519Verifier",
    "decode_consensus_parameters_v0_exact",
    "decode_checkpoint_finality_proof_v0_exact",
  ]) {
    if (!strictSource.includes(marker)) fail("schema_drift", 0, `strict Rust integration missing ${marker}`, "gate");
  }
  const expectedHonestBoundary = [
    "B2-E authenticates one old-set checkpoint/two-seal consensus-finality chain and binds the exact next-epoch commitment digest.",
    "The capability is inert and cannot authorize an EpochAnchorQC, handoff signature, first-new-epoch proposal, vote, or epoch transition.",
    "The committed protocol-version-1 variant proves exact inert u32 preservation and digest binding only; B2-E does not authenticate an upgrade plan or authorize protocol activation.",
    "The finalized commitment authenticates snapshot_state_root only as a committed claim; B2-E does not prove equality to a cutoff header state root or authenticated ancestry from that cutoff.",
    "B2-E does not verify JMT/ICS23 state membership, deterministic candidate construction, lowest fallback reason, PoP, governance, new-set/parameter authority, runtime identity or execution, receipt provenance, checkpoint body execution, or checkpoint-state preimage availability.",
    "The caller-supplied verifier acceptance is not a type-level attestation of verifier identity; the committed crypto lane uses real Node.js Ed25519 and Rust integration must use StrictEd25519Verifier.",
    "The committed B2-E fixture is next-view-only and makes no B2-E TimeoutCertificateV0 semantic-coverage claim; B2-A remains authoritative for ordinary TC semantics.",
    "Closure is limited to the exact Rust decoder entry points and committed StrictEd25519Verifier corpus integration test named in this manifest.",
    "B2 overall, complete epoch authorization, core integration, transport admission, and wire_conformance remain open.",
  ];
  if (JSON.stringify(manifest.honest_boundary) !== JSON.stringify(expectedHonestBoundary)) {
    fail("schema_drift", 0, "B2-E honest-boundary contract", "gate");
  }
}

function validateProjection(manifest) {
  const common = fs.readFileSync(COMMON_PROTO_PATH, "utf8");
  const light = fs.readFileSync(LIGHT_PROTO_PATH, "utf8");
  const expectedParameters = PARAMETER_LAYOUT.map(([logicalName, logicalType], index) => {
    const name = logicalType === "u128" ? `${logicalName}_u128_be` : logicalName;
    const type = logicalType === "bool" ? "bool" :
      logicalType === "leader" ? "LeaderSchedule" :
        logicalType === "rollout" ? "RolloutPhase" :
          logicalType === "u64" ? "uint64" :
            logicalType === "u128" ? "bytes" : "uint32";
    return { name, number: index + 1, type, cardinality: "singular" };
  });
  expectedParameters.push({ name: "parameters_hash", number: 55, type: "bytes", cardinality: "singular" });
  if (JSON.stringify(messageFields(common, "ConsensusParameters")) !== JSON.stringify(expectedParameters)) {
    fail("projection_drift", 0, "ConsensusParameters projection", "gate");
  }
  const certified = messageFields(light, "CertifiedHeader");
  const finality = messageFields(light, "ThreeChainFinalityProof");
  const expectedCertified = [
    { name: "header", number: 1, type: "BlockHeader", cardinality: "singular" },
    { name: "justify_qc", number: 5, type: "QuorumCertificate", cardinality: "singular" },
    { name: "timeout_certificate", number: 6, type: "TimeoutCertificate", cardinality: "singular" },
    { name: "epoch_anchor_authorization", number: 7, type: "EpochAnchorAuthorization", cardinality: "singular" },
    { name: "proposer_signature", number: 8, type: "bytes", cardinality: "singular" },
    { name: "certifying_qc", number: 9, type: "QuorumCertificate", cardinality: "singular" },
    { name: "block_id", number: 10, type: "bytes", cardinality: "singular" },
  ];
  const expectedFinality = [
    { name: "schema_version", number: 1, type: "uint32", cardinality: "singular" },
    { name: "genesis_hash", number: 2, type: "bytes", cardinality: "singular" },
    { name: "chain_id", number: 3, type: "string", cardinality: "singular" },
    { name: "protocol_version", number: 4, type: "uint32", cardinality: "singular" },
    { name: "epoch", number: 5, type: "uint64", cardinality: "singular" },
    { name: "validator_set_hash", number: 6, type: "bytes", cardinality: "singular" },
    { name: "consensus_parameters_hash", number: 7, type: "bytes", cardinality: "singular" },
    { name: "finalized_block", number: 8, type: "CertifiedHeader", cardinality: "singular" },
    { name: "child", number: 9, type: "CertifiedHeader", cardinality: "singular" },
    { name: "grandchild", number: 10, type: "CertifiedHeader", cardinality: "singular" },
    { name: "finality_proof_digest", number: 11, type: "bytes", cardinality: "singular" },
  ];
  if (JSON.stringify(certified) !== JSON.stringify(expectedCertified) || JSON.stringify(finality) !== JSON.stringify(expectedFinality)) {
    fail("projection_drift", 0, "CertifiedHeader/ThreeChainFinalityProof projection", "gate");
  }
  const handoffField = messageFields(light, "EpochHandoffProof").find(
    (field) => field.name === "old_checkpoint_finality",
  );
  if (JSON.stringify(handoffField) !== JSON.stringify({
    name: "old_checkpoint_finality",
    number: 4,
    type: "ThreeChainFinalityProof",
    cardinality: "singular",
  })) {
    fail("projection_drift", 0, "EpochHandoffProof checkpoint sidecar projection", "gate");
  }

  const projections = new Map(manifest.transport_projections.map((item) => [item.message, item.field_roles]));
  const expectedRoles = new Map([
    ["ConsensusParameters", {
      canonical: expectedParameters.slice(0, -1).map((field) => field.name),
      derived: ["parameters_hash"],
    }],
    ["CertifiedHeader", {
      canonical: expectedCertified.slice(0, -1).map((field) => field.name),
      derived: ["block_id"],
    }],
    ["ThreeChainFinalityProof", {
      canonical: expectedFinality.slice(0, -1).map((field) => field.name),
      derived: ["finality_proof_digest"],
    }],
    ["EpochHandoffProof", { sidecar: ["old_checkpoint_finality"] }],
  ]);
  if (JSON.stringify([...projections]) !== JSON.stringify([...expectedRoles])) {
    fail("projection_drift", 0, "transport canonical/derived/sidecar role manifest", "gate");
  }
}

function main() {
  const manifest = readJson(SCHEMA_PATH);
  const base = readJson(BASE_SCHEMA_PATH);
  validateManifest(manifest);
  validateRustDecoderTaxonomy(manifest, base);
  validateRustCapabilitySurface(manifest);
  validateProjection(manifest);
  const expected = buildCorpus();
  if (process.argv.includes("--emit-corpus")) {
    process.stdout.write(`${JSON.stringify(expected, null, 2)}\n`);
    return;
  }
  const committed = readJson(CORPUS_PATH);
  if (JSON.stringify(committed) !== JSON.stringify(expected)) {
    fail("source_vector_drift", 0, "committed B2-E corpus differs from deterministic source", "gate");
  }
  validateCorpus(committed);
  console.log(
    `PoCO-BFT v0 B2-E checkpoint/two-seal kernel: valid (` +
      `${committed.parser_campaigns.all_noncomplete_prefixes.case_count} prefixes, ` +
      `${committed.parser_campaigns.trailing_byte.case_count} trailing cases, ` +
      `${committed.parser_boundaries.length} parser boundaries, ` +
      `${committed.semantic_negatives.length} semantic/crypto negatives, ` +
      `${committed.real_ed25519_checks.total_signature_verifications} real Ed25519 verifications)`,
  );
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
