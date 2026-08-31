#!/usr/bin/env node

// Independent, standard-library-only B2-F gate. This checker deliberately
// consumes the committed B2-B/C/E raw CEV0 corpora, then builds two complete
// fields-1..11 compositions, serializes them, parses them again, and verifies
// every nested relation and Ed25519 signature without calling another gate.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "../..");
const DOC_ROOT = path.join(REPO_ROOT, "docs/protocol/poco-bft-v0");
const SCHEMA_PATH = path.join(
  DOC_ROOT,
  "schema/cev0-logical-schema-joint-handoff-kernel-v0.json",
);
const VECTOR_PATH = path.join(
  DOC_ROOT,
  "vectors/joint-handoff-composition-kernel-v0.json",
);
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
const DOMAIN_PROPOSAL = "trnm.poco-bft.proposal.v0";
const DOMAIN_FINALITY = "trnm.poco-bft.finality-proof.v0";
const DOMAIN_COMMITMENT = "trnm.poco-bft.epoch-commitment.v0";
const DOMAIN_DESCRIPTOR = "trnm.poco-bft.handoff-descriptor.v0";
const DOMAIN_HANDOFF_VOTE = "trnm.poco-bft.handoff-vote.v0";
const DOMAIN_CERTIFICATE = "trnm.poco-bft.handoff-certificate.v0";
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

const stats = {
  protoFields: 0,
  sourceCorpora: 0,
  sourceRawObjects: 0,
  roundTrips: 0,
  digestChecks: 0,
  signatureChecks: 0,
  positiveCases: 0,
  negativeCases: 0,
  compositionNegativeCases: 0,
  decodeNegativeCases: 0,
  negativeClasses: new Set(),
};

class GateError extends Error {
  constructor(code, message, layer = "semantic", offset = 0) {
    super(`${code} at byte ${offset}: ${message}`);
    this.name = "GateError";
    this.code = code;
    this.layer = layer;
    this.offset = offset;
  }
}

function fail(code, message, layer = "semantic", offset = 0) {
  throw new GateError(code, message, layer, offset);
}

function invariant(condition, message, code = "manifest_drift") {
  if (!condition) fail(code, message, "gate");
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, "utf8"));
}

function canonicalHex(value, label) {
  invariant(
    typeof value === "string" &&
      value.length % 2 === 0 &&
      /^[0-9a-f]*$/.test(value),
    `${label} is not canonical lowercase hex`,
    "source_vector_drift",
  );
  const decoded = Buffer.from(value, "hex");
  invariant(decoded.toString("hex") === value, `${label} hex round-trip drift`, "source_vector_drift");
  return decoded;
}

function clone(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]));
  }
  return value;
}

function u(value, width) {
  let remaining = typeof value === "bigint" ? value : BigInt(value);
  const maximum = 1n << BigInt(width * 8);
  if (remaining < 0n || remaining >= maximum) {
    fail("integer_overflow", `${value} does not fit u${width * 8}`, "encoder");
  }
  const result = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function cevBytes(value) {
  return Buffer.concat([u(value.length, 4), value]);
}

function consensusString(value) {
  return Buffer.concat([u(value.length, 2), value]);
}

function list(values, encoder) {
  return Buffer.concat([u(values.length, 4), ...values.map(encoder)]);
}

function optional(value, encoder) {
  return value === null
    ? Buffer.from([0])
    : Buffer.concat([Buffer.from([1]), encoder(value)]);
}

function frame(value) {
  return Buffer.concat([u(value.length, 4), value]);
}

function digest(domain, encoded) {
  stats.digestChecks += 1;
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

function rawSha256(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function b2eHash(label) {
  return crypto.createHash("sha256").update(`b2-e:${label}`, "utf8").digest();
}

function seedFor(family, id) {
  const prefix = family === "b2e"
    ? "trnm.poco-bft.checkpoint-finality.private-fixture.v0:"
    : "trnm.poco-bft.joint-handoff.private-fixture.v0:";
  return crypto.createHash("sha256").update(`${prefix}${id}`, "utf8").digest();
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
  invariant(
    der.length === SPKI_PREFIX.length + 32 &&
      der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX),
    "unexpected Ed25519 SPKI encoding",
    "crypto_backend_drift",
  );
  return Buffer.from(der.subarray(SPKI_PREFIX.length));
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
  invariant(signature.length === 64, "Ed25519 signer returned a non-64-byte signature", "crypto_backend_drift");
  return signature;
}

function verifySignature(publicKey, root, signature) {
  stats.signatureChecks += 1;
  try {
    return signature.length === 64 &&
      crypto.verify(null, root, publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
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
      fail("unexpected_eof", `need ${length} bytes`, "decoder", this.position);
    }
    const result = this.raw.subarray(this.position, this.position + length);
    this.position += length;
    return result;
  }

  uint(width) {
    const raw = this.take(width);
    let result = 0n;
    for (const byte of raw) result = (result << 8n) | BigInt(byte);
    return result;
  }

  u8() { return Number(this.uint(1)); }
  u16() { return Number(this.uint(2)); }
  u32() { return Number(this.uint(4)); }
  u64() { return this.uint(8); }
  u128() { return this.uint(16); }
  fixed(length) { return Buffer.from(this.take(length)); }

  bytes(maximum = 128) {
    const at = this.offset();
    const length = this.u32();
    if (length === 0 || length > maximum) {
      fail("length_limit_exceeded", `byte string length ${length}`, "decoder", at);
    }
    return this.fixed(length);
  }

  text(maximum = 128) {
    const at = this.offset();
    const length = this.u16();
    if (length === 0 || length > maximum) {
      fail("invalid_consensus_string", `consensus string length ${length}`, "decoder", at);
    }
    const raw = this.fixed(length);
    for (let index = 0; index < raw.length; index += 1) {
      const byte = raw[index];
      const lower = byte >= 0x61 && byte <= 0x7a;
      const digit = byte >= 0x30 && byte <= 0x39;
      const punctuation = byte === 0x2e || byte === 0x5f || byte === 0x3a || byte === 0x2d;
      if (!(lower || digit || (index > 0 && punctuation))) {
        fail("invalid_consensus_string", "noncanonical consensus string byte", "decoder", at);
      }
    }
    return raw;
  }

  count(maximum = 100) {
    const at = this.offset();
    const count = this.u32();
    if (count > maximum) fail("count_limit_exceeded", `count ${count}`, "decoder", at);
    return count;
  }

  finish() {
    if (this.position !== this.raw.length) {
      fail("trailing_bytes", `${this.raw.length - this.position} trailing bytes`, "decoder", this.position);
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
  for (const [name, type] of PARAMETER_LAYOUT) {
    const at = cursor.offset();
    if (type === "u8") fields[name] = cursor.u8();
    else if (type === "u16") fields[name] = cursor.u16();
    else if (type === "u32") fields[name] = cursor.u32();
    else if (type === "u64") fields[name] = cursor.u64();
    else if (type === "u128") fields[name] = cursor.u128();
    else {
      const value = cursor.u8();
      if (type === "bool") {
        if (value > 1) fail("invalid_boolean", name, "decoder", at);
        fields[name] = value === 1;
      } else if (type === "leader") {
        if (value !== 0) fail("invalid_consensus_parameters", "leader schedule", "decoder", at);
        fields[name] = value;
      } else {
        if (value > 3) fail("invalid_consensus_parameters", "rollout phase", "decoder", at);
        fields[name] = value;
      }
    }
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  if (
    fields.schema_version !== 0 ||
    fields.protocol_version !== 0 ||
    fields.max_chain_id_bytes < 1 || fields.max_chain_id_bytes > 128 ||
    fields.max_validator_id_bytes < 1 || fields.max_validator_id_bytes > 128 ||
    fields.min_validators < 4 || fields.max_validators > 100 ||
    fields.min_validators > fields.max_validators ||
    fields.quorum_numerator !== 2 || fields.quorum_denominator !== 3 || fields.quorum_addend !== 1 ||
    fields.finality_certified_chain_length !== 3 ||
    fields.epoch_seal_blocks !== 2 ||
    fields.snapshot_lead_blocks === 0n ||
    fields.snapshot_lead_blocks < BigInt(fields.finality_certified_chain_length) ||
    fields.epoch_length_blocks <= fields.snapshot_lead_blocks + 2n ||
    !fields.joint_handoff_old_quorum || !fields.joint_handoff_new_quorum
  ) {
    fail("invalid_consensus_parameters", "B2-F parameter invariants", "decoder", start);
  }
  return { fields, raw, hash: digest(DOMAIN_PARAMETERS, raw) };
}

function decodeParameters(raw, source = false) {
  const cursor = new Cursor(raw);
  const value = parseParameters(cursor);
  cursor.finish();
  if (raw.length !== 341) fail("invalid_consensus_parameters", "parameter preimage length", "decoder");
  invariant(encodeParameters(value.fields).equals(raw), "parameter round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function encodeValidatorSet(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis,
    consensusString(value.chain),
    u(value.protocol, 4),
    u(value.epoch, 8),
    value.parametersHash,
    list(value.validators, (validator) =>
      Buffer.concat([cevBytes(validator.id), validator.publicKey, u(validator.power, 8)]),
    ),
  ]);
}

function parseValidatorSet(cursor, parameters = null) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "validator set schema", "decoder", start);
  const genesis = cursor.fixed(32);
  if (genesis.equals(Buffer.alloc(32))) fail("context_mismatch", "zero validator-set genesis", "decoder", start);
  const chain = cursor.text(parameters?.fields.max_chain_id_bytes ?? 128);
  const protocol = cursor.u32();
  const epoch = cursor.u64();
  const parametersHash = cursor.fixed(32);
  const count = cursor.count(parameters?.fields.max_validators ?? 100);
  const validators = [];
  const keys = new Set();
  let previous = null;
  let totalPower = 0n;
  for (let index = 0; index < count; index += 1) {
    const at = cursor.offset();
    const id = cursor.bytes(parameters?.fields.max_validator_id_bytes ?? 128);
    const publicKey = cursor.fixed(32);
    const power = cursor.u64();
    if (previous !== null && Buffer.compare(previous, id) >= 0) {
      fail("noncanonical_validator_order", `validator ${index}`, "decoder", at);
    }
    if (publicKey.equals(Buffer.alloc(32)) || keys.has(publicKey.toString("hex")) || power === 0n) {
      fail("invalid_validator_set", `validator ${index}`, "decoder", at);
    }
    previous = id;
    keys.add(publicKey.toString("hex"));
    totalPower += power;
    validators.push({ id, publicKey, power });
  }
  if (count < (parameters?.fields.min_validators ?? 1)) {
    fail("invalid_validator_set", "too few validators", "decoder", start);
  }
  if (parameters !== null) {
    if (!parametersHash.equals(parameters.hash) || totalPower > parameters.fields.max_total_voting_power) {
      fail("context_mismatch", "validator-set parameter context", "semantic", start);
    }
    for (const validator of validators) {
      if (
        validator.power < parameters.fields.min_validator_power ||
        validator.power > parameters.fields.max_validator_power ||
        validator.power * parameters.fields.scale_ppm >
          totalPower * parameters.fields.max_validator_share_ppm
      ) {
        fail("invalid_validator_set", "validator power or concentration", "semantic", start);
      }
    }
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
    genesis,
    chain,
    protocol,
    epoch,
    parametersHash,
    validators,
    totalPower,
    quorumPower: (2n * totalPower) / 3n + 1n,
    byId: new Map(validators.map((validator) => [validator.id.toString("hex"), validator])),
    raw,
    hash: digest(DOMAIN_VALIDATOR_SET, raw),
  };
}

function decodeValidatorSet(raw, parameters = null, source = false) {
  const cursor = new Cursor(raw);
  const value = parseValidatorSet(cursor, parameters);
  cursor.finish();
  invariant(encodeValidatorSet(value).equals(raw), "validator-set round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function encodeCommitment(value) {
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
    optional(value.upgradePlanHash, (item) => item),
    u(value.fallbackUsed ? 1 : 0, 1),
    u(value.fallbackReason, 2),
    u(value.activationHeight, 8),
  ]);
}

function parseCommitment(cursor) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "commitment schema", "decoder", start);
  const genesis = cursor.fixed(32);
  const chain = cursor.text();
  const oldEpoch = cursor.u64();
  const newEpoch = cursor.u64();
  const snapshotCutoffHeight = cursor.u64();
  const snapshotStateRoot = cursor.fixed(32);
  const newProtocolVersion = cursor.u32();
  const newValidatorSetHash = cursor.fixed(32);
  const newParametersHash = cursor.fixed(32);
  const rolloutPhase = cursor.u8();
  const tagAt = cursor.offset();
  const upgradeTag = cursor.u8();
  if (upgradeTag > 1) fail("invalid_optional_tag", "upgrade hash", "decoder", tagAt);
  const upgradePlanHash = upgradeTag === 1 ? cursor.fixed(32) : null;
  const fallbackAt = cursor.offset();
  const fallbackRaw = cursor.u8();
  if (fallbackRaw > 1) fail("invalid_boolean", "fallback flag", "decoder", fallbackAt);
  const fallbackReason = cursor.u16();
  const activationHeight = cursor.u64();
  if (
    newEpoch !== oldEpoch + 1n ||
    snapshotStateRoot.equals(Buffer.alloc(32)) ||
    newValidatorSetHash.equals(Buffer.alloc(32)) ||
    newParametersHash.equals(Buffer.alloc(32)) ||
    rolloutPhase > 3 ||
    (upgradePlanHash !== null && upgradePlanHash.equals(Buffer.alloc(32))) ||
    (fallbackRaw === 1) === (fallbackReason === 0) ||
    fallbackReason > 9 ||
    activationHeight === 0n
  ) {
    fail("invalid_next_epoch_commitment", "commitment intrinsic invariants", "decoder", start);
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
    genesis,
    chain,
    oldEpoch,
    newEpoch,
    snapshotCutoffHeight,
    snapshotStateRoot,
    newProtocolVersion,
    newValidatorSetHash,
    newParametersHash,
    rolloutPhase,
    upgradePlanHash,
    fallbackUsed: fallbackRaw === 1,
    fallbackReason,
    activationHeight,
    raw,
    id: digest(DOMAIN_COMMITMENT, raw),
  };
}

function decodeCommitment(raw, source = false) {
  const cursor = new Cursor(raw);
  const value = parseCommitment(cursor);
  cursor.finish();
  invariant(encodeCommitment(value).equals(raw), "commitment round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function encodeHeader(header) {
  return Buffer.concat([
    u(0, 2),
    header.genesis,
    consensusString(header.chain),
    u(header.protocol, 4),
    u(header.epoch, 8),
    u(header.view, 8),
    u(header.height, 8),
    u(header.kind, 1),
    header.parentId,
    cevBytes(header.proposerId),
    header.setHash,
    header.parametersHash,
    header.payloadRoot,
    header.stateRoot,
    header.receiptsRoot,
    header.evidenceRoot,
    u(header.timestamp, 8),
    optional(header.nextCommitment, (item) => item),
  ]);
}

function parseHeader(cursor, parameters = null) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "header schema", "decoder", start);
  const genesis = cursor.fixed(32);
  const chain = cursor.text(parameters?.fields.max_chain_id_bytes ?? 128);
  const protocol = cursor.u32();
  const epoch = cursor.u64();
  const view = cursor.u64();
  const height = cursor.u64();
  const kind = cursor.u8();
  const parentId = cursor.fixed(32);
  const proposerId = cursor.bytes(parameters?.fields.max_validator_id_bytes ?? 128);
  const setHash = cursor.fixed(32);
  const parametersHash = cursor.fixed(32);
  const payloadRoot = cursor.fixed(32);
  const stateRoot = cursor.fixed(32);
  const receiptsRoot = cursor.fixed(32);
  const evidenceRoot = cursor.fixed(32);
  const timestamp = cursor.u64();
  const tagAt = cursor.offset();
  const nextTag = cursor.u8();
  if (nextTag > 1) fail("invalid_optional_tag", "header commitment tag", "decoder", tagAt);
  const nextCommitment = nextTag === 1 ? cursor.fixed(32) : null;
  if (
    protocol > 0 || view === 0n || height === 0n || kind > 4 ||
    ((kind === 0 || kind === 4) !== (nextCommitment === null))
  ) {
    fail("invalid_block_header", "header intrinsic invariants", "decoder", start);
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
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
  };
}

function decodeHeader(raw, parameters = null, source = false) {
  const cursor = new Cursor(raw);
  const value = parseHeader(cursor, parameters);
  cursor.finish();
  invariant(encodeHeader(value).equals(raw), "header round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function commonContext(scope, view, messageKind) {
  return Buffer.concat([
    u(0, 2),
    scope.genesis,
    consensusString(scope.chain),
    u(scope.protocol, 4),
    u(scope.epoch, 8),
    scope.setHash,
    u(view, 8),
    u(messageKind, 1),
  ]);
}

function qcVoteRoot(scope, view, height, blockId) {
  return digest(
    DOMAIN_VOTE,
    Buffer.concat([commonContext(scope, view, 1), u(height, 8), blockId]),
  );
}

function proposalRoot(header, justifyDigest) {
  return digest(
    DOMAIN_PROPOSAL,
    Buffer.concat([
      commonContext(
        {
          genesis: header.genesis,
          chain: header.chain,
          protocol: header.protocol,
          epoch: header.epoch,
          setHash: header.setHash,
        },
        header.view,
        0,
      ),
      u(header.height, 8),
      header.id,
      justifyDigest,
      Buffer.from([0]),
      Buffer.from([0]),
    ]),
  );
}

function encodeQc(qc) {
  return Buffer.concat([
    u(0, 2),
    qc.genesis,
    consensusString(qc.chain),
    u(qc.protocol, 4),
    u(qc.epoch, 8),
    qc.setHash,
    u(qc.view, 8),
    u(qc.height, 8),
    qc.blockId,
    list(qc.signatures, (share) => Buffer.concat([cevBytes(share.validatorId), share.signature])),
  ]);
}

function parseQc(cursor, parameters = null) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "QC schema", "decoder", start);
  const genesis = cursor.fixed(32);
  const chain = cursor.text(parameters?.fields.max_chain_id_bytes ?? 128);
  const protocol = cursor.u32();
  const epoch = cursor.u64();
  const setHash = cursor.fixed(32);
  const view = cursor.u64();
  const height = cursor.u64();
  const blockId = cursor.fixed(32);
  const count = cursor.count(100);
  const signatures = [];
  let previous = null;
  for (let index = 0; index < count; index += 1) {
    const at = cursor.offset();
    const validatorId = cursor.bytes(parameters?.fields.max_validator_id_bytes ?? 128);
    if (previous !== null && Buffer.compare(previous, validatorId) >= 0) {
      fail("noncanonical_signer_order", `QC signer ${index}`, "decoder", at);
    }
    previous = validatorId;
    signatures.push({ validatorId, signature: cursor.fixed(64) });
  }
  if (protocol > 0 || view === 0n || signatures.length === 0) {
    fail("invalid_quorum_certificate", "ordinary QC invariants", "decoder", start);
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
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
  };
}

function decodeQc(raw, parameters = null, source = false) {
  const cursor = new Cursor(raw);
  const value = parseQc(cursor, parameters);
  cursor.finish();
  invariant(encodeQc(value).equals(raw), "QC round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function sameScope(value, set) {
  return value.genesis.equals(set.genesis) &&
    value.chain.equals(set.chain) &&
    value.protocol === set.protocol &&
    value.epoch === set.epoch &&
    value.setHash.equals(set.hash);
}

function validateQc(qc, set) {
  if (!sameScope(qc, set)) fail("context_mismatch", "QC scope differs from validator set");
  const root = qcVoteRoot(qc, qc.view, qc.height, qc.blockId);
  let power = 0n;
  for (const share of qc.signatures) {
    const validator = set.byId.get(share.validatorId.toString("hex"));
    if (validator === undefined) fail("unknown_signer", "QC signer is not in the active set");
    if (!verifySignature(validator.publicKey, root, share.signature)) {
      fail("invalid_signature", "invalid QC Ed25519 signature", "crypto");
    }
    power += validator.power;
  }
  if (power < set.quorumPower) fail("insufficient_quorum", "QC power below threshold");
  return power;
}

function encodeCertified(certified) {
  return Buffer.concat([
    certified.header.raw ?? encodeHeader(certified.header),
    certified.justifyQc.raw ?? encodeQc(certified.justifyQc),
    Buffer.from([0]),
    Buffer.from([0]),
    certified.proposerSignature,
    certified.certifyingQc.raw ?? encodeQc(certified.certifyingQc),
  ]);
}

function parseCertified(cursor, parameters) {
  const start = cursor.offset();
  const header = parseHeader(cursor, parameters);
  const justifyQc = parseQc(cursor, parameters);
  const tcAt = cursor.offset();
  const tcTag = cursor.u8();
  if (tcTag !== 0) fail("invalid_checkpoint_finality", "B2-F checkpoint fixture carries a TC", "decoder", tcAt);
  const anchorAt = cursor.offset();
  const anchorTag = cursor.u8();
  if (anchorTag !== 0) fail("invalid_checkpoint_finality", "old checkpoint carries an epoch anchor", "decoder", anchorAt);
  const proposerSignature = cursor.fixed(64);
  const certifyingQc = parseQc(cursor, parameters);
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return { header, justifyQc, proposerSignature, certifyingQc, raw };
}

function encodeFinality(proof) {
  return Buffer.concat([
    u(0, 2),
    proof.genesis,
    consensusString(proof.chain),
    u(proof.protocol, 4),
    u(proof.epoch, 8),
    proof.setHash,
    proof.parametersHash,
    proof.finalizedBlock.raw ?? encodeCertified(proof.finalizedBlock),
    proof.child.raw ?? encodeCertified(proof.child),
    proof.grandchild.raw ?? encodeCertified(proof.grandchild),
  ]);
}

function parseFinality(cursor, parameters) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "finality schema", "decoder", start);
  const genesis = cursor.fixed(32);
  const chain = cursor.text(parameters.fields.max_chain_id_bytes);
  const protocol = cursor.u32();
  const epoch = cursor.u64();
  const setHash = cursor.fixed(32);
  const parametersHash = cursor.fixed(32);
  const finalizedBlock = parseCertified(cursor, parameters);
  const child = parseCertified(cursor, parameters);
  const grandchild = parseCertified(cursor, parameters);
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
    genesis,
    chain,
    protocol,
    epoch,
    setHash,
    parametersHash,
    finalizedBlock,
    child,
    grandchild,
    raw,
    id: digest(DOMAIN_FINALITY, raw),
  };
}

function decodeFinality(raw, parameters, source = false) {
  const cursor = new Cursor(raw);
  const value = parseFinality(cursor, parameters);
  cursor.finish();
  invariant(encodeFinality(value).equals(raw), "finality round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function validateCertified(certified, set, parameters) {
  const { header, justifyQc, certifyingQc } = certified;
  if (
    !sameScope(header, set) ||
    !header.parametersHash.equals(parameters.hash) ||
    !sameScope(justifyQc, set) ||
    !sameScope(certifyingQc, set)
  ) {
    fail("context_mismatch", "certified-header scope");
  }
  if (
    justifyQc.height + 1n !== header.height ||
    !justifyQc.blockId.equals(header.parentId) ||
    header.view !== justifyQc.view + 1n ||
    certifyingQc.view !== header.view ||
    certifyingQc.height !== header.height ||
    !certifyingQc.blockId.equals(header.id)
  ) {
    fail("invalid_checkpoint_finality", "certified-header direct relation");
  }
  const leader = set.validators[Number((header.view - 1n) % BigInt(set.validators.length))];
  if (!header.proposerId.equals(leader.id)) fail("invalid_checkpoint_finality", "scheduled proposer mismatch");
  validateQc(justifyQc, set);
  if (!verifySignature(leader.publicKey, proposalRoot(header, justifyQc.id), certified.proposerSignature)) {
    fail("invalid_signature", "invalid proposer Ed25519 signature", "crypto");
  }
  validateQc(certifyingQc, set);
}

function validateFinality(proof, set, parameters, commitment, parentTimestamp) {
  if (
    !proof.genesis.equals(set.genesis) ||
    !proof.chain.equals(set.chain) ||
    proof.protocol !== set.protocol ||
    proof.epoch !== set.epoch ||
    !proof.setHash.equals(set.hash) ||
    !proof.parametersHash.equals(parameters.hash)
  ) {
    fail("context_mismatch", "outer finality scope");
  }
  const blocks = [proof.finalizedBlock, proof.child, proof.grandchild];
  for (const block of blocks) validateCertified(block, set, parameters);
  const [checkpoint, seal1, seal2] = blocks;
  const epochEnd = (proof.epoch + 1n) * parameters.fields.epoch_length_blocks;
  const checkpointHeight = epochEnd - 2n;
  if (
    checkpoint.header.kind !== 1 || seal1.header.kind !== 2 || seal2.header.kind !== 3 ||
    checkpoint.header.height !== checkpointHeight ||
    seal1.header.height !== checkpointHeight + 1n ||
    seal2.header.height !== checkpointHeight + 2n
  ) {
    fail("invalid_checkpoint_finality", "checkpoint/two-seal kinds or geometry");
  }
  if (
    !seal1.header.parentId.equals(checkpoint.header.id) ||
    !seal2.header.parentId.equals(seal1.header.id) ||
    !seal1.justifyQc.id.equals(checkpoint.certifyingQc.id) ||
    !seal2.justifyQc.id.equals(seal1.certifyingQc.id)
  ) {
    fail("invalid_checkpoint_finality", "checkpoint/two-seal exact linkage");
  }
  if (
    !(checkpoint.certifyingQc.view < seal1.certifyingQc.view &&
      seal1.certifyingQc.view < seal2.certifyingQc.view)
  ) {
    fail("invalid_checkpoint_finality", "certifying views are not increasing");
  }
  const timestamps = [parentTimestamp, checkpoint.header.timestamp, seal1.header.timestamp];
  for (let index = 0; index < blocks.length; index += 1) {
    const delta = blocks[index].header.timestamp - timestamps[index];
    if (delta <= 0n || delta > parameters.fields.max_block_time_step_ms) {
      fail("invalid_checkpoint_finality", "authenticated timestamp step");
    }
  }
  for (const seal of [seal1.header, seal2.header]) {
    if (
      !seal.payloadRoot.equals(EMPTY_PAYLOAD_ROOT) ||
      !seal.receiptsRoot.equals(EMPTY_RECEIPTS_ROOT) ||
      !seal.evidenceRoot.equals(EMPTY_EVIDENCE_ROOT) ||
      !seal.stateRoot.equals(checkpoint.header.stateRoot)
    ) {
      fail("invalid_checkpoint_finality", "seal state or frozen roots");
    }
  }
  for (const certified of blocks) {
    if (
      certified.header.nextCommitment === null ||
      !certified.header.nextCommitment.equals(commitment.id)
    ) {
      fail("commitment_binding_mismatch", "checkpoint/seal commitment digest");
    }
  }
  if (
    commitment.snapshotCutoffHeight !== checkpointHeight - parameters.fields.snapshot_lead_blocks ||
    commitment.activationHeight !== epochEnd + 1n
  ) {
    fail("commitment_binding_mismatch", "cutoff or activation geometry");
  }
  return {
    checkpoint,
    seal1,
    seal2,
    checkpointHeight,
    activationHeight: epochEnd + 1n,
  };
}

function encodeDescriptor(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis,
    consensusString(value.chain),
    u(value.oldEpoch, 8),
    u(value.newEpoch, 8),
    u(value.oldProtocolVersion, 4),
    u(value.newProtocolVersion, 4),
    value.oldSetHash,
    value.newSetHash,
    value.oldParametersHash,
    value.newParametersHash,
    u(value.checkpointHeight, 8),
    value.checkpointBlockId,
    value.checkpointStateRoot,
    value.commitmentDigest,
    u(value.terminalHeight, 8),
    value.terminalBlockId,
    value.terminalQcDigest,
    u(value.terminalView, 8),
    u(value.activationHeight, 8),
    u(value.initialNewView, 8),
  ]);
}

function parseDescriptor(cursor) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "descriptor schema", "decoder", start);
  const genesis = cursor.fixed(32);
  const chain = cursor.text();
  const oldEpoch = cursor.u64();
  const newEpoch = cursor.u64();
  const oldProtocolVersion = cursor.u32();
  const newProtocolVersion = cursor.u32();
  const oldSetHash = cursor.fixed(32);
  const newSetHash = cursor.fixed(32);
  const oldParametersHash = cursor.fixed(32);
  const newParametersHash = cursor.fixed(32);
  const checkpointHeight = cursor.u64();
  const checkpointBlockId = cursor.fixed(32);
  const checkpointStateRoot = cursor.fixed(32);
  const commitmentDigest = cursor.fixed(32);
  const terminalHeight = cursor.u64();
  const terminalBlockId = cursor.fixed(32);
  const terminalQcDigest = cursor.fixed(32);
  const terminalView = cursor.u64();
  const activationHeight = cursor.u64();
  const initialNewView = cursor.u64();
  if (
    newEpoch !== oldEpoch + 1n ||
    checkpointHeight === 0n || terminalHeight === 0n || terminalView === 0n ||
    activationHeight === 0n || initialNewView !== 1n
  ) {
    fail("invalid_handoff_descriptor", "descriptor intrinsic invariants", "decoder", start);
  }
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
    genesis,
    chain,
    oldEpoch,
    newEpoch,
    oldProtocolVersion,
    newProtocolVersion,
    oldSetHash,
    newSetHash,
    oldParametersHash,
    newParametersHash,
    checkpointHeight,
    checkpointBlockId,
    checkpointStateRoot,
    commitmentDigest,
    terminalHeight,
    terminalBlockId,
    terminalQcDigest,
    terminalView,
    activationHeight,
    initialNewView,
    raw,
    id: digest(DOMAIN_DESCRIPTOR, raw),
  };
}

function decodeDescriptor(raw, source = false) {
  const cursor = new Cursor(raw);
  const value = parseDescriptor(cursor);
  cursor.finish();
  invariant(encodeDescriptor(value).equals(raw), "descriptor round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function handoffRolePreimage(descriptor, role) {
  const oldRole = role === "old";
  invariant(oldRole || role === "new", `unknown handoff role ${role}`, "gate_bug");
  return Buffer.concat([
    u(0, 2),
    descriptor.genesis,
    consensusString(descriptor.chain),
    u(oldRole ? descriptor.oldProtocolVersion : descriptor.newProtocolVersion, 4),
    u(oldRole ? descriptor.oldEpoch : descriptor.newEpoch, 8),
    oldRole ? descriptor.oldSetHash : descriptor.newSetHash,
    u(oldRole ? descriptor.terminalView : descriptor.initialNewView, 8),
    u(oldRole ? 3 : 4, 1),
    descriptor.id,
  ]);
}

function handoffRoleRoot(descriptor, role, domain = DOMAIN_HANDOFF_VOTE) {
  return digest(domain, handoffRolePreimage(descriptor, role));
}

function encodeCertificate(value) {
  return Buffer.concat([
    u(0, 2),
    value.descriptor.raw ?? encodeDescriptor(value.descriptor),
    list(value.oldSignatures, (share) => Buffer.concat([cevBytes(share.validatorId), share.signature])),
    list(value.newSignatures, (share) => Buffer.concat([cevBytes(share.validatorId), share.signature])),
  ]);
}

function parseSignatureList(cursor, role) {
  const count = cursor.count(100);
  const result = [];
  let previous = null;
  for (let index = 0; index < count; index += 1) {
    const at = cursor.offset();
    const validatorId = cursor.bytes();
    if (previous !== null && Buffer.compare(previous, validatorId) >= 0) {
      fail("noncanonical_signer_order", `${role} signer ${index}`, "decoder", at);
    }
    previous = validatorId;
    result.push({ validatorId, signature: cursor.fixed(64) });
  }
  return result;
}

function parseCertificate(cursor) {
  const start = cursor.offset();
  if (cursor.u16() !== 0) fail("invalid_schema_version", "certificate schema", "decoder", start);
  const descriptor = parseDescriptor(cursor);
  const oldSignatures = parseSignatureList(cursor, "old");
  const newSignatures = parseSignatureList(cursor, "new");
  const raw = Buffer.from(cursor.raw.subarray(start, cursor.offset()));
  return {
    descriptor,
    oldSignatures,
    newSignatures,
    raw,
    id: digest(DOMAIN_CERTIFICATE, raw),
  };
}

function decodeCertificate(raw, source = false) {
  const cursor = new Cursor(raw);
  const value = parseCertificate(cursor);
  cursor.finish();
  invariant(encodeCertificate(value).equals(raw), "certificate round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;
  return value;
}

function validateHandoffRole(certificate, role, set) {
  const shares = role === "old" ? certificate.oldSignatures : certificate.newSignatures;
  const root = handoffRoleRoot(certificate.descriptor, role);
  let power = 0n;
  for (const share of shares) {
    const validator = set.byId.get(share.validatorId.toString("hex"));
    if (validator === undefined) fail("handoff_role_mismatch", `${role} signer belongs to another set`);
    if (!verifySignature(validator.publicKey, root, share.signature)) {
      fail("invalid_signature", `${role} handoff signature is invalid`, "crypto");
    }
    power += validator.power;
  }
  if (power < set.quorumPower) {
    fail("insufficient_handoff_quorum", `${role} handoff power ${power}/${set.quorumPower}`);
  }
  return power;
}

function attachFixturePrivateKeys(set, family) {
  const byId = new Map();
  for (const validator of set.validators) {
    const id = validator.id.toString("ascii");
    const privateKey = privateKeyFromSeed(seedFor(family, id));
    invariant(
      publicKeyRaw(privateKey).equals(validator.publicKey),
      `${family} fixture public key mismatch for ${id}`,
      "source_vector_drift",
    );
    byId.set(validator.id.toString("hex"), { ...validator, privateKey });
  }
  return byId;
}

function makeValidator(id, family, power = 1n) {
  const privateKey = privateKeyFromSeed(seedFor(family, id));
  return {
    id: Buffer.from(id, "ascii"),
    publicKey: publicKeyRaw(privateKey),
    privateKey,
    power,
  };
}

function makeHeader(fields) {
  const value = { ...fields };
  value.raw = encodeHeader(value);
  value.id = digest(DOMAIN_BLOCK, value.raw);
  return value;
}

function makeQc(scope, signerMap, view, height, blockId, signerIds) {
  const root = qcVoteRoot(scope, view, height, blockId);
  const signatures = signerIds.map((id) => {
    const validator = signerMap.get(Buffer.from(id, "ascii").toString("hex"));
    invariant(validator !== undefined, `fixture QC signer ${id} is missing`, "gate_bug");
    return { validatorId: validator.id, signature: sign(validator.privateKey, root) };
  });
  const value = { ...scope, view, height, blockId, signatures };
  value.raw = encodeQc(value);
  value.id = digest(DOMAIN_QC, value.raw);
  return value;
}

function makeCertified(header, justifyQc, certifyingQc, signerMap) {
  const proposer = signerMap.get(header.proposerId.toString("hex"));
  invariant(proposer !== undefined, "fixture proposer is missing", "gate_bug");
  const value = {
    header,
    justifyQc,
    proposerSignature: sign(proposer.privateKey, proposalRoot(header, justifyQc.id)),
    certifyingQc,
  };
  value.raw = encodeCertified(value);
  return value;
}

function buildCheckpointProof(parameters, oldSet, commitment, options = {}) {
  const signerMap = attachFixturePrivateKeys(oldSet, "b2e");
  const scope = {
    genesis: oldSet.genesis,
    chain: oldSet.chain,
    protocol: oldSet.protocol,
    epoch: oldSet.epoch,
    setHash: oldSet.hash,
  };
  const checkpointState = b2eHash("checkpoint-state");
  const parentId = b2eHash("height-7-parent");
  const parentQc = makeQc(
    scope,
    signerMap,
    2n,
    7n,
    parentId,
    ["validator-a", "validator-b", "validator-c"],
  );
  const checkpointKind = options.checkpointWrongKind ? 4 : 1;
  const checkpoint = makeHeader({
    ...scope,
    view: 3n,
    height: 8n,
    kind: checkpointKind,
    parentId,
    proposerId: Buffer.from("validator-c", "ascii"),
    parametersHash: parameters.hash,
    payloadRoot: b2eHash("checkpoint-payload-root"),
    stateRoot: checkpointState,
    receiptsRoot: b2eHash("checkpoint-receipts-root"),
    evidenceRoot: b2eHash("checkpoint-evidence-root"),
    timestamp: 1000n,
    nextCommitment: options.checkpointWrongKind ? null : commitment.id,
  });
  const q0 = makeQc(
    scope,
    signerMap,
    3n,
    checkpoint.height,
    checkpoint.id,
    ["validator-a", "validator-b", "validator-c"],
  );
  const certifiedCheckpoint = makeCertified(checkpoint, parentQc, q0, signerMap);

  const seal1 = makeHeader({
    ...scope,
    view: 4n,
    height: 9n,
    kind: 2,
    parentId: checkpoint.id,
    proposerId: Buffer.from("validator-d", "ascii"),
    parametersHash: parameters.hash,
    payloadRoot: EMPTY_PAYLOAD_ROOT,
    stateRoot: checkpointState,
    receiptsRoot: EMPTY_RECEIPTS_ROOT,
    evidenceRoot: EMPTY_EVIDENCE_ROOT,
    timestamp: 2000n,
    nextCommitment: commitment.id,
  });
  const q1 = makeQc(
    scope,
    signerMap,
    4n,
    seal1.height,
    seal1.id,
    ["validator-b", "validator-c", "validator-d"],
  );
  const certifiedSeal1 = makeCertified(seal1, q0, q1, signerMap);

  const seal2 = makeHeader({
    ...scope,
    view: 5n,
    height: 10n,
    kind: 3,
    parentId: seal1.id,
    proposerId: Buffer.from("validator-a", "ascii"),
    parametersHash: parameters.hash,
    payloadRoot: EMPTY_PAYLOAD_ROOT,
    stateRoot: checkpointState,
    receiptsRoot: EMPTY_RECEIPTS_ROOT,
    evidenceRoot: EMPTY_EVIDENCE_ROOT,
    timestamp: 3000n,
    nextCommitment: commitment.id,
  });
  const q2 = makeQc(
    scope,
    signerMap,
    5n,
    seal2.height,
    seal2.id,
    ["validator-a", "validator-c", "validator-d"],
  );
  const alternateQ2 = makeQc(
    scope,
    signerMap,
    5n,
    seal2.height,
    seal2.id,
    ["validator-a", "validator-b", "validator-d"],
  );
  const certifiedSeal2 = makeCertified(seal2, q1, q2, signerMap);
  const proofValue = {
    ...scope,
    parametersHash: parameters.hash,
    finalizedBlock: certifiedCheckpoint,
    child: certifiedSeal1,
    grandchild: certifiedSeal2,
  };
  const raw = encodeFinality(proofValue);
  return { raw, alternateQ2, parentTimestamp: 500n, signerMap, scope };
}

function makeCertificate(descriptor, oldSet, newSet, options = {}) {
  const oldPrivate = attachFixturePrivateKeys(oldSet, "b2e");
  const newFamily = options.profile === "exact_fallback" ? "b2e" : "b2f";
  const newPrivate = attachFixturePrivateKeys(newSet, newFamily);
  const oldRoot = handoffRoleRoot(descriptor, "old");
  const newRoot = handoffRoleRoot(descriptor, "new");
  const oldIds = oldSet.validators
    .slice(0, options.oldQuorumLow ? 2 : 3)
    .map((validator) => validator.id.toString("ascii"));
  const newIds = newSet.validators
    .slice(0, 3)
    .map((validator) => validator.id.toString("ascii"));
  const oldSignatures = oldIds.map((id) => {
    const validator = oldPrivate.get(Buffer.from(id, "ascii").toString("hex"));
    return { validatorId: validator.id, signature: sign(validator.privateKey, oldRoot) };
  });
  const newSignatures = newIds.map((id) => {
    const validator = newPrivate.get(Buffer.from(id, "ascii").toString("hex"));
    return { validatorId: validator.id, signature: sign(validator.privateKey, newRoot) };
  });
  if (options.roleWrongRoot) {
    const validator = newPrivate.get(newSignatures[0].validatorId.toString("hex"));
    newSignatures[0].signature = sign(validator.privateKey, oldRoot);
  }
  if (options.domainWrong) {
    const validator = oldPrivate.get(oldSignatures[0].validatorId.toString("hex"));
    const wrongRoot = handoffRoleRoot(descriptor, "old", DOMAIN_QC);
    oldSignatures[0].signature = sign(validator.privateKey, wrongRoot);
  }
  if (options.signatureBitflip) {
    newSignatures[0].signature = Buffer.from(newSignatures[0].signature);
    newSignatures[0].signature[0] ^= 1;
  }
  const value = { descriptor, oldSignatures, newSignatures };
  return encodeCertificate(value);
}

function parseAuthorization(raw, oldSet, newSet, source = false) {
  const cursor = new Cursor(raw);
  const terminalHeader = parseHeader(cursor);
  const terminalQc = parseQc(cursor);
  const certificate = parseCertificate(cursor);
  cursor.finish();
  const encoded = Buffer.concat([
    encodeHeader(terminalHeader),
    encodeQc(terminalQc),
    encodeCertificate(certificate),
  ]);
  invariant(encoded.equals(raw), "authorization-kernel round-trip mismatch", "source_vector_drift");
  stats.roundTrips += 1;
  if (source) stats.sourceRawObjects += 1;

  const descriptor = certificate.descriptor;
  if (
    terminalHeader.kind !== 3 ||
    terminalQc.view !== terminalHeader.view ||
    terminalQc.height !== terminalHeader.height ||
    !terminalQc.blockId.equals(terminalHeader.id) ||
    !terminalQc.id.equals(descriptor.terminalQcDigest) ||
    terminalHeader.height !== descriptor.terminalHeight ||
    !terminalHeader.id.equals(descriptor.terminalBlockId) ||
    !terminalHeader.stateRoot.equals(descriptor.checkpointStateRoot) ||
    terminalHeader.nextCommitment === null ||
    !terminalHeader.nextCommitment.equals(descriptor.commitmentDigest)
  ) {
    fail("invalid_epoch_anchor_relations", "terminal authorization relation");
  }
  if (
    !descriptor.genesis.equals(oldSet.genesis) || !descriptor.genesis.equals(newSet.genesis) ||
    !descriptor.chain.equals(oldSet.chain) || !descriptor.chain.equals(newSet.chain) ||
    descriptor.oldProtocolVersion !== oldSet.protocol ||
    descriptor.newProtocolVersion !== newSet.protocol ||
    descriptor.oldEpoch !== oldSet.epoch || descriptor.newEpoch !== newSet.epoch ||
    !descriptor.oldSetHash.equals(oldSet.hash) || !descriptor.newSetHash.equals(newSet.hash) ||
    !descriptor.oldParametersHash.equals(oldSet.parametersHash) ||
    !descriptor.newParametersHash.equals(newSet.parametersHash)
  ) {
    fail("context_mismatch", "authorization descriptor/set binding");
  }
  return { terminalHeader, terminalQc, certificate, raw: Buffer.from(raw) };
}

function buffersEqual(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
}

function exactFallbackSet(oldSet, newSet) {
  return oldSet.validators.length === newSet.validators.length &&
    oldSet.validators.every((validator, index) => {
      const next = newSet.validators[index];
      return validator.id.equals(next.id) &&
        validator.publicKey.equals(next.publicKey) &&
        validator.power === next.power;
    });
}

function tokenFacts(proof, commitment, authorization, oldSet, newSet, oldParameters, newParameters) {
  const descriptor = authorization.certificate.descriptor;
  return {
    checkpoint_finality_proof_id_hex: proof.id.toString("hex"),
    next_epoch_commitment_digest_hex: commitment.id.toString("hex"),
    handoff_descriptor_digest_hex: descriptor.id.toString("hex"),
    handoff_certificate_digest_hex: authorization.certificate.id.toString("hex"),
    old_epoch: proof.epoch.toString(),
    new_epoch: commitment.newEpoch.toString(),
    old_validator_set_hash_hex: oldSet.hash.toString("hex"),
    new_validator_set_hash_hex: newSet.hash.toString("hex"),
    old_consensus_parameters_hash_hex: oldParameters.hash.toString("hex"),
    new_consensus_parameters_hash_hex: newParameters.hash.toString("hex"),
    checkpoint_height: proof.finalizedBlock.header.height.toString(),
    checkpoint_block_id_hex: proof.finalizedBlock.header.id.toString("hex"),
    checkpoint_state_root_hex: proof.finalizedBlock.header.stateRoot.toString("hex"),
    terminal_old_height: proof.grandchild.header.height.toString(),
    terminal_old_block_id_hex: proof.grandchild.header.id.toString("hex"),
    terminal_old_qc_digest_hex: proof.grandchild.certifyingQc.id.toString("hex"),
    activation_height: commitment.activationHeight.toString(),
    epoch_anchor_qc_output: false,
    aggregate_digest: null,
  };
}

function verifyBundle(bundle, diagnostic = null) {
  invariant(bundle.aggregate_digest_domain === null, "bundle claims an aggregate domain", "domain_mismatch");
  const oldParameters = decodeParameters(canonicalHex(
    bundle.old_consensus_parameters_cev0_hex,
    "old_consensus_parameters_cev0_hex",
  ));
  const newParameters = decodeParameters(canonicalHex(
    bundle.new_consensus_parameters_cev0_hex,
    "new_consensus_parameters_cev0_hex",
  ));
  const oldSet = decodeValidatorSet(canonicalHex(
    bundle.old_validator_set_cev0_hex,
    "old_validator_set_cev0_hex",
  ), oldParameters);
  const newSet = decodeValidatorSet(canonicalHex(
    bundle.new_validator_set_cev0_hex,
    "new_validator_set_cev0_hex",
  ), newParameters);
  const commitment = decodeCommitment(canonicalHex(
    bundle.next_epoch_commitment_cev0_hex,
    "next_epoch_commitment_cev0_hex",
  ));
  if (
    bundle.schema_version !== 0 ||
    bundle.genesis_hash_hex !== commitment.genesis.toString("hex") ||
    bundle.chain_id !== commitment.chain.toString("ascii")
  ) {
    fail("context_mismatch", "EpochHandoffProof transport context redundancy");
  }

  if (
    commitment.newProtocolVersion !== oldSet.protocol ||
    commitment.upgradePlanHash !== null ||
    oldSet.protocol !== 0 || newSet.protocol !== 0 ||
    oldParameters.fields.protocol_version !== 0 || newParameters.fields.protocol_version !== 0
  ) {
    fail("unauthorized_upgrade", "fields 1..11 cannot authorize an upgrade");
  }
  if (
    !oldSet.genesis.equals(commitment.genesis) ||
    !oldSet.chain.equals(commitment.chain) ||
    oldSet.epoch !== commitment.oldEpoch ||
    !oldSet.parametersHash.equals(oldParameters.hash)
  ) {
    fail("invalid_old_context", "old set/parameter/commitment context");
  }
  if (
    !newSet.genesis.equals(commitment.genesis) ||
    !newSet.chain.equals(commitment.chain) ||
    newSet.epoch !== commitment.newEpoch ||
    !newSet.hash.equals(commitment.newValidatorSetHash) ||
    !newSet.parametersHash.equals(commitment.newParametersHash) ||
    !newSet.parametersHash.equals(newParameters.hash)
  ) {
    fail("invalid_new_context", "new set/parameter/commitment context");
  }
  if (
    commitment.rolloutPhase !== newParameters.fields.rollout_phase ||
    commitment.newEpoch !== commitment.oldEpoch + 1n
  ) {
    fail("invalid_commitment_context", "commitment rollout or epoch relation");
  }
  if (commitment.fallbackUsed) {
    if (
      commitment.fallbackReason < 1 || commitment.fallbackReason > 9 ||
      !oldParameters.raw.equals(newParameters.raw) ||
      !exactFallbackSet(oldSet, newSet)
    ) {
      fail("invalid_commitment_context", "fallback is not an exact carry-forward");
    }
  }

  const proof = decodeFinality(canonicalHex(
    bundle.old_checkpoint_finality_cev0_hex,
    "old_checkpoint_finality_cev0_hex",
  ), oldParameters);
  const decodeParentTimestamp = BigInt(
    bundle.decode_authenticated_checkpoint_parent_timestamp_ms,
  );
  const compositionParentTimestamp = BigInt(
    bundle.composition_authenticated_checkpoint_parent_timestamp_ms,
  );
  validateFinality(
    proof,
    oldSet,
    oldParameters,
    commitment,
    decodeParentTimestamp,
  );
  const finalityFacts = compositionParentTimestamp === decodeParentTimestamp
    ? validateFinality(proof, oldSet, oldParameters, commitment, decodeParentTimestamp)
    : validateFinality(proof, oldSet, oldParameters, commitment, compositionParentTimestamp);
  const authorization = parseAuthorization(canonicalHex(
    bundle.epoch_anchor_authorization_kernel_cev0_hex,
    "epoch_anchor_authorization_kernel_cev0_hex",
  ), oldSet, newSet);

  validateQc(authorization.terminalQc, oldSet);
  validateHandoffRole(authorization.certificate, "old", oldSet);
  validateHandoffRole(authorization.certificate, "new", newSet);

  const descriptor = authorization.certificate.descriptor;
  if (
    !descriptor.genesis.equals(commitment.genesis) ||
    !descriptor.chain.equals(commitment.chain) ||
    descriptor.oldEpoch !== commitment.oldEpoch ||
    descriptor.newEpoch !== commitment.newEpoch ||
    descriptor.newProtocolVersion !== commitment.newProtocolVersion ||
    !descriptor.newSetHash.equals(commitment.newValidatorSetHash) ||
    !descriptor.newParametersHash.equals(commitment.newParametersHash) ||
    !descriptor.commitmentDigest.equals(commitment.id) ||
    descriptor.activationHeight !== commitment.activationHeight
  ) {
    fail("invalid_commitment_context", "descriptor/commitment relation");
  }
  if (
    descriptor.oldProtocolVersion !== oldSet.protocol ||
    !descriptor.oldSetHash.equals(oldSet.hash) ||
    !descriptor.oldParametersHash.equals(oldParameters.hash)
  ) {
    fail("invalid_old_context", "descriptor old context");
  }
  if (
    descriptor.newProtocolVersion !== newSet.protocol ||
    !descriptor.newSetHash.equals(newSet.hash) ||
    !descriptor.newParametersHash.equals(newParameters.hash)
  ) {
    fail("invalid_new_context", "descriptor new context");
  }
  const checkpoint = finalityFacts.checkpoint.header;
  if (
    descriptor.checkpointHeight !== checkpoint.height ||
    !descriptor.checkpointBlockId.equals(checkpoint.id) ||
    !descriptor.checkpointStateRoot.equals(checkpoint.stateRoot) ||
    !descriptor.commitmentDigest.equals(commitment.id) ||
    descriptor.activationHeight !== finalityFacts.activationHeight
  ) {
    fail("checkpoint_handoff_mismatch", "descriptor/checkpoint relation");
  }
  const terminal = finalityFacts.seal2;
  if (
    descriptor.terminalHeight !== terminal.header.height ||
    !descriptor.terminalBlockId.equals(terminal.header.id) ||
    !descriptor.terminalQcDigest.equals(terminal.certifyingQc.id) ||
    !authorization.terminalHeader.id.equals(terminal.header.id) ||
    !authorization.terminalQc.id.equals(terminal.certifyingQc.id)
  ) {
    if (
      diagnostic?.alternate_terminal_qc_digest_hex === descriptor.terminalQcDigest.toString("hex")
    ) {
      fail("exact_qc_substitution", "another valid QC subset is not the embedded certifying QC");
    }
    fail("terminal_handoff_mismatch", "descriptor/terminal exact relation");
  }
  return tokenFacts(proof, commitment, authorization, oldSet, newSet, oldParameters, newParameters);
}

function bundleFromRaw({
  oldParametersRaw,
  newParametersRaw,
  oldSetRaw,
  newSetRaw,
  commitmentRaw,
  proofRaw,
  authorizationRaw,
  parentTimestamp,
}) {
  return {
    schema_version: 0,
    genesis_hash_hex: null,
    chain_id: null,
    old_consensus_parameters_cev0_hex: oldParametersRaw.toString("hex"),
    new_consensus_parameters_cev0_hex: newParametersRaw.toString("hex"),
    old_validator_set_cev0_hex: oldSetRaw.toString("hex"),
    new_validator_set_cev0_hex: newSetRaw.toString("hex"),
    next_epoch_commitment_cev0_hex: commitmentRaw.toString("hex"),
    old_checkpoint_finality_cev0_hex: proofRaw.toString("hex"),
    epoch_anchor_authorization_kernel_cev0_hex: authorizationRaw.toString("hex"),
    decode_authenticated_checkpoint_parent_timestamp_ms: parentTimestamp.toString(),
    composition_authenticated_checkpoint_parent_timestamp_ms: parentTimestamp.toString(),
    aggregate_digest_domain: null,
  };
}

function buildComposition(profile, b2eCorpus, options = {}) {
  const oldParametersRaw = canonicalHex(
    b2eCorpus.valid_objects.consensus_parameters.cev0_hex,
    "B2-E parameters",
  );
  const newParametersRaw = Buffer.from(oldParametersRaw);
  const oldParameters = decodeParameters(oldParametersRaw);
  const newParameters = decodeParameters(newParametersRaw);
  const oldSetRaw = canonicalHex(
    b2eCorpus.valid_objects.old_validator_set.cev0_hex,
    "B2-E old set",
  );
  const oldSet = decodeValidatorSet(oldSetRaw, oldParameters);
  const newEpoch = oldSet.epoch + 1n;
  const epochEndHeight = newEpoch * oldParameters.fields.epoch_length_blocks;
  const checkpointHeight = epochEndHeight - BigInt(oldParameters.fields.epoch_seal_blocks);
  const snapshotCutoffHeight = checkpointHeight - oldParameters.fields.snapshot_lead_blocks;
  const activationHeight = epochEndHeight + 1n;

  let newValidators;
  let newFamily;
  if (profile === "exact_fallback") {
    newFamily = "b2e";
    newValidators = oldSet.validators.map((validator) => ({ ...validator }));
  } else {
    newFamily = "b2f";
    newValidators = ["next-a", "next-b", "next-c", "next-d"].map((id) =>
      makeValidator(id, newFamily),
    );
  }
  const intendedSetRaw = encodeValidatorSet({
    genesis: oldSet.genesis,
    chain: oldSet.chain,
    protocol: 0,
    epoch: newEpoch,
    parametersHash: newParameters.hash,
    validators: newValidators,
  });
  const intendedSet = decodeValidatorSet(intendedSetRaw, newParameters);

  const commitmentValue = {
    genesis: oldSet.genesis,
    chain: oldSet.chain,
    oldEpoch: oldSet.epoch,
    newEpoch,
    snapshotCutoffHeight,
    snapshotStateRoot: b2eHash("snapshot-state-root"),
    newProtocolVersion: options.upgrade ? 1 : 0,
    newValidatorSetHash: intendedSet.hash,
    newParametersHash: newParameters.hash,
    rolloutPhase: newParameters.fields.rollout_phase,
    upgradePlanHash: options.upgrade ? b2eHash("unauthorized-upgrade") : null,
    fallbackUsed: profile === "exact_fallback",
    fallbackReason: profile === "exact_fallback" ? 8 : 0,
    activationHeight,
  };
  const commitmentRaw = encodeCommitment(commitmentValue);
  const commitment = decodeCommitment(commitmentRaw);
  const checkpoint = buildCheckpointProof(oldParameters, oldSet, commitment, options);
  const proof = decodeFinality(checkpoint.raw, oldParameters);

  let suppliedSet = intendedSet;
  let suppliedSetRaw = intendedSetRaw;
  if (options.commitmentSetMismatch) {
    const validators = ["foreign-a", "foreign-b", "foreign-c", "foreign-d"].map((id) =>
      makeValidator(id, "b2f"),
    );
    suppliedSetRaw = encodeValidatorSet({
      genesis: oldSet.genesis,
      chain: oldSet.chain,
      protocol: 0,
      epoch: newEpoch,
      parametersHash: newParameters.hash,
      validators,
    });
    suppliedSet = decodeValidatorSet(suppliedSetRaw, newParameters);
    newFamily = "b2f";
  }

  let terminalHeader = proof.grandchild.header;
  let terminalQc = proof.grandchild.certifyingQc;
  if (options.foreignTerminal) {
    terminalHeader = makeHeader({
      ...checkpoint.scope,
      view: 5n,
      height: 10n,
      kind: 3,
      parentId: b2eHash("foreign-terminal-parent"),
      proposerId: Buffer.from("validator-a", "ascii"),
      parametersHash: oldParameters.hash,
      payloadRoot: EMPTY_PAYLOAD_ROOT,
      stateRoot: proof.finalizedBlock.header.stateRoot,
      receiptsRoot: EMPTY_RECEIPTS_ROOT,
      evidenceRoot: EMPTY_EVIDENCE_ROOT,
      timestamp: 3000n,
      nextCommitment: commitment.id,
    });
    terminalQc = makeQc(
      checkpoint.scope,
      checkpoint.signerMap,
      5n,
      terminalHeader.height,
      terminalHeader.id,
      ["validator-a", "validator-b", "validator-c"],
    );
  }
  if (options.substituteTerminalQc) terminalQc = checkpoint.alternateQ2;

  const descriptorValue = {
    genesis: oldSet.genesis,
    chain: oldSet.chain,
    oldEpoch: oldSet.epoch,
    newEpoch,
    oldProtocolVersion: 0,
    // Field 12 is absent in B2-F. Keep the independently decodable
    // authorization at v0 so the kernel itself rejects the v1 commitment.
    newProtocolVersion: 0,
    oldSetHash: oldSet.hash,
    newSetHash: suppliedSet.hash,
    oldParametersHash: oldParameters.hash,
    newParametersHash: newParameters.hash,
    checkpointHeight: proof.finalizedBlock.header.height,
    checkpointBlockId: proof.finalizedBlock.header.id,
    checkpointStateRoot: proof.finalizedBlock.header.stateRoot,
    commitmentDigest: commitment.id,
    terminalHeight: terminalHeader.height,
    terminalBlockId: terminalHeader.id,
    terminalQcDigest: terminalQc.id,
    terminalView: terminalHeader.view,
    activationHeight,
    initialNewView: 1n,
  };
  const descriptorRaw = encodeDescriptor(descriptorValue);
  const descriptor = decodeDescriptor(descriptorRaw);
  const certificateRaw = makeCertificate(descriptor, oldSet, suppliedSet, {
    ...options,
    profile,
    newFamily,
  });
  const authorizationRaw = Buffer.concat([
    terminalHeader.raw,
    terminalQc.raw,
    certificateRaw,
  ]);
  const bundle = bundleFromRaw({
    oldParametersRaw,
    newParametersRaw,
    oldSetRaw,
    newSetRaw: suppliedSetRaw,
    commitmentRaw,
    proofRaw: checkpoint.raw,
    authorizationRaw,
    parentTimestamp: checkpoint.parentTimestamp,
  });
  bundle.genesis_hash_hex = oldSet.genesis.toString("hex");
  bundle.chain_id = oldSet.chain.toString("ascii");
  return {
    bundle,
    diagnostic: {
      alternate_terminal_qc_digest_hex: checkpoint.alternateQ2.id.toString("hex"),
      role_wrong_root: options.roleWrongRoot === true,
      domain_wrong: options.domainWrong === true,
    },
  };
}

function assertDigestClaim(raw, domain, claimed, label) {
  invariant(
    digest(domain, raw).equals(canonicalHex(claimed, `${label}.digest`)),
    `${label} digest claim differs from raw bytes`,
    "source_vector_drift",
  );
}

function verifyB2BSource(corpus, parserCorpus) {
  invariant(
    parserCorpus.schema === "trnm_poco_bft_cev0_parser_anchor_handoff_kernel_vectors_v0" &&
      parserCorpus.cryptographic_validity_claimed === false &&
      parserCorpus.valid_raw_objects.length === 6 &&
      parserCorpus.trusted_output_and_candidate_bindings.every(
        (item) => item.b2b_decoder_output === false,
      ),
    "B2-B parser corpus identity/output policy drift",
    "source_vector_drift",
  );
  const oldSet = decodeValidatorSet(canonicalHex(corpus.validator_sets.old.cev0_hex, "B2-B old set"), null, true);
  const newSet = decodeValidatorSet(canonicalHex(corpus.validator_sets.new.cev0_hex, "B2-B new set"), null, true);
  invariant(oldSet.hash.toString("hex") === corpus.validator_sets.old.validator_set_id_hex, "B2-B old set hash drift", "source_vector_drift");
  invariant(newSet.hash.toString("hex") === corpus.validator_sets.new.validator_set_id_hex, "B2-B new set hash drift", "source_vector_drift");

  const header = decodeHeader(canonicalHex(corpus.terminal_old_header.cev0_hex, "B2-B terminal header"), null, true);
  invariant(header.id.toString("hex") === corpus.terminal_old_header.block_id_hex, "B2-B terminal block ID drift", "source_vector_drift");
  const qc = decodeQc(canonicalHex(corpus.terminal_old_qcs.exact_7.cev0_hex, "B2-B terminal QC"), null, true);
  invariant(qc.id.toString("hex") === corpus.terminal_old_qcs.exact_7.digest_hex, "B2-B terminal QC digest drift", "source_vector_drift");
  validateQc(qc, oldSet);

  const descriptor = decodeDescriptor(canonicalHex(corpus.handoff_descriptor.cev0_hex, "B2-B descriptor"), true);
  invariant(descriptor.id.toString("hex") === corpus.handoff_descriptor.digest_hex, "B2-B descriptor digest drift", "source_vector_drift");
  const certificate = decodeCertificate(canonicalHex(corpus.handoff_certificate_exact_7.cev0_hex, "B2-B certificate"), true);
  invariant(certificate.id.toString("hex") === corpus.handoff_certificate_exact_7.digest_hex, "B2-B certificate digest drift", "source_vector_drift");
  invariant(certificate.descriptor.raw.equals(descriptor.raw), "B2-B certificate descriptor substitution", "source_vector_drift");
  validateHandoffRole(certificate, "old", oldSet);
  validateHandoffRole(certificate, "new", newSet);

  const authorizationRaw = canonicalHex(corpus.epoch_anchor_authorization.cev0_hex, "B2-B authorization");
  invariant(
    corpus.epoch_anchor_authorization.digest_domain === null &&
      corpus.epoch_anchor_authorization.digest_hex === null,
    "B2-B authorization unexpectedly acquired a domain",
    "source_vector_drift",
  );
  const authorization = parseAuthorization(authorizationRaw, oldSet, newSet, true);
  invariant(authorization.terminalHeader.raw.equals(header.raw), "B2-B authorization header drift", "source_vector_drift");
  invariant(authorization.terminalQc.raw.equals(qc.raw), "B2-B authorization QC drift", "source_vector_drift");
  invariant(authorization.certificate.raw.equals(certificate.raw), "B2-B authorization certificate drift", "source_vector_drift");
}

function b2cSet(corpus, profile, role, commitment) {
  const context = corpus.context_profiles[profile][`${role}_set`];
  const template = corpus.validator_templates[context.validator_template];
  const value = {
    genesis: commitment.genesis,
    chain: commitment.chain,
    protocol: Number(context.protocol_version),
    epoch: BigInt(context.epoch),
    parametersHash: canonicalHex(context.consensus_parameters_hash_hex, `${profile}.${role}.parameters`),
    validators: template.map((validator) => ({
      id: canonicalHex(validator.validator_id_hex, `${profile}.${role}.id`),
      publicKey: canonicalHex(validator.consensus_public_key_hex, `${profile}.${role}.key`),
      power: BigInt(validator.effective_weight),
    })),
  };
  const raw = encodeValidatorSet(value);
  const set = decodeValidatorSet(raw);
  invariant(set.hash.toString("hex") === context.expected_validator_set_hash_hex, `${profile}.${role} set hash drift`, "source_vector_drift");
  return set;
}

function verifyB2CSource(corpus) {
  invariant(
    corpus.schema === "trnm_poco_bft_next_epoch_commitment_kernel_vectors_v0" &&
      corpus.valid_raw_objects.length === 3,
    "B2-C corpus identity drift",
    "source_vector_drift",
  );
  const decoded = new Map();
  for (const item of corpus.valid_raw_objects) {
    const raw = canonicalHex(item.cev0_hex, `B2-C ${item.id}`);
    const commitment = decodeCommitment(raw, true);
    assertDigestClaim(raw, DOMAIN_COMMITMENT, item.digest_hex, `B2-C ${item.id}`);
    decoded.set(item.id, commitment);
  }
  const normal = decoded.get("normal_same_version_no_upgrade");
  const normalOld = b2cSet(corpus, "normal_same_version", "old", normal);
  const normalNew = b2cSet(corpus, "normal_same_version", "new", normal);
  invariant(!exactFallbackSet(normalOld, normalNew), "B2-C normal context is not distinct-set", "source_vector_drift");
  invariant(normal.newValidatorSetHash.equals(normalNew.hash), "B2-C normal commitment/set relation", "source_vector_drift");

  const fallback = decoded.get("fallback_same_version");
  const fallbackOld = b2cSet(corpus, "fallback_same_version", "old", fallback);
  const fallbackNew = b2cSet(corpus, "fallback_same_version", "new", fallback);
  invariant(
    fallback.fallbackUsed && fallback.fallbackReason === 8 &&
      exactFallbackSet(fallbackOld, fallbackNew) &&
      fallback.newValidatorSetHash.equals(fallbackNew.hash) &&
      corpus.context_profiles.fallback_same_version.old_parameters.hash_hex ===
        corpus.context_profiles.fallback_same_version.new_parameters.hash_hex,
    "B2-C exact-fallback relation drift",
    "source_vector_drift",
  );
}

function verifyB2ESource(corpus) {
  invariant(
    corpus.schema === "trnm_poco_bft_checkpoint_two_seal_kernel_vectors_v0" &&
      corpus.real_ed25519_checks.total_signature_verifications === 21,
    "B2-E corpus identity drift",
    "source_vector_drift",
  );
  const rawParameters = canonicalHex(corpus.valid_objects.consensus_parameters.cev0_hex, "B2-E parameters");
  const parameters = decodeParameters(rawParameters, true);
  const leadTwoParameters = encodeParameters({
    ...parameters.fields,
    snapshot_lead_blocks: 2n,
  });
  try {
    decodeParameters(leadTwoParameters);
    fail("negative_accepted", "B2-F accepted snapshot lead shorter than finality chain", "gate");
  } catch (error) {
    invariant(
      error instanceof GateError && error.code === "invalid_consensus_parameters",
      "B2-F lead-two parameter negative rejected for the wrong reason",
      "negative_expectation_drift",
    );
  }
  assertDigestClaim(rawParameters, DOMAIN_PARAMETERS, corpus.valid_objects.consensus_parameters.digest_hex, "B2-E parameters");
  const rawSet = canonicalHex(corpus.valid_objects.old_validator_set.cev0_hex, "B2-E old set");
  const set = decodeValidatorSet(rawSet, parameters, true);
  assertDigestClaim(rawSet, DOMAIN_VALIDATOR_SET, corpus.valid_objects.old_validator_set.digest_hex, "B2-E old set");
  const rawCommitment = canonicalHex(corpus.valid_objects.next_epoch_commitment.cev0_hex, "B2-E commitment");
  const commitment = decodeCommitment(rawCommitment, true);
  assertDigestClaim(rawCommitment, DOMAIN_COMMITMENT, corpus.valid_objects.next_epoch_commitment.digest_hex, "B2-E commitment");
  const rawProof = canonicalHex(corpus.valid_objects.checkpoint_finality_proof.cev0_hex, "B2-E finality");
  const proof = decodeFinality(rawProof, parameters, true);
  assertDigestClaim(rawProof, DOMAIN_FINALITY, corpus.valid_objects.checkpoint_finality_proof.digest_hex, "B2-E finality");
  validateFinality(
    proof,
    set,
    parameters,
    commitment,
    BigInt(corpus.fixture.authenticated_checkpoint_parent_timestamp_ms),
  );
}

function stripProtoComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function protoMessageFields(filename, messageName) {
  const source = stripProtoComments(fs.readFileSync(filename, "utf8"));
  const marker = new RegExp(`\\bmessage\\s+${messageName}\\s*\\{`, "m");
  const match = marker.exec(source);
  invariant(match !== null, `protobuf message ${messageName} is missing`, "projection_drift");
  const open = source.indexOf("{", match.index);
  let depth = 1;
  let end = open + 1;
  while (end < source.length && depth > 0) {
    if (source[end] === "{") depth += 1;
    else if (source[end] === "}") depth -= 1;
    end += 1;
  }
  invariant(depth === 0, `protobuf message ${messageName} is unterminated`, "projection_drift");
  const body = source.slice(open + 1, end - 1);
  const fields = [];
  const regex = /\b(repeated\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([0-9]+)\s*;/g;
  for (const field of body.matchAll(regex)) {
    fields.push({
      number: Number(field[4]),
      name: field[3],
      proto_type: field[2],
      cardinality: field[1] === undefined ? "singular" : "repeated",
    });
  }
  return { fields, body };
}

function validateManifests(schema, vectors) {
  invariant(
    schema.schema === "trnm_poco_bft_cev0_logical_schema_joint_handoff_kernel_v0" &&
      schema.schema_version === 0 &&
      schema.aggregate_cev0.canonical_preimage === null &&
      schema.aggregate_cev0.digest_domain === null &&
      schema.aggregate_cev0.digest_field === null &&
      schema.composition.authorization_output === false,
    "B2-F logical schema identity or inert-output policy drift",
  );
  invariant(
    vectors.schema === "trnm_poco_bft_joint_handoff_composition_kernel_vectors_v0" &&
      vectors.schema_version === 0 &&
      vectors.aggregate_cev0 === false &&
      vectors.aggregate_digest_domain === null &&
      vectors.aggregate_digest === null,
    "B2-F vector identity or aggregate-domain policy drift",
  );
  const domains = new Set(schema.nested_domains);
  const expectedDomains = new Set([
    DOMAIN_PARAMETERS,
    DOMAIN_VALIDATOR_SET,
    DOMAIN_BLOCK,
    DOMAIN_VOTE,
    DOMAIN_QC,
    DOMAIN_PROPOSAL,
    DOMAIN_FINALITY,
    DOMAIN_COMMITMENT,
    DOMAIN_DESCRIPTOR,
    DOMAIN_HANDOFF_VOTE,
    DOMAIN_CERTIFICATE,
  ]);
  invariant(
    domains.size === expectedDomains.size && [...domains].every((domain) => expectedDomains.has(domain)),
    "B2-F nested domain set drift",
    "domain_mismatch",
  );
  invariant(
    schema.forbidden_aggregate_domains.every((domain) => !domains.has(domain)),
    "aggregate domain entered nested domain set",
    "domain_mismatch",
  );
  const classes = schema.rejection_classes.map((item) => item.class);
  invariant(
    JSON.stringify(classes) === JSON.stringify([
      "checkpoint", "terminal", "commitment", "context", "substitution",
      "quorum", "role", "domain", "signature", "upgrade",
    ]),
    "B2-F rejection class set drift",
  );

  const parsed = protoMessageFields(LIGHT_PROTO_PATH, "EpochHandoffProof");
  const locked = schema.transport_projection.fields;
  invariant(locked.length === 11, "EpochHandoffProof field lock is not 1..11", "projection_drift");
  for (let number = 1; number <= 11; number += 1) {
    const actual = parsed.fields.find((field) => field.number === number);
    const expected = locked[number - 1];
    invariant(
      actual !== undefined && expected.number === number &&
        actual.name === expected.name && actual.proto_type === expected.proto_type &&
        actual.cardinality === expected.cardinality && typeof expected.role === "string",
      `EpochHandoffProof field ${number} projection/role drift`,
      "projection_drift",
    );
  }
  for (const expected of schema.transport_projection.deferred_fields) {
    const actual = parsed.fields.find((field) => field.number === expected.number);
    invariant(actual?.name === expected.name, `deferred field ${expected.number} drift`, "projection_drift");
  }
  invariant(
    !parsed.fields.some((field) => field.number === 15) && /reserved\s+15\s*;/.test(parsed.body),
    "removed aggregate digest field 15 is not reserved",
    "projection_drift",
  );
  stats.protoFields = 11;

  invariant(vectors.source_corpora.length === 4, "source corpus count drift", "source_vector_drift");
  for (const source of vectors.source_corpora) {
    const filename = path.join(DOC_ROOT, "vectors", source.path);
    invariant(rawSha256(filename) === source.sha256, `${source.tranche} corpus SHA-256 drift`, "source_vector_drift");
  }
}

const NEGATIVE_BUILDERS = new Map([
  ["checkpoint_parent_timestamp_mismatch", { mutation: "composition_timestamp", node: "invalid_checkpoint_finality", rust: "invalid_checkpoint_finality", stage: "composition" }],
  ["terminal_foreign_block", { options: { foreignTerminal: true }, node: "terminal_handoff_mismatch", rust: "terminal_handoff_mismatch", stage: "composition" }],
  ["commitment_new_set_hash_mismatch", { options: { commitmentSetMismatch: true }, node: "invalid_new_context", rust: "invalid_new_context", stage: "composition" }],
  ["new_parameters_context_mismatch", { mutation: "new_parameters", node: "context_mismatch", rust: "invalid_new_context", stage: "composition" }],
  ["terminal_valid_qc_subset_substitution", { options: { substituteTerminalQc: true }, node: "exact_qc_substitution", rust: "terminal_handoff_mismatch", stage: "composition" }],
  ["old_role_one_below_quorum", { options: { oldQuorumLow: true }, node: "insufficient_handoff_quorum", rust: "insufficient_quorum", stage: "decode" }],
  ["new_role_uses_old_root", { options: { roleWrongRoot: true }, node: "handoff_role_mismatch", rust: "invalid_signature", stage: "composition" }],
  ["handoff_signature_qc_domain", { options: { domainWrong: true }, node: "domain_mismatch", rust: "invalid_signature", stage: "composition" }],
  ["new_role_signature_bitflip", { options: { signatureBitflip: true }, node: "invalid_signature", rust: "invalid_signature", stage: "composition" }],
  ["version_change_without_field_12", { options: { upgrade: true }, node: "unauthorized_upgrade", rust: "unsupported_protocol_upgrade", stage: "composition" }],
]);

function mutateNewParameters(bundle) {
  const result = structuredClone(bundle);
  const original = decodeParameters(canonicalHex(
    result.new_consensus_parameters_cev0_hex,
    "context negative parameters",
  ));
  const fields = { ...original.fields, base_timeout_ms: original.fields.base_timeout_ms + 1n };
  result.new_consensus_parameters_cev0_hex = encodeParameters(fields).toString("hex");
  return result;
}

function buildNegativeCase(specification, b2eCorpus) {
  const builder = NEGATIVE_BUILDERS.get(specification.id);
  invariant(builder !== undefined, `unknown negative ${specification.id}`, "manifest_drift");
  const built = buildComposition("distinct_set", b2eCorpus, builder.options ?? {});
  if (builder.mutation === "new_parameters") built.bundle = mutateNewParameters(built.bundle);
  if (builder.mutation === "composition_timestamp") {
    built.bundle.composition_authenticated_checkpoint_parent_timestamp_ms = "1000";
  }
  return {
    ...built,
    expectedNode: builder.node,
    expectedRust: builder.rust,
    expectedRustStage: builder.stage,
  };
}

function oldHandoffCountOffset(bundle) {
  const raw = canonicalHex(
    bundle.epoch_anchor_authorization_kernel_cev0_hex,
    "quorum negative authorization",
  );
  const cursor = new Cursor(raw);
  parseHeader(cursor);
  parseQc(cursor);
  const certificateStart = cursor.offset();
  invariant(cursor.u16() === 0, "certificate schema while locating old count", "gate_bug");
  parseDescriptor(cursor);
  invariant(cursor.offset() > certificateStart, "old count offset did not advance", "gate_bug");
  return cursor.offset();
}

function classifyExpectedFailure(specification, built, operation) {
  try {
    operation();
  } catch (error) {
    if (!(error instanceof GateError)) throw error;
    let observed = error.code;
    if (specification.id === "new_role_uses_old_root" && observed === "invalid_signature") {
      observed = "handoff_role_mismatch";
    }
    if (specification.id === "handoff_signature_qc_domain" && observed === "invalid_signature") {
      observed = "domain_mismatch";
    }
    if (specification.id === "terminal_foreign_block" && observed === "terminal_handoff_mismatch") {
      observed = "terminal_handoff_mismatch";
    }
    invariant(
      observed === built.expectedNode,
      `${specification.id} rejected as ${error.code}/${observed}, expected ${built.expectedNode}`,
      "negative_expectation_drift",
    );
    stats.negativeCases += 1;
    if (built.expectedRustStage === "composition") {
      stats.compositionNegativeCases += 1;
    } else {
      invariant(
        built.expectedRustStage === "decode",
        `${specification.id} has unsupported Rust stage ${built.expectedRustStage}`,
        "manifest_drift",
      );
      stats.decodeNegativeCases += 1;
    }
    stats.negativeClasses.add(specification.class);
    return;
  }
  fail("negative_accepted", specification.id, "gate");
}

function emittedCases(vectors, b2eCorpus) {
  const positive_cases = vectors.positive_cases.map((specification) => {
    const built = buildComposition(specification.id, b2eCorpus);
    const expected = verifyBundle(built.bundle, built.diagnostic);
    return { ...specification, raw_bundle: built.bundle, expected_token_facts: expected };
  });
  const negative_cases = vectors.negative_cases.map((specification) => {
    const built = buildNegativeCase(specification, b2eCorpus);
    return {
      ...specification,
      raw_bundle: built.bundle,
      expected_node_code: built.expectedNode,
      expected_rust_code: built.expectedRust,
      expected_rust_stage: built.expectedRustStage,
      ...(built.expectedRustStage === "decode"
        ? { expected_rust_offset: oldHandoffCountOffset(built.bundle) }
        : {}),
    };
  });
  return { positive_cases, negative_cases };
}

function canonicalComparable(value) {
  return JSON.stringify(value);
}

function main() {
  const schema = readJson(SCHEMA_PATH);
  const vectors = readJson(VECTOR_PATH);
  validateManifests(schema, vectors);

  const byTranche = new Map(vectors.source_corpora.map((item) => [item.tranche, item]));
  const loadSource = (tranche) => readJson(path.join(DOC_ROOT, "vectors", byTranche.get(tranche).path));
  const parserCorpus = loadSource("B2-B-parser");
  const b2bCorpus = loadSource("B2-B-crypto");
  const b2cCorpus = loadSource("B2-C");
  const b2eCorpus = loadSource("B2-E");
  verifyB2BSource(b2bCorpus, parserCorpus);
  stats.sourceCorpora += 2;
  verifyB2CSource(b2cCorpus);
  stats.sourceCorpora += 1;
  verifyB2ESource(b2eCorpus);
  stats.sourceCorpora += 1;

  const generated = emittedCases(vectors, b2eCorpus);
  if (process.argv.includes("--emit-corpus")) {
    process.stdout.write(`${JSON.stringify(generated, null, 2)}\n`);
    return;
  }

  for (let index = 0; index < vectors.positive_cases.length; index += 1) {
    const committed = vectors.positive_cases[index];
    const expected = generated.positive_cases[index];
    invariant(committed.raw_bundle !== undefined, `${committed.id} raw_bundle is not committed`, "manifest_drift");
    invariant(
      canonicalComparable(committed.raw_bundle) === canonicalComparable(expected.raw_bundle),
      `${committed.id} raw_bundle differs from independent generator`,
      "source_vector_drift",
    );
    const token = verifyBundle(committed.raw_bundle);
    invariant(
      canonicalComparable(committed.expected_token_facts) === canonicalComparable(token),
      `${committed.id} token facts drift`,
      "source_vector_drift",
    );
    stats.positiveCases += 1;
  }
  for (let index = 0; index < vectors.negative_cases.length; index += 1) {
    const committed = vectors.negative_cases[index];
    const expected = generated.negative_cases[index];
    invariant(committed.raw_bundle !== undefined, `${committed.id} raw_bundle is not committed`, "manifest_drift");
    invariant(
      canonicalComparable(committed.raw_bundle) === canonicalComparable(expected.raw_bundle) &&
        committed.expected_node_code === expected.expected_node_code &&
        committed.expected_rust_code === expected.expected_rust_code &&
        committed.expected_rust_stage === expected.expected_rust_stage &&
        committed.expected_rust_offset === expected.expected_rust_offset,
      `${committed.id} committed negative drift`,
      "source_vector_drift",
    );
    const built = buildNegativeCase(committed, b2eCorpus);
    classifyExpectedFailure(committed, built, () => verifyBundle(committed.raw_bundle, built.diagnostic));
  }

  const expectedStats = vectors.expected_gate_statistics;
  invariant(stats.protoFields === expectedStats.proto_fields_locked, "proto field statistic drift");
  invariant(stats.sourceCorpora === expectedStats.source_corpora, "source corpus statistic drift");
  invariant(stats.sourceRawObjects >= expectedStats.source_raw_objects_minimum, "source raw-object statistic drift");
  invariant(stats.positiveCases === expectedStats.positive_cases, "positive statistic drift");
  invariant(stats.negativeCases === expectedStats.negative_cases, "negative statistic drift");
  invariant(stats.negativeClasses.size === expectedStats.negative_classes, "negative class statistic drift");
  invariant(
    stats.compositionNegativeCases === expectedStats.composition_negative_cases,
    "composition-negative statistic drift",
  );
  invariant(
    stats.decodeNegativeCases === expectedStats.decode_negative_cases,
    "decode-negative statistic drift",
  );

  process.stdout.write(
    [
      "PoCO-BFT v0 B2-F joint-handoff schema gate passed:",
      `${stats.protoFields} EpochHandoffProof fields locked`,
      `${stats.sourceCorpora} source corpora`,
      `${stats.sourceRawObjects} source raw objects`,
      `${stats.roundTrips} exact CEV0 round-trips`,
      `${stats.digestChecks} digest computations`,
      `${stats.signatureChecks} Ed25519 verifications`,
      `${stats.positiveCases} positives`,
      `${stats.negativeCases} negatives/${stats.negativeClasses.size} classes`,
      "authorization_outputs=0",
      "aggregate_domains=0",
    ].join(" ") + "\n",
  );
}

export {
  decodeCommitment,
  decodeFinality,
  decodeHeader,
  decodeParameters,
  decodeValidatorSet,
  encodeCommitment,
  parseAuthorization,
  proposalRoot,
  qcVoteRoot,
  validateCertified,
  validateFinality,
  verifyBundle,
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    if (error instanceof GateError) {
      process.stderr.write(`${error.layer}: ${error.message}\n`);
      process.exit(1);
    }
    throw error;
  }
}
