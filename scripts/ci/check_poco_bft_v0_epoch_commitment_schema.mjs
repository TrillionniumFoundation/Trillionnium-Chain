#!/usr/bin/env node

// Independent B2-C exact CEV0/parser/projection gate for
// NextEpochCommitmentV0. Standard-library only. The decoded value and the
// same-version relation result are deliberately inert: this file has no path
// that constructs an epoch anchor or a trusted transition capability.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "../..");
const BASE_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-v0.json",
);
const B2B_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-anchor-handoff-v0.json",
);
const SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-epoch-commitment-v0.json",
);
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/next-epoch-commitment-kernel-v0.json",
);
const EPOCH_PROTO_PATH = path.join(
  REPO_ROOT,
  "proto/trnm/poco/bft/v0/epoch.proto",
);
const COMMON_PROTO_PATH = path.join(
  REPO_ROOT,
  "proto/trnm/poco/bft/v0/common.proto",
);
const RUST_DECODER_PATH = path.join(
  REPO_ROOT,
  "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs",
);
const RUST_EPOCH_PATH = path.join(
  REPO_ROOT,
  "trillionnium/crates/trnm-consensus-types/src/epoch.rs",
);

const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const DOMAIN_EPOCH_COMMITMENT = "trnm.poco-bft.epoch-commitment.v0";
const DOMAIN_VALIDATOR_SET = "trnm.poco-bft.validator-set.v0";
const V0_FINALITY_CERTIFIED_CHAIN_LENGTH = 3n;
const U64_MAX = (1n << 64n) - 1n;
const META = Symbol("b2c_meta");

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

function canonicalDecimal(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    fail("source_vector_drift", 0, `${label} is not canonical decimal text`, "gate");
  }
  return BigInt(value);
}

function canonicalHex(value, label, bytes = null) {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]*$/.test(value)
  ) {
    fail("source_vector_drift", 0, `${label} is not lowercase hex`, "gate");
  }
  const decoded = Buffer.from(value, "hex");
  if (decoded.toString("hex") !== value || (bytes !== null && decoded.length !== bytes)) {
    fail("source_vector_drift", 0, `${label} has a noncanonical width`, "gate");
  }
  return decoded;
}

function cloneValue(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneValue(item)]),
    );
  }
  return value;
}

function bytesEqual(first, second) {
  return Buffer.isBuffer(first) && Buffer.isBuffer(second) && first.equals(second);
}

function encodeUnsigned(value, width) {
  let remaining = typeof value === "bigint" ? value : BigInt(value);
  const limit = 1n << BigInt(width * 8);
  if (remaining < 0n || remaining >= limit) {
    fail("source_vector_drift", 0, `${value} does not fit u${width * 8}`, "gate");
  }
  const result = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function frame(value) {
  return Buffer.concat([encodeUnsigned(value.length, 4), value]);
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

function isZero(value) {
  return value.every((byte) => byte === 0);
}

function compareBytes(first, second) {
  return Buffer.compare(first, second);
}

class Decoder {
  constructor(buffer) {
    this.buffer = buffer;
    this.offset = 0;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0) {
      fail("length_limit_exceeded", this.offset, "invalid length");
    }
    if (length > this.buffer.length - this.offset) {
      fail("unexpected_eof", this.buffer.length, `need ${length} bytes`);
    }
    const start = this.offset;
    this.offset += length;
    return this.buffer.subarray(start, this.offset);
  }

  unsigned(width) {
    const raw = this.take(width);
    let value = 0n;
    for (const byte of raw) value = (value << 8n) | BigInt(byte);
    return value;
  }

  hash32() {
    return this.take(32);
  }

  consensusString() {
    const lengthOffset = this.offset;
    const length = Number(this.unsigned(2));
    if (length > 128) {
      fail(
        "length_limit_exceeded",
        lengthOffset,
        `ConsensusString length ${length} exceeds 128`,
      );
    }
    const value = this.take(length);
    if (
      value.length === 0 ||
      !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(value.toString("latin1"))
    ) {
      fail(
        "invalid_consensus_string",
        lengthOffset,
        "ConsensusString violates the frozen ASCII grammar",
      );
    }
    return value;
  }

  optionalHash32() {
    const tagOffset = this.offset;
    const tag = Number(this.unsigned(1));
    if (tag === 0) return null;
    if (tag !== 1) {
      fail("invalid_optional_tag", tagOffset, `optional tag ${tag} is not 0 or 1`);
    }
    return this.hash32();
  }

  boolean() {
    const boolOffset = this.offset;
    const value = Number(this.unsigned(1));
    if (value !== 0 && value !== 1) {
      fail("invalid_boolean", boolOffset, `boolean discriminant ${value} is invalid`);
    }
    return value === 1;
  }
}

function decodeNextEpochCommitmentExact(raw) {
  const decoder = new Decoder(raw);
  const offsets = {};
  const read = (name, operation) => {
    offsets[name] = decoder.offset;
    return operation();
  };
  const value = {
    schema_version: read("schema_version", () => decoder.unsigned(2)),
    genesis_hash: read("genesis_hash", () => decoder.hash32()),
    chain_id: read("chain_id", () => decoder.consensusString()),
    old_epoch: read("old_epoch", () => decoder.unsigned(8)),
    new_epoch: read("new_epoch", () => decoder.unsigned(8)),
    snapshot_cutoff_height: read("snapshot_cutoff_height", () => decoder.unsigned(8)),
    snapshot_state_root: read("snapshot_state_root", () => decoder.hash32()),
    new_protocol_version: read("new_protocol_version", () => decoder.unsigned(4)),
    new_validator_set_hash: read("new_validator_set_hash", () => decoder.hash32()),
    new_consensus_parameters_hash: read("new_consensus_parameters_hash", () =>
      decoder.hash32(),
    ),
    rollout_phase: read("rollout_phase", () => {
      const phase = Number(decoder.unsigned(1));
      if (phase > 3) {
        fail("invalid_rollout_phase", offsets.rollout_phase, `rollout phase ${phase} is invalid`);
      }
      return phase;
    }),
    upgrade_plan_hash: read("upgrade_plan_hash", () => decoder.optionalHash32()),
    fallback_used: read("fallback_used", () => decoder.boolean()),
    fallback_reason_code: read("fallback_reason_code", () => decoder.unsigned(2)),
    activation_height: read("activation_height", () => decoder.unsigned(8)),
  };
  if (decoder.offset !== raw.length) {
    fail("trailing_bytes", decoder.offset, `${raw.length - decoder.offset} trailing bytes`);
  }
  Object.defineProperty(value, META, { value: { offsets }, enumerable: false });
  admitCommitmentShape(value);
  return value;
}

function fieldOffset(value, field) {
  return value?.[META]?.offsets?.[field] ?? 0;
}

function admitCommitmentShape(value) {
  if (value.schema_version !== 0n) {
    fail(
      "invalid_schema_version",
      fieldOffset(value, "schema_version"),
      "schema_version is not 0",
      "admission",
    );
  }
  if (isZero(value.genesis_hash)) {
    fail(
      "zero_genesis_hash",
      fieldOffset(value, "genesis_hash"),
      "genesis_hash is zero",
      "admission",
    );
  }
  for (const field of [
    "snapshot_state_root",
    "new_validator_set_hash",
    "new_consensus_parameters_hash",
  ]) {
    if (isZero(value[field])) {
      fail(
        "invalid_next_epoch_commitment",
        fieldOffset(value, field),
        `${field} is zero`,
        "admission",
      );
    }
  }
  if (value.upgrade_plan_hash !== null && isZero(value.upgrade_plan_hash)) {
    fail(
      "invalid_next_epoch_commitment",
      fieldOffset(value, "upgrade_plan_hash"),
      "present upgrade_plan_hash is zero",
      "admission",
    );
  }
  if (value.old_epoch === U64_MAX || value.new_epoch !== value.old_epoch + 1n) {
    fail(
      "invalid_next_epoch_commitment",
      fieldOffset(value, "new_epoch"),
      "new_epoch is not the checked successor of old_epoch",
      "admission",
    );
  }
  if (value.fallback_reason_code > 9n) {
    fail(
      "invalid_fallback_reason",
      fieldOffset(value, "fallback_reason_code"),
      "fallback reason is outside 0..9",
      "admission",
    );
  }
  if (
    (value.fallback_used && value.fallback_reason_code === 0n) ||
    (!value.fallback_used && value.fallback_reason_code !== 0n)
  ) {
    fail(
      "invalid_fallback_reason",
      fieldOffset(value, "fallback_reason_code"),
      "fallback flag and reason disagree",
      "admission",
    );
  }
  if (value.activation_height === 0n) {
    fail(
      "invalid_next_epoch_commitment",
      fieldOffset(value, "activation_height"),
      "activation_height is zero",
      "admission",
    );
  }
}

function encodeConsensusString(value) {
  return Buffer.concat([encodeUnsigned(value.length, 2), value]);
}

function encodeCommitment(value) {
  return Buffer.concat([
    encodeUnsigned(value.schema_version, 2),
    value.genesis_hash,
    encodeConsensusString(value.chain_id),
    encodeUnsigned(value.old_epoch, 8),
    encodeUnsigned(value.new_epoch, 8),
    encodeUnsigned(value.snapshot_cutoff_height, 8),
    value.snapshot_state_root,
    encodeUnsigned(value.new_protocol_version, 4),
    value.new_validator_set_hash,
    value.new_consensus_parameters_hash,
    encodeUnsigned(value.rollout_phase, 1),
    value.upgrade_plan_hash === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), value.upgrade_plan_hash]),
    Buffer.from([value.fallback_used ? 1 : 0]),
    encodeUnsigned(value.fallback_reason_code, 2),
    encodeUnsigned(value.activation_height, 8),
  ]);
}

function encodeBytes(value) {
  return Buffer.concat([encodeUnsigned(value.length, 4), value]);
}

function expandValidatorSet(profile, corpus) {
  const validators = corpus.validator_templates[profile.validator_template];
  if (!Array.isArray(validators)) {
    fail("source_vector_drift", 0, "context references an unknown validator template", "gate");
  }
  return {
    genesis_hash: canonicalHex(corpus.fixtures.genesis_hash_hex, "genesis_hash", 32),
    chain_id: Buffer.from(corpus.fixtures.chain_id, "ascii"),
    protocol_version: canonicalDecimal(profile.protocol_version, "set protocol_version"),
    epoch: canonicalDecimal(profile.epoch, "set epoch"),
    consensus_parameters_hash: canonicalHex(
      profile.consensus_parameters_hash_hex,
      "set consensus_parameters_hash",
      32,
    ),
    validators: validators.map((validator) => ({
      validator_id: canonicalHex(validator.validator_id_hex, "validator_id"),
      consensus_public_key: canonicalHex(
        validator.consensus_public_key_hex,
        "consensus_public_key",
        32,
      ),
      effective_weight: canonicalDecimal(validator.effective_weight, "effective_weight"),
    })),
    expected_validator_set_hash: canonicalHex(
      profile.expected_validator_set_hash_hex,
      "expected_validator_set_hash",
      32,
    ),
  };
}

function encodeValidatorSet(value) {
  return Buffer.concat([
    encodeUnsigned(0, 2),
    value.genesis_hash,
    encodeConsensusString(value.chain_id),
    encodeUnsigned(value.protocol_version, 4),
    encodeUnsigned(value.epoch, 8),
    value.consensus_parameters_hash,
    encodeUnsigned(value.validators.length, 4),
    ...value.validators.map((validator) =>
      Buffer.concat([
        encodeBytes(validator.validator_id),
        validator.consensus_public_key,
        encodeUnsigned(validator.effective_weight, 8),
      ]),
    ),
  ]);
}

function validatorSetId(value) {
  return digest(DOMAIN_VALIDATOR_SET, encodeValidatorSet(value));
}

function expandParameters(value) {
  return {
    protocol_version: canonicalDecimal(value.protocol_version, "parameter protocol_version"),
    epoch_length_blocks: canonicalDecimal(value.epoch_length_blocks, "epoch_length_blocks"),
    snapshot_lead_blocks: canonicalDecimal(value.snapshot_lead_blocks, "snapshot_lead_blocks"),
    rollout_phase: value.rollout_phase,
    hash: canonicalHex(value.hash_hex, "parameter hash", 32),
  };
}

function expandContext(name, corpus) {
  const source = corpus.context_profiles[name];
  if (!source) fail("source_vector_drift", 0, `missing context profile ${name}`, "gate");
  return {
    genesis_hash: canonicalHex(corpus.fixtures.genesis_hash_hex, "genesis_hash", 32),
    chain_id: Buffer.from(corpus.fixtures.chain_id, "ascii"),
    old_set: expandValidatorSet(source.old_set, corpus),
    new_set: expandValidatorSet(source.new_set, corpus),
    old_parameters: expandParameters(source.old_parameters),
    new_parameters: expandParameters(source.new_parameters),
  };
}

function checkedAdd(first, second, code) {
  const result = first + second;
  if (result > U64_MAX) fail(code, 0, "u64 addition overflow", "context");
  return result;
}

function checkedMul(first, second, code) {
  const result = first * second;
  if (result > U64_MAX) fail(code, 0, "u64 multiplication overflow", "context");
  return result;
}

function checkedSub(first, second, code) {
  if (first < second) fail(code, 0, "u64 subtraction underflow", "context");
  return first - second;
}

function validatorsEqual(first, second) {
  return (
    first.length === second.length &&
    first.every(
      (validator, index) =>
        bytesEqual(validator.validator_id, second[index].validator_id) &&
        bytesEqual(validator.consensus_public_key, second[index].consensus_public_key) &&
        validator.effective_weight === second[index].effective_weight,
    )
  );
}

function parametersEqual(first, second) {
  return (
    first.protocol_version === second.protocol_version &&
    first.epoch_length_blocks === second.epoch_length_blocks &&
    first.snapshot_lead_blocks === second.snapshot_lead_blocks &&
    first.rollout_phase === second.rollout_phase &&
    bytesEqual(first.hash, second.hash)
  );
}

function validateSetShape(value, errorCode = "context_mismatch") {
  if (value.validators.length === 0 || value.validators.length > 100) {
    fail(errorCode, 0, "validator count is outside 1..100", "context");
  }
  for (let index = 0; index < value.validators.length; index += 1) {
    const validator = value.validators[index];
    if (
      validator.validator_id.length === 0 ||
      validator.validator_id.length > 128 ||
      isZero(validator.consensus_public_key) ||
      validator.effective_weight === 0n
    ) {
      fail(errorCode, 0, "validator shape is invalid", "context");
    }
    if (
      index > 0 &&
      compareBytes(value.validators[index - 1].validator_id, validator.validator_id) >= 0
    ) {
      fail(errorCode, 0, "validator order is not strictly canonical", "context");
    }
  }
}

function validateParameterGeometry(value) {
  if (
    value.snapshot_lead_blocks === 0n ||
    value.snapshot_lead_blocks < V0_FINALITY_CERTIFIED_CHAIN_LENGTH ||
    value.epoch_length_blocks <= value.snapshot_lead_blocks + 2n
  ) {
    fail(
      "context_mismatch",
      0,
      "parameter context violates the finality/snapshot/checkpoint/seal geometry",
      "context",
    );
  }
}

function validateSameVersionContext(commitment, context) {
  const fallbackError = commitment.fallback_used
    ? "fallback_context_mismatch"
    : "context_mismatch";
  validateSetShape(context.old_set);
  validateSetShape(context.new_set, fallbackError);
  validateParameterGeometry(context.old_parameters);
  validateParameterGeometry(context.new_parameters);

  if (
    context.old_set.protocol_version !== 0n ||
    context.new_set.protocol_version !== 0n ||
    context.old_parameters.protocol_version !== 0n ||
    context.new_parameters.protocol_version !== 0n ||
    commitment.new_protocol_version !== 0n
  ) {
    fail(
      "unsupported_protocol_transition",
      fieldOffset(commitment, "new_protocol_version"),
      "B2-C admits same-version v0 contexts only",
      "context",
    );
  }
  if (commitment.new_epoch !== commitment.old_epoch + 1n) {
    fail(
      "epoch_schedule_mismatch",
      fieldOffset(commitment, "new_epoch"),
      "new_epoch is not old_epoch + 1",
      "context",
    );
  }
  if (
    !bytesEqual(commitment.genesis_hash, context.genesis_hash) ||
    !bytesEqual(context.old_set.genesis_hash, context.genesis_hash) ||
    !bytesEqual(context.new_set.genesis_hash, context.genesis_hash) ||
    !bytesEqual(commitment.chain_id, context.chain_id) ||
    !bytesEqual(context.old_set.chain_id, context.chain_id) ||
    !bytesEqual(context.new_set.chain_id, context.chain_id) ||
    context.old_set.epoch !== commitment.old_epoch ||
    context.new_set.epoch !== commitment.new_epoch
  ) {
    fail("context_mismatch", 0, "genesis/chain/epoch context mismatch", "context");
  }
  const oldSetId = validatorSetId(context.old_set);
  const newSetId = validatorSetId(context.new_set);
  if (
    !bytesEqual(context.old_set.consensus_parameters_hash, context.old_parameters.hash) ||
    !bytesEqual(context.new_set.consensus_parameters_hash, context.new_parameters.hash) ||
    !bytesEqual(commitment.new_validator_set_hash, newSetId) ||
    !bytesEqual(commitment.new_consensus_parameters_hash, context.new_parameters.hash)
  ) {
    fail("context_mismatch", 0, "set/parameter commitment mismatch", "context");
  }
  // Retain both IDs as recomputed facts; the old ID has no field in this
  // object, but computing it proves the imported B2-A encoding is exercised.
  if (oldSetId.length !== 32) {
    fail("context_mismatch", 0, "old validator-set digest width mismatch", "context");
  }
  if (
    context.new_parameters.epoch_length_blocks !==
    context.old_parameters.epoch_length_blocks
  ) {
    fail("epoch_length_change", 0, "v0 does not authorize an epoch-length change", "context");
  }
  const epochEnd = checkedMul(
    checkedAdd(commitment.old_epoch, 1n, "epoch_schedule_mismatch"),
    context.old_parameters.epoch_length_blocks,
    "epoch_schedule_mismatch",
  );
  const checkpoint = checkedSub(epochEnd, 2n, "snapshot_cutoff_mismatch");
  const expectedCutoff = checkedSub(
    checkpoint,
    context.old_parameters.snapshot_lead_blocks,
    "snapshot_cutoff_mismatch",
  );
  if (commitment.snapshot_cutoff_height !== expectedCutoff) {
    fail(
      "snapshot_cutoff_mismatch",
      fieldOffset(commitment, "snapshot_cutoff_height"),
      "snapshot cutoff differs from the outgoing schedule",
      "context",
    );
  }
  const expectedActivation = checkedAdd(epochEnd, 1n, "activation_height_mismatch");
  if (commitment.activation_height !== expectedActivation) {
    fail(
      "activation_height_mismatch",
      fieldOffset(commitment, "activation_height"),
      "activation height differs from the outgoing schedule",
      "context",
    );
  }
  if (commitment.rollout_phase !== context.new_parameters.rollout_phase) {
    fail(
      "rollout_phase_mismatch",
      fieldOffset(commitment, "rollout_phase"),
      "rollout phase differs from the supplied new parameter context",
      "context",
    );
  }

  if (commitment.fallback_used) {
    if (
      commitment.upgrade_plan_hash !== null ||
      !parametersEqual(context.old_parameters, context.new_parameters) ||
      !validatorsEqual(context.old_set.validators, context.new_set.validators) ||
      context.old_set.protocol_version !== context.new_set.protocol_version ||
      context.old_parameters.rollout_phase !== context.new_parameters.rollout_phase
    ) {
      fail(
        "fallback_context_mismatch",
        0,
        "fallback does not exactly carry the old configuration",
        "context",
      );
    }
  } else if (commitment.upgrade_plan_hash !== null) {
    fail(
      "unsupported_upgrade_plan",
      fieldOffset(commitment, "upgrade_plan_hash"),
      "B2-C does not authorize UpgradePlanV0",
      "context",
    );
  }
}

function validateManifest(base, manifest) {
  if (
    manifest.schema !== "trnm_poco_bft_cev0_logical_schema_epoch_commitment_v0" ||
    manifest.schema_version !== 0 ||
    manifest.cryptographic_validity_claimed !== false
  ) {
    fail("schema_manifest_invalid", 0, "B2-C manifest identity/claim is invalid", "gate");
  }
  if (manifest.objects.length !== 1 || manifest.objects[0].name !== "NextEpochCommitmentV0") {
    fail("schema_manifest_invalid", 0, "manifest must contain exactly one object", "gate");
  }
  const expectedFields = [
    "schema_version",
    "genesis_hash",
    "chain_id",
    "old_epoch",
    "new_epoch",
    "snapshot_cutoff_height",
    "snapshot_state_root",
    "new_protocol_version",
    "new_validator_set_hash",
    "new_consensus_parameters_hash",
    "rollout_phase",
    "upgrade_plan_hash",
    "fallback_used",
    "fallback_reason_code",
    "activation_height",
  ];
  if (
    JSON.stringify(manifest.objects[0].fields.map((field) => field.name)) !==
    JSON.stringify(expectedFields)
  ) {
    fail("schema_manifest_invalid", 0, "canonical field order drift", "gate");
  }
  const imported = manifest.imports?.[0];
  if (
    imported?.schema !== base.schema ||
    !imported.reuse.includes("primitives") ||
    !imported.reuse.includes("Hash32") ||
    !imported.reuse.includes("ValidatorSetV0")
  ) {
    fail("schema_manifest_invalid", 0, "B2-A import contract drift", "gate");
  }
  const projection = manifest.transport_projections?.[0];
  if (
    projection?.proto_message !== "NextEpochCommitment" ||
    projection.fields.length !== 16 ||
    projection.fields.some(
      (field, index) =>
        field.number !== index + 1 ||
        field.role !== (index === 15 ? "derived" : "canonical"),
    )
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "projection must map fields 1..15 canonical and field 16 derived",
      "gate",
    );
  }
  const forbidden = new Set(manifest.forbidden_entry_points ?? []);
  for (const name of [
    "NextEpochCommitmentV0::authorize_epoch",
    "NextEpochCommitmentV0::epoch_anchor_qc",
    "NextEpochCommitmentV0::into_trusted_context",
    "NextEpochCommitmentV0::into_authorization",
  ]) {
    if (!forbidden.has(name)) {
      fail("schema_manifest_invalid", 0, `missing forbidden API ${name}`, "gate");
    }
  }
  if (manifest.same_version_v0_context_contract?.result !== "Result<()> only") {
    fail("schema_manifest_invalid", 0, "context result must stay inert", "gate");
  }
  if (
    "trusted_inputs" in manifest.same_version_v0_context_contract ||
    !Array.isArray(manifest.same_version_v0_context_contract?.caller_supplied_context_inputs) ||
    manifest.same_version_v0_context_contract.caller_supplied_context_inputs.length !== 4
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "context inputs must remain caller-supplied and externally authenticated",
      "gate",
    );
  }
  if (
    !manifest.same_version_v0_context_contract.checks.includes(
      "old and new snapshot_lead_blocks are each at least the v0 finality_certified_chain_length of 3, and each epoch_length_blocks is greater than snapshot_lead_blocks plus the two v0 seal blocks",
    )
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "snapshot lead/finality context contract drift",
      "gate",
    );
  }
  const expectedNodeEntries = [
    "decodeNextEpochCommitmentExact",
    "validateSameVersionContext",
  ];
  if (
    JSON.stringify(manifest.node_decoder_entry_points) !==
      JSON.stringify(expectedNodeEntries) ||
    typeof decodeNextEpochCommitmentExact !== "function" ||
    typeof validateSameVersionContext !== "function"
  ) {
    fail("schema_manifest_invalid", 0, "Node entry-point surface drift", "gate");
  }
  const expectedRustEntries = [
    "decode_next_epoch_commitment_v0_exact",
    "NextEpochCommitmentV0::validate_same_version_context",
  ];
  if (JSON.stringify(manifest.rust_entry_points) !== JSON.stringify(expectedRustEntries)) {
    fail("schema_manifest_invalid", 0, "landed Rust entry-point surface drift", "gate");
  }
}

function validateRustSurface() {
  const decoderSource = fs.readFileSync(RUST_DECODER_PATH, "utf8");
  const epochSource = fs.readFileSync(RUST_EPOCH_PATH, "utf8");
  if (!/pub fn decode_next_epoch_commitment_v0_exact\s*\(/m.test(decoderSource)) {
    fail("source_vector_drift", 0, "Rust exact decoder entry point is missing", "gate");
  }
  if (!/pub fn validate_same_version_context\s*\(/m.test(epochSource)) {
    fail("source_vector_drift", 0, "Rust context-validation entry point is missing", "gate");
  }
  if (
    /pub fn (?:authorize_epoch|epoch_anchor_qc|into_trusted_context|into_authorization)\s*\(/m.test(
      epochSource,
    )
  ) {
    fail("source_vector_drift", 0, "Rust commitment type exposes a forbidden capability", "gate");
  }
}

function extractProtoBlock(source, kind, name) {
  const marker = new RegExp(`\\b${kind}\\s+${name}\\s*\\{`, "m").exec(source);
  if (!marker) fail("proto_projection_drift", 0, `missing ${kind} ${name}`, "gate");
  let depth = 1;
  let cursor = marker.index + marker[0].length;
  const start = cursor;
  while (cursor < source.length && depth > 0) {
    if (source[cursor] === "{") depth += 1;
    if (source[cursor] === "}") depth -= 1;
    cursor += 1;
  }
  if (depth !== 0) fail("proto_projection_drift", 0, `unterminated ${name}`, "gate");
  return source.slice(start, cursor - 1);
}

function parseProtoFields(block) {
  const fields = [];
  const withoutComments = block.replaceAll(/\/\/[^\n]*/g, "");
  const pattern = /^\s*(repeated\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*;/gm;
  for (const match of withoutComments.matchAll(pattern)) {
    fields.push({
      cardinality: match[1] ? "repeated" : "singular",
      proto_type: match[2],
      name: match[3],
      number: Number(match[4]),
    });
  }
  return fields;
}

function parseProtoEnum(block) {
  const variants = [];
  const withoutComments = block.replaceAll(/\/\/[^\n]*/g, "");
  const pattern = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(\d+)\s*;/gm;
  for (const match of withoutComments.matchAll(pattern)) {
    variants.push({ name: match[1], value: Number(match[2]) });
  }
  return variants;
}

function validateProtoProjection(manifest) {
  const epochSource = fs.readFileSync(EPOCH_PROTO_PATH, "utf8");
  const actualFields = parseProtoFields(
    extractProtoBlock(epochSource, "message", "NextEpochCommitment"),
  ).map(({ number, name, proto_type, cardinality }) => ({
    number,
    name,
    proto_type,
    cardinality,
  }));
  const expectedFields = manifest.transport_projections[0].fields.map(
    ({ number, name, proto_type, cardinality }) => ({
      number,
      name,
      proto_type,
      cardinality,
    }),
  );
  if (JSON.stringify(actualFields) !== JSON.stringify(expectedFields)) {
    fail("proto_projection_drift", 0, "NextEpochCommitment projection drift", "gate");
  }
  const commonSource = fs.readFileSync(COMMON_PROTO_PATH, "utf8");
  const actualEnum = parseProtoEnum(extractProtoBlock(commonSource, "enum", "RolloutPhase"));
  if (JSON.stringify(actualEnum) !== JSON.stringify(manifest.transport_enums[0].variants)) {
    fail("proto_projection_drift", 0, "RolloutPhase projection drift", "gate");
  }
}

function validateRustTaxonomy(base, b2b, manifest) {
  if (!fs.existsSync(RUST_DECODER_PATH)) return;
  const source = fs.readFileSync(RUST_DECODER_PATH, "utf8");
  const match = /pub const fn as_str\(self\) -> &'static str \{\s*match self \{([\s\S]*?)\n\s*\}\n\s*\}/m.exec(
    source,
  );
  if (!match) fail("schema_manifest_invalid", 0, "Rust error vocabulary is missing", "gate");
  const rustCodes = [...match[1].matchAll(/Self::[A-Za-z0-9_]+\s*=>\s*"([a-z0-9_]+)"/g)].map(
    (item) => item[1],
  );
  const b2aCodes = base.decoder_error_codes.map((item) => item.code);
  const b2bCodes = b2b.decoder_error_codes.map((item) => item.code);
  const b2bAdditions = b2bCodes.filter((code) => !b2aCodes.includes(code));
  const b2cAdditions = (manifest.rust_decoder_error_additions ?? []).map(
    (item) => item.code,
  );
  const b2dAdditions = [
    "invalid_utf8",
    "noncanonical_event_attribute_order",
    "invalid_double_vote_evidence",
  ];
  const b2eAdditions = [
    "invalid_leader_schedule",
    "invalid_consensus_parameters",
    "invalid_finality_proof",
    "invalid_checkpoint_two_seal",
  ];
  const manifestCodes = manifest.decoder_error_codes.map((item) => item.code);
  const partitions = [
    ...b2aCodes,
    ...b2bAdditions,
    ...b2cAdditions,
    ...b2dAdditions,
    ...b2eAdditions,
  ];
  if (
    b2cAdditions.length !== 4 ||
    new Set(partitions).size !== partitions.length ||
    JSON.stringify([...manifestCodes, ...b2dAdditions, ...b2eAdditions]) !== JSON.stringify(rustCodes) ||
    JSON.stringify(
      rustCodes.filter(
        (code) =>
          !b2cAdditions.includes(code) &&
          !b2dAdditions.includes(code) &&
          !b2eAdditions.includes(code),
      ),
    ) !==
      JSON.stringify(b2bCodes) ||
    JSON.stringify(
      rustCodes.filter(
        (code) =>
          !b2bAdditions.includes(code) &&
          !b2cAdditions.includes(code) &&
          !b2dAdditions.includes(code) &&
          !b2eAdditions.includes(code),
      ),
    ) !== JSON.stringify(b2aCodes)
  ) {
    fail("schema_manifest_invalid", 0, "B2-A/B2-B/B2-C/B2-D/B2-E error sets overlap", "gate");
  }
  for (const code of b2cAdditions) {
    if (!manifestCodes.includes(code)) {
      fail("schema_manifest_invalid", 0, `missing B2-C decoder code ${code}`, "gate");
    }
  }
}

function assertError(operation, expected, label, expectedOffset = undefined) {
  try {
    operation();
  } catch (error) {
    if (error instanceof KernelError && error.code === expected) {
      if (expectedOffset !== undefined && error.offset !== expectedOffset) {
        throw new Error(
          `${label}: expected byte offset ${expectedOffset}, received ${error.offset}`,
        );
      }
      return;
    }
    throw new Error(`${label}: expected ${expected}, received ${error}`);
  }
  throw new Error(`${label}: expected ${expected}, operation succeeded`);
}

function mutateBoundary(kind, baseValue, presentValue) {
  const value = cloneValue(kind === "optional_tag_1" || kind === "zero_present_upgrade_hash"
    ? presentValue
    : baseValue);
  switch (kind) {
    case "chain_length_0":
      value.chain_id = Buffer.alloc(0);
      return encodeCommitment(value);
    case "chain_length_128":
      value.chain_id = Buffer.from(`a${"b".repeat(127)}`, "ascii");
      return encodeCommitment(value);
    case "chain_length_129":
      value.chain_id = Buffer.from(`a${"b".repeat(128)}`, "ascii");
      return encodeCommitment(value);
    case "chain_invalid_ascii":
      value.chain_id = Buffer.from("Uppercase", "ascii");
      return encodeCommitment(value);
    case "optional_tag_0":
      value.upgrade_plan_hash = null;
      return encodeCommitment(value);
    case "optional_tag_1":
      return encodeCommitment(value);
    case "optional_tag_2": {
      const raw = encodeCommitment(value);
      raw[fieldOffset(baseValue, "upgrade_plan_hash")] = 2;
      return raw;
    }
    case "rollout_phase_0":
      value.rollout_phase = 0;
      return encodeCommitment(value);
    case "rollout_phase_3":
      value.rollout_phase = 3;
      return encodeCommitment(value);
    case "rollout_phase_4":
      value.rollout_phase = 4;
      return encodeCommitment(value);
    case "fallback_false_reason_0":
      value.fallback_used = false;
      value.fallback_reason_code = 0n;
      return encodeCommitment(value);
    case "fallback_true_reason_1":
      value.fallback_used = true;
      value.fallback_reason_code = 1n;
      return encodeCommitment(value);
    case "fallback_true_reason_9":
      value.fallback_used = true;
      value.fallback_reason_code = 9n;
      return encodeCommitment(value);
    case "fallback_reason_10":
      value.fallback_used = true;
      value.fallback_reason_code = 10n;
      return encodeCommitment(value);
    case "fallback_false_reason_1":
      value.fallback_used = false;
      value.fallback_reason_code = 1n;
      return encodeCommitment(value);
    case "fallback_true_reason_0":
      value.fallback_used = true;
      value.fallback_reason_code = 0n;
      return encodeCommitment(value);
    case "fallback_bool_2": {
      const raw = encodeCommitment(value);
      raw[fieldOffset(baseValue, "fallback_used")] = 2;
      return raw;
    }
    case "schema_version_1":
      value.schema_version = 1n;
      return encodeCommitment(value);
    case "zero_genesis_hash":
      value.genesis_hash = Buffer.alloc(32);
      return encodeCommitment(value);
    case "zero_snapshot_state_root":
      value.snapshot_state_root = Buffer.alloc(32);
      return encodeCommitment(value);
    case "zero_new_validator_set_hash":
      value.new_validator_set_hash = Buffer.alloc(32);
      return encodeCommitment(value);
    case "zero_new_parameters_hash":
      value.new_consensus_parameters_hash = Buffer.alloc(32);
      return encodeCommitment(value);
    case "zero_present_upgrade_hash":
      value.upgrade_plan_hash = Buffer.alloc(32);
      return encodeCommitment(value);
    case "new_epoch_not_adjacent":
      value.new_epoch += 1n;
      return encodeCommitment(value);
    case "activation_height_0":
      value.activation_height = 0n;
      return encodeCommitment(value);
    default:
      fail("source_vector_drift", 0, `unknown boundary mutation ${kind}`, "gate");
  }
}

function hashLabel(label) {
  return crypto.createHash("sha256").update(label).digest();
}

function applyContextMutation(kind, commitment, context) {
  switch (kind) {
    case "none":
      return;
    case "old_protocol_version_1":
      context.old_set.protocol_version = 1n;
      return;
    case "new_protocol_version_1":
      commitment.new_protocol_version = 1n;
      return;
    case "new_context_protocol_version_1":
      context.new_set.protocol_version = 1n;
      return;
    case "genesis_context_mismatch":
      context.genesis_hash = hashLabel("mutated-genesis");
      return;
    case "chain_context_mismatch":
      context.chain_id = Buffer.from("trnm-other-chain", "ascii");
      return;
    case "old_epoch_context_mismatch":
      context.old_set.epoch += 1n;
      return;
    case "new_set_hash_mismatch":
      commitment.new_validator_set_hash = hashLabel("mutated-new-set");
      return;
    case "new_parameters_hash_mismatch":
      commitment.new_consensus_parameters_hash = hashLabel("mutated-new-parameters");
      return;
    case "epoch_length_change":
      context.new_parameters.epoch_length_blocks += 1n;
      return;
    case "old_snapshot_lead_zero":
      context.old_parameters.snapshot_lead_blocks = 0n;
      return;
    case "new_snapshot_lead_zero":
      context.new_parameters.snapshot_lead_blocks = 0n;
      return;
    case "snapshot_cutoff_mismatch":
      commitment.snapshot_cutoff_height += 1n;
      return;
    case "activation_height_mismatch":
      commitment.activation_height += 1n;
      return;
    case "rollout_phase_mismatch":
      commitment.rollout_phase = (context.new_parameters.rollout_phase + 1) % 4;
      return;
    case "fallback_parameters_changed": {
      const changed = hashLabel("fallback-mutated-parameters");
      context.new_parameters.hash = changed;
      context.new_set.consensus_parameters_hash = changed;
      commitment.new_consensus_parameters_hash = changed;
      commitment.new_validator_set_hash = validatorSetId(context.new_set);
      return;
    }
    case "fallback_validator_id_changed":
      context.new_set.validators[0].validator_id = Buffer.from("validator-aa", "ascii");
      commitment.new_validator_set_hash = validatorSetId(context.new_set);
      return;
    case "fallback_validator_key_changed":
      context.new_set.validators[0].consensus_public_key = hashLabel("changed-key");
      commitment.new_validator_set_hash = validatorSetId(context.new_set);
      return;
    case "fallback_validator_weight_changed":
      context.new_set.validators[0].effective_weight += 1n;
      commitment.new_validator_set_hash = validatorSetId(context.new_set);
      return;
    case "fallback_validator_order_changed":
      [context.new_set.validators[0], context.new_set.validators[1]] = [
        context.new_set.validators[1],
        context.new_set.validators[0],
      ];
      commitment.new_validator_set_hash = validatorSetId(context.new_set);
      return;
    case "fallback_upgrade_present":
      commitment.upgrade_plan_hash = hashLabel("fallback-upgrade");
      return;
    default:
      fail("source_vector_drift", 0, `unknown context mutation ${kind}`, "gate");
  }
}

function validateCorpus(corpus) {
  if (
    corpus.schema !== "trnm_poco_bft_next_epoch_commitment_kernel_vectors_v0" ||
    corpus.schema_version !== 0 ||
    corpus.cryptographic_validity_claimed !== false ||
    corpus.domain !== DOMAIN_EPOCH_COMMITMENT
  ) {
    fail("source_vector_drift", 0, "corpus identity/claim drift", "gate");
  }
  if (corpus.valid_raw_objects.length !== 3) {
    fail("source_vector_drift", 0, "expected three raw objects", "gate");
  }
}

function verifyRawObjects(corpus) {
  const decoded = new Map();
  let prefixCount = 0;
  let trailingCount = 0;
  for (const artifact of corpus.valid_raw_objects) {
    const raw = canonicalHex(artifact.cev0_hex, `${artifact.id}.cev0_hex`);
    if (raw.length !== artifact.length) {
      fail("source_vector_drift", 0, `${artifact.id} length drift`, "gate");
    }
    const value = decodeNextEpochCommitmentExact(raw);
    const reencoded = encodeCommitment(value);
    if (!reencoded.equals(raw)) {
      fail("source_vector_drift", 0, `${artifact.id} re-encoding drift`, "gate");
    }
    const expectedDigest = canonicalHex(artifact.digest_hex, `${artifact.id}.digest_hex`, 32);
    if (!digest(DOMAIN_EPOCH_COMMITMENT, raw).equals(expectedDigest)) {
      fail("digest_mismatch", 0, `${artifact.id} digest drift`, "gate");
    }
    const fieldExpectations = artifact.fields;
    for (const name of [
      "schema_version",
      "old_epoch",
      "new_epoch",
      "snapshot_cutoff_height",
      "new_protocol_version",
      "fallback_reason_code",
      "activation_height",
    ]) {
      if (value[name] !== canonicalDecimal(fieldExpectations[name], `${artifact.id}.${name}`)) {
        fail("source_vector_drift", 0, `${artifact.id}.${name} drift`, "gate");
      }
    }
    if (
      value.rollout_phase !== fieldExpectations.rollout_phase ||
      value.fallback_used !== fieldExpectations.fallback_used ||
      (fieldExpectations.upgrade_plan_hash_hex === null
        ? value.upgrade_plan_hash !== null
        : !bytesEqual(
            value.upgrade_plan_hash,
            canonicalHex(fieldExpectations.upgrade_plan_hash_hex, "upgrade_plan_hash", 32),
          ))
    ) {
      fail("source_vector_drift", 0, `${artifact.id} scalar/optional drift`, "gate");
    }
    for (let length = 0; length < raw.length; length += 1) {
      assertError(
        () => decodeNextEpochCommitmentExact(raw.subarray(0, length)),
        "unexpected_eof",
        `${artifact.id} prefix ${length}`,
      );
      prefixCount += 1;
    }
    assertError(
      () => decodeNextEpochCommitmentExact(Buffer.concat([raw, Buffer.from([0])])),
      "trailing_bytes",
      `${artifact.id} trailing byte`,
    );
    trailingCount += 1;
    decoded.set(artifact.id, value);
  }
  return { decoded, prefixCount, trailingCount };
}

function verifyBaseContexts(corpus, decoded) {
  let validContexts = 0;
  let expectedRejectedContexts = 0;
  for (const artifact of corpus.valid_raw_objects) {
    const context = expandContext(artifact.context_profile, corpus);
    const sourceProfile = corpus.context_profiles[artifact.context_profile];
    for (const role of ["old_set", "new_set"]) {
      const expected = canonicalHex(
        sourceProfile[role].expected_validator_set_hash_hex,
        `${artifact.context_profile}.${role}.expected_validator_set_hash_hex`,
        32,
      );
      if (!validatorSetId(context[role]).equals(expected)) {
        fail("digest_mismatch", 0, `${artifact.context_profile}.${role} digest drift`, "gate");
      }
    }
    if (artifact.context_expected === "valid") {
      validateSameVersionContext(decoded.get(artifact.id), context);
      validContexts += 1;
    } else {
      assertError(
        () => validateSameVersionContext(decoded.get(artifact.id), context),
        artifact.context_expected,
        `${artifact.id} expected context result`,
      );
      expectedRejectedContexts += 1;
    }
  }
  return { validContexts, expectedRejectedContexts };
}

function verifyBoundaries(corpus, decoded) {
  const base = decoded.get("normal_same_version_no_upgrade");
  const present = decoded.get("present_upgrade_shape_only");
  for (const test of corpus.boundary_cases) {
    const raw = mutateBoundary(test.mutation, base, present);
    if (test.expected === "valid") {
      decodeNextEpochCommitmentExact(raw);
    } else {
      assertError(
        () => decodeNextEpochCommitmentExact(raw),
        test.expected,
        `boundary ${test.id}`,
        test.expected_offset,
      );
    }
  }
}

function verifyContextRelations(corpus, decoded) {
  for (const test of corpus.context_relation_cases) {
    const artifact = corpus.valid_raw_objects.find((item) => item.id === test.base);
    if (!artifact) fail("source_vector_drift", 0, `missing base ${test.base}`, "gate");
    const commitment = cloneValue(decoded.get(test.base));
    const context = expandContext(artifact.context_profile, corpus);
    applyContextMutation(test.mutation, commitment, context);
    assertError(
      () => validateSameVersionContext(commitment, context),
      test.expected,
      `context relation ${test.id}`,
    );
  }
}

function verifySnapshotLeadFinalityBoundary(corpus, decoded) {
  const artifact = corpus.valid_raw_objects.find(
    (item) => item.id === "normal_same_version_no_upgrade",
  );
  if (!artifact) {
    fail("source_vector_drift", 0, "missing normal lead-boundary base", "gate");
  }

  for (const role of ["old_parameters", "new_parameters"]) {
    const commitment = cloneValue(decoded.get(artifact.id));
    const context = expandContext(artifact.context_profile, corpus);
    context[role].snapshot_lead_blocks = 2n;
    assertError(
      () => validateSameVersionContext(commitment, context),
      "context_mismatch",
      `${role} lead 2 below v0 finality length`,
    );
  }

  const commitment = cloneValue(decoded.get(artifact.id));
  const context = expandContext(artifact.context_profile, corpus);
  context.old_parameters.snapshot_lead_blocks = V0_FINALITY_CERTIFIED_CHAIN_LENGTH;
  context.new_parameters.snapshot_lead_blocks = V0_FINALITY_CERTIFIED_CHAIN_LENGTH;
  const epochEnd =
    (commitment.old_epoch + 1n) * context.old_parameters.epoch_length_blocks;
  commitment.snapshot_cutoff_height =
    epochEnd - 2n - V0_FINALITY_CERTIFIED_CHAIN_LENGTH;
  validateSameVersionContext(commitment, context);
  return 3;
}

function main() {
  const base = readJson(BASE_SCHEMA_PATH);
  const b2b = readJson(B2B_SCHEMA_PATH);
  const manifest = readJson(SCHEMA_PATH);
  const corpus = readJson(CORPUS_PATH);
  validateManifest(base, manifest);
  validateProtoProjection(manifest);
  validateRustTaxonomy(base, b2b, manifest);
  validateRustSurface();
  validateCorpus(corpus);
  const rawEvidence = verifyRawObjects(corpus);
  const contextEvidence = verifyBaseContexts(corpus, rawEvidence.decoded);
  verifyBoundaries(corpus, rawEvidence.decoded);
  verifyContextRelations(corpus, rawEvidence.decoded);
  const snapshotLeadBoundaryCases = verifySnapshotLeadFinalityBoundary(
    corpus,
    rawEvidence.decoded,
  );

  process.stdout.write(
    [
      "PoCO-BFT v0 B2-C epoch-commitment schema/parser gate: valid",
      `objects=${manifest.objects.length}`,
      `projections=${manifest.transport_projections.length}`,
      `raw_objects=${corpus.valid_raw_objects.length}`,
      `non_complete_prefixes=${rawEvidence.prefixCount}`,
      `trailing_cases=${rawEvidence.trailingCount}`,
      `boundary_cases=${corpus.boundary_cases.length}`,
      `context_relation_cases=${corpus.context_relation_cases.length}`,
      `snapshot_lead_boundary_cases=${snapshotLeadBoundaryCases}`,
      `valid_contexts=${contextEvidence.validContexts}`,
      `expected_inert_context_rejections=${contextEvidence.expectedRejectedContexts}`,
      "authorization_outputs=0",
    ].join("\n") + "\n",
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack ?? error}\n`);
  process.exitCode = 1;
}
