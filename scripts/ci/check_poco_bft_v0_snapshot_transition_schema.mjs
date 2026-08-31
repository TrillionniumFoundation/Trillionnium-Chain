import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vector = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json",
    ),
    "utf8",
  ),
);
const schema = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/protocol/poco-bft-v0/schema/poco-snapshot-transition-v0.json",
    ),
    "utf8",
  ),
);
const consumptionCertificateVector = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/protocol/poco-bft-v0/vectors/consumption-certificate-v0.json",
    ),
    "utf8",
  ),
);
const snapshotCandidateVector = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/protocol/poco-bft-v0/vectors/snapshot-candidate-kernel-v0.json",
    ),
    "utf8",
  ),
);
const jointHandoffVector = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/protocol/poco-bft-v0/vectors/joint-handoff-composition-kernel-v0.json",
    ),
    "utf8",
  ),
);

const invariant = (condition, message) => {
  if (!condition) throw new Error(message);
};
const sameJson = (actual, expected, message) =>
  invariant(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: ${JSON.stringify(actual)}`,
  );
const expectReject = (operation, message) => {
  let rejected = false;
  try {
    operation();
  } catch {
    rejected = true;
  }
  invariant(rejected, message);
};
const expectRejectReason = (operation, expectedReason, message) => {
  let error = null;
  try {
    operation();
  } catch (candidate) {
    error = candidate;
  }
  invariant(error !== null, `${message}: accepted`);
  invariant(error.message === expectedReason, `${message}: ${error.message}`);
};
const semanticInvariant = (condition, reason) => {
  if (!condition) throw new Error(reason);
};
const uint = (value, width) => {
  let remaining = BigInt(value);
  invariant(remaining >= 0n, "negative unsigned integer");
  const out = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    out[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  invariant(remaining === 0n, "integer overflow");
  return out;
};
const frame = (value) => Buffer.concat([uint(value.length, 4), value]);
const digest = (domain, encoded) =>
  crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        frame(Buffer.from("trnm.cev0.hash.v0")),
        frame(Buffer.from(domain)),
        frame(encoded),
      ]),
    )
    .digest();
const hex = (value) => Buffer.from(value, "hex");

class Cursor {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  take(length) {
    invariant(Number.isSafeInteger(length) && length >= 0, "invalid length");
    const end = this.offset + length;
    invariant(Number.isSafeInteger(end) && end <= this.bytes.length, "unexpected_end");
    const out = this.bytes.subarray(this.offset, end);
    this.offset = end;
    return out;
  }

  u8() {
    return this.take(1)[0];
  }

  u16() {
    return this.take(2).readUInt16BE();
  }

  u32() {
    return this.take(4).readUInt32BE();
  }

  u64() {
    return this.take(8).readBigUInt64BE();
  }

  u128() {
    let value = 0n;
    for (const byte of this.take(16)) value = (value << 8n) | BigInt(byte);
    return value;
  }

  fixed(length) {
    return Buffer.from(this.take(length));
  }

  bytesValue(maximum, minimum = 1) {
    const length = this.u32();
    invariant(length >= minimum && length <= maximum, "length_out_of_range");
    return this.take(length);
  }

  finish() {
    invariant(this.offset === this.bytes.length, "trailing_bytes");
  }
}

const isZero = (value) => value.equals(Buffer.alloc(value.length));
const strictHex = (value, label) => {
  invariant(
    typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value),
    `${label}: noncanonical hex`,
  );
  return Buffer.from(value, "hex");
};
const consensusString = (cursor) => {
  const length = cursor.u16();
  semanticInvariant(length >= 1 && length <= 128, "consensus_string_length");
  const value = cursor.fixed(length);
  const first = value[0];
  const firstOk =
    (first >= 0x61 && first <= 0x7a) || (first >= 0x30 && first <= 0x39);
  const tailOk = [...value.subarray(1)].every(
    (byte) =>
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2e ||
      byte === 0x5f ||
      byte === 0x3a ||
      byte === 0x2d,
  );
  semanticInvariant(firstOk && tailOk, "consensus_string_grammar");
  return value;
};
const optionalU64Exact = (cursor) => {
  const tag = cursor.u8();
  if (tag === 0) return null;
  semanticInvariant(tag === 1, "optional_tag");
  return cursor.u64();
};
const optionalHash32Exact = (cursor) => {
  const tag = cursor.u8();
  if (tag === 0) return null;
  semanticInvariant(tag === 1, "optional_tag");
  return cursor.fixed(32);
};
const decodeCompositeIdentity = (identity, count) => {
  const cursor = new Cursor(identity);
  const fields = [];
  for (let index = 0; index < count; index += 1) {
    fields.push(cursor.bytesValue(128));
  }
  cursor.finish();
  return fields;
};

const decodeConsumptionCertificateExact = (raw) => {
  const cursor = new Cursor(raw);
  semanticInvariant(cursor.u16() === 0, "certificate_schema");
  semanticInvariant(!isZero(cursor.fixed(32)), "certificate_genesis");
  consensusString(cursor);
  const provider = cursor.bytesValue(128);
  const consumer = cursor.bytesValue(128);
  cursor.bytesValue(128);
  cursor.bytesValue(128);
  semanticInvariant(!provider.equals(consumer), "certificate_same_party");
  cursor.fixed(32);
  cursor.bytesValue(128);
  cursor.u32();
  semanticInvariant(cursor.u128() > 0n, "certificate_zero_units");
  const billingStart = cursor.u64();
  const billingEnd = cursor.u64();
  semanticInvariant(billingStart <= billingEnd, "certificate_billing_interval");
  cursor.u64();
  cursor.fixed(32);
  optionalHash32Exact(cursor);
  const bodyEnd = cursor.offset;
  cursor.fixed(64);
  const suppliedId = cursor.fixed(32);
  cursor.finish();
  const bodyDigest = digest(
    consumptionCertificateVector.body_domain,
    raw.subarray(0, bodyEnd),
  );
  const certificateId = digest(consumptionCertificateVector.id_domain, bodyDigest);
  semanticInvariant(suppliedId.equals(certificateId), "certificate_id");
  return { certificateId };
};

const decodePopExact = (raw) => {
  const cursor = new Cursor(raw);
  semanticInvariant(cursor.u16() === 0, "pop_schema");
  semanticInvariant(!isZero(cursor.fixed(32)), "pop_genesis");
  consensusString(cursor);
  cursor.u64();
  const validatorId = cursor.bytesValue(128);
  const publicKey = cursor.fixed(32);
  semanticInvariant(!isZero(publicKey), "pop_public_key");
  const registrationNonce = cursor.u64();
  cursor.fixed(64);
  cursor.finish();
  return { validatorId, publicKey, registrationNonce };
};

const decodeValidatorSetExact = (raw) => {
  const cursor = new Cursor(raw);
  semanticInvariant(cursor.u16() === 0, "validator_set_schema");
  semanticInvariant(!isZero(cursor.fixed(32)), "validator_set_genesis");
  consensusString(cursor);
  semanticInvariant(cursor.u32() === 0, "validator_set_protocol");
  const epoch = cursor.u64();
  cursor.fixed(32);
  const count = cursor.u32();
  semanticInvariant(count >= 1 && count <= 100, "validator_set_count");
  let previousId = null;
  const keys = new Set();
  for (let index = 0; index < count; index += 1) {
    const validatorId = cursor.bytesValue(128);
    const publicKey = cursor.fixed(32);
    const power = cursor.u64();
    semanticInvariant(
      previousId === null || Buffer.compare(previousId, validatorId) < 0,
      "validator_set_order",
    );
    semanticInvariant(!isZero(publicKey), "validator_set_public_key");
    semanticInvariant(!keys.has(publicKey.toString("hex")), "validator_set_duplicate_key");
    semanticInvariant(power > 0n, "validator_set_power");
    previousId = validatorId;
    keys.add(publicKey.toString("hex"));
  }
  cursor.finish();
  return { epoch };
};

const parameterLayout = [
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
const parameterWidth = (type) => {
  if (type === "u16") return 2;
  if (type === "u32") return 4;
  if (type === "u64") return 8;
  if (type === "u128") return 16;
  return 1;
};
const parameterFieldOffset = (target) => {
  let offset = 0;
  for (const [name, type] of parameterLayout) {
    if (name === target) return offset;
    offset += parameterWidth(type);
  }
  throw new Error(`unknown parameter field ${target}`);
};
const decodeConsensusParametersExact = (raw) => {
  const cursor = new Cursor(raw);
  const fields = {};
  for (const [name, type] of parameterLayout) {
    let value;
    if (type === "u8") value = cursor.u8();
    else if (type === "u16") value = cursor.u16();
    else if (type === "u32") value = cursor.u32();
    else if (type === "u64") value = cursor.u64();
    else if (type === "u128") value = cursor.u128();
    else {
      value = cursor.u8();
      if (type === "bool") semanticInvariant(value <= 1, "parameters_boolean");
      else if (type === "leader") semanticInvariant(value === 0, "parameters_leader");
      else semanticInvariant(value <= 3, "parameters_rollout");
    }
    fields[name] = value;
  }
  cursor.finish();
  semanticInvariant(raw.length === 341, "parameters_length");
  semanticInvariant(fields.schema_version === 0, "parameters_schema");
  semanticInvariant(fields.protocol_version === 0, "parameters_protocol");
  semanticInvariant(
    fields.max_chain_id_bytes >= 1 && fields.max_chain_id_bytes <= 128,
    "parameters_chain_bound",
  );
  semanticInvariant(
    fields.max_validator_id_bytes >= 1 && fields.max_validator_id_bytes <= 128,
    "parameters_validator_bound",
  );
  semanticInvariant(
    fields.max_block_bytes > 0 &&
      fields.max_consensus_message_bytes > 0 &&
      fields.max_block_bytes <= fields.max_consensus_message_bytes,
    "parameters_message_bounds",
  );
  semanticInvariant(
    fields.min_validators >= 4 &&
      fields.min_validators <= fields.max_validators &&
      fields.max_validators <= 100,
    "parameters_validator_count",
  );
  semanticInvariant(
    fields.quorum_numerator === 2 &&
      fields.quorum_denominator === 3 &&
      fields.quorum_addend === 1,
    "parameters_quorum",
  );
  semanticInvariant(fields.finality_certified_chain_length === 3, "parameters_finality");
  semanticInvariant(fields.require_full_payload_before_vote === 1, "parameters_full_payload");
  semanticInvariant(
    fields.timeout_multiplier_denominator > 0 &&
      fields.timeout_multiplier_numerator > fields.timeout_multiplier_denominator,
    "parameters_timeout_multiplier",
  );
  semanticInvariant(fields.base_timeout_ms <= fields.timeout_max_ms, "parameters_timeout_max");
  semanticInvariant(fields.epoch_seal_blocks === 2, "parameters_seals");
  semanticInvariant(
    fields.snapshot_lead_blocks >= BigInt(fields.finality_certified_chain_length),
    "parameters_snapshot_lead_finality",
  );
  semanticInvariant(
    fields.snapshot_lead_blocks > 0n &&
      fields.epoch_length_blocks > fields.snapshot_lead_blocks + 2n,
    "parameters_epoch_geometry",
  );
  semanticInvariant(
    fields.joint_handoff_old_quorum === 1 && fields.joint_handoff_new_quorum === 1,
    "parameters_joint_quorum",
  );
  semanticInvariant(
    fields.upgrade_notice_epochs >= 1n && fields.max_protocol_version_jump === 1,
    "parameters_upgrade_bounds",
  );
  semanticInvariant(fields.scale_ppm > 0n, "parameters_scale");
  semanticInvariant(
    fields.per_certificate_unit_cap > 0n &&
      fields.per_certificate_unit_cap <= fields.per_consumer_provider_epoch_unit_cap &&
      fields.per_consumer_provider_epoch_unit_cap <=
        fields.per_task_provider_epoch_unit_cap &&
      fields.per_task_provider_epoch_unit_cap <= fields.per_provider_epoch_unit_cap,
    "parameters_unit_caps",
  );
  semanticInvariant(
    fields.units_per_power > 0n && fields.bond_atomic_units_per_power > 0n,
    "parameters_power_divisors",
  );
  semanticInvariant(
    fields.min_validator_power > 0n &&
      fields.min_validator_power <= fields.max_validator_power,
    "parameters_power_bounds",
  );
  semanticInvariant(
    fields.max_validator_share_ppm > 0n &&
      fields.max_validator_share_ppm * 3n < fields.scale_ppm,
    "parameters_share_cap",
  );
  semanticInvariant(
    fields.capped_weight_alpha_ppm <= fields.scale_ppm &&
      fields.full_weight_alpha_ppm === fields.scale_ppm,
    "parameters_alpha_bounds",
  );
  semanticInvariant(
    BigInt(fields.min_validators) * fields.min_validator_power <=
      fields.max_total_voting_power,
    "parameters_minimum_candidate_power",
  );
  semanticInvariant(fields.automatic_promotion === 0, "parameters_automatic_promotion");
  semanticInvariant(
    fields.trusting_period_epochs < fields.evidence_window_epochs &&
      fields.evidence_window_epochs <= fields.unbonding_delay_epochs,
    "parameters_weak_subjectivity",
  );
  semanticInvariant(
    fields.require_trusting_period_less_than_evidence === 1 &&
      fields.require_evidence_window_le_unbonding_delay === 1,
    "parameters_relationship_flags",
  );
  return fields;
};

const decodeKindPayloadExact = (kind, identity, payload) => {
  const cursor = new Cursor(payload);
  switch (kind) {
    case 1: {
      semanticInvariant(identity.length === 32, "certificate_identity_length");
      const certificate = decodeConsumptionCertificateExact(payload);
      semanticInvariant(certificate.certificateId.equals(identity), "certificate_identity_mismatch");
      return certificate;
    }
    case 2: {
      const [consumerId, consumerKeyId] = decodeCompositeIdentity(identity, 2);
      semanticInvariant(cursor.bytesValue(128).equals(consumerId), "consumer_id_mismatch");
      semanticInvariant(
        cursor.bytesValue(128).equals(consumerKeyId),
        "consumer_key_id_mismatch",
      );
      semanticInvariant(!isZero(cursor.fixed(32)), "consumer_public_key");
      const activeFrom = cursor.u64();
      const revokedAt = optionalU64Exact(cursor);
      semanticInvariant(revokedAt === null || revokedAt > activeFrom, "consumer_key_interval");
      break;
    }
    case 3: {
      const [consumerId, consumerKeyId, providerId] = decodeCompositeIdentity(identity, 3);
      semanticInvariant(!providerId.equals(consumerId), "provider_equals_consumer");
      semanticInvariant(cursor.bytesValue(128).equals(consumerId), "consumer_id_mismatch");
      semanticInvariant(
        cursor.bytesValue(128).equals(consumerKeyId),
        "consumer_key_id_mismatch",
      );
      semanticInvariant(cursor.bytesValue(128).equals(providerId), "provider_id_mismatch");
      cursor.u64();
      break;
    }
    case 4: {
      const identityCursor = new Cursor(identity);
      const consumerId = identityCursor.bytesValue(128);
      const providerId = identityCursor.bytesValue(128);
      const taskId = identityCursor.bytesValue(128);
      const outputCommitment = identityCursor.fixed(32);
      const billingStart = identityCursor.u64();
      const billingEnd = identityCursor.u64();
      const consumerNonce = identityCursor.u64();
      identityCursor.finish();
      semanticInvariant(!providerId.equals(consumerId), "tuple_same_party");
      semanticInvariant(cursor.bytesValue(128).equals(consumerId), "tuple_consumer_mismatch");
      semanticInvariant(cursor.bytesValue(128).equals(providerId), "tuple_provider_mismatch");
      semanticInvariant(cursor.bytesValue(128).equals(taskId), "tuple_task_mismatch");
      semanticInvariant(cursor.fixed(32).equals(outputCommitment), "tuple_output_mismatch");
      semanticInvariant(cursor.u64() === billingStart, "tuple_billing_start_mismatch");
      semanticInvariant(cursor.u64() === billingEnd, "tuple_billing_end_mismatch");
      semanticInvariant(cursor.u64() === consumerNonce, "tuple_nonce_mismatch");
      semanticInvariant(billingStart <= billingEnd, "tuple_billing_interval");
      cursor.fixed(32);
      semanticInvariant(cursor.u64() > billingEnd, "tuple_acceptance_height");
      break;
    }
    case 5: {
      const identityCursor = new Cursor(identity);
      const meterId = identityCursor.bytesValue(128);
      const meterVersion = identityCursor.u32();
      identityCursor.finish();
      semanticInvariant(cursor.bytesValue(128).equals(meterId), "meter_id_mismatch");
      semanticInvariant(cursor.u32() === meterVersion, "meter_version_mismatch");
      semanticInvariant(cursor.u128() > 0n, "meter_unit_scale");
      const activeFrom = cursor.u64();
      const retiredAt = optionalU64Exact(cursor);
      semanticInvariant(retiredAt === null || retiredAt > activeFrom, "meter_interval");
      break;
    }
    case 6:
      semanticInvariant(identity.length === 32, "settlement_identity_length");
      semanticInvariant(cursor.fixed(32).equals(identity), "settlement_identity_mismatch");
      cursor.fixed(32);
      semanticInvariant([1, 2, 3].includes(cursor.u8()), "settlement_state");
      cursor.u64();
      break;
    case 7:
      semanticInvariant(identity.length === 32, "measurement_identity_length");
      semanticInvariant(cursor.fixed(32).equals(identity), "measurement_identity_mismatch");
      optionalHash32Exact(cursor);
      semanticInvariant([1, 2, 3].includes(cursor.u8()), "measurement_state");
      break;
    case 8: {
      const [providerId, consumerId, taskId] = decodeCompositeIdentity(identity, 3);
      semanticInvariant(cursor.bytesValue(128).equals(providerId), "relationship_provider_mismatch");
      semanticInvariant(cursor.bytesValue(128).equals(consumerId), "relationship_consumer_mismatch");
      semanticInvariant(cursor.bytesValue(128).equals(taskId), "relationship_task_mismatch");
      semanticInvariant([1, 2, 3, 4].includes(cursor.u8()), "relationship_class");
      cursor.u64();
      break;
    }
    case 9: {
      semanticInvariant(identity.length <= 128, "validator_identity_length");
      const validatorId = cursor.bytesValue(128);
      semanticInvariant(validatorId.equals(identity), "validator_identity_mismatch");
      const consensusKey = cursor.fixed(32);
      semanticInvariant(!isZero(consensusKey), "validator_public_key");
      const registrationNonce = cursor.u64();
      semanticInvariant([1, 2].includes(cursor.u8()), "registration_state");
      const proof = decodePopExact(cursor.bytesValue(65_384));
      semanticInvariant(proof.validatorId.equals(validatorId), "pop_validator_mismatch");
      semanticInvariant(proof.publicKey.equals(consensusKey), "pop_key_mismatch");
      semanticInvariant(proof.registrationNonce === registrationNonce, "pop_nonce_mismatch");
      break;
    }
    case 10:
      semanticInvariant(identity.length <= 128, "bond_identity_length");
      semanticInvariant(cursor.bytesValue(128).equals(identity), "bond_identity_mismatch");
      semanticInvariant(cursor.u128() > 0n, "bond_amount");
      cursor.u64();
      semanticInvariant([1, 2].includes(cursor.u8()), "bond_state");
      break;
    case 11:
      semanticInvariant(identity.length <= 128, "jail_identity_length");
      semanticInvariant(cursor.bytesValue(128).equals(identity), "jail_identity_mismatch");
      cursor.u64();
      semanticInvariant([1, 2, 3].includes(cursor.u8()), "jail_reason");
      break;
    case 12:
      semanticInvariant(identity.length === 32, "lifecycle_identity_length");
      semanticInvariant(cursor.fixed(32).equals(identity), "lifecycle_identity_mismatch");
      semanticInvariant([1, 2, 3, 4, 5].includes(cursor.u8()), "lifecycle_state");
      cursor.u64();
      break;
    case 13: {
      semanticInvariant(identity.length === 9, "validator_configuration_identity_length");
      semanticInvariant([1, 2].includes(identity[0]), "validator_configuration_role");
      const epoch = identity.subarray(1).readBigUInt64BE();
      const validatorSet = decodeValidatorSetExact(payload);
      semanticInvariant(validatorSet.epoch === epoch, "validator_set_epoch_mismatch");
      return validatorSet;
    }
    case 14:
      semanticInvariant(identity.length === 9, "parameters_identity_length");
      semanticInvariant([1, 2].includes(identity[0]), "parameters_role");
      return decodeConsensusParametersExact(payload);
    case 15:
      semanticInvariant(identity.length === 8, "governance_identity_length");
      semanticInvariant(cursor.u8() <= 3, "rollout_phase");
      cursor.fixed(32);
      semanticInvariant(cursor.u64() > 0n, "governance_activation_height");
      semanticInvariant(cursor.u8() <= 1, "governance_approval");
      break;
    default:
      throw new Error("kind");
  }
  cursor.finish();
  return {};
};

const decodeSnapshotValueExact = (raw, expectedKey) => {
  semanticInvariant(raw.length > 0 && raw.length <= 65_536, "value_size");
  const cursor = new Cursor(raw);
  semanticInvariant(cursor.u16() === 0, "schema_version");
  const kind = cursor.u8();
  semanticInvariant(kind >= 1 && kind <= 15, "kind");
  const revision = cursor.u64();
  semanticInvariant(revision > 0n, "revision");
  const identity = cursor.bytesValue(452);
  const payload = cursor.bytesValue(65_384);
  cursor.finish();
  const key = digest(
    "trnm.poco-bft.snapshot-value-identity.v0",
    Buffer.concat([uint(0, 2), uint(kind, 1), frame(identity)]),
  );
  semanticInvariant(expectedKey === undefined || key.equals(expectedKey), "identity_key_mismatch");
  const semantic = decodeKindPayloadExact(kind, identity, payload);
  return { kind, revision, identity, payload, key, semantic };
};

const nonceFixtureIdentity = (fixture) =>
  Buffer.concat([
    frame(Buffer.from(fixture.consumer_id_utf8)),
    frame(Buffer.from(fixture.consumer_key_id_utf8)),
    frame(Buffer.from(fixture.provider_id_utf8)),
  ]);
const nonceFixturePayload = (fixture, nonce) =>
  Buffer.concat([nonceFixtureIdentity(fixture), uint(nonce, 8)]);
const nonceValue = (fixture, revision, nonce) => {
  const identity = nonceFixtureIdentity(fixture);
  const payload = nonceFixturePayload(fixture, nonce);
  const raw = Buffer.concat([
    uint(0, 2),
    uint(3, 1),
    uint(revision, 8),
    frame(identity),
    frame(payload),
  ]);
  invariant(raw.length <= 65_536, "fixture envelope exceeds value bound");
  return raw;
};
const nonceLogicalKey = (fixture) =>
  digest(
    "trnm.poco-bft.snapshot-value-identity.v0",
    Buffer.concat([uint(0, 2), uint(3, 1), frame(nonceFixtureIdentity(fixture))]),
  );

const decodeNonceValue = (raw, expectedKey) => {
  invariant(raw.length > 0 && raw.length <= 65_536, "value_too_large");
  const cursor = new Cursor(raw);
  invariant(cursor.u16() === 0, "schema_version");
  invariant(cursor.u8() === 3, "kind");
  const revision = cursor.u64();
  invariant(revision > 0n, "revision");
  const identity = cursor.bytesValue(452);
  const payload = cursor.bytesValue(65_384);
  cursor.finish();

  const key = digest(
    "trnm.poco-bft.snapshot-value-identity.v0",
    Buffer.concat([uint(0, 2), uint(3, 1), frame(identity)]),
  );
  invariant(key.equals(expectedKey), "identity_key_mismatch");

  const identityCursor = new Cursor(identity);
  const consumerId = identityCursor.bytesValue(128);
  const consumerKeyId = identityCursor.bytesValue(128);
  const providerId = identityCursor.bytesValue(128);
  identityCursor.finish();
  invariant(!providerId.equals(consumerId), "provider_equals_consumer");

  const payloadCursor = new Cursor(payload);
  invariant(payloadCursor.bytesValue(128).equals(consumerId), "consumer_id_mismatch");
  invariant(
    payloadCursor.bytesValue(128).equals(consumerKeyId),
    "consumer_key_id_mismatch",
  );
  invariant(payloadCursor.bytesValue(128).equals(providerId), "provider_id_mismatch");
  const nonce = payloadCursor.u64();
  payloadCursor.finish();
  return { revision, consumerId, consumerKeyId, providerId, nonce, key };
};

const entryBytesForKind = (kind, key, value) =>
  Buffer.concat([uint(0, 2), uint(kind, 1), frame(key), frame(value)]);
const entryBytes = (key, value) => entryBytesForKind(3, key, value);
const entriesRootFor = (entries) => {
  let layer = entries.map(({ kind, key, value }) =>
    digest("trnm.poco-bft.snapshot-entry.v0", entryBytesForKind(kind, key, value)),
  );
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      const right = layer[index + 1] ?? left;
      next.push(
        digest(
          "trnm.poco-bft.snapshot-node.v0",
          Buffer.concat([uint(0, 2), uint(level, 4), left, right]),
        ),
      );
    }
    layer = next;
    level += 1;
  }
  return digest(
    "trnm.poco-bft.snapshot-root.v0",
    Buffer.concat([
      uint(0, 2),
      uint(entries.length, 4),
      layer.length === 0
        ? Buffer.from([0])
        : Buffer.concat([Buffer.from([1]), layer[0]]),
    ]),
  );
};
const entriesRoot = (key, value) => entriesRootFor([{ kind: 3, key, value }]);
const manifest = (height, key, value) =>
  Buffer.concat([
    uint(0, 2),
    uint(8, 1),
    uint(height, 8),
    uint(1, 4),
    entriesRoot(key, value),
  ]);

const pocoKeyPrefix = Buffer.concat([
  Buffer.from("trnm/authenticated-state/v4"),
  Buffer.from([0, 8]),
]);
const pocoPhysicalKey = (components) =>
  Buffer.concat([pocoKeyPrefix, uint(components.length, 2), ...components.map(frame)]);
const decodePocoPhysicalKeyExact = (raw) => {
  semanticInvariant(
    raw.length >= pocoKeyPrefix.length && raw.subarray(0, pocoKeyPrefix.length).equals(pocoKeyPrefix),
    "physical_namespace_prefix",
  );
  const cursor = new Cursor(raw.subarray(pocoKeyPrefix.length));
  const count = cursor.u16();
  semanticInvariant(count >= 1 && count <= 3, "physical_component_count");
  const components = [];
  for (let index = 0; index < count; index += 1) {
    components.push(Buffer.from(cursor.bytesValue(128)));
  }
  cursor.finish();
  if (components.length === 1 && components[0].equals(Buffer.from("manifest"))) {
    return { role: "manifest" };
  }
  semanticInvariant(
    components.length === 3 && components[0].equals(Buffer.from("entry")),
    "physical_key_layout",
  );
  semanticInvariant(components[1].length === 1, "physical_kind_width");
  semanticInvariant(components[1][0] >= 1 && components[1][0] <= 15, "physical_kind");
  semanticInvariant(
    components[2].length >= 1 && components[2].length <= 128,
    "physical_logical_key_bound",
  );
  return { role: "entry", kind: components[1][0], key: components[2] };
};
const decodeManifestExact = (raw) => {
  const cursor = new Cursor(raw);
  semanticInvariant(cursor.u16() === 0, "manifest_schema");
  semanticInvariant(cursor.u8() === 8, "manifest_namespace");
  const height = cursor.u64();
  const count = cursor.u32();
  semanticInvariant(count <= 10_000, "manifest_count_bound");
  const root = cursor.fixed(32);
  cursor.finish();
  return { height, count, root };
};
const validateProductionProjection = (stateHeight, leaves) => {
  semanticInvariant(leaves.length >= 1 && leaves.length <= 10_001, "physical_leaf_count");
  let decodedManifest = null;
  const entries = [];
  for (const leaf of leaves) {
    const physical = decodePocoPhysicalKeyExact(leaf.key);
    if (physical.role === "manifest") {
      semanticInvariant(decodedManifest === null, "duplicate_manifest");
      decodedManifest = decodeManifestExact(leaf.value);
      continue;
    }
    const decoded = decodeSnapshotValueExact(leaf.value, physical.key);
    semanticInvariant(decoded.kind === physical.kind, "physical_value_kind");
    entries.push({ kind: physical.kind, key: physical.key, value: leaf.value });
  }
  semanticInvariant(decodedManifest !== null, "missing_manifest");
  semanticInvariant(decodedManifest.height <= BigInt(stateHeight), "manifest_height_ahead");
  entries.sort(
    (left, right) => left.kind - right.kind || Buffer.compare(left.key, right.key),
  );
  for (let index = 1; index < entries.length; index += 1) {
    semanticInvariant(
      entries[index - 1].kind < entries[index].kind ||
        Buffer.compare(entries[index - 1].key, entries[index].key) < 0,
      "duplicate_physical_entry",
    );
  }
  semanticInvariant(decodedManifest.count === entries.length, "manifest_entry_count");
  semanticInvariant(decodedManifest.root.equals(entriesRootFor(entries)), "manifest_entries_root");
  return { manifest: decodedManifest, entries };
};
const optionalBytes = (value) =>
  value === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), frame(value)]);
const mutation = (kind, key, oldValue, nextValue) =>
  Buffer.concat([
    uint(0, 2),
    uint(kind, 1),
    frame(key),
    optionalBytes(oldValue),
    optionalBytes(nextValue),
  ]);
const mutationLeaf = (raw) => digest("trnm.poco-bft.snapshot-mutation.v0", raw);
const mutationNode = (level, left, right) =>
  digest(
    "trnm.poco-bft.snapshot-mutation-node.v0",
    Buffer.concat([uint(0, 2), uint(level, 4), left, right]),
  );
const mutationOuter = (count, treeRoot) =>
  digest(
    "trnm.poco-bft.snapshot-mutation-root.v0",
    Buffer.concat([
      uint(0, 2),
      uint(count, 4),
      treeRoot === null
        ? Buffer.from([0])
        : Buffer.concat([Buffer.from([1]), treeRoot]),
    ]),
  );
const mutationRoot = (rawMutations) => {
  let layer = rawMutations.map(mutationLeaf);
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      const right = layer[index + 1] ?? left;
      next.push(mutationNode(level, left, right));
    }
    layer = next;
    level += 1;
  }
  return mutationOuter(rawMutations.length, layer[0] ?? null);
};
const compareMutationIdentity = (left, right) =>
  left.kind - right.kind || Buffer.compare(left.key, right.key);
const assertCanonicalMutations = (mutations) => {
  for (let index = 1; index < mutations.length; index += 1) {
    invariant(
      compareMutationIdentity(mutations[index - 1], mutations[index]) < 0,
      "mutations_not_canonical_or_unique",
    );
  }
};

// The schema gate asserts the complete ordered shape of all 15 kind layouts.
invariant(schema.schema === "trnm.poco-bft.snapshot-transition.v0", "schema identity drift");
invariant(schema.schema_version === 0, "top-level schema version drift");
sameJson(
  schema.value_envelope.fields,
  [
    { name: "schema_version", type: "u16", const: 0 },
    { name: "kind", type: "u8", minimum: 1, maximum: 15 },
    { name: "revision", type: "u64", minimum: 1 },
    { name: "identity", type: "Bytes", minimum_bytes: 1, maximum_bytes: 452 },
    { name: "payload", type: "Bytes", minimum_bytes: 1, maximum_bytes: 65_384 },
  ],
  "value envelope fields drift",
);
sameJson(
  schema.value_envelope.encoded_size,
  {
    fixed_and_length_prefix_bytes: 19,
    formula: "19 + identity.length + payload.length",
    maximum_bytes: 65_536,
    checked_independently_of_field_maxima: true,
  },
  "value envelope total-size rule drift",
);
invariant(19 + 452 + 65_384 > 65_536, "total-size check is no longer independently relevant");
invariant(
  schema.value_envelope.exact_decode === true &&
    schema.value_envelope.trailing_bytes === "reject",
  "value exact-decode rule drift",
);
sameJson(
  schema.cev0.optional_encoding,
  {
    tag_type: "u8",
    none: { tag: 0, following_bytes: 0 },
    some: { tag: 1, following_value: "exact declared type" },
    other_tags: "reject",
  },
  "optional tag encoding drift",
);
invariant(
  schema.logical_key.domain_ascii === "trnm.poco-bft.snapshot-value-identity.v0" &&
    schema.logical_key.type === "Hash32",
  "logical key hash contract drift",
);
sameJson(
  schema.logical_key.preimage_fields,
  [
    { name: "schema_version", type: "u16", const: 0 },
    { name: "kind", type: "u8", minimum: 1, maximum: 15 },
    { name: "identity", type: "Bytes", minimum_bytes: 1, maximum_bytes: 452 },
  ],
  "logical key preimage drift",
);
sameJson(
  schema.domain_hash,
  {
    algorithm: "SHA-256",
    hash_prefix_ascii: "trnm.cev0.hash.v0",
    input: [
      "CEV0 Bytes(hash_prefix_ascii)",
      "CEV0 Bytes(domain_ascii)",
      "CEV0 Bytes(encoded_object)",
    ],
  },
  "domain hash framing drift",
);

const fieldsOf = (part) => {
  if (part.field !== undefined) return [part.field];
  if (part.fields !== undefined) return part.fields;
  if (part.object !== undefined) return [{ name: `@${part.object}`, type: "ExactObject" }];
  return [];
};
const fieldShape = (part) => fieldsOf(part).map((field) => `${field.name}:${field.type}`);
const expectedLayouts = [
  [1, "consumption_certificate", "raw", ["certificate_id:Hash32"], "ExactObject", ["@ConsumptionCertificateV0:ExactObject"]],
  [2, "consumer_key_authorization", "CEV0", ["consumer_id:Bytes", "consumer_key_id:Bytes"], "CEV0", ["consumer_id:Bytes", "consumer_key_id:Bytes", "public_key:PublicKey32", "active_from:u64", "revoked_at:Optional<u64>"]],
  [3, "consumer_nonce", "CEV0", ["consumer_id:Bytes", "consumer_key_id:Bytes", "provider_id:Bytes"], "CEV0", ["consumer_id:Bytes", "consumer_key_id:Bytes", "provider_id:Bytes", "max_accepted_nonce:u64"]],
  [4, "unique_consumption_tuple", "CEV0", ["consumer_id:Bytes", "provider_id:Bytes", "task_id:Bytes", "output_commitment:Hash32", "billing_start_height:u64", "billing_end_height:u64", "consumer_nonce:u64"], "CEV0", ["consumer_id:Bytes", "provider_id:Bytes", "task_id:Bytes", "output_commitment:Hash32", "billing_start_height:u64", "billing_end_height:u64", "consumer_nonce:u64", "certificate_id:Hash32", "accepted_height:u64"]],
  [5, "meter_definition", "CEV0", ["meter_id:Bytes", "meter_version:u32"], "CEV0", ["meter_id:Bytes", "meter_version:u32", "unit_scale:u128", "active_from:u64", "retired_at:Optional<u64>"]],
  [6, "settlement", "raw", ["certificate_id:Hash32"], "CEV0", ["certificate_id:Hash32", "settlement_commitment:Hash32", "state:u8", "finalized_height:u64"]],
  [7, "measurement_evidence", "raw", ["certificate_id:Hash32"], "CEV0", ["certificate_id:Hash32", "evidence_root:Optional<Hash32>", "state:u8"]],
  [8, "relationship_classification", "CEV0", ["provider_id:Bytes", "consumer_id:Bytes", "task_id:Bytes"], "CEV0", ["provider_id:Bytes", "consumer_id:Bytes", "task_id:Bytes", "class:u8", "expires_at:u64"]],
  [9, "validator_registration", "raw", ["validator_id:Bytes"], "CEV0", ["validator_id:Bytes", "consensus_key:PublicKey32", "registration_nonce:u64", "state:u8", "proof_of_possession:ExactObjectBytes"]],
  [10, "active_bond", "raw", ["validator_id:Bytes"], "CEV0", ["validator_id:Bytes", "amount:u128", "locked_until:u64", "state:u8"]],
  [11, "jail_status", "raw", ["validator_id:Bytes"], "CEV0", ["validator_id:Bytes", "jailed_until:u64", "reason:u8"]],
  [12, "revocation_or_challenge", "raw", ["certificate_id:Hash32"], "CEV0", ["certificate_id:Hash32", "state:u8", "effective_height:u64"]],
  [13, "validator_configuration", "CEV0", ["role:u8", "epoch:u64"], "ExactObject", ["@ValidatorSetV0:ExactObject"]],
  [14, "consensus_parameters", "CEV0", ["role:u8", "epoch:u64"], "ExactObject", ["@ConsensusParametersV0:ExactObject"]],
  [15, "rollout_or_governance", "CEV0", ["target_epoch:u64"], "CEV0", ["phase:u8", "parameters_hash:Hash32", "activation_height:u64", "approved:u8"]],
];
invariant(schema.kinds.length === expectedLayouts.length, "kind count drift");
const kindById = new Map(schema.kinds.map((kind) => [kind.id, kind]));
invariant(kindById.size === 15, "duplicate kind id");
for (const [id, name, identityEncoding, identityFields, payloadEncoding, payloadFields] of expectedLayouts) {
  const kind = kindById.get(id);
  invariant(kind !== undefined, `missing kind ${id}`);
  invariant(kind.name === name, `kind ${id} name drift`);
  invariant(kind.identity.encoding === identityEncoding, `kind ${id} identity encoding drift`);
  invariant(kind.payload.encoding === payloadEncoding, `kind ${id} payload encoding drift`);
  sameJson(fieldShape(kind.identity), identityFields, `kind ${id} identity layout drift`);
  sameJson(fieldShape(kind.payload), payloadFields, `kind ${id} payload layout drift`);
}

const expectedConstraints = new Map([
  [1, [{ op: "eq", left: "payload.certificate_id", right: "identity.certificate_id" }]],
  [2, [
    { op: "eq", left: "payload.consumer_id", right: "identity.consumer_id" },
    { op: "eq", left: "payload.consumer_key_id", right: "identity.consumer_key_id" },
    { op: "none_or_gt", left: "payload.revoked_at", right: "payload.active_from" },
  ]],
  [3, [
    { op: "eq", left: "payload.consumer_id", right: "identity.consumer_id" },
    { op: "eq", left: "payload.consumer_key_id", right: "identity.consumer_key_id" },
    { op: "eq", left: "payload.provider_id", right: "identity.provider_id" },
    { op: "not_equal", left: "identity.provider_id", right: "identity.consumer_id" },
  ]],
  [4, [
    { op: "eq", left: "payload.consumer_id", right: "identity.consumer_id" },
    { op: "eq", left: "payload.provider_id", right: "identity.provider_id" },
    { op: "eq", left: "payload.task_id", right: "identity.task_id" },
    { op: "eq", left: "payload.output_commitment", right: "identity.output_commitment" },
    { op: "eq", left: "payload.billing_start_height", right: "identity.billing_start_height" },
    { op: "eq", left: "payload.billing_end_height", right: "identity.billing_end_height" },
    { op: "eq", left: "payload.consumer_nonce", right: "identity.consumer_nonce" },
    { op: "not_equal", left: "identity.provider_id", right: "identity.consumer_id" },
    { op: "lte", left: "identity.billing_start_height", right: "identity.billing_end_height" },
    { op: "lt", left: "identity.billing_end_height", right: "payload.accepted_height" },
  ]],
  [5, [
    { op: "eq", left: "payload.meter_id", right: "identity.meter_id" },
    { op: "eq", left: "payload.meter_version", right: "identity.meter_version" },
    { op: "none_or_gt", left: "payload.retired_at", right: "payload.active_from" },
  ]],
  [6, [{ op: "eq", left: "payload.certificate_id", right: "identity.certificate_id" }]],
  [7, [{ op: "eq", left: "payload.certificate_id", right: "identity.certificate_id" }]],
  [8, [
    { op: "eq", left: "payload.provider_id", right: "identity.provider_id" },
    { op: "eq", left: "payload.consumer_id", right: "identity.consumer_id" },
    { op: "eq", left: "payload.task_id", right: "identity.task_id" },
  ]],
  [9, [
    { op: "exact_decode", path: "payload.proof_of_possession", object: "ValidatorKeyProofOfPossessionV0" },
    { op: "eq", left: "payload.validator_id", right: "identity.validator_id" },
    { op: "eq", left: "payload.proof_of_possession.validator_id", right: "payload.validator_id" },
    { op: "eq", left: "payload.proof_of_possession.public_key", right: "payload.consensus_key" },
    { op: "eq", left: "payload.proof_of_possession.registration_nonce", right: "payload.registration_nonce" },
  ]],
  [10, [{ op: "eq", left: "payload.validator_id", right: "identity.validator_id" }]],
  [11, [{ op: "eq", left: "payload.validator_id", right: "identity.validator_id" }]],
  [12, [{ op: "eq", left: "payload.certificate_id", right: "identity.certificate_id" }]],
  [13, [{ op: "eq", left: "payload.epoch", right: "identity.epoch" }]],
  [14, []],
  [15, []],
]);
for (const [id, constraints] of expectedConstraints) {
  sameJson(kindById.get(id).constraints, constraints, `kind ${id} constraints drift`);
}

const visit = (value, callback) => {
  if (Array.isArray(value)) {
    for (const item of value) visit(item, callback);
  } else if (value !== null && typeof value === "object") {
    callback(value);
    for (const item of Object.values(value)) visit(item, callback);
  }
};
const idBytes = [];
const publicKeys = [];
visit(schema, (value) => {
  if (value.type === "Bytes" && value.semantic === "id") idBytes.push(value);
  if (value.type === "PublicKey32") publicKeys.push(value);
});
invariant(idBytes.length >= 30, "nested ID Bytes coverage unexpectedly small");
for (const field of idBytes) {
  invariant(
    field.minimum_bytes === 1 && field.maximum_bytes === 128,
    `nested ID Bytes bound drift at ${field.name}`,
  );
}
invariant(publicKeys.length === 3, "public-key shape count drift");
for (const field of publicKeys) invariant(field.nonzero === true, `${field.name} may be zero`);
sameJson(
  schema.external_exact_objects.ValidatorSetV0.constraints,
  [{ op: "all_nonzero", path: "validators[*].public_key" }],
  "validator-set public-key rule drift",
);
sameJson(
  schema.external_exact_objects.ConsensusParametersV0.semantic_constraints,
  [
    "snapshot_lead_blocks >= finality_certified_chain_length",
    "epoch_length_blocks > snapshot_lead_blocks + epoch_seal_blocks",
  ],
  "consensus-parameter snapshot/finality geometry drift",
);
const proofObject = schema.external_exact_objects.ValidatorKeyProofOfPossessionV0;
invariant(
  proofObject.exact_decode === true && proofObject.trailing_bytes === "reject",
  "PoP exact decoder rule drift",
);
sameJson(
  proofObject.fields.map((field) => `${field.name}:${field.type}`),
  [
    "schema_version:u16",
    "genesis_hash:Hash32",
    "chain_id:ConsensusString",
    "target_epoch:u64",
    "validator_id:Bytes",
    "public_key:PublicKey32",
    "registration_nonce:u64",
    "signature:FixedBytes",
  ],
  "PoP field layout drift",
);
invariant(
  proofObject.fields[1].nonzero === true &&
    proofObject.fields[2].minimum_bytes === 1 &&
    proofObject.fields[2].maximum_bytes === 128 &&
    proofObject.fields[5].nonzero === true &&
    proofObject.fields[7].exact_bytes === 64,
  "PoP field constraint drift",
);
const proofField = fieldsOf(kindById.get(9).payload).at(-1);
invariant(
  proofField.type === "ExactObjectBytes" &&
    proofField.minimum_bytes === 1 &&
    proofField.maximum_bytes === 65_384,
  "framed PoP bound drift",
);

const field = (kindId, section, name) =>
  fieldsOf(kindById.get(kindId)[section]).find((candidate) => candidate.name === name);
const assertAllowed = (kindId, section, name, expected) =>
  sameJson(field(kindId, section, name).allowed, expected, `kind ${kindId} ${name} enum drift`);
assertAllowed(6, "payload", "state", [1, 2, 3]);
assertAllowed(7, "payload", "state", [1, 2, 3]);
assertAllowed(8, "payload", "class", [1, 2, 3, 4]);
assertAllowed(9, "payload", "state", [1, 2]);
assertAllowed(10, "payload", "state", [1, 2]);
assertAllowed(11, "payload", "reason", [1, 2, 3]);
assertAllowed(12, "payload", "state", [1, 2, 3, 4, 5]);
assertAllowed(13, "identity", "role", [1, 2]);
assertAllowed(14, "identity", "role", [1, 2]);
assertAllowed(15, "payload", "phase", [0, 1, 2, 3]);
assertAllowed(15, "payload", "approved", [0, 1]);
sameJson(field(13, "identity", "role").meanings, { 1: "old", 2: "candidate" }, "kind 13 role meanings drift");
sameJson(field(14, "identity", "role").meanings, { 1: "active", 2: "next" }, "kind 14 role meanings drift");
invariant(kindById.get(13).identity.exact_bytes === 9, "kind 13 identity width drift");
invariant(kindById.get(14).identity.exact_bytes === 9, "kind 14 identity width drift");
invariant(kindById.get(15).identity.exact_bytes === 8, "kind 15 identity width drift");
invariant(field(5, "identity", "meter_version").minimum === undefined, "meter version zero forbidden");
invariant(field(5, "payload", "meter_version").minimum === undefined, "payload meter version zero forbidden");
invariant(field(5, "payload", "unit_scale").minimum === 1, "meter unit scale positivity drift");
invariant(field(10, "payload", "amount").minimum === 1, "active bond positivity drift");
invariant(field(15, "payload", "activation_height").minimum === 1, "activation height positivity drift");
for (const [kindId, name] of [[2, "revoked_at"], [5, "retired_at"], [7, "evidence_root"]]) {
  sameJson(field(kindId, "payload", name).allowed_tags, [0, 1], `kind ${kindId} optional tags drift`);
}

sameJson(
  schema.mutation.canonical_cev0.fields,
  [
    { name: "schema_version", type: "u16", const: 0 },
    { name: "kind", type: "u8", minimum: 1, maximum: 15 },
    { name: "logical_key", type: "Bytes", exact_bytes: 32 },
    { name: "expected_value", type: "Optional<Bytes>", allowed_tags: [0, 1], some_type: "exact ValueEnvelopeV0" },
    { name: "next_value", type: "Optional<Bytes>", allowed_tags: [0, 1], some_type: "exact ValueEnvelopeV0" },
  ],
  "mutation canonical encoding drift",
);
sameJson(
  schema.mutation.compare_and_set,
  {
    create: { expected_value: "None", next_value: "Some", next_revision: 1 },
    update: { expected_value: "Some", next_value: "Some", next_revision: "checked expected_revision + 1" },
    delete: { expected_value: "Some required", next_value: "None" },
    empty: "reject",
    precondition: "expected_value exactly equals the authenticated source value or absence",
  },
  "CAS semantics drift",
);
sameJson(
  schema.mutation.ordering,
  { key: ["kind u8", "raw logical_key bytes"], direction: "strict-ascending", duplicates: "reject-before-root" },
  "mutation order drift",
);
const orderedRootSchema = schema.mutation.ordered_root;
invariant(
  orderedRootSchema.leaf.domain_ascii === "trnm.poco-bft.snapshot-mutation.v0" &&
    orderedRootSchema.node.domain_ascii === "trnm.poco-bft.snapshot-mutation-node.v0" &&
    orderedRootSchema.outer.domain_ascii === "trnm.poco-bft.snapshot-mutation-root.v0",
  "mutation hash domain drift",
);
sameJson(
  orderedRootSchema.node.preimage_fields,
  [
    { name: "schema_version", type: "u16", const: 0 },
    { name: "level", type: "u32", first_leaf_parent_level: 0 },
    { name: "left", type: "Hash32" },
    { name: "right", type: "Hash32" },
  ],
  "mutation node CEV0 drift",
);
invariant(
  orderedRootSchema.node.odd_width === "duplicate-left-as-right-at-every-level",
  "odd duplication rule drift",
);
sameJson(
  orderedRootSchema.outer.preimage_fields,
  [
    { name: "schema_version", type: "u16", const: 0 },
    { name: "mutation_count", type: "u32", exact_list_length: true },
    { name: "tree_root", type: "Optional<Hash32>", none_tag: 0, some_tag: 1 },
  ],
  "mutation outer CEV0 drift",
);

sameJson(
  schema.production_persistence_seal,
  {
    scope: "B2-H3b1",
    inactive_namespace: "zero namespace-8 leaves is valid before PoCO activation",
    active_namespace: {
      manifest_count: 1,
      manifest_exact_bytes: 47,
      manifest_height: "at most committed state height",
      physical_completeness: "every physical namespace-8 entry is named by the manifest and every manifest member exists physically",
      semantic_values: "all physical entries pass their exact kind-specific decoder",
      hidden_or_unknown_physical_keys: "reject",
    },
    admission_paths: [
      "in_memory_state_codec_encode",
      "in_memory_state_codec_decode",
      "sqlite_precommit_before_domain_or_JMT_rows",
      "sqlite_startup_or_schema_migration",
      "abci_snapshot_restore_v3",
      "abci_snapshot_restore_v4",
    ],
    sqlite_atomicity: {
      transaction: "BEGIN IMMEDIATE",
      validation_order: "verify committed source head, materialize authenticated source namespace, overlay planned namespace writes, validate exact target projection, then write any domain/JMT row",
      failure: "rollback with committed head unchanged",
    },
    authority_non_claims: [
      "no production PoCO mutation input is authorized by this seal alone",
      "no chain/profile/parent/checkpoint execution or receipt provenance is established",
      "no cross-entry business semantics or authenticated B2-G authority is established",
    ],
  },
  "production persistence seal drift",
);

const atomic = schema.atomic_transition;
invariant(
  atomic.namespace.discriminant === 8 &&
    atomic.namespace.key_prefix_hex ===
      "74726e6d2f61757468656e746963617465642d73746174652f76340008",
  "namespace-8 prefix drift",
);
sameJson(
  atomic.state_head.fields,
  [
    "origin_proof_id",
    "origin_epoch",
    "origin_cutoff_height",
    "origin_cutoff_block_id",
    "height",
    "state_root",
    "manifest_height",
    "entries_root",
    "entry_count",
  ],
  "state-head fields drift",
);
invariant(
  atomic.state_head.type === "PocoStateHeadKernelV0" &&
    atomic.state_head.source_capability === "private-field AuthenticatedPocoSnapshotNamespaceV0" &&
    atomic.state_head.reusable_next_head === "only AppliedInMemoryPocoSnapshotTransitionV0.state_head()",
  "private reusable state-head contract drift",
);
sameJson(
  atomic.source_reverification_in_same_plan_call,
  [
    "state head height/state_root equal the current JMT latest version/root",
    "target version is the exact current JMT version + 1",
    "complete source proof bundle is reverified against state head height/state_root",
    "verified manifest height/entries_root/entry_count exactly equal the state head; live manifest height is at most source state version",
    "every source value is exact semantic-decoded before mutation planning",
  ],
  "same-call source re-verification drift",
);
sameJson(
  atomic.writes.manifest_rewrite_rule,
  {
    rewrite_at_target: "mutation_count > 0 or refresh_manifest_at_target is true",
    preserve_exact_source_bytes: "mutation_count = 0 and refresh_manifest_at_target is false",
    cutoff_requirement: "an actual epoch-cutoff projection sets refresh_manifest_at_target=true so the public B2-H2 verifier can require manifest_height=target state version",
  },
  "conditional manifest rewrite drift",
);
invariant(atomic.writes.atomic_unit === "one PlannedAuthUpdate", "atomic write unit drift");
sameJson(
  atomic.generic_auth_write_defense,
  {
    production_constructor: "AuthWrite::put rejects namespace-8 key preimages",
    test_only_constructor: "cfg(test) AuthWrite::delete verifies the same namespace-8 rejection",
    planner: "recheck every generic AuthWrite and reject namespace-8 key preimages",
    sealed_poco_constructors: "crate-private put/delete require a private-field PocoWritePermitV0 and accept only namespace-8 key preimages",
    permit_issuance: "production permit construction is private to the PoCO planner module; cfg(test) alone exposes an explicit crate-private test-only constructor",
  },
  "generic namespace defense drift",
);
const aggregate = atomic.aggregate_bounds;
invariant(
  aggregate.maximum_bytes === 8_388_608 &&
    aggregate.checked_arithmetic === true &&
    aggregate.entry_and_write_count_maximum === 10_000 &&
    aggregate.target_zero_absence_reproof_bundle.absences === 0 &&
    aggregate.target_zero_absence_reproof_bundle.maximum_encoded_ics23_proof_bytes_each ===
      1_048_576,
  "aggregate bound drift",
);
sameJson(
  aggregate.transition_input_projection,
  {
    mutation_terms: ["logical_key", "expected_value if Some", "next_value if Some"],
    generic_write_terms: ["key", "value if Some"],
  },
  "transition input projection drift",
);
sameJson(
  aggregate.target_poco_projection,
  {
    terms_per_entry: ["logical_key", "value"],
    bound: "sum over the complete post-mutation PoCO entry set before hashing",
  },
  "target projection drift",
);
sameJson(
  atomic.apply,
  {
    stale_plan: "reject if latest version/source root changed or target is no longer exact next version",
    stores_exact_writes: "bounded exact Vec<AuthWrite>",
    stores_tree_update_batch: false,
    replan_on_apply: "required against the supplied tree history after the stale-source check",
    no_batch_transplant: "a history-specific TreeUpdateBatch is never carried from plan to apply, including across equal version/root histories",
    recomputed_root_check: "replanned target root must equal the committed target state_root before apply",
    applied_root_check: "applied JMT root must equal the committed target state_root",
  },
  "history-bound apply contract drift",
);

function encodeSnapshotEnvelopeV0(kind, revision, identity, payload) {
  return Buffer.concat([
    uint(0, 2),
    uint(kind, 1),
    uint(revision, 8),
    frame(identity),
    frame(payload),
  ]);
}

function applyNestedPayloadDelta(base, variant, replacement, label) {
  invariant(base.length === variant.length, `${label}: source mutation length drift`);
  invariant(base.length === replacement.length, `${label}: replacement length drift`);
  const refreshed = Buffer.from(replacement);
  for (let index = 0; index < base.length; index += 1) {
    if (base[index] === variant[index]) continue;
    refreshed[index] = variant[index];
  }
  return refreshed;
}

function refreshedNestedSourceVectorV0() {
  const refreshed = structuredClone(vector);
  const sourceByKind = new Map([
    [13, strictHex(
      jointHandoffVector.positive_cases[0].raw_bundle.old_validator_set_cev0_hex,
      "validator set source",
    )],
    [14, strictHex(
      jointHandoffVector.positive_cases[0].raw_bundle.old_consensus_parameters_cev0_hex,
      "parameters source",
    )],
  ]);
  const originalPositiveByKind = new Map(
    vector.semantic_layout_corpus.positive_fixtures
      .filter((fixture) => sourceByKind.has(fixture.kind))
      .map((fixture) => [fixture.kind, fixture]),
  );
  const refreshedPositiveByKind = new Map(
    refreshed.semantic_layout_corpus.positive_fixtures
      .filter((fixture) => sourceByKind.has(fixture.kind))
      .map((fixture) => [fixture.kind, fixture]),
  );

  for (const [kind, replacement] of sourceByKind) {
    const original = originalPositiveByKind.get(kind);
    const target = refreshedPositiveByKind.get(kind);
    invariant(original !== undefined && target !== undefined, `kind ${kind}: positive source missing`);
    const identity = strictHex(target.identity_cev0_hex, `${target.id} identity`);
    target.payload_cev0_hex = replacement.toString("hex");
    target.value_cev0_hex = encodeSnapshotEnvelopeV0(
      target.kind,
      target.revision,
      identity,
      replacement,
    ).toString("hex");
  }

  for (const family of [
    "negative_fixtures",
    "external_object_negative_fixtures",
  ]) {
    for (let index = 0; index < vector.semantic_layout_corpus[family].length; index += 1) {
      const original = vector.semantic_layout_corpus[family][index];
      if (!sourceByKind.has(original.kind)) continue;
      const target = refreshed.semantic_layout_corpus[family][index];
      const originalPositive = originalPositiveByKind.get(original.kind);
      const payload = applyNestedPayloadDelta(
        strictHex(originalPositive.payload_cev0_hex, `${original.id} base payload`),
        strictHex(original.payload_cev0_hex, `${original.id} mutated payload`),
        sourceByKind.get(original.kind),
        original.id,
      );
      const identity = strictHex(target.identity_cev0_hex, `${target.id} identity`);
      target.payload_cev0_hex = payload.toString("hex");
      target.value_cev0_hex = encodeSnapshotEnvelopeV0(
        target.kind,
        target.revision,
        identity,
        payload,
      ).toString("hex");
    }
  }
  return refreshed;
}

if (process.argv.includes("--emit-refreshed-nested-sources")) {
  process.stdout.write(`${JSON.stringify(refreshedNestedSourceVectorV0(), null, 2)}\n`);
  process.exit(0);
}

// Consume the fixed shared raw corpus and exact-decode the common envelope plus
// every kind-specific identity/payload layout. The normal gate never generates
// or rewrites vector material; the explicit authoring mode above only emits a
// complete candidate vector to stdout.
const semanticCorpus = vector.semantic_layout_corpus;
sameJson(
  semanticCorpus.expected_statistics,
  {
    positive_values: 15,
    semantic_negatives: 15,
    external_object_negatives: 2,
    rollout_phase_boundary_values: 4,
    rejected_incomplete_prefixes: 2561,
  },
  "semantic corpus statistics drift",
);
invariant(
  semanticCorpus.positive_fixtures.length === 15 &&
    semanticCorpus.negative_fixtures.length === 15,
  "semantic corpus cardinality drift",
);
const parameterBoundaryFixture = semanticCorpus.positive_fixtures.find(
  (fixture) => fixture.kind === 14,
);
invariant(parameterBoundaryFixture !== undefined, "missing parameter boundary fixture");
const parameterBoundaryRaw = strictHex(
  parameterBoundaryFixture.payload_cev0_hex,
  "parameter boundary payload",
);
const snapshotLeadOffset = parameterFieldOffset("snapshot_lead_blocks");
const withSnapshotLead = (lead) => {
  const raw = Buffer.from(parameterBoundaryRaw);
  uint(lead, 8).copy(raw, snapshotLeadOffset);
  return raw;
};
expectRejectReason(
  () => decodeConsensusParametersExact(withSnapshotLead(2)),
  "parameters_snapshot_lead_finality",
  "lead-2 parameters below the v0 finality chain",
);
decodeConsensusParametersExact(withSnapshotLead(3));
sameJson(
  [...semanticCorpus.positive_fixtures.map((fixture) => fixture.kind)].sort(
    (left, right) => left - right,
  ),
  Array.from({ length: 15 }, (_, index) => index + 1),
  "positive kind coverage drift",
);
sameJson(
  [...semanticCorpus.negative_fixtures.map((fixture) => fixture.kind)].sort(
    (left, right) => left - right,
  ),
  Array.from({ length: 15 }, (_, index) => index + 1),
  "negative kind coverage drift",
);

let semanticPrefixNegatives = 0;
const decodedPositiveByKind = new Map();
for (const fixture of semanticCorpus.positive_fixtures) {
  invariant(fixture.expected === "accept", `${fixture.id}: expected outcome drift`);
  const identityBytes = strictHex(fixture.identity_cev0_hex, `${fixture.id} identity`);
  const payloadBytes = strictHex(fixture.payload_cev0_hex, `${fixture.id} payload`);
  const raw = strictHex(fixture.value_cev0_hex, `${fixture.id} value`);
  const logicalKey = strictHex(fixture.logical_key_hex, `${fixture.id} logical key`);
  invariant(identityBytes.length >= 1 && identityBytes.length <= 452, `${fixture.id}: identity bound`);
  invariant(payloadBytes.length >= 1 && payloadBytes.length <= 65_384, `${fixture.id}: payload bound`);
  invariant(raw.length <= 65_536, `${fixture.id}: envelope bound`);
  invariant(
    Buffer.concat([
      uint(0, 2),
      uint(fixture.kind, 1),
      uint(fixture.revision, 8),
      frame(identityBytes),
      frame(payloadBytes),
    ]).equals(raw),
    `${fixture.id}: noncanonical envelope bytes`,
  );
  const decoded = decodeSnapshotValueExact(raw, logicalKey);
  invariant(decoded.kind === fixture.kind, `${fixture.id}: kind mismatch`);
  invariant(decoded.revision === BigInt(fixture.revision), `${fixture.id}: revision mismatch`);
  invariant(decoded.identity.equals(identityBytes), `${fixture.id}: identity bytes mismatch`);
  invariant(decoded.payload.equals(payloadBytes), `${fixture.id}: payload bytes mismatch`);
  invariant(decoded.key.equals(logicalKey), `${fixture.id}: logical key mismatch`);
  decodedPositiveByKind.set(fixture.kind, decoded);
  for (let length = 0; length < raw.length; length += 1) {
    expectReject(
      () => decodeSnapshotValueExact(raw.subarray(0, length), logicalKey),
      `${fixture.id}: incomplete prefix ${length} accepted`,
    );
    semanticPrefixNegatives += 1;
  }
}
invariant(
  semanticPrefixNegatives === semanticCorpus.expected_statistics.rejected_incomplete_prefixes,
  "semantic prefix count drift",
);

// The four nested-object witnesses are byte-for-byte anchored to their
// independent source corpora; those dedicated gates retain full object and
// cryptographic campaigns while this gate still exact-parses fields needed for
// H3a self-binding.
invariant(
  decodedPositiveByKind
    .get(1)
    .payload.equals(strictHex(
      consumptionCertificateVector.fixture.certificate_cev0_hex,
      "consumption certificate source",
    )),
  "kind 1 nested source corpus drift",
);
const registrationPayload = new Cursor(decodedPositiveByKind.get(9).payload);
registrationPayload.bytesValue(128);
registrationPayload.fixed(32);
registrationPayload.u64();
registrationPayload.u8();
const nestedPop = registrationPayload.bytesValue(65_384);
registrationPayload.finish();
invariant(
  nestedPop.equals(strictHex(snapshotCandidateVector.pop_fixtures[0].cev0_hex, "PoP source")),
  "kind 9 nested source corpus drift",
);
const handoffRaw = jointHandoffVector.positive_cases[0].raw_bundle;
invariant(
  decodedPositiveByKind
    .get(13)
    .payload.equals(strictHex(handoffRaw.old_validator_set_cev0_hex, "validator set source")),
  "kind 13 nested source corpus drift",
);
invariant(
  decodedPositiveByKind
    .get(14)
    .payload.equals(
      strictHex(handoffRaw.old_consensus_parameters_cev0_hex, "parameters source"),
    ),
  "kind 14 nested source corpus drift",
);

for (const fixture of semanticCorpus.negative_fixtures) {
  const identityBytes = strictHex(fixture.identity_cev0_hex, `${fixture.id} identity`);
  const payloadBytes = strictHex(fixture.payload_cev0_hex, `${fixture.id} payload`);
  const raw = strictHex(fixture.value_cev0_hex, `${fixture.id} value`);
  const logicalKey = strictHex(fixture.logical_key_hex, `${fixture.id} logical key`);
  invariant(identityBytes.length >= 1 && identityBytes.length <= 452, `${fixture.id}: identity bound`);
  invariant(payloadBytes.length >= 1 && payloadBytes.length <= 65_384, `${fixture.id}: payload bound`);
  invariant(raw.length <= 65_536, `${fixture.id}: envelope bound`);
  invariant(
    Buffer.concat([
      uint(0, 2),
      uint(fixture.kind, 1),
      uint(fixture.revision, 8),
      frame(identityBytes),
      frame(payloadBytes),
    ]).equals(raw),
    `${fixture.id}: noncanonical negative envelope bytes`,
  );
  expectRejectReason(
    () => decodeSnapshotValueExact(raw, logicalKey),
    fixture.expected_reason,
    fixture.id,
  );
}

invariant(
  semanticCorpus.external_object_negative_fixtures.length === 2,
  "external-object negative cardinality drift",
);
for (const fixture of semanticCorpus.external_object_negative_fixtures) {
  const identityBytes = strictHex(fixture.identity_cev0_hex, `${fixture.id} identity`);
  const payloadBytes = strictHex(fixture.payload_cev0_hex, `${fixture.id} payload`);
  const raw = strictHex(fixture.value_cev0_hex, `${fixture.id} value`);
  const logicalKey = strictHex(fixture.logical_key_hex, `${fixture.id} logical key`);
  invariant(
    Buffer.concat([
      uint(0, 2),
      uint(fixture.kind, 1),
      uint(fixture.revision, 8),
      frame(identityBytes),
      frame(payloadBytes),
    ]).equals(raw),
    `${fixture.id}: noncanonical external-object envelope bytes`,
  );
  expectRejectReason(
    () => decodeSnapshotValueExact(raw, logicalKey),
    fixture.expected_reason,
    fixture.id,
  );
}

invariant(
  semanticCorpus.rollout_phase_boundary_fixtures.length === 4,
  "rollout phase boundary cardinality drift",
);
sameJson(
  semanticCorpus.rollout_phase_boundary_fixtures.map((fixture) => fixture.phase),
  [0, 1, 2, 3],
  "rollout phase boundary coverage drift",
);
for (const fixture of semanticCorpus.rollout_phase_boundary_fixtures) {
  invariant(fixture.expected === "accept" && fixture.kind === 15, `${fixture.id}: phase fixture drift`);
  const decoded = decodeSnapshotValueExact(
    strictHex(fixture.value_cev0_hex, `${fixture.id} value`),
    strictHex(fixture.logical_key_hex, `${fixture.id} logical key`),
  );
  invariant(
    Buffer.concat([
      uint(0, 2),
      uint(fixture.kind, 1),
      uint(fixture.revision, 8),
      frame(strictHex(fixture.identity_cev0_hex, `${fixture.id} identity`)),
      frame(strictHex(fixture.payload_cev0_hex, `${fixture.id} payload`)),
    ]).toString("hex") === fixture.value_cev0_hex &&
    decoded.identity.toString("hex") === fixture.identity_cev0_hex &&
      decoded.payload.toString("hex") === fixture.payload_cev0_hex &&
      decoded.revision === BigInt(fixture.revision),
    `${fixture.id}: fixed phase bytes drift`,
  );
}

const persistenceSeal = vector.production_persistence_seal;
invariant(
  persistenceSeal.schema === "trnm.poco-bft.production-persistence-seal.v0" &&
    persistenceSeal.state_height === 7 &&
    persistenceSeal.manifest_height === 6 &&
    persistenceSeal.exact_physical_leaf_count === 2,
  "production persistence vector header drift",
);
sameJson(
  persistenceSeal.admission_paths,
  [
    "in_memory_state_codec_encode",
    "in_memory_state_codec_decode",
    "sqlite_precommit",
    "sqlite_startup_or_migration",
    "abci_snapshot_restore_v3",
    "abci_snapshot_restore_v4",
  ],
  "production persistence admission paths drift",
);
sameJson(
  persistenceSeal.negative_cases,
  [
    { id: "missing_manifest", expected: "reject" },
    { id: "hidden_unreferenced_leaf", expected: "reject" },
    { id: "manifest_height_ahead_of_state", expected: "reject" },
    { id: "semantic_value_trailing_byte", expected: "reject" },
    { id: "malformed_namespace_key", expected: "reject" },
  ],
  "production persistence negative corpus drift",
);
const sealLogicalKey = strictHex(vector.logical_key_hex, "persistence logical key");
const sealSourceValue = strictHex(vector.source_value_hex, "persistence source value");
const sealManifest = strictHex(vector.source_manifest_cev0_hex, "persistence manifest");
const manifestPhysicalKey = pocoPhysicalKey([Buffer.from("manifest")]);
const entryPhysicalKey = pocoPhysicalKey([
  Buffer.from("entry"),
  Buffer.from([vector.kind]),
  sealLogicalKey,
]);
invariant(
  manifestPhysicalKey.toString("hex") === persistenceSeal.manifest_key_hex &&
    entryPhysicalKey.toString("hex") === persistenceSeal.entry_key_hex,
  "production physical key vector drift",
);
const validProductionLeaves = [
  { key: manifestPhysicalKey, value: sealManifest },
  { key: entryPhysicalKey, value: sealSourceValue },
];
const validatedProduction = validateProductionProjection(
  persistenceSeal.state_height,
  validProductionLeaves,
);
invariant(
  validatedProduction.manifest.height === BigInt(persistenceSeal.manifest_height) &&
    validatedProduction.manifest.count === 1 &&
    validatedProduction.entries.length === 1,
  "valid production projection drift",
);
expectReject(
  () => validateProductionProjection(persistenceSeal.state_height, validProductionLeaves.slice(1)),
  "production projection without manifest accepted",
);
const hiddenFixture = semanticCorpus.positive_fixtures.find((fixture) => fixture.kind === 2);
const hiddenLogicalKey = strictHex(hiddenFixture.logical_key_hex, "hidden logical key");
expectReject(
  () => validateProductionProjection(persistenceSeal.state_height, [
    ...validProductionLeaves,
    {
      key: pocoPhysicalKey([Buffer.from("entry"), Buffer.from([2]), hiddenLogicalKey]),
      value: strictHex(hiddenFixture.value_cev0_hex, "hidden semantic value"),
    },
  ]),
  "unreferenced production leaf accepted",
);
const futureManifest = Buffer.from(sealManifest);
futureManifest.writeBigUInt64BE(BigInt(persistenceSeal.state_height + 1), 3);
expectReject(
  () => validateProductionProjection(persistenceSeal.state_height, [
    { key: manifestPhysicalKey, value: futureManifest },
    validProductionLeaves[1],
  ]),
  "future production manifest accepted",
);
expectReject(
  () => validateProductionProjection(persistenceSeal.state_height, [
    validProductionLeaves[0],
    { key: entryPhysicalKey, value: Buffer.concat([sealSourceValue, Buffer.from([0])]) },
  ]),
  "trailing semantic production value accepted",
);
expectReject(
  () => validateProductionProjection(persistenceSeal.state_height, [
    validProductionLeaves[0],
    { key: Buffer.concat([entryPhysicalKey, Buffer.from([0])]), value: sealSourceValue },
  ]),
  "malformed namespace physical key accepted",
);

// Retain an exact, independent kind-3 decoder and reproduce the shared vector.
const primaryFixture = {
  consumer_id_utf8: vector.consumer_id_utf8,
  consumer_key_id_utf8: vector.consumer_key_id_utf8,
  provider_id_utf8: vector.provider_id_utf8,
};
const identity = nonceFixtureIdentity(primaryFixture);
const key = nonceLogicalKey(primaryFixture);
const source = nonceValue(primaryFixture, 1, 9);
const target = nonceValue(primaryFixture, 2, 10);
invariant(identity.toString("hex") === vector.identity_cev0_hex, "nonce identity CEV0 drift");
invariant(key.toString("hex") === vector.logical_key_hex, "logical key drift");
invariant(source.toString("hex") === vector.source_value_hex, "source value drift");
invariant(target.toString("hex") === vector.target_value_hex, "target value drift");
const decodedSource = decodeNonceValue(source, key);
const decodedTarget = decodeNonceValue(target, key);
invariant(
  decodedSource.consumerId.toString() === vector.consumer_id_utf8 &&
    decodedSource.consumerKeyId.toString() === vector.consumer_key_id_utf8 &&
    decodedSource.providerId.toString() === vector.provider_id_utf8 &&
    decodedSource.nonce === 9n &&
    decodedSource.revision === 1n,
  "source semantic drift",
);
invariant(
  decodedTarget.nonce === 10n && decodedTarget.revision === 2n,
  "target semantic drift",
);
invariant(entryBytes(key, source).toString("hex") === vector.source_entry_cev0_hex, "source entry drift");
invariant(entryBytes(key, target).toString("hex") === vector.target_entry_cev0_hex, "target entry drift");
invariant(entriesRoot(key, source).toString("hex") === vector.source_entries_root_hex, "source entries root drift");
invariant(entriesRoot(key, target).toString("hex") === vector.target_entries_root_hex, "target entries root drift");
invariant(manifest(vector.source_height, key, source).toString("hex") === vector.source_manifest_cev0_hex, "source manifest drift");
invariant(manifest(vector.target_height, key, target).toString("hex") === vector.target_manifest_cev0_hex, "target manifest drift");
const rawMutation = mutation(3, key, source, target);
invariant(rawMutation.toString("hex") === vector.mutation_cev0_hex, "mutation CEV0 drift");
invariant(mutationRoot([rawMutation]).toString("hex") === vector.mutation_root_hex, "single mutation root drift");
invariant(mutationRoot([]).toString("hex") === vector.empty_mutation_root_hex, "empty mutation root drift");
invariant(
  !manifest(vector.source_height, key, target).equals(
    manifest(vector.target_height, key, target),
  ),
  "manifest height is not bound when explicitly refreshed",
);
invariant(
  !mutationRoot([mutation(3, key, target, source)]).equals(mutationRoot([rawMutation])),
  "CAS direction is not bound",
);

let prefixNegatives = 0;
for (const raw of [source, target]) {
  for (let length = 0; length < raw.length; length += 1) {
    expectReject(
      () => decodeNonceValue(raw.subarray(0, length), key),
      "incomplete value accepted",
    );
    prefixNegatives += 1;
  }
}
for (const [name, raw, badKey] of [
  ["trailing", Buffer.concat([source, Buffer.from([0])]), key],
  ["key_substitution", source, Buffer.concat([Buffer.from([key[0] ^ 1]), key.subarray(1)])],
  ["kind_substitution", Buffer.concat([source.subarray(0, 2), Buffer.from([10]), source.subarray(3)]), key],
  ["zero_revision", Buffer.concat([source.subarray(0, 3), Buffer.alloc(8), source.subarray(11)]), key],
]) {
  expectReject(() => decodeNonceValue(raw, badKey), `${name} accepted`);
}
const equalPartyFixture = {
  consumer_id_utf8: "same-party",
  consumer_key_id_utf8: "key",
  provider_id_utf8: "same-party",
};
expectReject(
  () =>
    decodeNonceValue(
      nonceValue(equalPartyFixture, 1, 0),
      nonceLogicalKey(equalPartyFixture),
    ),
  "provider=consumer nonce accepted",
);

// Independent fixed two-leaf and three-leaf mutation-tree campaign.
const mutationFixtures = vector.mutation_tree_fixtures.map((fixture) => {
  const fixtureKey = nonceLogicalKey(fixture);
  const oldValue = nonceValue(fixture, fixture.source_revision, fixture.source_nonce);
  const nextValue = nonceValue(fixture, fixture.target_revision, fixture.target_nonce);
  const raw = mutation(3, fixtureKey, oldValue, nextValue);
  invariant(fixtureKey.toString("hex") === fixture.logical_key_hex, `${fixture.id} key drift`);
  invariant(raw.toString("hex") === fixture.mutation_cev0_hex, `${fixture.id} mutation drift`);
  return { id: fixture.id, kind: 3, key: fixtureKey, raw };
});
expectReject(
  () => assertCanonicalMutations(mutationFixtures),
  "deliberately unsorted mutation fixtures accepted",
);
const canonicalFixtures = [...mutationFixtures].sort(compareMutationIdentity);
assertCanonicalMutations(canonicalFixtures);
sameJson(
  canonicalFixtures.map((fixture) => fixture.id),
  vector.mutation_tree_canonical_ids,
  "canonical mutation sort drift",
);
const canonicalRaw = canonicalFixtures.map((fixture) => fixture.raw);
const leaves = canonicalRaw.map(mutationLeaf);
const level0Pair = mutationNode(0, leaves[0], leaves[1]);
const level0OddDuplicate = mutationNode(0, leaves[2], leaves[2]);
invariant(
  level0Pair.toString("hex") === vector.three_leaf_level0_pair_node_hex,
  "three-leaf pair node drift",
);
invariant(
  level0OddDuplicate.toString("hex") ===
    vector.three_leaf_level0_odd_duplicate_node_hex,
  "three-leaf odd duplicate node drift",
);
const twoLeafManual = mutationOuter(2, level0Pair);
const threeLeafManual = mutationOuter(
  3,
  mutationNode(1, level0Pair, level0OddDuplicate),
);
invariant(
  !twoLeafManual.equals(mutationOuter(3, level0Pair)),
  "mutation count is not independently bound",
);
invariant(
  !mutationOuter(0, null).equals(mutationOuter(0, Buffer.alloc(32))),
  "outer optional-root tag is not bound",
);
invariant(twoLeafManual.equals(mutationRoot(canonicalRaw.slice(0, 2))), "two-leaf algorithm disagreement");
invariant(threeLeafManual.equals(mutationRoot(canonicalRaw)), "three-leaf algorithm disagreement");
invariant(twoLeafManual.toString("hex") === vector.two_leaf_root_hex, "two-leaf fixed root drift");
invariant(threeLeafManual.toString("hex") === vector.three_leaf_root_hex, "three-leaf fixed root drift");
const reversedRaw = [...canonicalRaw].reverse();
const reversedRoot = mutationRoot(reversedRaw);
invariant(
  reversedRoot.toString("hex") === vector.three_leaf_reversed_root_hex &&
    !reversedRoot.equals(threeLeafManual),
  "mutation root is not order-sensitive",
);
expectReject(
  () => assertCanonicalMutations([...canonicalFixtures].reverse()),
  "reversed mutation order accepted",
);

console.log(
  `[ok] B2-H3a/H3b1 snapshot transition + production persistence seal: 15/15 fixed raw layouts exact-decoded; snapshot lead 2 rejected / 3 accepted; ${semanticPrefixNegatives} all-kind incomplete prefixes + 15 targeted semantic + 2 imported-object drift negatives rejected; phases 0..3 accepted; 5 persistence negatives rejected; independent nonce vector adds ${prefixNegatives} prefixes + 5 negatives; fixed 2/3-leaf roots verify canonical sorting, level-u32, odd duplication, count binding, and order sensitivity`,
);
