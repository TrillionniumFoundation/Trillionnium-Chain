#!/usr/bin/env node
/*
 * Strict H3b2b1 operation-sequence authoring evidence.
 *
 * Node derives decisions, proofs, raw operation roots, mutation roots, entry
 * roots, and manifests.  A sequence advances only through one fixed Rust event
 * carrying production-derived raw evidence.  No status string or normalized
 * side fact can make a draft complete.
 */

import crypto from "node:crypto";
import fs from "node:fs";

const DRAFT_SCHEMA = "trnm.poco-bft.application-operation-sequence-draft.v0";
const SOURCE_SCHEMA = "trnm.poco-bft.application-full-genesis-export.v0";
const FINAL_SCHEMA = "trnm.poco-bft.application-operation-sequences.vector.v0";
const STEP_TEMPLATE_SCHEMA = "trnm.poco-bft.application-operation-step-template.v0";
const NEGATIVE_TEMPLATE_SCHEMA = "trnm.poco-bft.application-operation-negative-template.v0";
const STEP_EVENT_SCHEMA = "trnm.poco-bft.application-operation-rust-step-event.v0";
const NEGATIVE_EVENT_SCHEMA = "trnm.poco-bft.application-operation-rust-negative-event.v0";
const STEP_REQUEST_SCHEMA = "trnm.poco-bft.application-operation-rust-step-request.v0";
const NEGATIVE_REQUEST_SCHEMA = "trnm.poco-bft.application-operation-rust-negative-request.v0";
const SCAFFOLD_SCHEMA = "trnm.poco-bft.application-operation-required-scaffold.v0";
const FINAL_VECTOR_RELATIVE_PATH =
  "docs/protocol/poco-bft-v0/vectors/poco-application-operation-sequences-v0.json";
const OPERATION_SCHEMA = "trnm_poco_application_operation_v0";
const PAYLOAD_TYPE = "trnm.poco.application-operation.v0";
const AUTHORITY_SCHEMA = "trnm_poco_application_authority_v0";
const AUTHORITY_IDENTITY = Buffer.from("trnm.poco.application-authority.v0");
const KERNEL_PREREQUISITE =
  "Core epoch activation + authenticated next-epoch configuration transition";

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;
const U32_MAX = (1n << 32n) - 1n;
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0");
const HASH_V1_PREFIX = Buffer.from("trnm.domain.hash.v1");
const EMPTY_LEAF_DOMAIN = "trnm.poco-bft.nullifier-empty-leaf.v0";
const OCCUPIED_LEAF_DOMAIN = "trnm.poco-bft.nullifier-occupied-leaf.v0";
const NULLIFIER_KEY_DOMAIN = "trnm.poco-bft.nullifier-key.v0";
const NULLIFIER_NODE_DOMAIN = "trnm.poco-bft.nullifier-node.v0";
const DECISION_PREIMAGE_DOMAIN = "trnm.poco-bft.application-decision-preimage.v0";
const DECISION_ID_DOMAIN = "trnm.poco-bft.application-decision-id.v0";
const OPERATION_DOMAIN = "trnm.poco-bft.application-operation.v0";
const OPERATION_NODE_DOMAIN = "trnm.poco-bft.application-operation-node.v0";
const OPERATION_ROOT_DOMAIN = "trnm.poco-bft.application-operation-root.v0";
const BUSINESS_INTENT_DOMAIN = "trnm.poco-bft.application-business-intent.v1";
const SNAPSHOT_VALUE_PAYLOAD_DOMAIN = "trnm.poco-bft.snapshot-value-payload.v0";
const VALIDATOR_REGISTRATION_POP_DOMAIN = "trnm.poco-bft.validator-registration-pop.v0";
const MUTATION_DOMAIN = "trnm.poco-bft.application-mutation.v0";
const MUTATION_NODE_DOMAIN = "trnm.poco-bft.application-mutation-node.v0";
const MUTATION_ROOT_DOMAIN = "trnm.poco-bft.application-mutation-root.v0";
const ENTRY_DOMAIN = "trnm.poco-bft.snapshot-entry.v0";
const ENTRY_NODE_DOMAIN = "trnm.poco-bft.snapshot-node.v0";
const ENTRY_ROOT_DOMAIN = "trnm.poco-bft.snapshot-root.v0";
const SEMANTIC_IDENTITY_DOMAIN = "trnm.poco-bft.snapshot-value-identity.v0";
const RECEIPT_ROOT_DOMAIN = "trnm.poco-bft.checkpoint-receipts.v0";
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const STORE_FAILPOINTS = [
  ["before_sql_commit", "source"],
  ["after_sql_commit_before_status", "target"],
];

const CONTEXT_FIELDS = [
  "chain_id_utf8",
  "genesis_hash_hex",
  "source_version",
  "source_root_hex",
  "target_height",
  "active_epoch",
  "active_parameters_cev0_hex",
  "active_parameters_hash_hex",
  "authority_signer_commitment_hex",
];
const AUTHORITY_FIELDS = [
  "envelope_hex",
  "revision",
  "last_target_height",
  "nullifier_root_hex",
  "nullifier_count",
];
const AUTHORITY_STATE_FIELDS = [
  "schema",
  "revision",
  "last_target_height",
  "nullifier_root_hex",
  "nullifier_count",
  "consumer_keys",
  "meter_policies",
  "meter_usage",
  "consumer_provider_usage",
  "task_provider_usage",
  "provider_usage",
  "funded_unused_reservations",
  "active_certificates",
  "pending_challenges",
  "pending_governance_proposals",
  "finalized_governance_approvals",
  "validator_registration_history",
];
const ENTRY_FIELDS = ["kind", "logical_key_hex", "value_hex", "canonical_entry_cev0_hex"];
const MUTATION_FIELDS = [
  "kind",
  "logical_key_hex",
  "expected_value_hex",
  "next_value_hex",
  "canonical_cev0_hex",
];
const OPERATION_FIELDS = [
  "schema",
  "target_height",
  "expected_state_revision",
  "body",
  "semantic_changes",
  "nullifier_non_membership_checks",
  "nullifier_insertions",
];
const METER_POLICY_FIELDS = [
  "meter_id_hex",
  "meter_version",
  "task_id_hex",
  "output_commitment_hex",
  "unit_scale",
  "evidence_policy",
  "per_certificate_cap",
  "rolling_cap",
  "rolling_epoch_span",
  "retention_blocks",
  "active_from_height",
  "retired_at_height",
];
const SIGNED_TX_FIELDS = [
  "schema",
  "chain_id",
  "command_id",
  "signer_id",
  "signer_role",
  "public_key_hex",
  "nonce",
  "issued_at_unix_ms",
  "expires_at_unix_ms",
  "payload_type",
  "payload_hex",
  "payload_hash_hex",
  "signature_hex",
];
const BODY_FIELDS = {
  authorize_consumer_key: ["kind", "consumer_id_hex", "consumer_key_id_hex", "public_key_hex", "active_from_height", "decision_id_hex"],
  revoke_consumer_key: ["kind", "consumer_id_hex", "consumer_key_id_hex", "public_key_hex", "active_from_height", "revoked_at_height", "decision_id_hex"],
  prune_revoked_consumer_key: ["kind", "consumer_id_hex", "consumer_key_id_hex"],
  define_meter_policy: ["kind", "policy", "decision_id_hex"],
  retire_meter_policy: ["kind", "meter_id_hex", "meter_version", "retired_at_height", "decision_id_hex"],
  prune_retired_meter: ["kind", "meter_id_hex", "meter_version"],
  fund_settlement: ["kind", "certificate_id_hex", "settlement_commitment_hex", "reserved_units", "funding_decision_id_hex"],
  accept_certificate: ["kind", "certificate_id_hex", "funding_decision_id_hex", "acceptance_decision_id_hex", "meter_decision_id_hex", "evidence_decision_id_hex"],
  release_settlement: ["kind", "certificate_id_hex", "release_decision_id_hex"],
  open_challenge: ["kind", "certificate_id_hex", "challenge_id_hex", "opening_decision_id_hex"],
  resolve_challenge: ["kind", "certificate_id_hex", "challenge_id_hex", "resolution", "resolution_decision_id_hex"],
  propose_governance: ["kind", "target_epoch", "phase", "parameters_hash_hex", "activation_height", "proposal_decision_id_hex"],
  approve_governance: ["kind", "target_epoch", "parameters_hash_hex", "activation_height", "decision_id_hex"],
  register_validator: ["kind", "validator_id_hex", "target_epoch", "registration_decision_id_hex"],
  rotate_validator: ["kind", "validator_id_hex", "target_epoch", "previous_history_head_hex", "previous_registration_nonce", "registration_decision_id_hex"],
  revoke_validator: ["kind", "validator_id_hex", "revocation_decision_id_hex"],
  prune_revoked_validator_history: ["kind", "validator_id_hex"],
  prune_expired_certificate: ["kind", "certificate_id_hex"],
};
const BUSINESS_INTENT_OMISSIONS = {
  authorize_consumer_key: ["/body/active_from_height"],
  define_meter_policy: ["/body/policy/active_from_height"],
  register_validator: ["/body/target_epoch"],
};
const BUSINESS_INTENT_PUT_SEMANTIC_KIND = {
  authorize_consumer_key: 2,
  define_meter_policy: 5,
  fund_settlement: 6,
  register_validator: 9,
  rotate_validator: 9,
  resolve_challenge: 12,
  approve_governance: 15,
};

const REQUIRED_AUTOMATA = [
  {
    id: "certificate_challenge_rejected",
    execution_scope: "full_application_store",
    block_operation_kinds: [
      ["authorize_consumer_key", "define_meter_policy", "register_validator", "fund_settlement"],
      ["accept_certificate"],
      ["open_challenge"],
      ["resolve_challenge"],
    ],
    terminal_resolution: "rejected",
    negative_operation_kind: "resolve_challenge",
    negative_reject_stage: "authority",
    negative_error_code: "challenge_not_pending",
    subject_fields: ["certificate_id_hex", "challenge_id_hex"],
    negative_replay_nullifier_family: null,
  },
  {
    id: "certificate_challenge_sustained",
    execution_scope: "full_application_store",
    block_operation_kinds: [
      ["authorize_consumer_key", "define_meter_policy", "register_validator", "fund_settlement"],
      ["accept_certificate"],
      ["open_challenge"],
      ["resolve_challenge"],
    ],
    terminal_resolution: "sustained",
    negative_operation_kind: "resolve_challenge",
    negative_reject_stage: "authority",
    negative_error_code: "challenge_not_pending",
    subject_fields: ["certificate_id_hex", "challenge_id_hex"],
    negative_replay_nullifier_family: null,
  },
  {
    id: "governance_propose_approve",
    execution_scope: "full_application_store",
    block_operation_kinds: [["propose_governance"], ["approve_governance"]],
    terminal_resolution: null,
    negative_operation_kind: "approve_governance",
    negative_reject_stage: "authority",
    negative_error_code: "governance_approval_lacks_authenticated_proposal",
    subject_fields: ["target_epoch", "parameters_hash_hex", "activation_height"],
    negative_replay_nullifier_family: null,
  },
  {
    id: "validator_register_rotate",
    execution_scope: "full_application_store",
    block_operation_kinds: [["register_validator"], ["rotate_validator"]],
    terminal_resolution: null,
    negative_operation_kind: "rotate_validator",
    negative_reject_stage: "authority",
    negative_error_code: "validator_consensus_key_already_active",
    subject_fields: ["validator_id_hex", "target_epoch"],
    negative_replay_nullifier_family: null,
  },
  {
    id: "release_refund_replay",
    execution_scope: "full_application_store",
    block_operation_kinds: [["fund_settlement"], ["release_settlement"]],
    terminal_resolution: null,
    negative_operation_kind: "fund_settlement",
    negative_reject_stage: "proof",
    negative_error_code: "nullifier_non_membership_root_mismatch",
    subject_fields: ["certificate_id_hex"],
    negative_replay_nullifier_family: 1,
  },
  {
    id: "certificate_prune_replay",
    execution_scope: "isolated_prune_transition_kernel",
    block_operation_kinds: [["prune_expired_certificate"]],
    terminal_resolution: null,
    negative_operation_kind: "fund_settlement",
    negative_reject_stage: "proof",
    negative_error_code: "nullifier_non_membership_root_mismatch",
    subject_fields: ["certificate_id_hex"],
    negative_replay_nullifier_family: 1,
  },
  {
    id: "consumer_key_prune_replay",
    execution_scope: "isolated_prune_transition_kernel",
    block_operation_kinds: [["prune_revoked_consumer_key"]],
    terminal_resolution: null,
    negative_operation_kind: "authorize_consumer_key",
    negative_reject_stage: "proof",
    negative_error_code: "nullifier_non_membership_root_mismatch",
    subject_fields: ["consumer_id_hex", "consumer_key_id_hex"],
    negative_replay_nullifier_family: 10,
  },
  {
    id: "meter_prune_replay",
    execution_scope: "isolated_prune_transition_kernel",
    block_operation_kinds: [["prune_retired_meter"]],
    terminal_resolution: null,
    negative_operation_kind: "define_meter_policy",
    negative_reject_stage: "proof",
    negative_error_code: "nullifier_non_membership_root_mismatch",
    subject_fields: ["meter_id_hex", "meter_version"],
    negative_replay_nullifier_family: 12,
  },
  {
    id: "validator_prune_replay",
    execution_scope: "isolated_prune_transition_kernel",
    block_operation_kinds: [["prune_revoked_validator_history"]],
    terminal_resolution: null,
    negative_operation_kind: "register_validator",
    negative_reject_stage: "proof",
    negative_error_code: "nullifier_non_membership_root_mismatch",
    subject_fields: ["validator_id_hex"],
    negative_replay_nullifier_family: 14,
  },
];
const REJECT_STAGES = new Set(["admission", "exact_decode", "context", "authority", "semantic", "proof", "overlay", "seal", "storage"]);
const REJECT_STAGE_PRIORITY = Object.fromEntries([...REJECT_STAGES].map((stage, index) => [stage, index]));

const automatonForId = (id) => {
  const matches = REQUIRED_AUTOMATA.filter((item) => item.id === id);
  invariant(matches.length === 1, "sequence ID is not one required automaton: " + id);
  return matches[0];
};
const emptySubjects = (automaton) => Object.fromEntries(automaton.subject_fields.map((field) => [field, null]));
const bodySubjectValues = (automaton, body) => {
  const values = {};
  for (const field of automaton.subject_fields) {
    if (field in body) values[field] = body[field];
    else if (body.policy !== undefined && field in body.policy) values[field] = body.policy[field];
  }
  return values;
};
const mergeSubjects = (subjects, automaton, body, label) => {
  const values = bodySubjectValues(automaton, body);
  for (const [field, value] of Object.entries(values)) {
    invariant(subjects[field] === null || subjects[field] === value, label + " subject substitution at " + field);
    subjects[field] = value;
  }
};
const validateSubjects = (subjects, automaton, label, requireComplete = true) => {
  fieldOrder(subjects, automaton.subject_fields, label);
  if (requireComplete) for (const field of automaton.subject_fields) invariant(subjects[field] !== null, label + " is incomplete at " + field);
};
const semanticIdentityDigest = (kind, identity) => domainHash(
  SEMANTIC_IDENTITY_DOMAIN,
  Buffer.concat([uint(0, 2), uint(kind, 1), frame(identity)]),
);
const joinedIdentity = (parts) => Buffer.concat(parts.map((part) => frame(part)));
const expectedReplayIdentifier = (automaton, subjects) => {
  switch (automaton.negative_replay_nullifier_family) {
    case null: return null;
    case 1: return hash32(subjects.certificate_id_hex, "certificate replay subject");
    case 10: return semanticIdentityDigest(2, joinedIdentity([
      opaqueHex(subjects.consumer_id_hex, "consumer replay subject"),
      opaqueHex(subjects.consumer_key_id_hex, "consumer-key replay subject"),
    ]));
    case 12: return semanticIdentityDigest(5, Buffer.concat([
      frame(opaqueHex(subjects.meter_id_hex, "meter replay subject")),
      uint(subjects.meter_version, 4),
    ]));
    case 14: return semanticIdentityDigest(9, opaqueHex(subjects.validator_id_hex, "validator replay subject"));
    default: fail("unhandled replay family");
  }
};

const fail = (message) => { throw new Error(message); };
const invariant = (condition, message) => { if (!condition) fail(message); };
const clone = (value) => structuredClone(value);
const sameJson = (left, right, message) => invariant(JSON.stringify(left) === JSON.stringify(right), message);
const fieldOrder = (value, expected, label) => {
  invariant(value !== null && typeof value === "object" && !Array.isArray(value), label + " is not an object");
  sameJson(Object.keys(value), expected, label + " field order drift");
};
const unique = (values, label) => invariant(new Set(values).size === values.length, label + " contain duplicates");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest();
const canonicalBytes = (value) => Buffer.from(JSON.stringify(value));
const uint = (value, bytes) => {
  let remaining = BigInt(value);
  invariant(remaining >= 0n, "negative unsigned integer");
  const result = Buffer.alloc(bytes);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  invariant(remaining === 0n, "unsigned integer overflow");
  return result;
};
const frame = (value) => Buffer.concat([uint(value.length, 4), value]);
const frame64 = (value) => Buffer.concat([uint(value.length, 8), value]);
const domainHash = (domain, encoded) => sha256(Buffer.concat([HASH_PREFIX, Buffer.from(domain), encoded].map(frame)));
const hashDomainV1 = (domain, parts) => sha256(Buffer.concat([HASH_V1_PREFIX, frame64(Buffer.from(domain)), ...parts.map(frame64)]));
const orderedRoot = (leafDomain, nodeDomain, rootDomain, values) => {
  let layer = values.map((value) => domainHash(leafDomain, value));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      const right = layer[index + 1] ?? left;
      next.push(domainHash(nodeDomain, Buffer.concat([uint(0, 2), uint(level, 4), left, right])));
    }
    layer = next;
    level += 1;
  }
  return domainHash(rootDomain, Buffer.concat([uint(0, 2), uint(values.length, 4), layer.length === 0 ? uint(0, 1) : Buffer.concat([uint(1, 1), layer[0]])]));
};
const checkpointOrderedRoot = (domain, values) => {
  let layer = values.map((value, index) => hashDomainV1(domain + ".leaf", [uint(index, 4), value]));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      const right = layer[index + 1] ?? left;
      next.push(hashDomainV1(domain + ".node", [uint(level, 4), left, right]));
    }
    layer = next;
    level += 1;
  }
  return layer.length === 0
    ? hashDomainV1(domain, [uint(values.length, 4), uint(0, 1)])
    : hashDomainV1(domain, [uint(values.length, 4), uint(1, 1), layer[0]]);
};
const asSafeU64 = (value, label) => {
  invariant(typeof value === "number" && Number.isSafeInteger(value) && value >= 0, label + " must be a nonnegative JSON safe integer u64");
  invariant(BigInt(value) <= U64_MAX, label + " exceeds u64");
  return BigInt(value);
};
const asU32 = (value, label) => {
  const result = asSafeU64(value, label);
  invariant(result <= U32_MAX, label + " exceeds u32");
  return result;
};
const asU8 = (value, label) => {
  const result = asSafeU64(value, label);
  invariant(result <= 255n, label + " exceeds u8");
  return result;
};
const asU128 = (value, label) => {
  invariant(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), label + " is not canonical decimal-string u128");
  const result = BigInt(value);
  invariant(result <= U128_MAX, label + " exceeds u128");
  return result;
};
const evenHex = (value, label, minimumBytes = 0, maximumBytes = Number.MAX_SAFE_INTEGER) => {
  invariant(typeof value === "string" && value.length % 2 === 0 && (value.length === 0 || /^[0-9a-f]+$/.test(value)), label + " is not canonical lowercase hex");
  const result = Buffer.from(value, "hex");
  invariant(result.length >= minimumBytes && result.length <= maximumBytes, label + " byte length is outside bound");
  return result;
};
const hash32 = (value, label) => {
  const result = evenHex(value, label, 32, 32);
  invariant(result.length === 32, label + " is not Hash32");
  return result;
};
const nonzeroHash32 = (value, label) => {
  const result = hash32(value, label);
  invariant(!result.equals(Buffer.alloc(32)), label + " is zero");
  return result;
};
const opaqueHex = (value, label) => evenHex(value, label, 1, 128);
const readRaw = (filename) => {
  const raw = fs.readFileSync(filename);
  return { raw, value: JSON.parse(raw.toString("utf8")) };
};
const output = (value) => process.stdout.write(JSON.stringify(value, null, 2) + "\n");

const pointerParts = (pointer) => {
  invariant(typeof pointer === "string" && pointer.startsWith("/"), "invalid JSON pointer " + pointer);
  return pointer.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
};
const pointerGet = (value, pointer) => {
  let current = value;
  for (const part of pointerParts(pointer)) {
    invariant(current !== null && typeof current === "object" && part in current, "missing JSON pointer " + pointer);
    current = current[part];
  }
  return current;
};
const pointerSet = (value, pointer, replacement) => {
  const parts = pointerParts(pointer);
  let current = value;
  for (const part of parts.slice(0, -1)) {
    invariant(current !== null && typeof current === "object" && part in current, "missing JSON pointer " + pointer);
    current = current[part];
  }
  invariant(parts.at(-1) in current, "missing JSON pointer " + pointer);
  current[parts.at(-1)] = replacement;
};
const pointerDelete = (value, pointer) => {
  const parts = pointerParts(pointer);
  let current = value;
  for (const part of parts.slice(0, -1)) {
    invariant(current !== null && typeof current === "object" && part in current, "missing JSON pointer " + pointer);
    current = current[part];
  }
  invariant(parts.at(-1) in current, "missing JSON pointer " + pointer);
  delete current[parts.at(-1)];
};

const decisionBindings = (kind) => {
  const table = {
    authorize_consumer_key: [["/body/decision_id_hex", "authorize-consumer-key"]],
    revoke_consumer_key: [["/body/decision_id_hex", "revoke-consumer-key"]],
    prune_revoked_consumer_key: [],
    define_meter_policy: [["/body/decision_id_hex", "define-meter"]],
    retire_meter_policy: [["/body/decision_id_hex", "retire-meter"]],
    prune_retired_meter: [],
    fund_settlement: [["/body/funding_decision_id_hex", "fund-settlement"]],
    accept_certificate: [["/body/acceptance_decision_id_hex", "accept-certificate"], ["/body/meter_decision_id_hex", "meter-certificate"], ["/body/evidence_decision_id_hex", "evidence-certificate"]],
    release_settlement: [["/body/release_decision_id_hex", "release-settlement"]],
    open_challenge: [["/body/challenge_id_hex", "challenge-id"], ["/body/opening_decision_id_hex", "open-challenge"]],
    resolve_challenge: [["/body/resolution_decision_id_hex", "resolve-challenge"]],
    propose_governance: [["/body/proposal_decision_id_hex", "propose-governance"]],
    approve_governance: [["/body/decision_id_hex", "approve-governance"]],
    register_validator: [["/body/registration_decision_id_hex", "register-validator"]],
    rotate_validator: [["/body/registration_decision_id_hex", "rotate-validator"]],
    revoke_validator: [["/body/revocation_decision_id_hex", "revoke-validator"]],
    prune_revoked_validator_history: [],
    prune_expired_certificate: [],
  };
  invariant(kind in table, "unknown operation kind " + kind);
  return table[kind];
};

const validateMeterPolicy = (policy, label) => {
  fieldOrder(policy, METER_POLICY_FIELDS, label);
  opaqueHex(policy.meter_id_hex, label + ".meter_id_hex");
  asU32(policy.meter_version, label + ".meter_version");
  opaqueHex(policy.task_id_hex, label + ".task_id_hex");
  if (policy.output_commitment_hex !== null) hash32(policy.output_commitment_hex, label + ".output_commitment_hex");
  asU128(policy.unit_scale, label + ".unit_scale");
  invariant(["required", "forbidden", "optional"].includes(policy.evidence_policy), label + ".evidence_policy drift");
  asU128(policy.per_certificate_cap, label + ".per_certificate_cap");
  asU128(policy.rolling_cap, label + ".rolling_cap");
  asSafeU64(policy.rolling_epoch_span, label + ".rolling_epoch_span");
  asSafeU64(policy.retention_blocks, label + ".retention_blocks");
  asSafeU64(policy.active_from_height, label + ".active_from_height");
  if (policy.retired_at_height !== null) asSafeU64(policy.retired_at_height, label + ".retired_at_height");
};
const validateBody = (body, label) => {
  invariant(typeof body?.kind === "string" && body.kind in BODY_FIELDS, label + ".kind is unknown");
  fieldOrder(body, BODY_FIELDS[body.kind], label);
  const id = (field) => opaqueHex(body[field], label + "." + field);
  const h = (field) => hash32(body[field], label + "." + field);
  const u64 = (field) => asSafeU64(body[field], label + "." + field);
  const u32 = (field) => asU32(body[field], label + "." + field);
  switch (body.kind) {
    case "authorize_consumer_key": id("consumer_id_hex"); id("consumer_key_id_hex"); h("public_key_hex"); u64("active_from_height"); h("decision_id_hex"); break;
    case "revoke_consumer_key": id("consumer_id_hex"); id("consumer_key_id_hex"); h("public_key_hex"); u64("active_from_height"); u64("revoked_at_height"); h("decision_id_hex"); break;
    case "prune_revoked_consumer_key": id("consumer_id_hex"); id("consumer_key_id_hex"); break;
    case "define_meter_policy": validateMeterPolicy(body.policy, label + ".policy"); h("decision_id_hex"); break;
    case "retire_meter_policy": id("meter_id_hex"); u32("meter_version"); u64("retired_at_height"); h("decision_id_hex"); break;
    case "prune_retired_meter": id("meter_id_hex"); u32("meter_version"); break;
    case "fund_settlement": h("certificate_id_hex"); h("settlement_commitment_hex"); asU128(body.reserved_units, label + ".reserved_units"); h("funding_decision_id_hex"); break;
    case "accept_certificate": h("certificate_id_hex"); h("funding_decision_id_hex"); h("acceptance_decision_id_hex"); h("meter_decision_id_hex"); h("evidence_decision_id_hex"); break;
    case "release_settlement": h("certificate_id_hex"); h("release_decision_id_hex"); break;
    case "open_challenge": h("certificate_id_hex"); h("challenge_id_hex"); h("opening_decision_id_hex"); break;
    case "resolve_challenge": h("certificate_id_hex"); h("challenge_id_hex"); invariant(["rejected", "sustained"].includes(body.resolution), label + ".resolution drift"); h("resolution_decision_id_hex"); break;
    case "propose_governance": u64("target_epoch"); asU8(body.phase, label + ".phase"); h("parameters_hash_hex"); u64("activation_height"); h("proposal_decision_id_hex"); break;
    case "approve_governance": u64("target_epoch"); h("parameters_hash_hex"); u64("activation_height"); h("decision_id_hex"); break;
    case "register_validator": id("validator_id_hex"); u64("target_epoch"); h("registration_decision_id_hex"); break;
    case "rotate_validator": id("validator_id_hex"); u64("target_epoch"); h("previous_history_head_hex"); u64("previous_registration_nonce"); h("registration_decision_id_hex"); break;
    case "revoke_validator": id("validator_id_hex"); h("revocation_decision_id_hex"); break;
    case "prune_revoked_validator_history": id("validator_id_hex"); break;
    case "prune_expired_certificate": h("certificate_id_hex"); break;
    default: fail("unreachable operation body");
  }
};
const compareKindKey = (left, right) => left.kind - right.kind || Buffer.compare(left.key, right.key);
const validateProofArray = (values, label) => {
  invariant(Array.isArray(values) && values.length <= 16, label + " count exceeds bound");
  let previous = null;
  for (const [index, item] of values.entries()) {
    fieldOrder(item, ["family", "identifier_hex", "proof_hex"], label + "[" + index + "]");
    invariant(Number.isInteger(item.family) && item.family >= 1 && item.family <= 14, label + " family outside 1..14");
    const identifier = hash32(item.identifier_hex, label + " identifier");
    const proof = evenHex(item.proof_hex, label + " proof", 8230, 8230);
    invariant(proof.readUInt16BE(0) === 0 && proof.readUInt16BE(2) === 0 && proof.readUInt16BE(4) === 256, label + " proof header drift");
    invariant(proof.subarray(6, 38).equals(deriveNullifierKey(item.family, identifier)), label + " proof key drift");
    const identity = { family: item.family, identifier };
    if (previous !== null) invariant(previous.family < identity.family || (previous.family === identity.family && Buffer.compare(previous.identifier, identity.identifier) < 0), label + " are not strictly sorted unique");
    previous = identity;
  }
};
const validateOperation = (operation, label) => {
  fieldOrder(operation, OPERATION_FIELDS, label);
  invariant(operation.schema === OPERATION_SCHEMA, label + " schema drift");
  asSafeU64(operation.target_height, label + ".target_height");
  asSafeU64(operation.expected_state_revision, label + ".expected_state_revision");
  validateBody(operation.body, label + ".body");
  invariant(Array.isArray(operation.semantic_changes) && operation.semantic_changes.length >= 1 && operation.semantic_changes.length <= 32, label + " semantic change count outside 1..32");
  let previous = null;
  for (const [index, change] of operation.semantic_changes.entries()) {
    fieldOrder(change, ["kind", "logical_key_hex", "next_value_hex"], label + ".semantic_changes[" + index + "]");
    invariant(Number.isInteger(change.kind) && change.kind >= 1 && change.kind <= 15, label + " semantic kind outside 1..15");
    const key = hash32(change.logical_key_hex, label + " semantic key");
    if (change.next_value_hex !== null) evenHex(change.next_value_hex, label + " semantic next value", 1, 65536);
    const identity = { kind: change.kind, key };
    if (previous !== null) invariant(compareKindKey(previous, identity) < 0, label + " semantic changes are not strictly sorted unique");
    previous = identity;
  }
  const prune = operation.body.kind.startsWith("prune_");
  if (operation.body.kind === "release_settlement") {
    const expectedKey = semanticIdentityDigest(6, hash32(operation.body.certificate_id_hex, label + " release certificate ID")).toString("hex");
    invariant(operation.semantic_changes.length === 1 && operation.semantic_changes[0].kind === 6 && operation.semantic_changes[0].logical_key_hex === expectedKey && operation.semantic_changes[0].next_value_hex === null, label + " release delete is not the one exact same-certificate kind-6 tombstone");
  } else {
    invariant(operation.semantic_changes.every((change) => (change.next_value_hex === null) === prune), label + " delete authority is not prune-only");
  }
  validateProofArray(operation.nullifier_non_membership_checks, label + ".nullifier_non_membership_checks");
  validateProofArray(operation.nullifier_insertions, label + ".nullifier_insertions");
  return operation;
};

const emptyLeafHash = () => domainHash(EMPTY_LEAF_DOMAIN, uint(0, 2));
const occupiedLeafHash = (key) => domainHash(OCCUPIED_LEAF_DOMAIN, Buffer.concat([uint(0, 2), key]));
const nullifierNodeHash = (level, left, right) => domainHash(NULLIFIER_NODE_DOMAIN, Buffer.concat([uint(0, 2), uint(level, 4), left, right]));
const deriveNullifierKey = (family, identifier) => domainHash(NULLIFIER_KEY_DOMAIN, Buffer.concat([uint(0, 2), uint(family, 1), identifier]));
const DEFAULT_HASHES = [emptyLeafHash()];
for (let level = 0; level < 256; level += 1) DEFAULT_HASHES.push(nullifierNodeHash(level, DEFAULT_HASHES[level], DEFAULT_HASHES[level]));
const keyInteger = (key) => BigInt("0x" + key.toString("hex"));
const sparseRoot = (keys) => {
  let nodes = new Map(keys.map((key) => [keyInteger(key), occupiedLeafHash(key)]));
  invariant(nodes.size === keys.length, "duplicate sparse leaf");
  for (let level = 0; level < 256; level += 1) {
    const bit = 1n << BigInt(level);
    const parents = new Set([...nodes.keys()].map((position) => position & ~bit));
    const next = new Map();
    for (const parent of parents) {
      const digest = nullifierNodeHash(level, nodes.get(parent) ?? DEFAULT_HASHES[level], nodes.get(parent | bit) ?? DEFAULT_HASHES[level]);
      if (!digest.equals(DEFAULT_HASHES[level + 1])) next.set(parent, digest);
    }
    nodes = next;
  }
  return nodes.get(0n) ?? DEFAULT_HASHES[256];
};
const sparseProof = (keys, targetKey) => {
  const target = keyInteger(targetKey);
  let nodes = new Map(keys.map((key) => [keyInteger(key), occupiedLeafHash(key)]));
  invariant(nodes.size === keys.length && !nodes.has(target), "nullifier is already occupied");
  const siblings = [];
  for (let level = 0; level < 256; level += 1) {
    const bit = 1n << BigInt(level);
    const normalizedTarget = target & ~(bit - 1n);
    siblings.push(nodes.get(normalizedTarget ^ bit) ?? DEFAULT_HASHES[level]);
    const parents = new Set([...nodes.keys()].map((position) => position & ~bit));
    const next = new Map();
    for (const parent of parents) {
      const digest = nullifierNodeHash(level, nodes.get(parent) ?? DEFAULT_HASHES[level], nodes.get(parent | bit) ?? DEFAULT_HASHES[level]);
      if (!digest.equals(DEFAULT_HASHES[level + 1])) next.set(parent, digest);
    }
    nodes = next;
  }
  return { root: nodes.get(0n) ?? DEFAULT_HASHES[256], proof: Buffer.concat([uint(0, 2), uint(0, 2), uint(256, 2), targetKey, ...siblings]) };
};
const normalizedOccupied = (state) => {
  fieldOrder(state, ["root_hex", "count", "occupied"], "authoring nullifier state");
  invariant(typeof state.count === "string" && /^(0|[1-9][0-9]*)$/.test(state.count), "authoring nullifier count must be decimal string");
  invariant(BigInt(state.count) <= U64_MAX, "authoring nullifier count exceeds u64");
  invariant(Array.isArray(state.occupied), "authoring occupied set is not an array");
  const entries = state.occupied.map((item, index) => {
    fieldOrder(item, ["family", "identifier_hex"], "occupied[" + index + "]");
    invariant(Number.isInteger(item.family) && item.family >= 1 && item.family <= 14, "occupied family outside 1..14");
    const identifier = hash32(item.identifier_hex, "occupied identifier");
    return { family: item.family, identifier_hex: item.identifier_hex, identifier, key: deriveNullifierKey(item.family, identifier) };
  });
  unique(entries.map((item) => item.key.toString("hex")), "occupied nullifier keys");
  invariant(BigInt(state.count) === BigInt(entries.length), "authoring nullifier count differs from retained set");
  invariant(sparseRoot(entries.map((item) => item.key)).equals(hash32(state.root_hex, "authoring nullifier root")), "authoring nullifier root drift");
  return entries;
};
const canonicalNullifierState = (state) => {
  const entries = normalizedOccupied(state).sort((left, right) => left.family - right.family || Buffer.compare(left.identifier, right.identifier));
  return { root_hex: state.root_hex, count: state.count, occupied: entries.map(({ family, identifier_hex }) => ({ family, identifier_hex })) };
};

const namespacedKey = (namespace, components) => {
  invariant(components.length > 0 && components.length <= 0xffff, "authenticated key component count");
  const encoded = [Buffer.from("trnm/authenticated-state/v4"), uint(0, 1), uint(namespace, 1), uint(components.length, 2)];
  for (const component of components) {
    invariant(component.length > 0, "empty authenticated key component");
    encoded.push(frame(component));
  }
  return Buffer.concat(encoded);
};
const manifestKey = () => namespacedKey(8, [Buffer.from("manifest")]);
const entryKey = (kind, logicalKey) => namespacedKey(8, [Buffer.from("entry"), uint(kind, 1), logicalKey]);
const canonicalEntry = (kind, logicalKey, value) => Buffer.concat([uint(0, 2), uint(kind, 1), frame(logicalKey), frame(value)]);
const canonicalMutation = (item) => {
  const optional = (value) => value === null ? uint(0, 1) : Buffer.concat([uint(1, 1), frame(value)]);
  return Buffer.concat([uint(0, 2), uint(item.kind, 1), frame(item.key), optional(item.expected), optional(item.next)]);
};
const decodeManifest = (bytes) => {
  invariant(bytes.length === 47 && bytes.readUInt16BE(0) === 0 && bytes[2] === 8, "manifest header drift");
  return { height: bytes.readBigUInt64BE(3), count: bytes.readUInt32BE(11), root: bytes.subarray(15) };
};
const readFrame = (bytes, cursor, label) => {
  invariant(cursor.offset + 4 <= bytes.length, label + " truncated length");
  const length = bytes.readUInt32BE(cursor.offset);
  cursor.offset += 4;
  invariant(cursor.offset + length <= bytes.length, label + " truncated bytes");
  const result = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return result;
};
const semanticTake = (bytes, cursor, length, label) => {
  invariant(Number.isInteger(length) && length >= 0 && cursor.offset + length <= bytes.length, label + " truncated bytes");
  const result = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return result;
};
const semanticU8 = (bytes, cursor, label) => semanticTake(bytes, cursor, 1, label)[0];
const semanticU16 = (bytes, cursor, label) => semanticTake(bytes, cursor, 2, label).readUInt16BE(0);
const semanticU32 = (bytes, cursor, label) => semanticTake(bytes, cursor, 4, label).readUInt32BE(0);
const semanticU64 = (bytes, cursor, label) => semanticTake(bytes, cursor, 8, label).readBigUInt64BE(0);
const semanticU128 = (bytes, cursor, label) => {
  const raw = semanticTake(bytes, cursor, 16, label);
  return (raw.readBigUInt64BE(0) << 64n) | raw.readBigUInt64BE(8);
};
const semanticFrame = (bytes, cursor, label, maximum = 65536) => {
  const length = semanticU32(bytes, cursor, label + ".length");
  invariant(length <= maximum, label + " exceeds bound");
  return semanticTake(bytes, cursor, length, label);
};
const semanticOptionalU64 = (bytes, cursor, label) => {
  const marker = semanticU8(bytes, cursor, label + ".marker");
  invariant(marker === 0 || marker === 1, label + " optional marker drift");
  return marker === 0 ? null : semanticU64(bytes, cursor, label).toString();
};
const semanticOptionalHash32 = (bytes, cursor, label) => {
  const marker = semanticU8(bytes, cursor, label + ".marker");
  invariant(marker === 0 || marker === 1, label + " optional marker drift");
  return marker === 0 ? null : semanticTake(bytes, cursor, 32, label).toString("hex");
};
const semanticFinish = (bytes, cursor, label) => invariant(cursor.offset === bytes.length, label + " trailing bytes");
const semanticEnum = (value, minimum, maximum, label) => {
  invariant(value >= minimum && value <= maximum, label + " discriminant drift");
  return value;
};
const decodeValidatorPopIntent = (proof, validatorId, consensusKey, registrationNonce, label) => {
  const cursor = { offset: 0 };
  const schemaVersion = semanticU16(proof, cursor, label + ".schema");
  invariant(schemaVersion === 0, label + " schema drift");
  const genesisHash = semanticTake(proof, cursor, 32, label + ".genesis_hash");
  invariant(!genesisHash.equals(Buffer.alloc(32)), label + " zero genesis hash");
  const chainLength = semanticU16(proof, cursor, label + ".chain_id.length");
  invariant(chainLength >= 1 && chainLength <= 128, label + " chain ID length drift");
  const chainBytes = semanticTake(proof, cursor, chainLength, label + ".chain_id");
  const chainId = chainBytes.toString("utf8");
  invariant(Buffer.from(chainId).equals(chainBytes) && chainId === chainId.trim(), label + " chain ID is not canonical UTF-8");
  const targetEpoch = semanticU64(proof, cursor, label + ".target_epoch");
  const proofValidator = semanticFrame(proof, cursor, label + ".validator_id", 128);
  const proofKey = semanticTake(proof, cursor, 32, label + ".public_key");
  const proofNonce = semanticU64(proof, cursor, label + ".registration_nonce");
  semanticTake(proof, cursor, 64, label + ".signature");
  semanticFinish(proof, cursor, label);
  invariant(proofValidator.equals(validatorId), label + " validator identity mismatch");
  invariant(proofKey.equals(consensusKey), label + " consensus key mismatch");
  invariant(proofNonce === registrationNonce, label + " registration nonce mismatch");
  return {
    normalized: {
      schema_version: schemaVersion,
      genesis_hash_hex: genesisHash.toString("hex"),
      chain_id_utf8: chainId,
      validator_id_hex: proofValidator.toString("hex"),
      public_key_hex: proofKey.toString("hex"),
      registration_nonce: proofNonce.toString(),
    },
    target_epoch: targetEpoch,
  };
};
const decodeSemanticIntentFact = (kind, logicalKeyHex, valueHex, label) => {
  const bytes = evenHex(valueHex, label + ".value", 1, 65536);
  const cursor = { offset: 0 };
  invariant(semanticU16(bytes, cursor, label + ".schema") === 0, label + " schema drift");
  invariant(semanticU8(bytes, cursor, label + ".kind") === kind, label + " kind drift");
  const revision = semanticU64(bytes, cursor, label + ".revision");
  invariant(revision > 0n, label + " zero revision");
  const identity = semanticFrame(bytes, cursor, label + ".identity", 4096);
  const payload = semanticFrame(bytes, cursor, label + ".payload", 65536);
  semanticFinish(bytes, cursor, label + ".envelope");
  invariant(semanticIdentityDigest(kind, identity).toString("hex") === logicalKeyHex, label + " logical key/value identity mismatch");
  const payloadCursor = { offset: 0 };
  const payloadDigestHex = domainHash(SNAPSHOT_VALUE_PAYLOAD_DOMAIN, payload).toString("hex");
  const fixed = (length, field) => semanticTake(payload, payloadCursor, length, label + "." + field);
  const frameValue = (field) => semanticFrame(payload, payloadCursor, label + "." + field, 128);
  const finish = () => semanticFinish(payload, payloadCursor, label + ".payload");
  let fact;
  const validation = {};
  switch (kind) {
    case 1:
      invariant(identity.length === 32 && payload.length > 0, label + " certificate shape drift");
      fact = { tag: "consumption_certificate", payload_digest_hex: payloadDigestHex };
      break;
    case 2: {
      const identityCursor = { offset: 0 };
      const consumer = semanticFrame(identity, identityCursor, label + ".identity.consumer", 128);
      const consumerKey = semanticFrame(identity, identityCursor, label + ".identity.consumer_key", 128);
      semanticFinish(identity, identityCursor, label + ".identity");
      invariant(frameValue("consumer").equals(consumer) && frameValue("consumer_key").equals(consumerKey), label + " consumer-key identity mismatch");
      const publicKey = fixed(32, "public_key");
      invariant(!publicKey.equals(Buffer.alloc(32)), label + " zero consumer public key");
      const activeFrom = semanticU64(payload, payloadCursor, label + ".active_from_height");
      const revokedAt = semanticOptionalU64(payload, payloadCursor, label + ".revoked_at_height");
      invariant(revokedAt === null, label + " lineage consumer key is not active");
      fact = {
        consumer_id_hex: consumer.toString("hex"),
        consumer_key_id_hex: consumerKey.toString("hex"),
        public_key_hex: publicKey.toString("hex"),
        state: 1,
      };
      invariant(activeFrom >= 0n, label + " active height drift");
      validation.active_from_height = activeFrom;
      finish();
      break;
    }
    case 3:
      frameValue("consumer"); frameValue("consumer_key"); frameValue("provider");
      fact = { tag: "consumer_nonce", max_accepted_nonce: semanticU64(payload, payloadCursor, label + ".max_accepted_nonce").toString() };
      finish();
      break;
    case 4:
      frameValue("consumer"); frameValue("provider"); frameValue("task"); fixed(32, "output_commitment");
      semanticU64(payload, payloadCursor, label + ".billing_start"); semanticU64(payload, payloadCursor, label + ".billing_end"); semanticU64(payload, payloadCursor, label + ".consumer_nonce");
      fact = {
        tag: "unique_consumption_tuple",
        certificate_id_hex: fixed(32, "certificate_id").toString("hex"),
        accepted_height: semanticU64(payload, payloadCursor, label + ".accepted_height").toString(),
      };
      finish();
      break;
    case 5: {
      const identityCursor = { offset: 0 };
      const identityMeter = semanticFrame(identity, identityCursor, label + ".identity.meter_id", 128);
      const identityVersion = semanticU32(identity, identityCursor, label + ".identity.meter_version");
      semanticFinish(identity, identityCursor, label + ".identity");
      const payloadMeter = frameValue("meter_id");
      const payloadVersion = semanticU32(payload, payloadCursor, label + ".meter_version");
      invariant(payloadMeter.equals(identityMeter) && payloadVersion === identityVersion, label + " meter identity mismatch");
      const unitScale = semanticU128(payload, payloadCursor, label + ".unit_scale");
      invariant(unitScale > 0n, label + " zero unit scale");
      validation.active_from_height = semanticU64(payload, payloadCursor, label + ".active_from_height");
      const retiredAt = semanticOptionalU64(payload, payloadCursor, label + ".retired_at_height");
      invariant(retiredAt === null, label + " lineage meter is not active");
      fact = {
        meter_id_hex: identityMeter.toString("hex"),
        meter_version: identityVersion,
        unit_scale: unitScale.toString(),
        state: 1,
      };
      finish();
      break;
    }
    case 6:
      invariant(identity.length === 32 && fixed(32, "certificate_id").equals(identity), label + " settlement identity mismatch");
      {
        const commitment = fixed(32, "commitment");
        const state = semanticEnum(semanticU8(payload, payloadCursor, label + ".state"), 1, 3, label + ".state");
        invariant(state === 1, label + " lineage settlement is not funded-unused");
        validation.finalized_height = semanticU64(payload, payloadCursor, label + ".finalized_height");
        fact = {
          certificate_id_hex: identity.toString("hex"),
          commitment_hex: commitment.toString("hex"),
          state,
        };
      }
      finish();
      break;
    case 7:
      invariant(identity.length === 32 && fixed(32, "certificate_id").equals(identity), label + " measurement identity mismatch");
      fact = {
        tag: "measurement_evidence",
        evidence_root_hex: semanticOptionalHash32(payload, payloadCursor, label + ".evidence_root"),
        state: semanticEnum(semanticU8(payload, payloadCursor, label + ".state"), 1, 3, label + ".state"),
      };
      finish();
      break;
    case 8:
      frameValue("provider"); frameValue("consumer"); frameValue("task");
      fact = {
        tag: "relationship_classification",
        class: semanticEnum(semanticU8(payload, payloadCursor, label + ".class"), 1, 4, label + ".class"),
        expires_at_height: semanticU64(payload, payloadCursor, label + ".expires_at_height").toString(),
      };
      finish();
      break;
    case 9: {
      const validatorId = frameValue("validator_id");
      invariant(validatorId.equals(identity), label + " validator identity mismatch");
      const consensusKey = fixed(32, "consensus_key");
      invariant(!consensusKey.equals(Buffer.alloc(32)), label + " zero validator key");
      const registrationNonce = semanticU64(payload, payloadCursor, label + ".registration_nonce");
      const state = semanticEnum(semanticU8(payload, payloadCursor, label + ".state"), 1, 2, label + ".state");
      const proof = semanticFrame(payload, payloadCursor, label + ".proof", 65536);
      finish();
      const proofIntent = decodeValidatorPopIntent(proof, validatorId, consensusKey, registrationNonce, label + ".proof");
      invariant(state === 1, label + " lineage validator registration is not active");
      fact = {
        validator_id_hex: validatorId.toString("hex"),
        consensus_key_hex: consensusKey.toString("hex"),
        registration_nonce: registrationNonce.toString(),
        proof: proofIntent.normalized,
        state,
      };
      validation.proof_target_epoch = proofIntent.target_epoch;
      break;
    }
    case 10:
      invariant(frameValue("validator_id").equals(identity), label + " bond identity mismatch");
      fact = {
        tag: "active_bond",
        amount: semanticU128(payload, payloadCursor, label + ".amount").toString(),
        locked_until_epoch: semanticU64(payload, payloadCursor, label + ".locked_until_epoch").toString(),
        state: semanticEnum(semanticU8(payload, payloadCursor, label + ".state"), 1, 2, label + ".state"),
      };
      finish();
      break;
    case 11:
      invariant(frameValue("validator_id").equals(identity), label + " jail identity mismatch");
      fact = {
        tag: "jail_status",
        jailed_until_epoch: semanticU64(payload, payloadCursor, label + ".jailed_until_epoch").toString(),
        reason: semanticEnum(semanticU8(payload, payloadCursor, label + ".reason"), 1, 3, label + ".reason"),
      };
      finish();
      break;
    case 12:
      invariant(identity.length === 32 && fixed(32, "certificate_id").equals(identity), label + " lifecycle identity mismatch");
      fact = {
        state: semanticEnum(semanticU8(payload, payloadCursor, label + ".state"), 1, 5, label + ".state"),
      };
      validation.effective_height = semanticU64(payload, payloadCursor, label + ".effective_height");
      finish();
      break;
    case 13:
      invariant(identity.length === 9 && (identity[0] === 1 || identity[0] === 2) && payload.length > 0, label + " validator configuration shape drift");
      fact = { tag: "validator_configuration", payload_digest_hex: payloadDigestHex };
      break;
    case 14:
      invariant(identity.length === 9 && (identity[0] === 1 || identity[0] === 2) && payload.length > 0, label + " consensus parameters shape drift");
      fact = { tag: "consensus_parameters", payload_digest_hex: payloadDigestHex };
      break;
    case 15:
      invariant(identity.length === 8, label + " governance identity width drift");
      {
        const phase = semanticEnum(semanticU8(payload, payloadCursor, label + ".phase"), 0, 3, label + ".phase");
        const parametersHash = fixed(32, "parameters_hash");
        const activationHeight = semanticU64(payload, payloadCursor, label + ".activation_height");
        const approval = semanticEnum(semanticU8(payload, payloadCursor, label + ".approval"), 0, 1, label + ".approval");
        invariant(approval === 1, label + " lineage governance is not approved");
        fact = {
          target_epoch: identity.readBigUInt64BE(0).toString(),
          phase,
          parameters_hash_hex: parametersHash.toString("hex"),
          activation_height: activationHeight.toString(),
          approved: true,
        };
      }
      finish();
      break;
    default: fail(label + " unsupported semantic kind");
  }
  return { identity_hex: identity.toString("hex"), fact, revision, validation };
};
const normalizedSemanticIntent = (operation) => {
  const expectedPutKind = BUSINESS_INTENT_PUT_SEMANTIC_KIND[operation.body.kind];
  if (expectedPutKind !== undefined) {
    invariant(operation.semantic_changes.length === 1 && operation.semantic_changes[0].kind === expectedPutKind && operation.semantic_changes[0].next_value_hex !== null, "business-intent operation does not name its one exact semantic fact");
  } else {
    invariant(operation.semantic_changes.every((change) => change.next_value_hex === null), "business-intent normalization has no exact nondelete semantic map for operation kind");
  }
  return operation.semantic_changes.map((change, index) => {
    if (change.next_value_hex === null) {
      return { kind: change.kind, logical_key_hex: change.logical_key_hex, action: "delete", identity_hex: null, fact: null };
    }
    const decoded = decodeSemanticIntentFact(change.kind, change.logical_key_hex, change.next_value_hex, `business-intent semantic change ${index}`);
    const body = operation.body;
    switch (change.kind) {
      case 2:
        invariant(decoded.fact.consumer_id_hex === body.consumer_id_hex && decoded.fact.consumer_key_id_hex === body.consumer_key_id_hex && decoded.fact.public_key_hex === body.public_key_hex, "business-intent consumer-key fact/body drift");
        break;
      case 5:
        invariant(decoded.fact.meter_id_hex === body.policy.meter_id_hex && decoded.fact.meter_version === body.policy.meter_version && decoded.fact.unit_scale === body.policy.unit_scale, "business-intent meter fact/body drift");
        break;
      case 6:
        invariant(decoded.fact.certificate_id_hex === body.certificate_id_hex && decoded.fact.commitment_hex === body.settlement_commitment_hex, "business-intent settlement fact/body drift");
        break;
      case 9:
        invariant(decoded.fact.validator_id_hex === body.validator_id_hex, "business-intent validator fact/body drift");
        break;
      case 12: {
        const expectedState = body.resolution === "rejected" ? 4 : body.resolution === "sustained" ? 5 : null;
        invariant(expectedState !== null && decoded.identity_hex === body.certificate_id_hex && decoded.fact.state === expectedState, "business-intent challenge fact/body drift");
        break;
      }
      case 15:
        invariant(decoded.fact.target_epoch === String(body.target_epoch) && decoded.fact.parameters_hash_hex === body.parameters_hash_hex && decoded.fact.activation_height === String(body.activation_height) && decoded.fact.approved === true, "business-intent governance fact/body drift");
        break;
      default: fail("business-intent semantic kind lacks an exact fact/body join");
    }
    return { kind: change.kind, logical_key_hex: change.logical_key_hex, action: "put", identity_hex: decoded.identity_hex, fact: decoded.fact };
  });
};
const decodeAuthorityEnvelope = (envelopeHex, label) => {
  const bytes = evenHex(envelopeHex, label + ".envelope", 1, 65536);
  const cursor = { offset: 0 };
  invariant(bytes.length >= 19 && bytes.readUInt16BE(0) === 0 && bytes[2] === 16, label + " envelope header drift");
  cursor.offset = 3;
  const revision = bytes.readBigUInt64BE(cursor.offset);
  cursor.offset += 8;
  invariant(revision > 0n && revision <= BigInt(Number.MAX_SAFE_INTEGER), label + " envelope revision outside authoring range");
  const identity = readFrame(bytes, cursor, label + ".identity");
  invariant(identity.equals(AUTHORITY_IDENTITY), label + " authority identity drift");
  const payload = readFrame(bytes, cursor, label + ".payload");
  invariant(cursor.offset === bytes.length, label + " envelope trailing bytes");
  const state = JSON.parse(payload.toString("utf8"));
  invariant(canonicalBytes(state).equals(payload), label + " authority payload is not canonical JSON");
  fieldOrder(state, AUTHORITY_STATE_FIELDS, label + ".state");
  invariant(state.schema === AUTHORITY_SCHEMA, label + " authority schema drift");
  asSafeU64(state.revision, label + ".state.revision");
  asSafeU64(state.last_target_height, label + ".state.last_target_height");
  asSafeU64(state.nullifier_count, label + ".state.nullifier_count");
  hash32(state.nullifier_root_hex, label + ".state.nullifier_root_hex");
  invariant(BigInt(state.revision) === revision, label + " envelope/state revision drift");
  for (const field of AUTHORITY_STATE_FIELDS.slice(5)) invariant(Array.isArray(state[field]), label + ".state." + field + " is not an array");
  const logicalKey = domainHash(SEMANTIC_IDENTITY_DOMAIN, Buffer.concat([uint(0, 2), uint(16, 1), frame(identity)]));
  return {
    logicalKey,
    summary: {
      envelope_hex: envelopeHex,
      revision: state.revision,
      last_target_height: state.last_target_height,
      nullifier_root_hex: state.nullifier_root_hex,
      nullifier_count: state.nullifier_count,
    },
    state,
  };
};
const validateAuthoritySummary = (summary, expected, label) => {
  fieldOrder(summary, AUTHORITY_FIELDS, label);
  const decoded = decodeAuthorityEnvelope(summary.envelope_hex, label);
  sameJson(summary, decoded.summary, label + " summary differs from exact envelope");
  if (expected !== undefined) sameJson(summary, expected, label + " differs from authenticated projection");
  return decoded;
};
const validateContext = (context, label) => {
  fieldOrder(context, CONTEXT_FIELDS, label);
  invariant(typeof context.chain_id_utf8 === "string" && context.chain_id_utf8.length >= 1 && context.chain_id_utf8.length <= 128 && context.chain_id_utf8 === context.chain_id_utf8.trim(), label + ".chain_id_utf8 drift");
  hash32(context.genesis_hash_hex, label + ".genesis_hash_hex");
  asSafeU64(context.source_version, label + ".source_version");
  nonzeroHash32(context.source_root_hex, label + ".source_root_hex");
  asSafeU64(context.target_height, label + ".target_height");
  invariant(context.target_height === context.source_version + 1, label + " target is not exact successor");
  asSafeU64(context.active_epoch, label + ".active_epoch");
  evenHex(context.active_parameters_cev0_hex, label + ".active_parameters_cev0_hex", 1, 65536);
  hash32(context.active_parameters_hash_hex, label + ".active_parameters_hash_hex");
  nonzeroHash32(context.authority_signer_commitment_hex, label + ".authority_signer_commitment_hex");
  return context;
};
const projectionEvidence = (projection, version, exactHeight, live, label) => {
  fieldOrder(projection, ["manifest_hex", "entries_root_hex", "entries"], label);
  invariant(Array.isArray(projection.entries) && projection.entries.length >= 1 && projection.entries.length <= 10000, label + " entry count outside bound");
  let previous = null;
  const entries = projection.entries.map((entry, index) => {
    fieldOrder(entry, ENTRY_FIELDS, label + ".entries[" + index + "]");
    invariant(Number.isInteger(entry.kind) && entry.kind >= 1 && entry.kind <= 16, label + " kind outside 1..16");
    const key = hash32(entry.logical_key_hex, label + " logical key");
    const value = evenHex(entry.value_hex, label + " value", 1, 65536);
    const identity = { kind: entry.kind, key };
    if (previous !== null) invariant(compareKindKey(previous, identity) < 0, label + " entries are not strictly sorted unique");
    previous = identity;
    const canonical = canonicalEntry(entry.kind, key, value);
    invariant(canonical.toString("hex") === entry.canonical_entry_cev0_hex, label + " canonical entry drift");
    if (live !== undefined) invariant(live.get(entryKey(entry.kind, key).toString("hex")) === entry.value_hex, label + " entry absent from authenticated history");
    return { kind: entry.kind, key, value, raw: entry, canonical };
  });
  const root = orderedRoot(ENTRY_DOMAIN, ENTRY_NODE_DOMAIN, ENTRY_ROOT_DOMAIN, entries.map((entry) => entry.canonical));
  invariant(root.equals(hash32(projection.entries_root_hex, label + ".entries_root_hex")), label + " entries root drift");
  const manifestHex = evenHex(projection.manifest_hex, label + ".manifest_hex", 47, 47);
  const manifest = decodeManifest(manifestHex);
  invariant(exactHeight ? manifest.height === BigInt(version) : manifest.height <= BigInt(version), label + " manifest height drift");
  invariant(manifest.count === entries.length && manifest.root.equals(root), label + " manifest count/root drift");
  if (live !== undefined) invariant(live.get(manifestKey().toString("hex")) === projection.manifest_hex, label + " manifest absent from authenticated history");
  const authorities = entries.filter((entry) => entry.kind === 16);
  invariant(authorities.length === 1, label + " must contain exactly one authority entry");
  const decoded = decodeAuthorityEnvelope(authorities[0].raw.value_hex, label + ".authority");
  invariant(authorities[0].key.equals(decoded.logicalKey), label + " authority logical key drift");
  return { entries, manifest, authority: decoded.summary };
};
const validateInitial = (initial, label) => {
  fieldOrder(initial, ["version", "jmt_root_hex", "active_genesis", "production_context", "history", "projection"], label);
  asSafeU64(initial.version, label + ".version");
  nonzeroHash32(initial.jmt_root_hex, label + ".jmt_root_hex");
  invariant(Array.isArray(initial.history) && initial.history.length >= 1, label + " history is empty");
  const live = new Map();
  let genesisLive = null;
  let prior = null;
  for (const [index, item] of initial.history.entries()) {
    fieldOrder(item, ["version", "jmt_root_hex", "writes"], label + ".history[" + index + "]");
    asSafeU64(item.version, label + " history version");
    if (prior === null) invariant(item.version === 0, label + " history does not start at genesis version zero");
    else invariant(item.version === prior + 1, label + " history is not contiguous");
    prior = item.version;
    nonzeroHash32(item.jmt_root_hex, label + " history root");
    invariant(Array.isArray(item.writes), label + " history writes are not an array");
    for (const [writeIndex, write] of item.writes.entries()) {
      fieldOrder(write, ["physical_key_hex", "value_hex"], label + ".history.write[" + writeIndex + "]");
      const key = evenHex(write.physical_key_hex, label + " history key", 1);
      if (write.value_hex === null) live.delete(key.toString("hex"));
      else {
        evenHex(write.value_hex, label + " history value");
        live.set(key.toString("hex"), write.value_hex);
      }
    }
    if (index === 0) genesisLive = new Map(live);
  }
  invariant(genesisLive !== null, label + " genesis history is missing");
  invariant(prior === initial.version && initial.history.at(-1).jmt_root_hex === initial.jmt_root_hex, label + " history head drift");
  const genesis = initial.active_genesis;
  fieldOrder(genesis, ["chain_id_utf8", "genesis_hash_hex", "validator_lifecycle", "poco_authority_config", "active_parameters", "other_apphash_writes"], label + ".active_genesis");
  invariant(typeof genesis.chain_id_utf8 === "string" && genesis.chain_id_utf8.length >= 1 && genesis.chain_id_utf8.length <= 128 && genesis.chain_id_utf8 === genesis.chain_id_utf8.trim(), label + " chain ID drift");
  hash32(genesis.genesis_hash_hex, label + " genesis hash");
  for (const [recordLabel, record] of [["validator_lifecycle", genesis.validator_lifecycle], ["poco_authority_config", genesis.poco_authority_config]]) {
    fieldOrder(record, ["physical_key_hex", "value_hex"], label + "." + recordLabel);
    evenHex(record.physical_key_hex, label + " named key", 1);
    evenHex(record.value_hex, label + " named value", 1);
    invariant(genesisLive.get(record.physical_key_hex) === record.value_hex, label + " named genesis record is unauthenticated at version zero");
  }
  fieldOrder(genesis.active_parameters, ["physical_key_hex", "value_hex", "cev0_hex", "hash_hex"], label + ".active_parameters");
  evenHex(genesis.active_parameters.physical_key_hex, label + " parameter key", 1);
  evenHex(genesis.active_parameters.value_hex, label + " parameter value", 1);
  evenHex(genesis.active_parameters.cev0_hex, label + " parameter CEV0", 1);
  hash32(genesis.active_parameters.hash_hex, label + " parameter hash");
  invariant(genesisLive.get(genesis.active_parameters.physical_key_hex) === genesis.active_parameters.value_hex, label + " parameters are unauthenticated at version zero");
  invariant(Array.isArray(genesis.other_apphash_writes), label + " other writes are not an array");
  const namedGenesisKeys = new Set([
    genesis.validator_lifecycle.physical_key_hex,
    genesis.poco_authority_config.physical_key_hex,
    genesis.active_parameters.physical_key_hex,
  ]);
  let previousOtherKey = null;
  for (const write of genesis.other_apphash_writes) {
    fieldOrder(write, ["physical_key_hex", "value_hex"], label + " other AppHash write");
    evenHex(write.physical_key_hex, label + " other key", 1);
    evenHex(write.value_hex, label + " other value");
    invariant(previousOtherKey === null || previousOtherKey < write.physical_key_hex, label + " other genesis writes are not strictly sorted unique");
    invariant(!namedGenesisKeys.has(write.physical_key_hex), label + " other genesis write duplicates a named record");
    invariant(genesisLive.get(write.physical_key_hex) === write.value_hex, label + " other genesis write is unauthenticated at version zero");
    previousOtherKey = write.physical_key_hex;
  }
  validateContext(initial.production_context, label + ".production_context");
  invariant(initial.production_context.chain_id_utf8 === genesis.chain_id_utf8 && initial.production_context.genesis_hash_hex === genesis.genesis_hash_hex, label + " production context chain/genesis drift");
  invariant(initial.production_context.source_version === initial.version && initial.production_context.source_root_hex === initial.jmt_root_hex, label + " production context source drift");
  invariant(initial.production_context.active_parameters_cev0_hex === genesis.active_parameters.cev0_hex && initial.production_context.active_parameters_hash_hex === genesis.active_parameters.hash_hex, label + " production context parameter drift");
  const projection = projectionEvidence(initial.projection, initial.version, false, live, label + ".projection");
  return { live, genesis, context: clone(initial.production_context), projection };
};

const contextPreimage = (context, normalizedOperation) => domainHash(DECISION_PREIMAGE_DOMAIN, Buffer.concat([
  uint(0, 2),
  frame(hash32(context.genesis_hash_hex, "context genesis hash")),
  frame(Buffer.from(context.chain_id_utf8)),
  uint(context.source_version, 8),
  hash32(context.source_root_hex, "context source root"),
  uint(context.target_height, 8),
  uint(context.active_epoch, 8),
  hash32(context.active_parameters_hash_hex, "context parameter hash"),
  hash32(context.authority_signer_commitment_hex, "context signer commitment"),
  frame(canonicalBytes(normalizedOperation)),
]));
const decisionId = (preimage, label) => domainHash(DECISION_ID_DOMAIN, Buffer.concat([uint(0, 2), frame(Buffer.from(label)), preimage]));

const resolveIdentifier = (operation, decisions, descriptor) => {
  fieldOrder(descriptor, ["source", "value"], "proof identifier descriptor");
  if (descriptor.source === "literal") return hash32(descriptor.value, "literal proof identifier");
  if (descriptor.source === "pointer") return hash32(pointerGet(operation, descriptor.value), "pointer proof identifier");
  if (descriptor.source === "decision") {
    invariant(descriptor.value in decisions, "unknown decision label " + descriptor.value);
    return Buffer.from(decisions[descriptor.value], "hex");
  }
  fail("unknown proof identifier source " + descriptor.source);
};
const proofIdentityCompare = (left, right) => left.family - right.family || Buffer.compare(left.identifier, right.identifier);
const populateProofs = (operation, decisions, proofPlan, state) => {
  invariant(Array.isArray(proofPlan), "proof_plan is not an array");
  const occupiedBefore = normalizedOccupied(state);
  const resolved = proofPlan.map((spec, index) => {
    const stored = Object.keys(spec).length === 4;
    fieldOrder(spec, stored ? ["list", "family", "identifier", "resolved_identifier_hex"] : ["list", "family", "identifier"], "proof_plan[" + index + "]");
    invariant(["non_membership", "insertion"].includes(spec.list), "invalid proof list");
    invariant(Number.isInteger(spec.family) && spec.family >= 1 && spec.family <= 14, "proof family outside 1..14");
    const identifier = resolveIdentifier(operation, decisions, spec.identifier);
    if (stored) invariant(spec.resolved_identifier_hex === identifier.toString("hex"), "resolved proof identifier drift");
    return { list: spec.list, family: spec.family, descriptor: clone(spec.identifier), resolved_identifier_hex: identifier.toString("hex"), identifier, key: deriveNullifierKey(spec.family, identifier) };
  });
  const checks = resolved.filter((item) => item.list === "non_membership").sort(proofIdentityCompare);
  const insertions = resolved.filter((item) => item.list === "insertion").sort(proofIdentityCompare);
  for (const [label, items] of [["non-membership", checks], ["insertion", insertions]]) {
    for (let index = 1; index < items.length; index += 1) invariant(proofIdentityCompare(items[index - 1], items[index]) < 0, label + " proof identities are duplicated");
  }
  const initialKeys = occupiedBefore.map((item) => item.key);
  const initialRoot = sparseRoot(initialKeys);
  const rawChecks = checks.map((item) => {
    const proof = sparseProof(initialKeys, item.key);
    invariant(proof.root.equals(initialRoot), "all absence proofs must use the one initial root");
    return { family: item.family, identifier_hex: item.resolved_identifier_hex, proof_hex: proof.proof.toString("hex") };
  });
  const occupiedAfter = [...occupiedBefore];
  const rawInsertions = [];
  for (const item of insertions) {
    const keys = occupiedAfter.map((entry) => entry.key);
    const proof = sparseProof(keys, item.key);
    invariant(proof.root.equals(sparseRoot(keys)), "insertion proof source root drift");
    rawInsertions.push({ family: item.family, identifier_hex: item.resolved_identifier_hex, proof_hex: proof.proof.toString("hex") });
    occupiedAfter.push({ family: item.family, identifier_hex: item.resolved_identifier_hex, identifier: item.identifier, key: item.key });
  }
  occupiedAfter.sort((left, right) => left.family - right.family || Buffer.compare(left.identifier, right.identifier));
  operation.nullifier_non_membership_checks = rawChecks;
  operation.nullifier_insertions = rawInsertions;
  const after = {
    root_hex: sparseRoot(occupiedAfter.map((item) => item.key)).toString("hex"),
    count: String(occupiedAfter.length),
    occupied: occupiedAfter.map(({ family, identifier_hex }) => ({ family, identifier_hex })),
  };
  return {
    before: canonicalNullifierState(state),
    after,
    canonicalPlan: [...checks, ...insertions].map((item) => ({ list: item.list, family: item.family, identifier: item.descriptor, resolved_identifier_hex: item.resolved_identifier_hex })),
  };
};

const validateSourceExport = (filename, scope) => {
  const source = readRaw(filename);
  fieldOrder(source.value, scope === "full_application_store"
    ? ["schema", "schema_version", "initial", "authoring_nullifier_state"]
    : ["schema", "schema_version", "lineage_base_intent", "initial", "authoring_nullifier_state"], "Rust source export");
  const expectedSchema = scope === "full_application_store"
    ? SOURCE_SCHEMA
    : "trnm.poco-bft.application-isolated-prune-source-export.v0";
  invariant(source.value.schema === expectedSchema && source.value.schema_version === 0, "Rust source export schema/scope drift");
  const initial = validateInitial(source.value.initial, "Rust source export initial");
  const nullifier = canonicalNullifierState({
    root_hex: source.value.authoring_nullifier_state.root_hex,
    count: String(source.value.authoring_nullifier_state.count),
    occupied: source.value.authoring_nullifier_state.occupied,
  });
  invariant(nullifier.root_hex === initial.projection.authority.nullifier_root_hex && BigInt(nullifier.count) === BigInt(initial.projection.authority.nullifier_count), "source export nullifier state differs from authenticated authority envelope");
  let lineage = null;
  if (scope === "isolated_prune_transition_kernel") {
    lineage = source.value.lineage_base_intent;
    fieldOrder(lineage, ["operation_kind", "normalized_business_intent_digest_hex", "subjects"], "isolated source lineage");
    invariant(typeof lineage.operation_kind === "string" && lineage.operation_kind in BODY_FIELDS, "isolated source lineage operation kind drift");
    hash32(lineage.normalized_business_intent_digest_hex, "isolated source lineage digest");
    invariant(lineage.subjects !== null && typeof lineage.subjects === "object" && !Array.isArray(lineage.subjects), "isolated source lineage subjects drift");
  }
  return {
    digest: sha256(source.raw).toString("hex"),
    raw_json_hex: source.raw.toString("hex"),
    initial: clone(source.value.initial),
    nullifier,
    lineage,
  };
};
const sourceDigestList = (sequences) => [...new Set(sequences.map((sequence) => sequence.source_export_sha256_hex))].sort();
const validateDraftShape = (draft) => {
  fieldOrder(draft, ["schema", "schema_version", "source_exports_sha256_hex", "source_exports", "required_automata", "sequences"], "draft");
  invariant(draft.schema === DRAFT_SCHEMA && draft.schema_version === 0, "draft schema drift");
  invariant(Array.isArray(draft.source_exports_sha256_hex), "source export digest list is not an array");
  draft.source_exports_sha256_hex.forEach((digest, index) => hash32(digest, "source export digest " + index));
  unique(draft.source_exports_sha256_hex, "source export digests");
  sameJson([...draft.source_exports_sha256_hex].sort(), draft.source_exports_sha256_hex, "source export digests are not sorted");
  invariant(Array.isArray(draft.source_exports), "source export registry is not an array");
  sameJson(draft.source_exports.map((item) => item.sha256_hex), draft.source_exports_sha256_hex, "source export registry digest order drift");
  for (const [index, source] of draft.source_exports.entries()) {
    fieldOrder(source, ["sha256_hex", "raw_json_hex"], "source export registry " + index);
    const raw = evenHex(source.raw_json_hex, "source export raw JSON", 1, 16 * 1024 * 1024);
    invariant(sha256(raw).toString("hex") === source.sha256_hex, "source export raw digest drift");
    const parsed = JSON.parse(raw.toString("utf8"));
    fieldOrder(parsed, parsed.schema === SOURCE_SCHEMA
      ? ["schema", "schema_version", "initial", "authoring_nullifier_state"]
      : ["schema", "schema_version", "lineage_base_intent", "initial", "authoring_nullifier_state"], "retained source export");
    invariant(parsed.schema_version === 0 && [SOURCE_SCHEMA, "trnm.poco-bft.application-isolated-prune-source-export.v0"].includes(parsed.schema), "retained source export schema drift");
    if (parsed.schema !== SOURCE_SCHEMA) {
      fieldOrder(parsed.lineage_base_intent, ["operation_kind", "normalized_business_intent_digest_hex", "subjects"], "retained isolated source lineage");
      invariant(typeof parsed.lineage_base_intent.operation_kind === "string" && parsed.lineage_base_intent.operation_kind in BODY_FIELDS, "retained isolated lineage operation kind drift");
      hash32(parsed.lineage_base_intent.normalized_business_intent_digest_hex, "retained isolated lineage digest");
      invariant(parsed.lineage_base_intent.subjects !== null && typeof parsed.lineage_base_intent.subjects === "object" && !Array.isArray(parsed.lineage_base_intent.subjects), "retained isolated lineage subjects drift");
    }
  }
  sameJson(draft.required_automata, REQUIRED_AUTOMATA, "required automata drift");
  invariant(Array.isArray(draft.sequences) && draft.sequences.length >= 1, "draft has no sequences");
  sameJson(draft.source_exports_sha256_hex, sourceDigestList(draft.sequences), "draft source export digest set drift");
  for (const sequence of draft.sequences) {
    const retained = draft.source_exports.find((source) => source.sha256_hex === sequence.source_export_sha256_hex);
    invariant(retained !== undefined, "sequence source export bytes are not retained");
    const parsed = JSON.parse(Buffer.from(retained.raw_json_hex, "hex").toString("utf8"));
    const expectedSchema = sequence.execution_scope === "full_application_store" ? SOURCE_SCHEMA : "trnm.poco-bft.application-isolated-prune-source-export.v0";
    invariant(parsed.schema === expectedSchema, "sequence source export scope/schema drift");
    sameJson(parsed.initial, sequence.initial, "sequence initial differs from retained source export");
    sameJson(canonicalNullifierState({ ...parsed.authoring_nullifier_state, count: String(parsed.authoring_nullifier_state.count) }), sequence._authoring.initial_nullifier_state, "sequence nullifier differs from retained source export");
    sameJson(parsed.lineage_base_intent ?? null, sequence._authoring.lineage_base_intent, "sequence lineage differs from retained source export");
  }
};
const newSequence = (source, id, scope, prerequisite) => {
  invariant(scope === "full_application_store" || scope === "isolated_prune_transition_kernel", "invalid execution scope");
  invariant(scope === "full_application_store" ? prerequisite === "" : prerequisite === KERNEL_PREREQUISITE, "execution scope/prerequisite drift");
  const automaton = automatonForId(id);
  invariant(automaton.execution_scope === scope, "required automaton scope drift");
  return {
    id,
    execution_scope: scope,
    activation_prerequisite: prerequisite,
    source_export_sha256_hex: source.digest,
    subjects: emptySubjects(automaton),
    initial: source.initial,
    steps: [],
    negatives: [],
    _authoring: { initial_nullifier_state: source.nullifier, lineage_base_intent: source.lineage },
  };
};
const emptyDraft = (sequence, source) => ({
  schema: DRAFT_SCHEMA,
  schema_version: 0,
  source_exports_sha256_hex: [sequence.source_export_sha256_hex],
  source_exports: [{ sha256_hex: source.digest, raw_json_hex: source.raw_json_hex }],
  required_automata: clone(REQUIRED_AUTOMATA),
  sequences: [sequence],
});

const successRequestDigest = (draft, sequence, step) => sha256(canonicalBytes({
  schema: STEP_REQUEST_SCHEMA,
  schema_version: 0,
  source_export_sha256_hex: sequence.source_export_sha256_hex,
  sequence_id: sequence.id,
  step_id: step.id,
  execution_scope: sequence.execution_scope,
  activation_prerequisite: sequence.activation_prerequisite,
  context: step.context,
  raw_operation_json_hexes: step.operations.map((operation) => operation.raw_operation_json_hex),
  operation_ids_hex: step.operations.map((operation) => operation.operation_id_hex),
  operation_root_hex: step.operation_root_hex,
  operation_count: step.operation_count,
})).toString("hex");
const negativeRequestDigest = (sequence, negative) => sha256(canonicalBytes({
  schema: NEGATIVE_REQUEST_SCHEMA,
  schema_version: 0,
  source_export_sha256_hex: sequence.source_export_sha256_hex,
  sequence_id: sequence.id,
  negative_id: negative.id,
  execution_scope: sequence.execution_scope,
  context: negative.context,
  source: negative.source,
  base_positive: negative.base_positive,
  fault_model: negative.fault_model,
  raw_operation_json_hexes: negative.raw_operation_json_hexes,
  expected_reject: negative.expected_reject,
  expected_writes: negative.expected_writes,
  expected_unchanged: negative.expected_unchanged,
})).toString("hex");

const normalizeOperationForDecision = (operation, bindings) => {
  const normalized = clone(operation);
  normalized.nullifier_non_membership_checks = [];
  normalized.nullifier_insertions = [];
  for (const [pointer] of bindings) pointerSet(normalized, pointer, "0".repeat(64));
  return normalized;
};
const normalizedBusinessIntentBody = (operation) => {
  const body = clone(operation.body);
  const normalized = { operation_kind: operation.body.kind, body };
  for (const [pointer] of decisionBindings(operation.body.kind)) {
    invariant(pointer.startsWith("/body/"), "business-intent decision binding leaves body");
    pointerSet(normalized, pointer, "0".repeat(64));
  }
  for (const pointer of BUSINESS_INTENT_OMISSIONS[operation.body.kind] ?? []) pointerDelete(normalized, pointer);
  return normalized;
};
const normalizedBusinessIntentDigest = (operation) => {
  const normalized = normalizedBusinessIntentBody(operation);
  normalized.semantic_intent = normalizedSemanticIntent(operation);
  return domainHash(BUSINESS_INTENT_DOMAIN, canonicalBytes(normalized)).toString("hex");
};
const deriveBlockStep = (draft, template) => {
  validateDraftShape(draft);
  fieldOrder(template, ["schema", "schema_version", "sequence_id", "id", "operations"], "step template");
  invariant(template.schema === STEP_TEMPLATE_SCHEMA && template.schema_version === 0, "step template schema drift");
  const sequence = draft.sequences.find((item) => item.id === template.sequence_id);
  invariant(sequence !== undefined, "unknown sequence " + template.sequence_id);
  invariant(!sequence.steps.some((step) => step.id === template.id), "duplicate step ID");
  invariant(sequence.negatives.length === 0, "cannot append a positive step after negative evidence");
  const evaluated = evaluateSequence(draft, sequence);
  invariant(!evaluated.partial, "previous Rust evidence is incomplete");
  invariant(Array.isArray(template.operations) && template.operations.length >= 1 && template.operations.length <= 32, "block operation count outside 1..32");
  const context = clone(evaluated.state.context);
  const automaton = automatonForId(sequence.id);
  const sourceRevision = evaluated.state.projection.authority.revision;
  let nullifier = evaluated.state.nullifier;
  const operations = [];
  for (const [index, operationTemplate] of template.operations.entries()) {
    fieldOrder(operationTemplate, ["id", "operation_kind", "operation", "proof_plan"], "operation template " + index);
    invariant(!operations.some((item) => item.id === operationTemplate.id), "duplicate operation ID within block");
    const operation = clone(operationTemplate.operation);
    fieldOrder(operation, OPERATION_FIELDS, "operation template raw");
    invariant(operation.schema === OPERATION_SCHEMA && operation.body.kind === operationTemplate.operation_kind, "operation kind/schema drift");
    invariant(operation.target_height === context.target_height, "operation target differs from production context");
    invariant(operation.expected_state_revision === sourceRevision, "all operations in one block must bind the same source authority revision");
    invariant(operation.nullifier_non_membership_checks.length === 0 && operation.nullifier_insertions.length === 0, "template contains caller-supplied nullifier proofs");
    validateOperation(operation, "operation template");
    const bindings = decisionBindings(operationTemplate.operation_kind);
    for (const [pointer] of bindings) invariant(pointerGet(operation, pointer) === "0".repeat(64), "template decision field is not zero at " + pointer);
    const normalized = clone(operation);
    const preimage = contextPreimage(context, normalized);
    const decisions = {};
    for (const [pointer, label] of bindings) {
      const derived = decisionId(preimage, label).toString("hex");
      decisions[label] = derived;
      pointerSet(operation, pointer, derived);
    }
    const proofs = populateProofs(operation, decisions, operationTemplate.proof_plan, nullifier);
    nullifier = proofs.after;
    validateOperation(operation, "derived operation");
    mergeSubjects(sequence.subjects, automaton, operation.body, "derived operation");
    const raw = canonicalBytes(operation);
    const operationIdHex = domainHash(OPERATION_DOMAIN, raw).toString("hex");
    operations.push({
      id: operationTemplate.id,
      operation_kind: operationTemplate.operation_kind,
      raw_operation_json_hex: raw.toString("hex"),
      operation_id_hex: operationIdHex,
      _authoring: {
        normalized_operation_json_hex: canonicalBytes(normalized).toString("hex"),
        decision_preimage_hex: preimage.toString("hex"),
        derived_decisions: decisions,
        proof_plan: proofs.canonicalPlan,
        nullifier_before: proofs.before,
        nullifier_after: proofs.after,
      },
    });
  }
  const rawOperations = operations.map((operation) => Buffer.from(operation.raw_operation_json_hex, "hex"));
  sequence.steps.push({
    id: template.id,
    context,
    operations,
    operation_root_hex: orderedRoot(OPERATION_DOMAIN, OPERATION_NODE_DOMAIN, OPERATION_ROOT_DOMAIN, rawOperations).toString("hex"),
    operation_count: operations.length,
    rust_event: null,
  });
  validateSubjects(sequence.subjects, automaton, "sequence subjects", false);
  return draft;
};

const deriveNegative = (draft, template) => {
  validateDraftShape(draft);
  fieldOrder(template, ["schema", "schema_version", "sequence_id", "id", "raw_operation_json_hexes", "expected_reject"], "negative template");
  invariant(template.schema === NEGATIVE_TEMPLATE_SCHEMA && template.schema_version === 0, "negative template schema drift");
  const sequence = draft.sequences.find((item) => item.id === template.sequence_id);
  invariant(sequence !== undefined && !sequence.negatives.some((item) => item.id === template.id), "unknown sequence or duplicate negative ID");
  const evaluated = evaluateSequence(draft, sequence);
  invariant(!evaluated.partial && sequence.steps.length >= 1, "negative evidence requires complete positive steps");
  const automaton = automatonForId(sequence.id);
  validateSubjects(sequence.subjects, automaton, "negative sequence subjects");
  invariant(Array.isArray(template.raw_operation_json_hexes) && template.raw_operation_json_hexes.length === 1, "required negative must contain exactly one raw operation");
  const decodedNegatives = template.raw_operation_json_hexes.map((rawHex, index) => {
    const raw = evenHex(rawHex, "negative raw operation " + index, 1, 1048576);
    const operation = JSON.parse(raw.toString("utf8"));
    invariant(canonicalBytes(operation).equals(raw), "negative raw operation is not canonical JSON");
    validateOperation(operation, "negative raw operation " + index);
    invariant(operation.target_height === evaluated.state.context.target_height && operation.expected_state_revision === evaluated.state.projection.authority.revision, "negative operation does not bind the current authenticated target/revision");
    invariant(operation.body.kind === automaton.negative_operation_kind, "negative operation kind differs from required automaton");
    const subjects = emptySubjects(automaton);
    mergeSubjects(subjects, automaton, operation.body, "negative operation");
    for (const field of automaton.subject_fields) invariant(subjects[field] === sequence.subjects[field], "negative operation substitutes sequence subject " + field);
    return operation;
  });
  fieldOrder(template.expected_reject, ["stage", "error_code"], "negative expected reject");
  invariant(REJECT_STAGES.has(template.expected_reject.stage), "negative reject stage drift");
  invariant(/^[a-z][a-z0-9_]*$/.test(template.expected_reject.error_code), "negative error code is not stable snake_case");
  invariant(template.expected_reject.stage === automaton.negative_reject_stage && template.expected_reject.error_code === automaton.negative_error_code, "negative expected rejection differs from frozen automaton");
  if (automaton.negative_replay_nullifier_family !== null) {
    const expectedIdentifier = expectedReplayIdentifier(automaton, sequence.subjects).toString("hex");
    const candidates = [...decodedNegatives[0].nullifier_non_membership_checks, ...decodedNegatives[0].nullifier_insertions]
      .filter((item) => item.family === automaton.negative_replay_nullifier_family && item.identifier_hex === expectedIdentifier);
    invariant(candidates.length === 1, "negative replay lacks the one exact family/subject proof");
  }
  const negativeIntent = normalizedBusinessIntentDigest(decodedNegatives[0]);
  let basePositive;
  if (sequence.execution_scope === "full_application_store") {
    const candidates = sequence.steps.flatMap((step) => step.operations.map((operation, operationIndex) => ({ step, operation, operationIndex })))
      .filter((item) => item.operation.operation_kind === automaton.negative_operation_kind);
    invariant(candidates.length === 1, "full-store negative lacks one unambiguous successful base operation");
    const base = candidates[0];
    const baseOperation = JSON.parse(Buffer.from(base.operation.raw_operation_json_hex, "hex").toString("utf8"));
    invariant(normalizedBusinessIntentDigest(baseOperation) === negativeIntent, "negative business intent differs from successful base operation");
    basePositive = {
      source: "sequence_step",
      step_id: base.step.id,
      operation_index: base.operationIndex,
      normalized_business_intent_digest_hex: negativeIntent,
    };
  } else {
    const lineage = sequence._authoring.lineage_base_intent;
    invariant(
      lineage !== null && lineage.operation_kind === automaton.negative_operation_kind && lineage.normalized_business_intent_digest_hex === negativeIntent,
      `isolated replay lacks exact Rust source-lineage business intent (rust=${lineage?.normalized_business_intent_digest_hex ?? "missing"}, node=${negativeIntent})`,
    );
    sameJson(lineage.subjects, sequence.subjects, "isolated source lineage subject drift");
    basePositive = {
      source: "source_lineage",
      step_id: null,
      operation_index: null,
      normalized_business_intent_digest_hex: negativeIntent,
    };
  }
  const source = sourceEvidenceFromState(evaluated.state);
  const negative = {
    id: template.id,
    context: clone(evaluated.state.context),
    base_positive: basePositive,
    fault_model: {
      kind: "state_dependent_same_subject_replay",
      authenticated_source_relation: "terminal_or_pruned_successor",
      expected_first_error_stage: automaton.negative_reject_stage,
      expected_first_error_code: automaton.negative_error_code,
    },
    raw_operation_json_hexes: clone(template.raw_operation_json_hexes),
    source,
    expected_reject: clone(template.expected_reject),
    expected_writes: 0,
    expected_unchanged: {
      version: source.version,
      jmt_root_hex: source.jmt_root_hex,
      manifest_hex: source.manifest_hex,
      authority: clone(source.authority),
    },
    rust_event: null,
  };
  sequence.negatives.push(negative);
  return draft;
};

const validateNegativeLineage = (sequence, negative, automaton, lineage, label) => {
  fieldOrder(negative.base_positive, ["source", "step_id", "operation_index", "normalized_business_intent_digest_hex"], label + ".base_positive");
  hash32(negative.base_positive.normalized_business_intent_digest_hex, label + " business intent digest");
  fieldOrder(negative.fault_model, ["kind", "authenticated_source_relation", "expected_first_error_stage", "expected_first_error_code"], label + ".fault_model");
  sameJson(negative.fault_model, {
    kind: "state_dependent_same_subject_replay",
    authenticated_source_relation: "terminal_or_pruned_successor",
    expected_first_error_stage: automaton.negative_reject_stage,
    expected_first_error_code: automaton.negative_error_code,
  }, label + " fault model drift");
  const negativeOperation = JSON.parse(Buffer.from(negative.raw_operation_json_hexes[0], "hex").toString("utf8"));
  const digest = normalizedBusinessIntentDigest(negativeOperation);
  invariant(digest === negative.base_positive.normalized_business_intent_digest_hex, label + " negative intent digest drift");
  if (sequence.execution_scope === "full_application_store") {
    invariant(negative.base_positive.source === "sequence_step" && typeof negative.base_positive.step_id === "string" && Number.isInteger(negative.base_positive.operation_index), label + " full-store base reference drift");
    const step = sequence.steps.find((item) => item.id === negative.base_positive.step_id);
    const record = step?.operations[negative.base_positive.operation_index];
    invariant(record !== undefined && record.operation_kind === automaton.negative_operation_kind, label + " full-store base operation is missing/wrong kind");
    const baseOperation = JSON.parse(Buffer.from(record.raw_operation_json_hex, "hex").toString("utf8"));
    invariant(normalizedBusinessIntentDigest(baseOperation) === digest, label + " negative differs from successful base business intent");
  } else {
    invariant(negative.base_positive.source === "source_lineage" && negative.base_positive.step_id === null && negative.base_positive.operation_index === null, label + " isolated base reference drift");
    invariant(lineage !== null && lineage.operation_kind === automaton.negative_operation_kind && lineage.normalized_business_intent_digest_hex === digest, label + " isolated source lineage drift");
    sameJson(lineage.subjects, sequence.subjects, label + " isolated lineage subject drift");
  }
};

const sourceEvidenceFromState = (state) => ({
  version: state.context.source_version,
  jmt_root_hex: state.context.source_root_hex,
  manifest_hex: state.projection.raw.manifest_hex,
  authority: clone(state.projection.authority),
});
const validateSourceEvidence = (source, state, label) => {
  fieldOrder(source, ["version", "jmt_root_hex", "manifest_hex", "authority"], label);
  asSafeU64(source.version, label + ".version");
  nonzeroHash32(source.jmt_root_hex, label + ".jmt_root_hex");
  evenHex(source.manifest_hex, label + ".manifest_hex", 47, 47);
  validateAuthoritySummary(source.authority, state.projection.authority, label + ".authority");
  sameJson(source, sourceEvidenceFromState(state), label + " differs from current authenticated source");
};

const validateSignedTransaction = (rawHex, expectedOperationHex, context, label) => {
  const raw = evenHex(rawHex, label, 1, 1048576 + 4096);
  const tx = JSON.parse(raw.toString("utf8"));
  invariant(canonicalBytes(tx).equals(raw), label + " is not canonical JSON");
  fieldOrder(tx, SIGNED_TX_FIELDS, label + ".envelope");
  invariant(tx.schema === "trnm_signed_command_envelope_v1" && tx.chain_id === context.chain_id_utf8, label + " schema/chain drift");
  invariant(typeof tx.command_id === "string" && tx.command_id.length >= 1 && tx.command_id.length <= 160, label + " command ID drift");
  invariant(typeof tx.signer_id === "string" && tx.signer_id.length >= 1 && tx.signer_id.length <= 256, label + " signer ID drift");
  invariant(tx.signer_role === "operator", label + " signer role is not operator");
  const publicKey = nonzeroHash32(tx.public_key_hex, label + " public key");
  asSafeU64(tx.nonce, label + ".nonce");
  invariant(tx.nonce > 0, label + " nonce is zero");
  asSafeU64(tx.issued_at_unix_ms, label + ".issued_at_unix_ms");
  asSafeU64(tx.expires_at_unix_ms, label + ".expires_at_unix_ms");
  invariant(tx.expires_at_unix_ms > tx.issued_at_unix_ms, label + " expiry is not after issuance");
  invariant(tx.payload_type === PAYLOAD_TYPE && tx.payload_hex === expectedOperationHex, label + " payload binding drift");
  const payload = evenHex(tx.payload_hex, label + " payload", 1, 1048576);
  invariant(hashDomainV1("trnm.command.payload.v1", [payload]).toString("hex") === tx.payload_hash_hex, label + " payload hash drift");
  const signature = evenHex(tx.signature_hex, label + " signature", 64, 64);
  const signingBytes = Buffer.concat([
    frame64(Buffer.from(tx.schema)),
    frame64(Buffer.from(tx.chain_id)),
    frame64(Buffer.from(tx.command_id)),
    frame64(Buffer.from(tx.signer_id)),
    frame64(Buffer.from(tx.signer_role)),
    frame64(Buffer.from(tx.public_key_hex)),
    uint(tx.nonce, 8),
    uint(tx.issued_at_unix_ms, 8),
    uint(tx.expires_at_unix_ms, 8),
    frame64(Buffer.from(tx.payload_type)),
    frame64(payload),
    frame64(Buffer.from(tx.payload_hash_hex)),
  ]);
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: "der", type: "spki" });
  invariant(crypto.verify(null, signingBytes, key, signature), label + " Ed25519 signature invalid");
  return tx;
};
const validateReplayRun = (run, targetRoot, operationCount, label) => {
  fieldOrder(run, ["target_jmt_root_hex", "receipts_root_hex", "receipt_bytes_hexes"], label);
  invariant(run.target_jmt_root_hex === targetRoot, label + " target root drift");
  hash32(run.receipts_root_hex, label + ".receipts_root_hex");
  invariant(Array.isArray(run.receipt_bytes_hexes) && run.receipt_bytes_hexes.length === operationCount, label + " receipt count drift");
  const receipts = run.receipt_bytes_hexes.map((value, index) => evenHex(value, label + " receipt " + index));
  invariant(checkpointOrderedRoot(RECEIPT_ROOT_DOMAIN, receipts).toString("hex") === run.receipts_root_hex, label + " receipt root drift");
};
const sourceStateFingerprint = (state) => ({
  version: state.context.source_version,
  jmt_root_hex: state.context.source_root_hex,
  manifest_hex: state.projection.raw.manifest_hex,
  entries_root_hex: state.projection.raw.entries_root_hex,
  authority_envelope_hex: state.projection.authority.envelope_hex,
});
const targetStateFingerprint = (target) => ({
  version: target.version,
  jmt_root_hex: target.jmt_root_hex,
  manifest_hex: target.manifest_hex,
  entries_root_hex: target.entries_root_hex,
  authority_envelope_hex: target.authority.envelope_hex,
});
const validateStateFingerprint = (fingerprint, expected, label) => {
  fieldOrder(fingerprint, ["version", "jmt_root_hex", "manifest_hex", "entries_root_hex", "authority_envelope_hex"], label);
  sameJson(fingerprint, expected, label + " differs from authenticated state");
};
const validateScopeEvidence = (scopeEvidence, sequence, step, state, target, label) => {
  if (sequence.execution_scope === "isolated_prune_transition_kernel") {
    invariant(scopeEvidence === null, label + " isolated kernel must not claim production replay");
    return;
  }
  fieldOrder(scopeEvidence, ["kind", "ordered_signed_tx_hexes", "process_proposal", "finalize_block", "sqlite_commit", "sqlite_restart", "snapshot_v3_restore", "snapshot_v4_restore", "sqlite_failpoint_outcomes"], label);
  invariant(scopeEvidence.kind === "full_application_store", label + " scope kind drift");
  invariant(Array.isArray(scopeEvidence.ordered_signed_tx_hexes) && scopeEvidence.ordered_signed_tx_hexes.length === step.operation_count, label + " signed tx count drift");
  const txs = scopeEvidence.ordered_signed_tx_hexes.map((raw, index) => validateSignedTransaction(raw, step.operations[index].raw_operation_json_hex, step.context, label + ".tx[" + index + "]"));
  unique(txs.map((tx) => tx.command_id), label + " command IDs");
  unique(txs.map((tx) => tx.signer_id + ":" + tx.nonce), label + " signer nonces");
  validateReplayRun(scopeEvidence.process_proposal, target.jmt_root_hex, step.operation_count, label + ".process_proposal");
  validateReplayRun(scopeEvidence.finalize_block, target.jmt_root_hex, step.operation_count, label + ".finalize_block");
  sameJson(scopeEvidence.process_proposal, scopeEvidence.finalize_block, label + " ProcessProposal/FinalizeBlock receipts or roots differ");
  const targetFingerprint = targetStateFingerprint(target);
  for (const field of ["sqlite_commit", "sqlite_restart", "snapshot_v3_restore", "snapshot_v4_restore"]) {
    validateStateFingerprint(scopeEvidence[field], targetFingerprint, label + "." + field);
  }
  invariant(Array.isArray(scopeEvidence.sqlite_failpoint_outcomes) && scopeEvidence.sqlite_failpoint_outcomes.length === STORE_FAILPOINTS.length, label + " failpoint evidence count drift");
  const sourceFingerprint = sourceStateFingerprint(state);
  for (const [index, [failpoint, outcome]] of STORE_FAILPOINTS.entries()) {
    const item = scopeEvidence.sqlite_failpoint_outcomes[index];
    fieldOrder(item, ["failpoint", "call_returned_error", "restart_state"], label + ".failpoint[" + index + "]");
    invariant(item.failpoint === failpoint && item.call_returned_error === true, label + " failpoint identity/error drift");
    validateStateFingerprint(item.restart_state, outcome === "source" ? sourceFingerprint : targetFingerprint, label + ".failpoint restart");
  }
};

const validateMutationEvidence = (bundle, sourceProjection, targetProjection, operations, label) => {
  fieldOrder(bundle, ["mutation_root_hex", "mutation_count", "items"], label);
  hash32(bundle.mutation_root_hex, label + ".mutation_root_hex");
  asU32(bundle.mutation_count, label + ".mutation_count");
  invariant(Array.isArray(bundle.items) && bundle.items.length === bundle.mutation_count, label + " mutation count drift");
  let previous = null;
  const items = bundle.items.map((item, index) => {
    fieldOrder(item, MUTATION_FIELDS, label + ".items[" + index + "]");
    invariant(Number.isInteger(item.kind) && item.kind >= 1 && item.kind <= 16, label + " mutation kind outside 1..16");
    const key = hash32(item.logical_key_hex, label + " mutation key");
    const expected = item.expected_value_hex === null ? null : evenHex(item.expected_value_hex, label + " expected value", 1, 65536);
    const next = item.next_value_hex === null ? null : evenHex(item.next_value_hex, label + " next value", 1, 65536);
    invariant(expected !== null || next !== null, label + " mutation has neither source nor target");
    const identity = { kind: item.kind, key };
    if (previous !== null) invariant(compareKindKey(previous, identity) < 0, label + " mutations are not strictly sorted unique");
    previous = identity;
    const canonical = canonicalMutation({ kind: item.kind, key, expected, next });
    invariant(canonical.toString("hex") === item.canonical_cev0_hex, label + " canonical mutation bytes drift");
    return { kind: item.kind, key, expected, next, canonical, raw: item };
  });
  invariant(orderedRoot(MUTATION_DOMAIN, MUTATION_NODE_DOMAIN, MUTATION_ROOT_DOMAIN, items.map((item) => item.canonical)).toString("hex") === bundle.mutation_root_hex, label + " mutation root drift");
  const source = new Map(sourceProjection.entries.map((entry) => [entry.kind + ":" + entry.raw.logical_key_hex, entry.raw.value_hex]));
  const target = new Map(targetProjection.entries.map((entry) => [entry.kind + ":" + entry.raw.logical_key_hex, entry.raw.value_hex]));
  const identities = [...new Set([...source.keys(), ...target.keys()])].sort((left, right) => {
    const [leftKind, leftKey] = left.split(":");
    const [rightKind, rightKey] = right.split(":");
    return Number(leftKind) - Number(rightKind) || Buffer.compare(Buffer.from(leftKey, "hex"), Buffer.from(rightKey, "hex"));
  });
  const expectedDiff = identities.filter((identity) => source.get(identity) !== target.get(identity)).map((identity) => {
    const [kind, logicalKey] = identity.split(":");
    const expectedValue = source.get(identity) ?? null;
    const nextValue = target.get(identity) ?? null;
    const canonical = canonicalMutation({ kind: Number(kind), key: Buffer.from(logicalKey, "hex"), expected: expectedValue === null ? null : Buffer.from(expectedValue, "hex"), next: nextValue === null ? null : Buffer.from(nextValue, "hex") });
    return { kind: Number(kind), logical_key_hex: logicalKey, expected_value_hex: expectedValue, next_value_hex: nextValue, canonical_cev0_hex: canonical.toString("hex") };
  });
  sameJson(bundle.items, expectedDiff, label + " mutations differ from complete source/target projection diff");
  const semantic = operations
    .flatMap((operation) => operation.semantic_changes.map((change) => ({ kind: change.kind, logical_key_hex: change.logical_key_hex, next_value_hex: change.next_value_hex })))
    .sort((left, right) => left.kind - right.kind || Buffer.compare(Buffer.from(left.logical_key_hex, "hex"), Buffer.from(right.logical_key_hex, "hex")));
  unique(semantic.map((change) => change.kind + ":" + change.logical_key_hex), label + " semantic changes across block");
  const nonAuthority = bundle.items.filter((item) => item.kind !== 16).map((item) => ({ kind: item.kind, logical_key_hex: item.logical_key_hex, next_value_hex: item.next_value_hex }));
  sameJson(nonAuthority, semantic, label + " mutations differ from ordered raw semantic changes");
  invariant(bundle.items.filter((item) => item.kind === 16).length === 1, label + " lacks the one atomic authority mutation");
};

const validateNextContext = (next, current, target, label) => {
  validateContext(next, label);
  invariant(next.chain_id_utf8 === current.chain_id_utf8 && next.genesis_hash_hex === current.genesis_hash_hex, label + " chain/genesis drift");
  invariant(next.source_version === target.version && next.source_root_hex === target.jmt_root_hex, label + " does not derive from target head");
  invariant(next.active_epoch === current.active_epoch, label + " active epoch changed before authenticated activation");
  invariant(next.active_parameters_cev0_hex === current.active_parameters_cev0_hex && next.active_parameters_hash_hex === current.active_parameters_hash_hex, label + " active parameters changed before authenticated activation");
  invariant(next.authority_signer_commitment_hex === current.authority_signer_commitment_hex, label + " signer commitment substitution");
};

const validateStepEvent = (draft, sequence, step, state, predictedNullifier) => {
  const event = step.rust_event;
  fieldOrder(event, ["schema", "schema_version", "source_export_sha256_hex", "draft_request_sha256_hex", "sequence_id", "step_id", "execution_scope", "context", "source", "operation", "scope_evidence", "mutations", "target", "next_production_context"], "Rust step event");
  invariant(event.schema === STEP_EVENT_SCHEMA && event.schema_version === 0, "Rust step event schema drift");
  invariant(event.source_export_sha256_hex === sequence.source_export_sha256_hex && event.draft_request_sha256_hex === successRequestDigest(draft, sequence, step), "Rust step event source/request digest drift");
  invariant(event.sequence_id === sequence.id && event.step_id === step.id && event.execution_scope === sequence.execution_scope, "Rust step event identity/scope drift");
  sameJson(event.context, step.context, "Rust step event context drift");
  validateSourceEvidence(event.source, state, "Rust step event source");
  fieldOrder(event.operation, ["raw_json_hexes", "operation_ids_hex", "operation_root_hex", "operation_count"], "Rust step event operation");
  sameJson(event.operation.raw_json_hexes, step.operations.map((operation) => operation.raw_operation_json_hex), "Rust raw operations drift");
  sameJson(event.operation.operation_ids_hex, step.operations.map((operation) => operation.operation_id_hex), "Rust operation IDs drift");
  invariant(event.operation.operation_root_hex === step.operation_root_hex && event.operation.operation_count === step.operation_count, "Rust operation root/count drift");
  fieldOrder(event.target, ["version", "jmt_root_hex", "manifest_hex", "entries_root_hex", "entries", "authority"], "Rust step target");
  invariant(event.target.version === step.context.target_height, "Rust target version drift");
  nonzeroHash32(event.target.jmt_root_hex, "Rust target JMT root");
  invariant(event.target.jmt_root_hex !== state.context.source_root_hex, "operation block left JMT root unchanged");
  const targetProjectionRaw = { manifest_hex: event.target.manifest_hex, entries_root_hex: event.target.entries_root_hex, entries: event.target.entries };
  const targetProjection = projectionEvidence(targetProjectionRaw, event.target.version, true, undefined, "Rust target projection");
  validateAuthoritySummary(event.target.authority, targetProjection.authority, "Rust target authority");
  invariant(event.target.authority.revision === state.projection.authority.revision + 1 && event.target.authority.last_target_height === event.target.version, "target authority is not the one sealed block successor");
  invariant(event.target.authority.nullifier_root_hex === predictedNullifier.root_hex && BigInt(event.target.authority.nullifier_count) === BigInt(predictedNullifier.count), "target authority/nullifier proof transition drift");
  const decodedOperations = step.operations.map((record) => JSON.parse(Buffer.from(record.raw_operation_json_hex, "hex").toString("utf8")));
  validateMutationEvidence(event.mutations, state.projection, targetProjection, decodedOperations, "Rust mutation evidence");
  validateScopeEvidence(event.scope_evidence, sequence, step, state, event.target, "Rust scope evidence");
  validateNextContext(event.next_production_context, step.context, event.target, "Rust next production context");
  return {
    context: clone(event.next_production_context),
    projection: { raw: targetProjectionRaw, ...targetProjection },
    nullifier: predictedNullifier,
  };
};

const checkOperationRecord = (sequence, step, record, context, sourceRevision, nullifier, label) => {
  fieldOrder(record, ["id", "operation_kind", "raw_operation_json_hex", "operation_id_hex", "_authoring"], label);
  invariant(typeof record.id === "string" && record.id.length > 0, label + " id is empty");
  invariant(typeof record.operation_kind === "string" && record.operation_kind in BODY_FIELDS, label + " kind drift");
  const raw = evenHex(record.raw_operation_json_hex, label + " raw operation", 1, 1048576);
  const operation = JSON.parse(raw.toString("utf8"));
  invariant(canonicalBytes(operation).equals(raw), label + " raw operation is not canonical JSON");
  validateOperation(operation, label + " decoded operation");
  invariant(operation.body.kind === record.operation_kind && operation.target_height === context.target_height && operation.expected_state_revision === sourceRevision, label + " source/target/revision binding drift");
  invariant(domainHash(OPERATION_DOMAIN, raw).toString("hex") === record.operation_id_hex, label + " operation ID drift");
  fieldOrder(record._authoring, ["normalized_operation_json_hex", "decision_preimage_hex", "derived_decisions", "proof_plan", "nullifier_before", "nullifier_after"], label + " authoring");
  const bindings = decisionBindings(record.operation_kind);
  const normalized = normalizeOperationForDecision(operation, bindings);
  invariant(canonicalBytes(normalized).toString("hex") === record._authoring.normalized_operation_json_hex, label + " normalized operation drift");
  const preimage = contextPreimage(context, normalized);
  invariant(preimage.toString("hex") === record._authoring.decision_preimage_hex, label + " decision preimage drift");
  const decisions = {};
  for (const [pointer, decisionLabel] of bindings) {
    const expected = decisionId(preimage, decisionLabel).toString("hex");
    invariant(pointerGet(operation, pointer) === expected, label + " decision field drift");
    decisions[decisionLabel] = expected;
  }
  sameJson(record._authoring.derived_decisions, decisions, label + " derived decisions drift");
  sameJson(record._authoring.nullifier_before, canonicalNullifierState(nullifier), label + " nullifier source drift");
  const regenerated = clone(normalized);
  for (const [pointer, decisionLabel] of bindings) pointerSet(regenerated, pointer, decisions[decisionLabel]);
  const proofResult = populateProofs(regenerated, decisions, record._authoring.proof_plan, nullifier);
  sameJson(proofResult.canonicalPlan, record._authoring.proof_plan, label + " canonical proof plan drift");
  sameJson(regenerated, operation, label + " proof bytes/order drift");
  sameJson(proofResult.after, record._authoring.nullifier_after, label + " nullifier target drift");
  return { operation, nullifier: proofResult.after };
};

const validateNegativeEvent = (sequence, negative, state) => {
  const event = negative.rust_event;
  fieldOrder(event, ["schema", "schema_version", "source_export_sha256_hex", "draft_request_sha256_hex", "sequence_id", "negative_id", "execution_scope", "context", "source", "raw_operation_json_hexes", "actual_rejection", "execution_evidence", "writes", "target_after"], "Rust negative event");
  invariant(event.schema === NEGATIVE_EVENT_SCHEMA && event.schema_version === 0, "Rust negative event schema drift");
  invariant(event.source_export_sha256_hex === sequence.source_export_sha256_hex && event.draft_request_sha256_hex === negativeRequestDigest(sequence, negative), "Rust negative source/request digest drift");
  invariant(event.sequence_id === sequence.id && event.negative_id === negative.id && event.execution_scope === sequence.execution_scope, "Rust negative identity/scope drift");
  sameJson(event.context, negative.context, "Rust negative context drift");
  validateSourceEvidence(event.source, state, "Rust negative source");
  sameJson(event.raw_operation_json_hexes, negative.raw_operation_json_hexes, "Rust negative raw operations drift");
  const automaton = automatonForId(sequence.id);
  const validateActualRejection = (actual, label) => {
    fieldOrder(actual, ["stage", "error_code", "classifier_priority", "error_chain_sha256_hex", "rejected_nullifier"], label);
    invariant(actual.stage === automaton.negative_reject_stage && actual.error_code === automaton.negative_error_code, label + " stable classifier drift");
    invariant(actual.classifier_priority === REJECT_STAGE_PRIORITY[actual.stage], label + " classifier first-error priority drift");
    nonzeroHash32(actual.error_chain_sha256_hex, label + ".error_chain_sha256_hex");
    if (automaton.negative_replay_nullifier_family === null) {
      invariant(actual.rejected_nullifier === null, label + " unexpectedly claims a rejected nullifier");
    } else {
      fieldOrder(actual.rejected_nullifier, ["family", "identifier_hex", "key_hex", "proof_source_root_hex"], label + ".rejected_nullifier");
      const identifier = expectedReplayIdentifier(automaton, sequence.subjects);
      const expectedKey = deriveNullifierKey(actual.rejected_nullifier.family, identifier);
      invariant(normalizedOccupied(state.nullifier).some((item) => item.key.equals(expectedKey)), label + " replay subject is not occupied in the authenticated current nullifier set");
      invariant(state.nullifier.root_hex === state.projection.authority.nullifier_root_hex && BigInt(state.nullifier.count) === BigInt(state.projection.authority.nullifier_count), label + " current nullifier set differs from authenticated authority");
      invariant(actual.rejected_nullifier.family === automaton.negative_replay_nullifier_family && actual.rejected_nullifier.identifier_hex === identifier.toString("hex"), label + " rejected nullifier family/subject drift");
      invariant(actual.rejected_nullifier.key_hex === expectedKey.toString("hex"), label + " rejected nullifier key drift");
      const operation = JSON.parse(Buffer.from(negative.raw_operation_json_hexes[0], "hex").toString("utf8"));
      const proof = [...operation.nullifier_non_membership_checks, ...operation.nullifier_insertions]
        .find((item) => item.family === actual.rejected_nullifier.family && item.identifier_hex === actual.rejected_nullifier.identifier_hex);
      invariant(proof !== undefined && proofSourceRoot(proof.proof_hex).toString("hex") === actual.rejected_nullifier.proof_source_root_hex, label + " rejected proof source root drift");
      invariant(actual.rejected_nullifier.proof_source_root_hex !== state.nullifier.root_hex, label + " replay rejection did not prove a stale/non-membership root mismatch against current authority");
    }
  };
  validateActualRejection(event.actual_rejection, "Rust actual rejection");
  if (sequence.execution_scope === "full_application_store") {
    fieldOrder(event.execution_evidence, ["kind", "ordered_signed_tx_hexes", "process_proposal_status", "process_executor_actual", "independent_executor_actual", "finalize_block_not_invoked_after_reject", "pending_after_reject", "sqlite_restart"], "Rust negative execution evidence");
    invariant(event.execution_evidence.kind === "full_application_store", "Rust negative execution scope drift");
    invariant(Array.isArray(event.execution_evidence.ordered_signed_tx_hexes) && event.execution_evidence.ordered_signed_tx_hexes.length === negative.raw_operation_json_hexes.length, "Rust negative signed tx count drift");
    event.execution_evidence.ordered_signed_tx_hexes.forEach((raw, index) => validateSignedTransaction(raw, negative.raw_operation_json_hexes[index], negative.context, "Rust negative signed tx " + index));
    invariant(event.execution_evidence.process_proposal_status === "reject" && event.execution_evidence.finalize_block_not_invoked_after_reject === true, "negative proposal/finalize control-flow drift");
    validateActualRejection(event.execution_evidence.process_executor_actual, "ProcessProposal executor actual rejection");
    validateActualRejection(event.execution_evidence.independent_executor_actual, "independent executor actual rejection");
    sameJson(event.execution_evidence.process_executor_actual, event.execution_evidence.independent_executor_actual, "independent production rejection classification drift");
    sameJson(event.actual_rejection, event.execution_evidence.process_executor_actual, "top-level actual rejection is not production-derived");
    invariant(event.execution_evidence.pending_after_reject === null, "rejected proposal left a pending block");
    validateStateFingerprint(event.execution_evidence.sqlite_restart, sourceStateFingerprint(state), "Rust negative SQLite restart");
  } else {
    fieldOrder(event.execution_evidence, ["kind", "kernel"], "Rust negative execution evidence");
    invariant(event.execution_evidence.kind === "isolated_prune_transition_kernel", "Rust negative kernel scope drift");
    validateActualRejection(event.execution_evidence.kernel, "kernel actual rejection");
    sameJson(event.actual_rejection, event.execution_evidence.kernel, "top-level actual rejection is not kernel-derived");
  }
  invariant(event.writes === 0 && negative.expected_writes === 0, "rejected operation performed writes");
  fieldOrder(event.target_after, ["version", "jmt_root_hex", "manifest_hex", "authority"], "Rust negative target_after");
  sameJson(event.target_after, negative.expected_unchanged, "Rust negative changed head/manifest/authority/nullifier");
};

const evaluateSequence = (draft, sequence) => {
  fieldOrder(sequence, ["id", "execution_scope", "activation_prerequisite", "source_export_sha256_hex", "subjects", "initial", "steps", "negatives", "_authoring"], "sequence " + sequence.id);
  invariant(typeof sequence.id === "string" && sequence.id.length > 0, "empty sequence ID");
  invariant(sequence.execution_scope === "full_application_store" || sequence.execution_scope === "isolated_prune_transition_kernel", "invalid sequence scope");
  invariant(sequence.execution_scope === "full_application_store" ? sequence.activation_prerequisite === "" : sequence.activation_prerequisite === KERNEL_PREREQUISITE, "sequence prerequisite/scope drift");
  hash32(sequence.source_export_sha256_hex, "sequence source export digest");
  const automaton = automatonForId(sequence.id);
  invariant(automaton.execution_scope === sequence.execution_scope, "sequence automaton scope drift");
  validateSubjects(sequence.subjects, automaton, "sequence subjects", false);
  const reconstructedSubjects = emptySubjects(automaton);
  fieldOrder(sequence._authoring, ["initial_nullifier_state", "lineage_base_intent"], "sequence authoring");
  const initial = validateInitial(sequence.initial, "sequence " + sequence.id + " initial");
  let nullifier = canonicalNullifierState(sequence._authoring.initial_nullifier_state);
  invariant(nullifier.root_hex === initial.projection.authority.nullifier_root_hex && BigInt(nullifier.count) === BigInt(initial.projection.authority.nullifier_count), "sequence initial nullifier differs from authority envelope");
  let state = {
    context: clone(initial.context),
    projection: { raw: clone(sequence.initial.projection), ...initial.projection },
    nullifier,
  };
  invariant(Array.isArray(sequence.steps) && Array.isArray(sequence.negatives), "sequence steps/negatives are not arrays");
  unique(sequence.steps.map((step) => step.id), "step IDs in " + sequence.id);
  let partial = false;
  let awaiting = false;
  for (const [stepIndex, step] of sequence.steps.entries()) {
    fieldOrder(step, ["id", "context", "operations", "operation_root_hex", "operation_count", "rust_event"], "step " + sequence.id + "/" + step.id);
    invariant(!awaiting, "a step follows an unverified Rust event");
    sameJson(step.context, state.context, "step context is not production-derived");
    validateContext(step.context, "step context");
    invariant(Array.isArray(step.operations) && step.operations.length >= 1 && step.operations.length <= 32 && step.operation_count === step.operations.length, "step operation count drift");
    unique(step.operations.map((operation) => operation.id), "operation IDs in step");
    let predicted = state.nullifier;
    const decoded = [];
    for (const [operationIndex, record] of step.operations.entries()) {
      const result = checkOperationRecord(sequence, step, record, step.context, state.projection.authority.revision, predicted, "step operation " + operationIndex);
      decoded.push(result.operation);
      mergeSubjects(reconstructedSubjects, automaton, result.operation.body, "authenticated operation path");
      predicted = result.nullifier;
    }
    const rawOperations = step.operations.map((record) => Buffer.from(record.raw_operation_json_hex, "hex"));
    invariant(orderedRoot(OPERATION_DOMAIN, OPERATION_NODE_DOMAIN, OPERATION_ROOT_DOMAIN, rawOperations).toString("hex") === step.operation_root_hex, "step operation root drift");
    if (step.rust_event === null) {
      invariant(stepIndex === sequence.steps.length - 1 && sequence.negatives.length === 0, "only final positive step may await Rust evidence");
      partial = true;
      awaiting = true;
      continue;
    }
    state = validateStepEvent(draft, sequence, step, state, predicted);
  }
  unique(sequence.negatives.map((negative) => negative.id), "negative IDs in " + sequence.id);
  sameJson(sequence.subjects, reconstructedSubjects, "stored sequence subjects differ from exact positive operation bodies");
  for (const negative of sequence.negatives) {
    fieldOrder(negative, ["id", "context", "base_positive", "fault_model", "raw_operation_json_hexes", "source", "expected_reject", "expected_writes", "expected_unchanged", "rust_event"], "negative " + negative.id);
    sameJson(negative.context, state.context, "negative context differs from current production context");
    validateSourceEvidence(negative.source, state, "negative source");
    invariant(Array.isArray(negative.raw_operation_json_hexes) && negative.raw_operation_json_hexes.length >= 1 && negative.raw_operation_json_hexes.length <= 32, "negative raw operation count drift");
    negative.raw_operation_json_hexes.forEach((raw, index) => evenHex(raw, "negative raw operation " + index, 1, 1048576));
    invariant(negative.raw_operation_json_hexes.length === 1, "required negative operation count drift");
    const negativeRaw = Buffer.from(negative.raw_operation_json_hexes[0], "hex");
    const negativeOperation = JSON.parse(negativeRaw.toString("utf8"));
    invariant(canonicalBytes(negativeOperation).equals(negativeRaw), "negative raw operation is not canonical JSON");
    validateOperation(negativeOperation, "negative decoded operation");
    invariant(negativeOperation.target_height === state.context.target_height && negativeOperation.expected_state_revision === state.projection.authority.revision, "negative target/revision binding drift");
    invariant(negativeOperation.body.kind === automaton.negative_operation_kind, "negative operation kind drift");
    const negativeSubjects = emptySubjects(automaton);
    mergeSubjects(negativeSubjects, automaton, negativeOperation.body, "negative operation");
    sameJson(negativeSubjects, sequence.subjects, "negative operation subject differs from positive/pruned subject");
    if (automaton.negative_replay_nullifier_family !== null) {
      const expectedIdentifier = expectedReplayIdentifier(automaton, sequence.subjects).toString("hex");
      const candidates = [...negativeOperation.nullifier_non_membership_checks, ...negativeOperation.nullifier_insertions]
        .filter((item) => item.family === automaton.negative_replay_nullifier_family && item.identifier_hex === expectedIdentifier);
      invariant(candidates.length === 1, "negative replay proof family/subject drift");
    }
    fieldOrder(negative.expected_reject, ["stage", "error_code"], "negative expected reject");
    invariant(REJECT_STAGES.has(negative.expected_reject.stage) && /^[a-z][a-z0-9_]*$/.test(negative.expected_reject.error_code), "negative rejection contract drift");
    invariant(negative.expected_writes === 0, "negative expected writes is not zero");
    invariant(negative.expected_reject.stage === automaton.negative_reject_stage && negative.expected_reject.error_code === automaton.negative_error_code, "negative expected rejection differs from automaton");
    validateNegativeLineage(sequence, negative, automaton, sequence._authoring.lineage_base_intent, "negative lineage");
    sameJson(negative.expected_unchanged, { version: state.context.source_version, jmt_root_hex: state.context.source_root_hex, manifest_hex: state.projection.raw.manifest_hex, authority: state.projection.authority }, "negative unchanged state drift");
    if (negative.rust_event === null) partial = true;
    else validateNegativeEvent(sequence, negative, state);
  }
  if (sequence.negatives.length > 0) validateSubjects(sequence.subjects, automaton, "completed sequence subjects");
  return { partial, state };
};

const checkDraft = (draft, requireAutomatonCompleteness = true) => {
  validateDraftShape(draft);
  unique(draft.sequences.map((sequence) => sequence.id), "sequence IDs");
  let partial = false;
  const fullDigests = new Set();
  for (const sequence of draft.sequences) {
    const result = evaluateSequence(draft, sequence);
    const automaton = validateSequenceAutomatonProgress(sequence);
    partial ||= result.partial || (requireAutomatonCompleteness && !automaton.complete);
    if (sequence.execution_scope === "full_application_store") fullDigests.add(sequence.source_export_sha256_hex);
  }
  invariant(fullDigests.size <= 1, "full-store sequences do not share one exact real full-genesis export");
  return { partial };
};

const parseRustEvents = (filename) => {
  const raw = fs.readFileSync(filename, "utf8").trim();
  if (raw.startsWith("[") || (raw.startsWith("{") && !raw.includes("\n"))) {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value : [value];
  }
  const events = [];
  for (const line of raw.split(/\r?\n/)) {
    const start = line.indexOf("{");
    if (start === -1) continue;
    try { events.push(JSON.parse(line.slice(start))); } catch { /* ignore harness text */ }
  }
  invariant(events.length > 0, "Rust export contains no JSON events");
  return events;
};
const mergeRust = (draft, events) => {
  validateDraftShape(draft);
  for (const event of events) {
    invariant(event?.schema === STEP_EVENT_SCHEMA || event?.schema === NEGATIVE_EVENT_SCHEMA, "Rust export contains unknown event schema");
    const sequence = draft.sequences.find((item) => item.id === event.sequence_id);
    invariant(sequence !== undefined, "Rust event names unknown sequence");
    if (event.schema === STEP_EVENT_SCHEMA) {
      const step = sequence.steps.find((item) => item.id === event.step_id);
      invariant(step !== undefined && step.rust_event === null, "Rust event names unknown/already-merged step");
      step.rust_event = clone(event);
    } else {
      const negative = sequence.negatives.find((item) => item.id === event.negative_id);
      invariant(negative !== undefined && negative.rust_event === null, "Rust event names unknown/already-merged negative");
      negative.rust_event = clone(event);
    }
    checkDraft(draft);
  }
  return draft;
};

const decodedNegativeKinds = (negative) => negative.raw_operation_json_hexes.map((rawHex, index) => {
  const raw = Buffer.from(rawHex, "hex");
  const operation = JSON.parse(raw.toString("utf8"));
  invariant(canonicalBytes(operation).equals(raw), "coverage negative operation is not canonical JSON");
  validateOperation(operation, "coverage negative operation " + index);
  return operation.body.kind;
});
const terminalResolution = (sequence) => {
  const last = sequence.steps.at(-1)?.operations.at(-1);
  if (last?.operation_kind !== "resolve_challenge") return null;
  return JSON.parse(Buffer.from(last.raw_operation_json_hex, "hex").toString("utf8")).body.resolution;
};
const validateSequenceAutomatonProgress = (sequence) => {
  const automaton = automatonForId(sequence.id);
  invariant(sequence.execution_scope === automaton.execution_scope, "sequence scope differs from required automaton: " + sequence.id);
  invariant(sequence.steps.length <= automaton.block_operation_kinds.length, "sequence has extra operation blocks: " + sequence.id);
  for (const [index, step] of sequence.steps.entries()) {
    sameJson(step.operations.map((operation) => operation.operation_kind), automaton.block_operation_kinds[index], "sequence operation block differs from required automaton: " + sequence.id + " block " + (index + 1));
  }
  const positiveComplete = sequence.steps.length === automaton.block_operation_kinds.length;
  if (positiveComplete) invariant(terminalResolution(sequence) === automaton.terminal_resolution, "sequence terminal resolution differs from required automaton: " + sequence.id);
  invariant(sequence.negatives.length <= 1, "sequence has extra required negatives: " + sequence.id);
  if (sequence.negatives.length === 1) {
    const negative = sequence.negatives[0];
    const kinds = decodedNegativeKinds(negative);
    invariant(kinds.length === 1 && kinds[0] === automaton.negative_operation_kind, "sequence negative operation differs from required automaton: " + sequence.id);
    invariant(negative.expected_reject.stage === automaton.negative_reject_stage && negative.expected_reject.error_code === automaton.negative_error_code, "sequence negative classifier differs from required automaton: " + sequence.id);
  }
  return { automaton, complete: positiveComplete && sequence.negatives.length === 1 };
};
const validateAutomataCoverage = (draft) => {
  const matched = new Map();
  for (const sequence of draft.sequences) {
    const status = validateSequenceAutomatonProgress(sequence);
    const automaton = status.automaton;
    invariant(status.complete, "required automaton is incomplete: " + automaton.id);
    invariant(!matched.has(automaton.id), "required automaton covered more than once: " + automaton.id);
    matched.set(automaton.id, sequence);
  }
  for (const automaton of REQUIRED_AUTOMATA) invariant(matched.has(automaton.id), "missing required automaton " + automaton.id);
  invariant(matched.size === draft.sequences.length && draft.sequences.length === REQUIRED_AUTOMATA.length, "final corpus contains unmatched/extra sequences");
  const full = REQUIRED_AUTOMATA.filter((item) => item.execution_scope === "full_application_store").map((item) => matched.get(item.id));
  invariant(new Set(full.map((sequence) => sequence.source_export_sha256_hex)).size === 1, "five full-store automata do not share one real full-genesis export");
  const fullDigest = full[0].source_export_sha256_hex;
  for (const automaton of REQUIRED_AUTOMATA.filter((item) => item.execution_scope === "isolated_prune_transition_kernel")) {
    const sequence = matched.get(automaton.id);
    invariant(sequence.source_export_sha256_hex !== fullDigest && sequence.activation_prerequisite === KERNEL_PREREQUISITE, "isolated prune source/scope is presented as production reachable");
  }
};
const finalize = (draft, requireCoverage = true) => {
  const checked = checkDraft(draft, requireCoverage);
  invariant(!checked.partial, "cannot finalize a partial operation sequence corpus");
  if (requireCoverage) validateAutomataCoverage(draft);
  const sequences = clone(draft.sequences);
  for (const sequence of sequences) {
    delete sequence._authoring;
    for (const step of sequence.steps) for (const operation of step.operations) delete operation._authoring;
  }
  return {
    schema: FINAL_SCHEMA,
    schema_version: 0,
    source_exports_sha256_hex: clone(draft.source_exports_sha256_hex),
    source_exports: clone(draft.source_exports),
    required_automata: clone(draft.required_automata),
    sequences,
  };
};

const replayRawProofs = (operation, state, label) => {
  const before = canonicalNullifierState(state);
  const occupied = normalizedOccupied(before);
  const initialRoot = sparseRoot(occupied.map((item) => item.key));
  for (const [index, proofItem] of operation.nullifier_non_membership_checks.entries()) {
    const identifier = Buffer.from(proofItem.identifier_hex, "hex");
    const key = deriveNullifierKey(proofItem.family, identifier);
    invariant(!occupied.some((item) => item.key.equals(key)), label + " absence checks an occupied nullifier");
    invariant(proofSourceRoot(proofItem.proof_hex).equals(initialRoot), label + " absence proof " + index + " does not use the initial root");
  }
  const after = [...occupied];
  for (const [index, proofItem] of operation.nullifier_insertions.entries()) {
    invariant(BigInt(after.length) < U64_MAX, label + " nullifier count exhausted before proof walk");
    const identifier = Buffer.from(proofItem.identifier_hex, "hex");
    const key = deriveNullifierKey(proofItem.family, identifier);
    invariant(!after.some((item) => item.key.equals(key)), label + " insertion replays an occupied nullifier");
    const currentRoot = sparseRoot(after.map((item) => item.key));
    invariant(proofSourceRoot(proofItem.proof_hex).equals(currentRoot), label + " insertion proof " + index + " source root drift");
    after.push({ family: proofItem.family, identifier_hex: proofItem.identifier_hex, identifier, key });
  }
  after.sort((left, right) => left.family - right.family || Buffer.compare(left.identifier, right.identifier));
  return {
    root_hex: sparseRoot(after.map((item) => item.key)).toString("hex"),
    count: String(after.length),
    occupied: after.map(({ family, identifier_hex }) => ({ family, identifier_hex })),
  };
};
const checkFinal = (finalValue, requireCoverage = true) => {
  fieldOrder(finalValue, ["schema", "schema_version", "source_exports_sha256_hex", "source_exports", "required_automata", "sequences"], "final vector");
  invariant(finalValue.schema === FINAL_SCHEMA && finalValue.schema_version === 0, "final schema drift");
  sameJson(finalValue.required_automata, REQUIRED_AUTOMATA, "final required automata drift");
  invariant(Array.isArray(finalValue.source_exports_sha256_hex) && Array.isArray(finalValue.source_exports), "final source registry drift");
  sameJson(finalValue.source_exports.map((source) => source.sha256_hex), finalValue.source_exports_sha256_hex, "final source registry order drift");
  unique(finalValue.source_exports_sha256_hex, "final source export digests");
  sameJson([...finalValue.source_exports_sha256_hex].sort(), finalValue.source_exports_sha256_hex, "final source export digests are not sorted");
  const parsedSources = new Map();
  for (const [index, source] of finalValue.source_exports.entries()) {
    fieldOrder(source, ["sha256_hex", "raw_json_hex"], "final source export " + index);
    const raw = evenHex(source.raw_json_hex, "final source raw JSON", 1, 16 * 1024 * 1024);
    invariant(sha256(raw).toString("hex") === source.sha256_hex, "final source raw digest drift");
    const parsed = JSON.parse(raw.toString("utf8"));
    fieldOrder(parsed, parsed.schema === SOURCE_SCHEMA
      ? ["schema", "schema_version", "initial", "authoring_nullifier_state"]
      : ["schema", "schema_version", "lineage_base_intent", "initial", "authoring_nullifier_state"], "final retained source export");
    invariant(parsed.schema_version === 0 && [SOURCE_SCHEMA, "trnm.poco-bft.application-isolated-prune-source-export.v0"].includes(parsed.schema), "final retained source version/schema drift");
    if (parsed.schema !== SOURCE_SCHEMA) {
      fieldOrder(parsed.lineage_base_intent, ["operation_kind", "normalized_business_intent_digest_hex", "subjects"], "final isolated source lineage");
      invariant(typeof parsed.lineage_base_intent.operation_kind === "string" && parsed.lineage_base_intent.operation_kind in BODY_FIELDS, "final isolated lineage operation kind drift");
      hash32(parsed.lineage_base_intent.normalized_business_intent_digest_hex, "final isolated lineage digest");
      invariant(parsed.lineage_base_intent.subjects !== null && typeof parsed.lineage_base_intent.subjects === "object" && !Array.isArray(parsed.lineage_base_intent.subjects), "final isolated lineage subjects drift");
    }
    parsedSources.set(source.sha256_hex, parsed);
  }
  invariant(Array.isArray(finalValue.sequences) && finalValue.sequences.length >= 1, "final vector has no sequences");
  sameJson(finalValue.source_exports_sha256_hex, sourceDigestList(finalValue.sequences), "final source digest set drift");
  unique(finalValue.sequences.map((sequence) => sequence.id), "final sequence IDs");
  const pseudoDraft = { ...finalValue, schema: DRAFT_SCHEMA };
  for (const sequence of finalValue.sequences) {
    fieldOrder(sequence, ["id", "execution_scope", "activation_prerequisite", "source_export_sha256_hex", "subjects", "initial", "steps", "negatives"], "final sequence " + sequence.id);
    const automaton = automatonForId(sequence.id);
    invariant(automaton.execution_scope === sequence.execution_scope, "final sequence scope drift");
    invariant(sequence.execution_scope === "full_application_store" ? sequence.activation_prerequisite === "" : sequence.activation_prerequisite === KERNEL_PREREQUISITE, "final sequence prerequisite drift");
    validateSubjects(sequence.subjects, automaton, "final sequence subjects");
    const retained = parsedSources.get(sequence.source_export_sha256_hex);
    invariant(retained !== undefined, "final sequence source bytes missing");
    const expectedSourceSchema = sequence.execution_scope === "full_application_store" ? SOURCE_SCHEMA : "trnm.poco-bft.application-isolated-prune-source-export.v0";
    invariant(retained.schema === expectedSourceSchema, "final sequence source scope/schema drift");
    sameJson(retained.initial, sequence.initial, "final sequence initial differs from retained source");
    const initial = validateInitial(sequence.initial, "final sequence initial");
    let nullifier = canonicalNullifierState({ ...retained.authoring_nullifier_state, count: String(retained.authoring_nullifier_state.count) });
    invariant(nullifier.root_hex === initial.projection.authority.nullifier_root_hex && BigInt(nullifier.count) === BigInt(initial.projection.authority.nullifier_count), "final initial nullifier/authority drift");
    let state = {
      context: clone(initial.context),
      projection: { raw: clone(sequence.initial.projection), ...initial.projection },
      nullifier,
    };
    const subjects = emptySubjects(automaton);
    unique(sequence.steps.map((step) => step.id), "final step IDs");
    for (const [stepIndex, step] of sequence.steps.entries()) {
      fieldOrder(step, ["id", "context", "operations", "operation_root_hex", "operation_count", "rust_event"], "final step " + stepIndex);
      sameJson(step.context, state.context, "final step context continuity drift");
      validateContext(step.context, "final step context");
      invariant(Array.isArray(step.operations) && step.operations.length === step.operation_count && step.operations.length >= 1 && step.operations.length <= 32, "final step operation count drift");
      unique(step.operations.map((operation) => operation.id), "final operation IDs");
      let predicted = state.nullifier;
      const rawOperations = [];
      for (const [operationIndex, record] of step.operations.entries()) {
        fieldOrder(record, ["id", "operation_kind", "raw_operation_json_hex", "operation_id_hex"], "final operation " + operationIndex);
        const raw = evenHex(record.raw_operation_json_hex, "final raw operation", 1, 1048576);
        const operation = JSON.parse(raw.toString("utf8"));
        invariant(canonicalBytes(operation).equals(raw), "final operation JSON is not canonical");
        validateOperation(operation, "final decoded operation");
        invariant(operation.body.kind === record.operation_kind && operation.target_height === step.context.target_height && operation.expected_state_revision === state.projection.authority.revision, "final operation context/revision drift");
        invariant(domainHash(OPERATION_DOMAIN, raw).toString("hex") === record.operation_id_hex, "final operation ID drift");
        const bindings = decisionBindings(record.operation_kind);
        const normalized = normalizeOperationForDecision(operation, bindings);
        const preimage = contextPreimage(step.context, normalized);
        for (const [pointer, decisionLabel] of bindings) invariant(pointerGet(operation, pointer) === decisionId(preimage, decisionLabel).toString("hex"), "final operation decision drift");
        predicted = replayRawProofs(operation, predicted, "final operation proof transition");
        mergeSubjects(subjects, automaton, operation.body, "final operation subject");
        rawOperations.push(raw);
      }
      invariant(orderedRoot(OPERATION_DOMAIN, OPERATION_NODE_DOMAIN, OPERATION_ROOT_DOMAIN, rawOperations).toString("hex") === step.operation_root_hex, "final operation root drift");
      invariant(step.rust_event !== null, "final vector contains missing Rust step evidence");
      state = validateStepEvent(pseudoDraft, sequence, step, state, predicted);
    }
    sameJson(subjects, sequence.subjects, "final subjects differ from raw positive operation path");
    invariant(sequence.negatives.length === 1, "final automaton negative count drift");
    for (const negative of sequence.negatives) {
      fieldOrder(negative, ["id", "context", "base_positive", "fault_model", "raw_operation_json_hexes", "source", "expected_reject", "expected_writes", "expected_unchanged", "rust_event"], "final negative");
      sameJson(negative.context, state.context, "final negative context drift");
      validateSourceEvidence(negative.source, state, "final negative source");
      invariant(negative.raw_operation_json_hexes.length === 1, "final negative raw operation count drift");
      const raw = evenHex(negative.raw_operation_json_hexes[0], "final negative raw operation", 1, 1048576);
      const operation = JSON.parse(raw.toString("utf8"));
      invariant(canonicalBytes(operation).equals(raw), "final negative operation is not canonical JSON");
      validateOperation(operation, "final negative operation");
      invariant(operation.body.kind === automaton.negative_operation_kind && operation.target_height === state.context.target_height && operation.expected_state_revision === state.projection.authority.revision, "final negative operation binding drift");
      const negativeSubjects = emptySubjects(automaton);
      mergeSubjects(negativeSubjects, automaton, operation.body, "final negative subject");
      sameJson(negativeSubjects, sequence.subjects, "final negative subject substitution");
      invariant(negative.expected_reject.stage === automaton.negative_reject_stage && negative.expected_reject.error_code === automaton.negative_error_code && negative.expected_writes === 0, "final negative expected contract drift");
      validateNegativeLineage(sequence, negative, automaton, retained.lineage_base_intent ?? null, "final negative lineage");
      sameJson(negative.expected_unchanged, { version: state.context.source_version, jmt_root_hex: state.context.source_root_hex, manifest_hex: state.projection.raw.manifest_hex, authority: state.projection.authority }, "final negative unchanged contract drift");
      invariant(negative.rust_event !== null, "final vector contains missing Rust negative evidence");
      validateNegativeEvent(sequence, negative, state);
    }
  }
  if (requireCoverage) validateAutomataCoverage(pseudoDraft);
  return { valid: true };
};

const makeAuthorityEnvelope = (revision, lastTargetHeight, nullifierRootHex, nullifierCount) => {
  const state = {
    schema: AUTHORITY_SCHEMA,
    revision,
    last_target_height: lastTargetHeight,
    nullifier_root_hex: nullifierRootHex,
    nullifier_count: nullifierCount,
    consumer_keys: [],
    meter_policies: [],
    meter_usage: [],
    consumer_provider_usage: [],
    task_provider_usage: [],
    provider_usage: [],
    funded_unused_reservations: [],
    active_certificates: [],
    pending_challenges: [],
    pending_governance_proposals: [],
    finalized_governance_approvals: [],
    validator_registration_history: [],
  };
  const payload = canonicalBytes(state);
  return Buffer.concat([uint(0, 2), uint(16, 1), uint(revision, 8), frame(AUTHORITY_IDENTITY), frame(payload)]);
};
const makeSemanticEnvelope = (kind, revision, identity, payload) => Buffer.concat([
  uint(0, 2), uint(kind, 1), uint(revision, 8), frame(identity), frame(payload),
]);
const makeProjection = (height, rawEntries) => {
  const entries = rawEntries.map(({ kind, logical_key_hex, value_hex }) => {
    const canonical = canonicalEntry(kind, Buffer.from(logical_key_hex, "hex"), Buffer.from(value_hex, "hex"));
    return { kind, logical_key_hex, value_hex, canonical_entry_cev0_hex: canonical.toString("hex") };
  }).sort((left, right) => left.kind - right.kind || Buffer.compare(Buffer.from(left.logical_key_hex, "hex"), Buffer.from(right.logical_key_hex, "hex")));
  const entriesRoot = orderedRoot(ENTRY_DOMAIN, ENTRY_NODE_DOMAIN, ENTRY_ROOT_DOMAIN, entries.map((entry) => Buffer.from(entry.canonical_entry_cev0_hex, "hex")));
  const manifest = Buffer.concat([uint(0, 2), uint(8, 1), uint(height, 8), uint(entries.length, 4), entriesRoot]);
  return { manifest_hex: manifest.toString("hex"), entries_root_hex: entriesRoot.toString("hex"), entries };
};
const makeMutationBundle = (sourceProjection, targetProjection) => {
  const source = new Map(sourceProjection.entries.map((entry) => [entry.kind + ":" + entry.logical_key_hex, entry.value_hex]));
  const target = new Map(targetProjection.entries.map((entry) => [entry.kind + ":" + entry.logical_key_hex, entry.value_hex]));
  const keys = [...new Set([...source.keys(), ...target.keys()])].sort((left, right) => {
    const [lk, lx] = left.split(":"); const [rk, rx] = right.split(":");
    return Number(lk) - Number(rk) || Buffer.compare(Buffer.from(lx, "hex"), Buffer.from(rx, "hex"));
  });
  const items = keys.filter((key) => source.get(key) !== target.get(key)).map((key) => {
    const [kind, logicalKey] = key.split(":");
    const expected = source.get(key) ?? null;
    const next = target.get(key) ?? null;
    const canonical = canonicalMutation({ kind: Number(kind), key: Buffer.from(logicalKey, "hex"), expected: expected === null ? null : Buffer.from(expected, "hex"), next: next === null ? null : Buffer.from(next, "hex") });
    return { kind: Number(kind), logical_key_hex: logicalKey, expected_value_hex: expected, next_value_hex: next, canonical_cev0_hex: canonical.toString("hex") };
  });
  return {
    mutation_root_hex: orderedRoot(MUTATION_DOMAIN, MUTATION_NODE_DOMAIN, MUTATION_ROOT_DOMAIN, items.map((item) => Buffer.from(item.canonical_cev0_hex, "hex"))).toString("hex"),
    mutation_count: items.length,
    items,
  };
};
const makeSignedTx = (operationHex, context, signingKey, publicKey, nonce) => {
  const payload = Buffer.from(operationHex, "hex");
  const tx = {
    schema: "trnm_signed_command_envelope_v1",
    chain_id: context.chain_id_utf8,
    command_id: "poco-authoring-self-test-" + nonce,
    signer_id: "did:operator:self-test",
    signer_role: "operator",
    public_key_hex: publicKey.toString("hex"),
    nonce,
    issued_at_unix_ms: 1000,
    expires_at_unix_ms: 10000,
    payload_type: PAYLOAD_TYPE,
    payload_hex: operationHex,
    payload_hash_hex: hashDomainV1("trnm.command.payload.v1", [payload]).toString("hex"),
    signature_hex: "",
  };
  const signingBytes = Buffer.concat([frame64(Buffer.from(tx.schema)), frame64(Buffer.from(tx.chain_id)), frame64(Buffer.from(tx.command_id)), frame64(Buffer.from(tx.signer_id)), frame64(Buffer.from(tx.signer_role)), frame64(Buffer.from(tx.public_key_hex)), uint(tx.nonce, 8), uint(tx.issued_at_unix_ms, 8), uint(tx.expires_at_unix_ms, 8), frame64(Buffer.from(tx.payload_type)), frame64(payload), frame64(Buffer.from(tx.payload_hash_hex))]);
  tx.signature_hex = crypto.sign(null, signingBytes, signingKey).toString("hex");
  return canonicalBytes(tx).toString("hex");
};
const proofSourceRoot = (proofHex) => {
  const proof = Buffer.from(proofHex, "hex");
  const key = proof.subarray(6, 38);
  let current = DEFAULT_HASHES[0];
  const keyValue = keyInteger(key);
  for (let level = 0; level < 256; level += 1) {
    const sibling = proof.subarray(38 + level * 32, 38 + (level + 1) * 32);
    current = ((keyValue >> BigInt(level)) & 1n) === 0n ? nullifierNodeHash(level, current, sibling) : nullifierNodeHash(level, sibling, current);
  }
  return current;
};
const expectFailure = (operation, label) => {
  let rejected = false;
  try { operation(); } catch { rejected = true; }
  invariant(rejected, "anti-tamper self-test did not reject " + label);
};

const mutateHex = (value) => (value[0] === "0" ? "1" : "0") + value.slice(1);
const makeSelfTestSource = () => {
  const emptyNullifier = {
    root_hex: DEFAULT_HASHES[256].toString("hex"),
    count: "0",
    occupied: [],
  };
  const authorityEnvelope = makeAuthorityEnvelope(1, 0, emptyNullifier.root_hex, 0).toString("hex");
  const authorityKey = decodeAuthorityEnvelope(authorityEnvelope, "self-test authority").logicalKey;
  const projection = makeProjection(0, [{
    kind: 16,
    logical_key_hex: authorityKey.toString("hex"),
    value_hex: authorityEnvelope,
  }]);
  const initial = {
    version: 0,
    jmt_root_hex: "aa".repeat(32),
    active_genesis: {
      chain_id_utf8: "trnm-self-test",
      genesis_hash_hex: "cc".repeat(32),
      validator_lifecycle: { physical_key_hex: "01", value_hex: "a1" },
      poco_authority_config: { physical_key_hex: "02", value_hex: "a2" },
      active_parameters: { physical_key_hex: "03", value_hex: "a3", cev0_hex: "04", hash_hex: "dd".repeat(32) },
      other_apphash_writes: [],
    },
    production_context: {
      chain_id_utf8: "trnm-self-test",
      genesis_hash_hex: "cc".repeat(32),
      source_version: 0,
      source_root_hex: "aa".repeat(32),
      target_height: 1,
      active_epoch: 0,
      active_parameters_cev0_hex: "04",
      active_parameters_hash_hex: "dd".repeat(32),
      authority_signer_commitment_hex: "ee".repeat(32),
    },
    history: [{
      version: 0,
      jmt_root_hex: "aa".repeat(32),
      writes: [
        { physical_key_hex: "01", value_hex: "a1" },
        { physical_key_hex: "02", value_hex: "a2" },
        { physical_key_hex: "03", value_hex: "a3" },
        { physical_key_hex: manifestKey().toString("hex"), value_hex: projection.manifest_hex },
        { physical_key_hex: entryKey(16, authorityKey).toString("hex"), value_hex: authorityEnvelope },
      ],
    }],
    projection,
  };
  const value = {
    schema: SOURCE_SCHEMA,
    schema_version: 0,
    initial,
    authoring_nullifier_state: emptyNullifier,
  };
  const raw = Buffer.from(JSON.stringify(value, null, 2) + "\n");
  return {
    digest: sha256(raw).toString("hex"),
    raw_json_hex: raw.toString("hex"),
    initial,
    nullifier: emptyNullifier,
    lineage: null,
  };
};
const makePersistenceEvidence = (sourceState, target) => {
  const source = sourceStateFingerprint(sourceState);
  const targetFingerprint = targetStateFingerprint(target);
  return {
    sqlite_commit: clone(targetFingerprint),
    sqlite_restart: clone(targetFingerprint),
    snapshot_v3_restore: clone(targetFingerprint),
    snapshot_v4_restore: clone(targetFingerprint),
    sqlite_failpoint_outcomes: STORE_FAILPOINTS.map(([failpoint, outcome]) => ({
      failpoint,
      call_returned_error: true,
      restart_state: clone(outcome === "source" ? source : targetFingerprint),
    })),
  };
};
const selfTest = () => {
  const assertIntentOmission = (baseBody, pointer, replacement, retainedPointer, retainedReplacement, label) => {
    const base = { body: clone(baseBody) };
    const targetAdvanced = clone(base);
    pointerSet(targetAdvanced, pointer, replacement);
    invariant(JSON.stringify(normalizedBusinessIntentBody(base)) === JSON.stringify(normalizedBusinessIntentBody(targetAdvanced)), label + " target-bound field was not omitted");
    const substituted = clone(base);
    pointerSet(substituted, retainedPointer, retainedReplacement);
    invariant(JSON.stringify(normalizedBusinessIntentBody(base)) !== JSON.stringify(normalizedBusinessIntentBody(substituted)), label + " retained subject/content was omitted");
  };
  assertIntentOmission({
    kind: "authorize_consumer_key", consumer_id_hex: "01", consumer_key_id_hex: "02",
    public_key_hex: "11".repeat(32), active_from_height: 1, decision_id_hex: "22".repeat(32),
  }, "/body/active_from_height", 281, "/body/public_key_hex", "33".repeat(32), "consumer-key intent");
  assertIntentOmission({
    kind: "define_meter_policy",
    policy: {
      meter_id_hex: "03", meter_version: 1, task_id_hex: "04", output_commitment_hex: null,
      unit_scale: "1", evidence_policy: "optional", per_certificate_cap: "1", rolling_cap: "1",
      rolling_epoch_span: 1, retention_blocks: 280, active_from_height: 1, retired_at_height: null,
    },
    decision_id_hex: "44".repeat(32),
  }, "/body/policy/active_from_height", 281, "/body/policy/task_id_hex", "05", "meter intent");
  assertIntentOmission({
    kind: "register_validator", validator_id_hex: "06", target_epoch: 1,
    registration_decision_id_hex: "55".repeat(32),
  }, "/body/target_epoch", 2, "/body/validator_id_hex", "07", "validator intent");

  const releaseCertificate = "88".repeat(32);
  const releaseDelete = {
    schema: OPERATION_SCHEMA,
    target_height: 2,
    expected_state_revision: 2,
    body: {
      kind: "release_settlement",
      certificate_id_hex: releaseCertificate,
      release_decision_id_hex: "99".repeat(32),
    },
    semantic_changes: [{
      kind: 6,
      logical_key_hex: semanticIdentityDigest(6, Buffer.from(releaseCertificate, "hex")).toString("hex"),
      next_value_hex: null,
    }],
    nullifier_non_membership_checks: [],
    nullifier_insertions: [],
  };
  validateOperation(releaseDelete, "self-test release tombstone");
  const wrongReleaseKind = clone(releaseDelete);
  wrongReleaseKind.semantic_changes[0].kind = 7;
  expectFailure(() => validateOperation(wrongReleaseKind, "self-test wrong release kind"), "wrong-kind release tombstone");
  const extraReleaseDelete = clone(releaseDelete);
  extraReleaseDelete.semantic_changes.push({ kind: 7, logical_key_hex: "ff".repeat(32), next_value_hex: null });
  expectFailure(() => validateOperation(extraReleaseDelete, "self-test extra release delete"), "extra release tombstone");

  const validatorId = Buffer.from("validator-lineage-self-test");
  const validatorKey = Buffer.alloc(32, 0x71);
  const validatorLogicalKey = semanticIdentityDigest(9, validatorId).toString("hex");
  const makeValidatorLineageValue = (revision, key, nonce, proofEpoch, signatureByte) => {
    const chain = Buffer.from("trnm-self-test");
    const proof = Buffer.concat([
      uint(0, 2), Buffer.alloc(32, 0x72), uint(chain.length, 2), chain,
      uint(proofEpoch, 8), frame(validatorId), key, uint(nonce, 8), Buffer.alloc(64, signatureByte),
    ]);
    const payload = Buffer.concat([frame(validatorId), key, uint(nonce, 8), uint(1, 1), frame(proof)]);
    return makeSemanticEnvelope(9, revision, validatorId, payload).toString("hex");
  };
  const validatorIntentOperation = {
    schema: OPERATION_SCHEMA,
    target_height: 1,
    expected_state_revision: 1,
    body: {
      kind: "register_validator",
      validator_id_hex: validatorId.toString("hex"),
      target_epoch: 1,
      registration_decision_id_hex: "00".repeat(32),
    },
    semantic_changes: [{
      kind: 9,
      logical_key_hex: validatorLogicalKey,
      next_value_hex: makeValidatorLineageValue(1, validatorKey, 1, 1, 0x73),
    }],
    nullifier_non_membership_checks: [],
    nullifier_insertions: [],
  };
  const validatorIntentDigest = normalizedBusinessIntentDigest(validatorIntentOperation);
  const validatorVolatileOnly = clone(validatorIntentOperation);
  validatorVolatileOnly.body.target_epoch = 28;
  validatorVolatileOnly.semantic_changes[0].next_value_hex = makeValidatorLineageValue(9, validatorKey, 1, 28, 0x74);
  invariant(normalizedBusinessIntentDigest(validatorVolatileOnly) === validatorIntentDigest, "validator lineage bound revision/target epoch/signature volatility");
  const validatorKeySubstitution = clone(validatorIntentOperation);
  const substitutedKey = Buffer.alloc(32, 0x75);
  validatorKeySubstitution.semantic_changes[0].next_value_hex = makeValidatorLineageValue(1, substitutedKey, 1, 1, 0x73);
  invariant(normalizedBusinessIntentDigest(validatorKeySubstitution) !== validatorIntentDigest, "validator lineage omitted consensus key/PoP invariants");
  const validatorNonceSubstitution = clone(validatorIntentOperation);
  validatorNonceSubstitution.semantic_changes[0].next_value_hex = makeValidatorLineageValue(1, validatorKey, 2, 1, 0x73);
  invariant(normalizedBusinessIntentDigest(validatorNonceSubstitution) !== validatorIntentDigest, "validator lineage omitted registration nonce");

  const source = makeSelfTestSource();
  const supersededGenesisLeaf = clone(source.initial);
  supersededGenesisLeaf.active_genesis.other_apphash_writes = [{ physical_key_hex: "04", value_hex: "a4" }];
  supersededGenesisLeaf.history[0].writes.push({ physical_key_hex: "04", value_hex: "a4" });
  supersededGenesisLeaf.history.push({
    version: 1,
    jmt_root_hex: "ab".repeat(32),
    writes: [{ physical_key_hex: "04", value_hex: null }],
  });
  supersededGenesisLeaf.version = 1;
  supersededGenesisLeaf.jmt_root_hex = "ab".repeat(32);
  supersededGenesisLeaf.production_context.source_version = 1;
  supersededGenesisLeaf.production_context.source_root_hex = "ab".repeat(32);
  supersededGenesisLeaf.production_context.target_height = 2;
  validateInitial(supersededGenesisLeaf, "self-test superseded dynamic genesis leaf");
  const unauthenticatedGenesisLeaf = clone(supersededGenesisLeaf);
  unauthenticatedGenesisLeaf.active_genesis.other_apphash_writes[0].value_hex = "a5";
  expectFailure(() => validateInitial(unauthenticatedGenesisLeaf, "self-test unauthenticated genesis leaf"), "unauthenticated version-zero genesis leaf");
  const sequence = newSequence(source, "release_refund_replay", "full_application_store", "");
  const draft = emptyDraft(sequence, source);
  checkDraft(draft);

  const certificateId = "22".repeat(32);
  const settlementCommitment = "33".repeat(32);
  const semanticKey = semanticIdentityDigest(6, Buffer.from(certificateId, "hex")).toString("hex");
  const settlementValueV1 = makeSemanticEnvelope(6, 1, Buffer.from(certificateId, "hex"), Buffer.concat([
    Buffer.from(certificateId, "hex"),
    Buffer.from(settlementCommitment, "hex"),
    uint(1, 1),
    uint(1, 8),
  ])).toString("hex");
  const template = {
    schema: STEP_TEMPLATE_SCHEMA,
    schema_version: 0,
    sequence_id: sequence.id,
    id: "block-1",
    operations: [{
      id: "fund-settlement",
      operation_kind: "fund_settlement",
      operation: {
        schema: OPERATION_SCHEMA,
        target_height: 1,
        expected_state_revision: 1,
        body: {
          kind: "fund_settlement",
          certificate_id_hex: certificateId,
          settlement_commitment_hex: settlementCommitment,
          reserved_units: "1",
          funding_decision_id_hex: "00".repeat(32),
        },
        semantic_changes: [{ kind: 6, logical_key_hex: semanticKey, next_value_hex: settlementValueV1 }],
        nullifier_non_membership_checks: [],
        nullifier_insertions: [],
      },
      proof_plan: [
        { list: "insertion", family: 3, identifier: { source: "decision", value: "fund-settlement" } },
        { list: "non_membership", family: 2, identifier: { source: "literal", value: "44".repeat(32) } },
        { list: "insertion", family: 1, identifier: { source: "pointer", value: "/body/certificate_id_hex" } },
      ],
    }],
  };
  deriveBlockStep(draft, template);
  const step = draft.sequences[0].steps[0];
  invariant(step.operations[0]._authoring.proof_plan.map((item) => item.list).join(",") === "non_membership,insertion,insertion", "self-test proof plan was not canonicalized");
  const absenceProof = JSON.parse(Buffer.from(step.operations[0].raw_operation_json_hex, "hex").toString("utf8")).nullifier_non_membership_checks[0];
  invariant(proofSourceRoot(absenceProof.proof_hex).equals(DEFAULT_HASHES[256]), "self-test absence proof does not bind the one initial root");

  const predicted = step.operations.at(-1)._authoring.nullifier_after;
  const sourceProjection = draft.sequences[0].initial.projection;
  const sourceAuthority = sourceProjection.entries.find((entry) => entry.kind === 16);
  const targetAuthorityEnvelope = makeAuthorityEnvelope(2, 1, predicted.root_hex, Number(predicted.count)).toString("hex");
  const targetProjection = makeProjection(1, [
    { kind: 6, logical_key_hex: semanticKey, value_hex: settlementValueV1 },
    { kind: 16, logical_key_hex: sourceAuthority.logical_key_hex, value_hex: targetAuthorityEnvelope },
  ]);
  const targetAuthority = decodeAuthorityEnvelope(targetAuthorityEnvelope, "self-test target authority").summary;
  const target = {
    version: 1,
    jmt_root_hex: "bb".repeat(32),
    manifest_hex: targetProjection.manifest_hex,
    entries_root_hex: targetProjection.entries_root_hex,
    entries: targetProjection.entries,
    authority: targetAuthority,
  };
  const initialValidated = validateInitial(draft.sequences[0].initial, "self-test initial");
  const state = {
    context: clone(initialValidated.context),
    projection: { raw: clone(sourceProjection), ...initialValidated.projection },
    nullifier: source.nullifier,
  };
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(SPKI_ED25519_PREFIX.length);
  const signedTx = makeSignedTx(step.operations[0].raw_operation_json_hex, step.context, privateKey, rawPublicKey, 1);
  const receiptBytes = [""];
  const replay = {
    target_jmt_root_hex: target.jmt_root_hex,
    receipts_root_hex: checkpointOrderedRoot(RECEIPT_ROOT_DOMAIN, receiptBytes.map((value) => Buffer.from(value, "hex"))).toString("hex"),
    receipt_bytes_hexes: receiptBytes,
  };
  const persistence = makePersistenceEvidence(state, target);
  const event = {
    schema: STEP_EVENT_SCHEMA,
    schema_version: 0,
    source_export_sha256_hex: source.digest,
    draft_request_sha256_hex: successRequestDigest(draft, sequence, step),
    sequence_id: sequence.id,
    step_id: step.id,
    execution_scope: sequence.execution_scope,
    context: clone(step.context),
    source: sourceEvidenceFromState(state),
    operation: {
      raw_json_hexes: step.operations.map((operation) => operation.raw_operation_json_hex),
      operation_ids_hex: step.operations.map((operation) => operation.operation_id_hex),
      operation_root_hex: step.operation_root_hex,
      operation_count: step.operation_count,
    },
    scope_evidence: {
      kind: "full_application_store",
      ordered_signed_tx_hexes: [signedTx],
      process_proposal: clone(replay),
      finalize_block: clone(replay),
      ...persistence,
    },
    mutations: makeMutationBundle(sourceProjection, targetProjection),
    target,
    next_production_context: {
      ...clone(step.context),
      source_version: 1,
      source_root_hex: target.jmt_root_hex,
      target_height: 2,
    },
  };
  mergeRust(draft, [event]);
  invariant(checkDraft(draft).partial === true, "self-test incomplete automaton was presented as complete after success evidence");

  const tamperSuccess = (label, mutate) => {
    const altered = clone(draft);
    mutate(altered, altered.sequences[0].steps[0].rust_event);
    expectFailure(() => checkDraft(altered), label);
  };
  tamperSuccess("completion status side fact", (altered) => { altered.status = "complete"; });
  tamperSuccess("target root", (_altered, rust) => { rust.target.jmt_root_hex = "bc".repeat(32); });
  tamperSuccess("mutation bytes", (_altered, rust) => { rust.mutations.items[0].canonical_cev0_hex = mutateHex(rust.mutations.items[0].canonical_cev0_hex); });
  tamperSuccess("mutation root", (_altered, rust) => { rust.mutations.mutation_root_hex = "cd".repeat(32); });
  tamperSuccess("manifest", (_altered, rust) => { rust.target.manifest_hex = mutateHex(rust.target.manifest_hex); });
  tamperSuccess("source digest", (_altered, rust) => { rust.source_export_sha256_hex = "de".repeat(32); });
  tamperSuccess("execution scope", (_altered, rust) => { rust.execution_scope = "isolated_prune_transition_kernel"; });
  tamperSuccess("production context", (_altered, rust) => { rust.context.target_height = 2; });
  tamperSuccess("active parameter continuation", (_altered, rust) => { rust.next_production_context.active_parameters_hash_hex = "ab".repeat(32); });
  tamperSuccess("target entry canonical bytes", (_altered, rust) => { rust.target.entries[0].canonical_entry_cev0_hex = mutateHex(rust.target.entries[0].canonical_entry_cev0_hex); });
  tamperSuccess("target authority", (_altered, rust) => { rust.target.authority.nullifier_root_hex = "ac".repeat(32); });
  tamperSuccess("signed transaction", (_altered, rust) => { rust.scope_evidence.ordered_signed_tx_hexes[0] = mutateHex(rust.scope_evidence.ordered_signed_tx_hexes[0]); });
  tamperSuccess("SQLite restart", (_altered, rust) => { rust.scope_evidence.sqlite_restart.jmt_root_hex = "ad".repeat(32); });
  tamperSuccess("failpoint outcome", (_altered, rust) => { rust.scope_evidence.sqlite_failpoint_outcomes[0].restart_state = clone(rust.scope_evidence.sqlite_failpoint_outcomes[1].restart_state); });
  tamperSuccess("retained source raw bytes", (altered) => { altered.source_exports[0].raw_json_hex += "20"; });
  tamperSuccess("retained source digest substitution", (altered) => { altered.source_exports[0].sha256_hex = "af".repeat(32); });

  const extraContext = clone(template);
  extraContext.context = clone(step.context);
  expectFailure(() => deriveBlockStep(clone(emptyDraft(newSequence(source, sequence.id, sequence.execution_scope, ""), source)), extraContext), "caller supplied context");
  const unsorted = clone(template);
  unsorted.operations[0].operation.semantic_changes = [
    { kind: 6, logical_key_hex: "ff".repeat(32), next_value_hex: "01" },
    { kind: 6, logical_key_hex: "00".repeat(32), next_value_hex: "01" },
  ];
  expectFailure(() => deriveBlockStep(emptyDraft(newSequence(source, sequence.id, sequence.execution_scope, ""), source), unsorted), "unsorted semantic changes");
  const duplicateProof = clone(template);
  duplicateProof.operations[0].proof_plan.push(clone(duplicateProof.operations[0].proof_plan[1]));
  expectFailure(() => deriveBlockStep(emptyDraft(newSequence(source, sequence.id, sequence.execution_scope, ""), source), duplicateProof), "duplicate proof identity");
  const wrongType = clone(template);
  wrongType.operations[0].operation.target_height = "1";
  expectFailure(() => deriveBlockStep(emptyDraft(newSequence(source, sequence.id, sequence.execution_scope, ""), source), wrongType), "numeric type substitution");

  const replayOperation = JSON.parse(Buffer.from(step.operations[0].raw_operation_json_hex, "hex").toString("utf8"));
  replayOperation.target_height = 2;
  replayOperation.expected_state_revision = 2;
  replayOperation.semantic_changes[0].next_value_hex = makeSemanticEnvelope(6, 2, Buffer.from(certificateId, "hex"), Buffer.concat([
    Buffer.from(certificateId, "hex"),
    Buffer.from(settlementCommitment, "hex"),
    uint(1, 1),
    uint(2, 8),
  ])).toString("hex");
  invariant(normalizedBusinessIntentDigest(replayOperation) === normalizedBusinessIntentDigest(JSON.parse(Buffer.from(step.operations[0].raw_operation_json_hex, "hex").toString("utf8"))), "settlement lineage bound target height or envelope revision");
  const settlementSubstitution = clone(replayOperation);
  settlementSubstitution.body.settlement_commitment_hex = "34".repeat(32);
  settlementSubstitution.semantic_changes[0].next_value_hex = makeSemanticEnvelope(6, 2, Buffer.from(certificateId, "hex"), Buffer.concat([
    Buffer.from(certificateId, "hex"), Buffer.from(settlementSubstitution.body.settlement_commitment_hex, "hex"), uint(1, 1), uint(2, 8),
  ])).toString("hex");
  invariant(normalizedBusinessIntentDigest(settlementSubstitution) !== normalizedBusinessIntentDigest(replayOperation), "settlement lineage omitted exact commitment fact");
  const negativeTemplate = {
    schema: NEGATIVE_TEMPLATE_SCHEMA,
    schema_version: 0,
    sequence_id: sequence.id,
    id: "refund-replay",
    raw_operation_json_hexes: [canonicalBytes(replayOperation).toString("hex")],
    expected_reject: { stage: "proof", error_code: "nullifier_non_membership_root_mismatch" },
  };
  deriveNegative(draft, negativeTemplate);
  const negative = draft.sequences[0].negatives[0];
  const rejectedIdentifier = Buffer.from(certificateId, "hex");
  const actualRejection = {
    stage: "proof",
    error_code: "nullifier_non_membership_root_mismatch",
    classifier_priority: REJECT_STAGE_PRIORITY.proof,
    error_chain_sha256_hex: sha256(Buffer.from("self-test production proof error chain")).toString("hex"),
    rejected_nullifier: {
      family: 1,
      identifier_hex: certificateId,
      key_hex: deriveNullifierKey(1, rejectedIdentifier).toString("hex"),
      proof_source_root_hex: proofSourceRoot(replayOperation.nullifier_non_membership_checks[0].proof_hex).toString("hex"),
    },
  };
  const negativeEvent = {
    schema: NEGATIVE_EVENT_SCHEMA,
    schema_version: 0,
    source_export_sha256_hex: source.digest,
    draft_request_sha256_hex: negativeRequestDigest(sequence, negative),
    sequence_id: sequence.id,
    negative_id: negative.id,
    execution_scope: sequence.execution_scope,
    context: clone(negative.context),
    source: clone(negative.source),
    raw_operation_json_hexes: clone(negative.raw_operation_json_hexes),
    actual_rejection: clone(actualRejection),
    execution_evidence: {
      kind: "full_application_store",
      ordered_signed_tx_hexes: [makeSignedTx(negative.raw_operation_json_hexes[0], negative.context, privateKey, rawPublicKey, 2)],
      process_proposal_status: "reject",
      process_executor_actual: clone(actualRejection),
      independent_executor_actual: clone(actualRejection),
      finalize_block_not_invoked_after_reject: true,
      pending_after_reject: null,
      sqlite_restart: sourceStateFingerprint({
        context: clone(negative.context),
        projection: { raw: targetProjection, authority: targetAuthority },
      }),
    },
    writes: 0,
    target_after: clone(negative.expected_unchanged),
  };
  mergeRust(draft, [negativeEvent]);
  invariant(checkDraft(draft).partial === true, "self-test incomplete positive path was presented as complete after negative evidence");
  const tamperNegative = (label, mutate) => {
    const altered = clone(draft);
    const rust = altered.sequences[0].negatives[0].rust_event;
    mutate(altered, rust);
    expectFailure(() => checkDraft(altered), label);
  };
  tamperNegative("negative writes", (_altered, rust) => { rust.writes = 1; });
  tamperNegative("actual reject stage", (_altered, rust) => { rust.actual_rejection.stage = "semantic"; });
  tamperNegative("actual reject code", (_altered, rust) => { rust.actual_rejection.error_code = "semantic_failure"; });
  tamperNegative("classifier priority", (_altered, rust) => { rust.actual_rejection.classifier_priority = 0; });
  tamperNegative("empty error chain digest", (_altered, rust) => { rust.actual_rejection.error_chain_sha256_hex = "00".repeat(32); });
  tamperNegative("rejected nullifier subject", (_altered, rust) => { rust.actual_rejection.rejected_nullifier.identifier_hex = "ef".repeat(32); });
  tamperNegative("independent classifier mismatch", (_altered, rust) => { rust.execution_evidence.independent_executor_actual.error_code = "semantic_failure"; });
  tamperNegative("unchanged target", (_altered, rust) => { rust.target_after.jmt_root_hex = "ef".repeat(32); });
  const subjectSwap = clone(draft);
  const rawSwap = JSON.parse(Buffer.from(subjectSwap.sequences[0].negatives[0].raw_operation_json_hexes[0], "hex").toString("utf8"));
  rawSwap.body.certificate_id_hex = "ef".repeat(32);
  subjectSwap.sequences[0].negatives[0].raw_operation_json_hexes[0] = canonicalBytes(rawSwap).toString("hex");
  expectFailure(() => checkDraft(subjectSwap), "same-kind negative subject substitution");

  const pathSpoof = clone(draft);
  pathSpoof.sequences[0].id = "certificate_prune_replay";
  pathSpoof.sequences[0].negatives[0].rust_event.sequence_id = "certificate_prune_replay";
  expectFailure(() => validateAutomataCoverage(pathSpoof), "sequence-ID coverage spoof");

  const finalVector = finalize(draft, false);
  checkFinal(finalVector, false);
  const tamperFinal = (label, mutate) => {
    const altered = clone(finalVector);
    mutate(altered);
    expectFailure(() => checkFinal(altered, false), "final " + label);
  };
  tamperFinal("status side fact", (value) => { value.status = "complete"; });
  tamperFinal("source raw whitespace", (value) => { value.source_exports[0].raw_json_hex += "20"; });
  tamperFinal("mutation root", (value) => { value.sequences[0].steps[0].rust_event.mutations.mutation_root_hex = "fa".repeat(32); });
  tamperFinal("scope", (value) => { value.sequences[0].steps[0].rust_event.scope_evidence.kind = "kernel"; });
  tamperFinal("subject", (value) => { value.sequences[0].subjects.certificate_id_hex = "fb".repeat(32); });
  tamperFinal("negative actual", (value) => { value.sequences[0].negatives[0].rust_event.actual_rejection.error_code = "other"; });
  tamperFinal("proof bytes", (value) => {
    const record = value.sequences[0].steps[0].operations[0];
    const operation = JSON.parse(Buffer.from(record.raw_operation_json_hex, "hex").toString("utf8"));
    operation.nullifier_non_membership_checks[0].proof_hex = mutateHex(operation.nullifier_non_membership_checks[0].proof_hex);
    record.raw_operation_json_hex = canonicalBytes(operation).toString("hex");
  });
  tamperFinal("coordinated proof sibling rehash", (value) => {
    const finalStep = value.sequences[0].steps[0];
    const record = finalStep.operations[0];
    const operation = JSON.parse(Buffer.from(record.raw_operation_json_hex, "hex").toString("utf8"));
    const proof = operation.nullifier_non_membership_checks[0].proof_hex;
    operation.nullifier_non_membership_checks[0].proof_hex = proof.slice(0, 76) + (proof[76] === "0" ? "1" : "0") + proof.slice(77);
    const raw = canonicalBytes(operation);
    record.raw_operation_json_hex = raw.toString("hex");
    record.operation_id_hex = domainHash(OPERATION_DOMAIN, raw).toString("hex");
    finalStep.operation_root_hex = orderedRoot(OPERATION_DOMAIN, OPERATION_NODE_DOMAIN, OPERATION_ROOT_DOMAIN, [raw]).toString("hex");
  });
  const temporaryDirectory = fs.mkdtempSync("/tmp/trnm-poco-author-self-test-");
  try {
    const fullSourcePath = temporaryDirectory + "/full.json";
    fs.writeFileSync(fullSourcePath, Buffer.from(source.raw_json_hex, "hex"));
    const isolatedPaths = {};
    for (const automaton of REQUIRED_AUTOMATA.filter((item) => item.execution_scope === "isolated_prune_transition_kernel")) {
      const subjects = emptySubjects(automaton);
      for (const field of automaton.subject_fields) subjects[field] = field === "meter_version" ? 1 : "55".repeat(32);
      const isolated = {
        schema: "trnm.poco-bft.application-isolated-prune-source-export.v0",
        schema_version: 0,
        lineage_base_intent: {
          operation_kind: automaton.negative_operation_kind,
          normalized_business_intent_digest_hex: "66".repeat(32),
          subjects,
        },
        initial: clone(source.initial),
        authoring_nullifier_state: clone(source.nullifier),
      };
      const filename = temporaryDirectory + "/" + automaton.id + ".json";
      fs.writeFileSync(filename, Buffer.from(JSON.stringify(isolated, null, 2) + "\n"));
      isolatedPaths[automaton.id] = filename;
    }
    const scaffold = scaffoldRequired([
      "--full-source", fullSourcePath,
      "--certificate-prune-source", isolatedPaths.certificate_prune_replay,
      "--consumer-key-prune-source", isolatedPaths.consumer_key_prune_replay,
      "--meter-prune-source", isolatedPaths.meter_prune_replay,
      "--validator-prune-source", isolatedPaths.validator_prune_replay,
    ]);
    invariant(scaffold.schema === SCAFFOLD_SCHEMA && scaffold.sequences.length === 9, "required scaffold did not emit all nine automata");
    invariant(scaffold.sequences.every((item) => item.source_export_sha256_hex.length === 64 && item.next_block_templates.length >= 1 && item.next_block_templates[0].derive_ready === false), "required scaffold lacks source-bound complete next-block skeletons");
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
  process.stdout.write("poco application sequence authoring self-test: pass (success + negative + anti-tamper)\n");
};

const requiredArgument = (args, name) => {
  const index = args.indexOf(name);
  invariant(index !== -1 && index + 1 < args.length && !args[index + 1].startsWith("--"), "missing required argument " + name);
  return args[index + 1];
};
const optionalArgument = (args, name, fallback = null) => {
  const index = args.indexOf(name);
  return index === -1 ? fallback : requiredArgument(args, name);
};
const appendSequence = (draft, source, id, scope, prerequisite) => {
  validateDraftShape(draft);
  invariant(!draft.sequences.some((sequence) => sequence.id === id), "sequence already exists: " + id);
  const sequence = newSequence(source, id, scope, prerequisite);
  draft.sequences.push(sequence);
  const existing = draft.source_exports.find((item) => item.sha256_hex === source.digest);
  if (existing === undefined) draft.source_exports.push({ sha256_hex: source.digest, raw_json_hex: source.raw_json_hex });
  else invariant(existing.raw_json_hex === source.raw_json_hex, "same source digest names different raw bytes");
  draft.source_exports.sort((left, right) => left.sha256_hex.localeCompare(right.sha256_hex));
  draft.source_exports_sha256_hex = draft.source_exports.map((item) => item.sha256_hex);
  validateDraftShape(draft);
  return draft;
};
const scaffoldOperation = (kind, firstContext, sourceRevision, blockIndex, operationIndex) => {
  const body = {};
  for (const field of BODY_FIELDS[kind]) {
    if (field === "kind") body[field] = kind;
    else if (decisionBindings(kind).some(([pointer]) => pointer === "/body/" + field)) body[field] = "00".repeat(32);
    else if (field === "policy") body[field] = Object.fromEntries(METER_POLICY_FIELDS.map((name) => [name, "$REQUIRED_EXACT_" + name.toUpperCase()]));
    else body[field] = "$REQUIRED_EXACT_" + field.toUpperCase();
  }
  return {
    id: `block-${blockIndex + 1}-operation-${operationIndex + 1}-${kind}`,
    operation_kind: kind,
    operation: {
      schema: OPERATION_SCHEMA,
      target_height: blockIndex === 0 ? firstContext.target_height : "$FROM_PREVIOUS_VERIFIED_RUST_EVENT_NEXT_PRODUCTION_CONTEXT_TARGET_HEIGHT",
      expected_state_revision: blockIndex === 0 ? sourceRevision : "$FROM_PREVIOUS_VERIFIED_RUST_EVENT_TARGET_AUTHORITY_REVISION",
      body,
      semantic_changes: [{
        kind: "$REQUIRED_EXACT_U8_KIND_1_TO_15",
        logical_key_hex: "$REQUIRED_EXACT_HASH32_DERIVED_FROM_RAW_VALUE_IDENTITY",
        next_value_hex: "$REQUIRED_EXACT_VALUE_HEX_OR_NULL_FOR_PRIVATE_PRUNE",
      }],
      nullifier_non_membership_checks: [],
      nullifier_insertions: [],
    },
    proof_plan: [{
      list: "$REQUIRED_NON_MEMBERSHIP_OR_INSERTION",
      family: "$REQUIRED_EXACT_U8_FAMILY_1_TO_14",
      identifier: { source: "$REQUIRED_LITERAL_POINTER_OR_DECISION", value: "$REQUIRED_EXACT_DESCRIPTOR" },
    }],
    exact_field_contract: {
      operation_field_order: clone(OPERATION_FIELDS),
      body_field_order: clone(BODY_FIELDS[kind]),
      meter_policy_field_order: kind === "define_meter_policy" ? clone(METER_POLICY_FIELDS) : null,
      semantic_change_field_order: ["kind", "logical_key_hex", "next_value_hex"],
      proof_plan_field_order: ["list", "family", "identifier"],
      proof_identifier_field_order: ["source", "value"],
      decision_fields_must_be_zero_before_derive: decisionBindings(kind).map(([pointer]) => pointer),
    },
  };
};
const scaffoldRequired = (args) => {
  const sources = {
    full_application_store: validateSourceExport(requiredArgument(args, "--full-source"), "full_application_store"),
    certificate_prune_replay: validateSourceExport(requiredArgument(args, "--certificate-prune-source"), "isolated_prune_transition_kernel"),
    consumer_key_prune_replay: validateSourceExport(requiredArgument(args, "--consumer-key-prune-source"), "isolated_prune_transition_kernel"),
    meter_prune_replay: validateSourceExport(requiredArgument(args, "--meter-prune-source"), "isolated_prune_transition_kernel"),
    validator_prune_replay: validateSourceExport(requiredArgument(args, "--validator-prune-source"), "isolated_prune_transition_kernel"),
  };
  const sequences = REQUIRED_AUTOMATA.map((automaton) => {
    const source = automaton.execution_scope === "full_application_store" ? sources.full_application_store : sources[automaton.id];
    const initial = validateInitial(source.initial, "scaffold source " + automaton.id);
    return {
      sequence_id: automaton.id,
      execution_scope: automaton.execution_scope,
      activation_prerequisite: automaton.execution_scope === "full_application_store" ? "" : KERNEL_PREREQUISITE,
      source_export_sha256_hex: source.digest,
      source_export_schema: automaton.execution_scope === "full_application_store" ? SOURCE_SCHEMA : "trnm.poco-bft.application-isolated-prune-source-export.v0",
      source_production_context: clone(initial.context),
      source_authority_revision: initial.projection.authority.revision,
      required_subject_fields: clone(automaton.subject_fields),
      source_lineage_required: automaton.execution_scope === "isolated_prune_transition_kernel",
      next_block_templates: automaton.block_operation_kinds.map((kinds, blockIndex) => ({
        schema: STEP_TEMPLATE_SCHEMA,
        schema_version: 0,
        sequence_id: automaton.id,
        id: `block-${blockIndex + 1}`,
        context_source: blockIndex === 0
          ? { kind: "exact_source_export", source_export_sha256_hex: source.digest, production_context: clone(initial.context), authority_revision: initial.projection.authority.revision }
          : { kind: "previous_verified_rust_step_event", field: "next_production_context", authority_revision_field: "target.authority.revision" },
        operations: kinds.map((kind, operationIndex) => scaffoldOperation(kind, initial.context, initial.projection.authority.revision, blockIndex, operationIndex)),
        derive_ready: false,
        unresolved_rule: "Replace every $REQUIRED/$FROM marker with exact Rust-source/fixture-derived bytes; derive rejects markers, caller context, caller proofs, wrong field order, wrong numeric type, duplicate or unsorted changes.",
      })),
      required_negative_template: {
        schema: NEGATIVE_TEMPLATE_SCHEMA,
        schema_version: 0,
        sequence_id: automaton.id,
        id: "required-state-dependent-same-subject-replay",
        raw_operation_json_hexes: ["$REQUIRED_EXACT_CANONICAL_RAW_OPERATION_HEX_FROM_BASE_BUSINESS_INTENT"],
        expected_reject: { stage: automaton.negative_reject_stage, error_code: automaton.negative_error_code },
        base_lineage_contract: automaton.execution_scope === "full_application_store"
          ? "must match the one successful same-kind sequence operation after context/decision/proof refresh"
          : "must match source_export.lineage_base_intent operation_kind/digest/subjects",
        rejected_nullifier_contract: automaton.negative_replay_nullifier_family === null
          ? null
          : { family: automaton.negative_replay_nullifier_family, identifier: "exact digest re-derived from required_subject_fields", key: "domain-derived exact nullifier key", proof_source_root: "decoded from exact rejected proof" },
      },
    };
  });
  const registry = new Map();
  for (const source of Object.values(sources)) registry.set(source.digest, { sha256_hex: source.digest, raw_json_hex: source.raw_json_hex });
  return {
    schema: SCAFFOLD_SCHEMA,
    schema_version: 0,
    source_exports_sha256_hex: [...registry.keys()].sort(),
    source_exports: [...registry.values()].sort((left, right) => left.sha256_hex.localeCompare(right.sha256_hex)),
    exact_template_field_order: ["schema", "schema_version", "sequence_id", "id", "operations"],
    exact_operation_template_field_order: ["id", "operation_kind", "operation", "proof_plan"],
    sequences,
    placeholder_policy: "This is a non-authorizing scaffold only. No marker is accepted by derive, merge, check, check-final, or finalize.",
  };
};

const usage = () => fail([
  "usage:",
  "  author... self-test",
  "  author... init --source FILE --sequence-id ID --scope SCOPE [--activation-prerequisite TEXT]",
  "  author... append --draft FILE --source FILE --sequence-id ID --scope SCOPE [--activation-prerequisite TEXT]",
  "  author... derive --draft FILE --template FILE",
  "  author... derive-negative --draft FILE --template FILE",
  "  author... merge --draft FILE --rust-events FILE",
  "  author... check --draft FILE",
  "  author... finalize --draft FILE",
  `  author... check-final --vector FILE (canonical: ${FINAL_VECTOR_RELATIVE_PATH})`,
  "  author... scaffold-required --full-source FILE --certificate-prune-source FILE --consumer-key-prune-source FILE --meter-prune-source FILE --validator-prune-source FILE",
].join("\n"));

const main = () => {
  const [command, ...args] = process.argv.slice(2);
  if (command === undefined) usage();
  if (command === "self-test") {
    invariant(args.length === 0, "self-test takes no arguments");
    selfTest();
    return;
  }
  if (command === "init") {
    const scope = requiredArgument(args, "--scope");
    const source = validateSourceExport(requiredArgument(args, "--source"), scope);
    const prerequisite = optionalArgument(args, "--activation-prerequisite", scope === "full_application_store" ? "" : KERNEL_PREREQUISITE);
    const sequence = newSequence(source, requiredArgument(args, "--sequence-id"), scope, prerequisite);
    output(emptyDraft(sequence, source));
    return;
  }
  if (command === "append") {
    const draft = readRaw(requiredArgument(args, "--draft")).value;
    const scope = requiredArgument(args, "--scope");
    const source = validateSourceExport(requiredArgument(args, "--source"), scope);
    const prerequisite = optionalArgument(args, "--activation-prerequisite", scope === "full_application_store" ? "" : KERNEL_PREREQUISITE);
    output(appendSequence(draft, source, requiredArgument(args, "--sequence-id"), scope, prerequisite));
    return;
  }
  if (command === "derive" || command === "derive-negative") {
    const draft = readRaw(requiredArgument(args, "--draft")).value;
    const template = readRaw(requiredArgument(args, "--template")).value;
    output(command === "derive" ? deriveBlockStep(draft, template) : deriveNegative(draft, template));
    return;
  }
  if (command === "merge") {
    const draft = readRaw(requiredArgument(args, "--draft")).value;
    output(mergeRust(draft, parseRustEvents(requiredArgument(args, "--rust-events"))));
    return;
  }
  if (command === "check") {
    const result = checkDraft(readRaw(requiredArgument(args, "--draft")).value);
    output({ schema: "trnm.poco-bft.application-operation-sequence-check.v0", schema_version: 0, partial: result.partial });
    return;
  }
  if (command === "finalize") {
    output(finalize(readRaw(requiredArgument(args, "--draft")).value));
    return;
  }
  if (command === "check-final") {
    checkFinal(readRaw(requiredArgument(args, "--vector")).value);
    output({ schema: "trnm.poco-bft.application-operation-final-check.v0", schema_version: 0, valid: true });
    return;
  }
  if (command === "scaffold-required") {
    output(scaffoldRequired(args));
    return;
  }
  usage();
};

try {
  main();
} catch (error) {
  process.stderr.write("application sequence authoring error: " + error.message + "\n");
  process.exitCode = 1;
}
