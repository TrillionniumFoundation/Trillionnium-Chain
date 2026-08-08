#!/usr/bin/env node

/*
 * H3b2b3b checkpoint-28 independent evidence gate.
 *
 * The committed Rust vector is structurally consumed here without accepting
 * a Rust-normalized capability. Exact old/new configuration, commitment,
 * parent/checkpoint/seal headers, both finality proofs, strict proposer/QC
 * signatures, native execution/header/preparation seals, and the private
 * joint authorization seal are independently reconstructed. H2 ICS23 is
 * replayed through the import-safe H3a consumer, while checkpoint/two-seal
 * finality and both handoff roles are replayed through the import-safe B2-F
 * consumer. `--structural-only` remains explicitly non-authoritative.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseLosslessUnsignedJson } from "./check_poco_bft_v0_authenticated_candidate_selection.mjs";
import { validateScenario as validateH3aScenario } from "./check_poco_bft_v0_authenticated_next_epoch_commitment.mjs";
import {
  decodeCommitment,
  decodeFinality,
  decodeHeader,
  decodeParameters,
  decodeValidatorSet,
  parseAuthorization,
  validateCertified,
  verifyBundle,
} from "./check_poco_bft_v0_joint_handoff_schema.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCHEMA_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/schema/poco-authenticated-checkpoint-handoff-v0.json");
const VECTOR_PATH = process.env.TRNM_POCO_AUTHENTICATED_CHECKPOINT_HANDOFF_VECTOR ?? path.join(
  ROOT,
  "docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json",
);
const CANDIDATE_VECTOR_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json");
const H3A_VECTOR_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/vectors/poco-authenticated-next-epoch-commitment-v0.json");
const CHECKPOINT_HEADER_SOURCE_PATH = path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/poco_checkpoint_header.rs");
const JOINT_HANDOFF_SOURCE_PATH = path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/poco_joint_handoff.rs");
const NATIVE_EXECUTION_SOURCE_PATH = path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/native_execution.rs");
const APP_LIB_SOURCE_PATH = path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/lib.rs");

const SCHEMA_ID = "trnm.poco-bft.authenticated-checkpoint-handoff.v0";
const FIXTURE_SCHEMA = "trnm.poco-bft.authenticated-checkpoint-handoff-fixture.v0";
const FIXTURE_SCOPE = "empty_state_preserving_native_checkpoint_raw_two_seal_and_same_version_joint_handoff_not_production_host_or_activation_authority";
const CANDIDATE_VECTOR_RELATIVE = "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json";
const H3A_VECTOR_RELATIVE = "docs/protocol/poco-bft-v0/vectors/poco-authenticated-next-epoch-commitment-v0.json";
const ACCEPTED_CHECKPOINT_AUTHORITY_CONTRACT =
  "only DurablyBoundPocoCheckpointHeaderV0; the raw non-durable binder is module-private/test-only and cannot enter the production-visible joint-handoff constructor";
const DURABLE_CHECKPOINT_WRAPPERS_CONTRACT =
  "reserve_prepared_poco_checkpoint_header_v0(&PocoPreparationJournalV0, PreparedPocoCheckpointHeaderV0) -> Result<DurablyPreparedPocoCheckpointHeaderV0> and bind_durably_prepared_poco_checkpoint_header_v0(&PocoPreparationJournalV0, DurablyPreparedPocoCheckpointHeaderV0, &BlockHeader, &BlockBodyV0, &ExecutionReceiptsV0) -> Result<DurablyBoundPocoCheckpointHeaderV0> are the only durable wrapper path; journal.bind(&reservation, &bound_record)? must succeed before the sole production DurablyBoundPocoCheckpointHeaderV0 construction";
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U32 = (1n << 32n) - 1n;
const MAX_U16 = (1n << 16n) - 1n;

const PROFILE_KEYS = [
  "epoch_length_blocks",
  "snapshot_lead_blocks",
  "old_epoch",
  "new_epoch",
  "cutoff_height",
  "checkpoint_parent_height",
  "checkpoint_height",
  "seal_1_height",
  "seal_2_height",
  "activation_height",
  "native_execution_profile",
  "comet_hash_mapping",
  "aggregate_digest",
  "epoch_anchor_qc_output",
];
const PROFILE = Object.freeze({
  epoch_length_blocks: 10n,
  snapshot_lead_blocks: 3n,
  old_epoch: 2n,
  new_epoch: 3n,
  cutoff_height: 25n,
  checkpoint_parent_height: 27n,
  checkpoint_height: 28n,
  seal_1_height: 29n,
  seal_2_height: 30n,
  activation_height: 31n,
});
const NEGATIVE_FAMILIES = Object.freeze([
  "positive/fallback H3 source or cutoff tuple splice",
  "lead-two parameter regression",
  "native execution parent, target, state, payload, receipt, or authorization substitution",
  "prepare-to-bind header, root, commitment, timestamp, proposer, or native BlockId TOCTOU substitution",
  "Comet/native identity substitution",
  "checkpoint parent or ordinary justify-QC splice",
  "checkpoint/seal kind, ancestry, root, state, commitment, proposal, QC subset, or strict signature substitution",
  "terminal header/QC, descriptor, activation context, role-root, one-sided quorum, duplicate signer, or handoff signature-domain substitution",
  "old/new configuration, version, upgrade-plan, final private seal, or whole-chain scenario splice",
  "generic verifier, inert-token conversion, caller authority input, telemetry promotion, or activation output API regression",
]);
const NEGATIVE_CASE_IDS = Object.freeze([
  "whole_chain_positive_checkpoint_fallback_raw",
  "whole_chain_fallback_checkpoint_positive_raw",
  "native_execution_authorization_cross_scenario",
  "joint_private_seal_bitflip",
  "joint_private_seal_cross_scenario",
  "recursive_comet_field_injection",
]);
const EMPTY_PAYLOAD_CEV0_HEX = "00000000";
const EMPTY_RECEIPTS_CEV0_HEX = "00000000";
const EMPTY_PAYLOAD_ROOT_HEX = "0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2";
const EMPTY_RECEIPTS_ROOT_HEX = "b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156";
const EMPTY_EVIDENCE_ROOT_HEX = "df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047";
const HASH_V1_PREFIX = Buffer.from("trnm.domain.hash.v1", "ascii");

const stats = {
  scenarios: 0,
  rawRoundTrips: 0,
  strictCertifiedHeaders: 0,
  privateSeals: 0,
  h2MembersStructurallyBound: 0,
  h2MembershipsVerified: 0,
  b2fBundles: 0,
  handoffSignaturesVerified: 0,
  negatives: 0,
};
const observedNegativeCaseIds = new Set();

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function bytes(value, label) {
  invariant(typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value), `${label}: canonical lowercase even-length hex required`);
  return Buffer.from(value, "hex");
}

function exactHex(value, byteLength, label) {
  const raw = bytes(value, label);
  invariant(raw.length === byteLength, `${label}: expected ${byteLength} bytes`);
  return raw;
}

function boundedHex(value, minimum, maximum, label) {
  const raw = bytes(value, label);
  invariant(raw.length >= minimum && raw.length <= maximum, `${label}: byte length out of bounds`);
  return raw;
}

function exactKeys(value, expected, label) {
  invariant(value !== null && typeof value === "object" && !Array.isArray(value), `${label}: object required`);
  invariant(JSON.stringify(Object.keys(value)) === JSON.stringify(expected), `${label}: exact field order drift`);
}

function rustUnsigned(value, maximum, label) {
  invariant(typeof value === "number" || typeof value === "bigint", `${label}: unquoted JSON integer required`);
  invariant(typeof value === "bigint" || (Number.isSafeInteger(value) && value >= 0), `${label}: lossless unsigned integer required`);
  const decoded = BigInt(value);
  invariant(decoded >= 0n && decoded <= maximum, `${label}: unsigned integer out of range`);
  return decoded;
}

const rustU64 = (value, label) => rustUnsigned(value, MAX_U64, label);
const rustU32 = (value, label) => rustUnsigned(value, MAX_U32, label);
const rustU16 = (value, label) => rustUnsigned(value, MAX_U16, label);

function u(value, width) {
  let remaining = BigInt(value);
  invariant(remaining >= 0n, "negative unsigned integer");
  const raw = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    raw[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  invariant(remaining === 0n, "unsigned integer overflow");
  return raw;
}

function frame64(raw) {
  return Buffer.concat([u(raw.length, 8), raw]);
}

function hashV1(domain, parts) {
  return crypto.createHash("sha256").update(Buffer.concat([
    HASH_V1_PREFIX,
    frame64(Buffer.from(domain, "ascii")),
    ...parts.map(frame64),
  ])).digest();
}

function sameBuffer(left, right, label) {
  invariant(Buffer.from(left).equals(Buffer.from(right)), label);
}

function equivalentEvidence(left, right) {
  if (
    (typeof left === "number" || typeof left === "bigint") &&
    (typeof right === "number" || typeof right === "bigint")
  ) {
    return BigInt(left) === BigInt(right);
  }
  if (Buffer.isBuffer(left) || Buffer.isBuffer(right)) {
    return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) &&
      left.length === right.length && left.every((value, index) => equivalentEvidence(value, right[index]));
  }
  if (left !== null && right !== null && typeof left === "object" && typeof right === "object") {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return JSON.stringify(leftKeys) === JSON.stringify(rightKeys) &&
      leftKeys.every((key) => equivalentEvidence(left[key], right[key]));
  }
  return left === right;
}

function runLosslessNumberSelfTests() {
  const accepted = [
    ["9007199254740991", "number"],
    ["9007199254740992", "bigint"],
    ["18446744073709551615", "bigint"],
  ];
  for (const [literal, expectedType] of accepted) {
    const parsed = parseLosslessUnsignedJson(Buffer.from(`{"value":${literal}}`), `lossless ${literal}`);
    invariant(typeof parsed.value === expectedType, `${literal}: lossless type drift`);
    invariant(rustU64(parsed.value, literal) === BigInt(literal), `${literal}: lossless value drift`);
  }
  const rejected = [`{"value":"7"}`, `{"value":01}`, `{"value":1.0}`, `{"value":1e0}`, `{"value":-1}`, `{"value":18446744073709551616}`];
  for (const raw of rejected) {
    let failed = false;
    try {
      const parsed = parseLosslessUnsignedJson(Buffer.from(raw), "lossless rejection");
      rustU64(parsed.value, "lossless rejection");
    } catch {
      failed = true;
    }
    invariant(failed, `${raw}: malformed or quoted u64 accepted`);
  }
  return `${accepted.length}/${rejected.length}`;
}

function validateProfile(profile, label) {
  exactKeys(profile, PROFILE_KEYS, label);
  for (const [key, expected] of Object.entries(PROFILE)) {
    invariant(rustU64(profile[key], `${label}.${key}`) === expected, `${label}.${key}: compact geometry drift`);
  }
  invariant(profile.native_execution_profile === "empty_state_preserving_no_runtime_receipt_mapping_claim", `${label}: native execution profile drift`);
  invariant(profile.comet_hash_mapping === null, `${label}: Comet hash mapping must remain explicitly absent`);
  invariant(profile.aggregate_digest === null, `${label}: aggregate digest must remain absent`);
  invariant(profile.epoch_anchor_qc_output === false, `${label}: EpochAnchorQC output must remain absent`);
}

function validateSchema(schema, candidateRaw, h3aRaw) {
  exactKeys(schema, [
    "schema", "schema_version", "status", "scope", "compact_profile", "source_corpora",
    "authority_flow", "vector_contract", "scenario_contract", "numeric_contract",
    "source_api_contract", "negative_families", "current_status", "does_not_establish",
  ], "schema");
  invariant(schema.schema === SCHEMA_ID && rustU16(schema.schema_version, "schema.schema_version") === 0n, "schema identity/version");
  validateProfile(schema.compact_profile, "schema.compact_profile");
  exactKeys(schema.source_corpora, [
    "candidate_vector_path", "candidate_vector_sha256_hex", "commitment_vector_path",
    "commitment_vector_sha256_hex", "reuse",
  ], "schema.source_corpora");
  invariant(schema.source_corpora.candidate_vector_path === CANDIDATE_VECTOR_RELATIVE, "schema candidate path drift");
  invariant(schema.source_corpora.candidate_vector_sha256_hex === sha256(candidateRaw), "schema candidate SHA drift");
  invariant(schema.source_corpora.commitment_vector_path === H3A_VECTOR_RELATIVE, "schema commitment path drift");
  invariant(schema.source_corpora.commitment_vector_sha256_hex === sha256(h3aRaw), "schema commitment SHA drift");
  invariant(schema.vector_contract.fixture_schema === FIXTURE_SCHEMA && schema.vector_contract.fixture_scope === FIXTURE_SCOPE, "schema vector identity drift");
  invariant(schema.vector_contract.identity_nonclaims.comet_hash_mapping === null, "schema maps a Comet hash");
  invariant(schema.vector_contract.identity_nonclaims.aggregate_digest === null, "schema invents aggregate digest");
  invariant(schema.vector_contract.identity_nonclaims.epoch_anchor_qc_output === false, "schema invents EpochAnchorQC output");
  invariant(
    JSON.stringify(schema.negative_families) === JSON.stringify(NEGATIVE_FAMILIES),
    "schema negative-family list drift",
  );
  exactKeys(schema.current_status, [
    "dedicated_checkpoint_28_vector",
    "schema_source_and_structural_node_gate",
    "independent_node_crypto_recomputation",
    "named_node_negative_campaign",
  ], "schema.current_status");
  invariant(schema.current_status.dedicated_checkpoint_28_vector.includes("landed"), "schema hides landed vector");
  invariant(schema.current_status.independent_node_crypto_recomputation.includes("landed"), "schema hides landed independent crypto");
  invariant(schema.current_status.named_node_negative_campaign.includes("landed"), "schema hides landed named negatives");
  invariant(
    schema.source_api_contract.raw_consumer_verifier ===
      "StrictEd25519Verifier is hard-coded inside the crate-private raw consumer",
    "schema raw-consumer verifier drift",
  );
  invariant(
    schema.source_api_contract.accepted_checkpoint_authority ===
      ACCEPTED_CHECKPOINT_AUTHORITY_CONTRACT,
    "schema accepted checkpoint authority drift",
  );
  invariant(
    schema.source_api_contract.durable_checkpoint_wrappers ===
      DURABLE_CHECKPOINT_WRAPPERS_CONTRACT,
    "schema durable checkpoint wrapper contract drift",
  );
}

function functionSignature(source, name, label) {
  const start = source.indexOf(`fn ${name}`);
  invariant(start >= 0, `${label}: missing ${name}`);
  const end = source.indexOf("{", start);
  invariant(end > start, `${label}: unterminated ${name} signature`);
  return source.slice(start, end);
}

function balancedDefinition(source, marker, label) {
  const start = source.indexOf(marker);
  invariant(start >= 0, `${label}: missing ${marker}`);
  const open = source.indexOf("{", start);
  invariant(open > start, `${label}: missing opening brace`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return {
          start,
          end: index + 1,
          signature: source.slice(start, open),
          body: source.slice(open + 1, index),
          source: source.slice(start, index + 1),
        };
      }
    }
  }
  throw new Error(`${label}: unterminated definition`);
}

function functionDefinition(source, name, label) {
  return balancedDefinition(source, `fn ${name}`, label);
}

function functionReturnType(signature, label) {
  const close = signature.lastIndexOf(")");
  invariant(close >= 0, `${label}: malformed return type`);
  const suffix = signature.slice(close + 1).replace(/\s+/g, " ").trim();
  invariant(suffix.startsWith("-> "), `${label}: missing explicit return type`);
  return suffix.slice(3).trim();
}

function countLiteral(source, literal) {
  let count = 0;
  let offset = 0;
  while (true) {
    const found = source.indexOf(literal, offset);
    if (found < 0) return count;
    count += 1;
    offset = found + literal.length;
  }
}

function braceDepthBefore(source, offset, label) {
  invariant(offset >= 0 && offset <= source.length, `${label}: invalid source offset`);
  let depth = 0;
  for (let index = 0; index < offset; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") depth -= 1;
    invariant(depth >= 0, `${label}: unbalanced source braces`);
  }
  return depth;
}

function functionParameters(signature, label) {
  const open = signature.indexOf("(");
  const close = signature.lastIndexOf(")");
  invariant(open >= 0 && close > open, `${label}: malformed parameter list`);
  return signature
    .slice(open + 1, close)
    .split(",")
    .map((item) => item.replace(/\s+/g, " ").trim())
    .filter((item) => item.length > 0);
}

function lockConstructorParameters(signature, expected, label) {
  invariant(
    JSON.stringify(functionParameters(signature, label)) === JSON.stringify(expected),
    `${label}: constructor parameter surface drift`,
  );
  invariant(
    !/(?:comet|cometbft|request[_a-z]*hash|block[_a-z]*hash|part[_a-z]*set)/i.test(signature),
    `${label}: host/Comet identity entered private authority constructor`,
  );
}

function lockFunctionContract(source, name, parameters, returnType, label) {
  const definition = functionDefinition(source, name, label);
  lockConstructorParameters(definition.signature, parameters, label);
  invariant(
    functionReturnType(definition.signature, label) === returnType,
    `${label}: return type drift`,
  );
  return definition;
}

function validatePrivateSourceSurface() {
  const checkpoint = fs.readFileSync(CHECKPOINT_HEADER_SOURCE_PATH, "utf8");
  const joint = fs.readFileSync(JOINT_HANDOFF_SOURCE_PATH, "utf8");
  const nativeExecution = fs.readFileSync(NATIVE_EXECUTION_SOURCE_PATH, "utf8");
  const appLib = fs.readFileSync(APP_LIB_SOURCE_PATH, "utf8");
  invariant(appLib.includes("mod poco_checkpoint_header;"), "checkpoint-header module not registered privately");
  invariant(appLib.includes("mod poco_joint_handoff;"), "joint-handoff module not registered privately");

  const prepare = functionSignature(checkpoint, "prepare_poco_checkpoint_header_v0", "checkpoint source");
  lockConstructorParameters(prepare, [
    "commitment_authority: AuthorizedPocoPreheaderNextEpochCommitmentV0",
    "checkpoint_view: View",
    "checkpoint_proposer_id: ValidatorId",
    "checkpoint_timestamp_ms: u64",
    "native_execution: AuthorizedNativeCheckpointExecutionV0",
    "evidence: Vec<DoubleVoteEvidenceV0>",
  ], "checkpoint prepare");
  invariant(!prepare.includes("StateRoot"), "prepare accepts naked state root");
  const bind = functionSignature(checkpoint, "bind_prepared_poco_checkpoint_header_v0", "checkpoint source");
  lockConstructorParameters(bind, [
    "prepared: PreparedPocoCheckpointHeaderV0",
    "exact_header: &BlockHeader",
    "exact_body: &BlockBodyV0",
    "exact_receipts: &ExecutionReceiptsV0",
  ], "checkpoint bind");
  invariant(
    functionReturnType(bind, "checkpoint bind") ===
      "Result<AuthorizedPocoCheckpointHeaderV0>",
    "checkpoint bind return type drift",
  );
  invariant(
    !/pub\(crate\)\s+fn\s+bind_prepared_poco_checkpoint_header_v0\s*\(/.test(checkpoint),
    "raw checkpoint bind is visible outside its module",
  );
  invariant(
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+bind_prepared_poco_checkpoint_header_for_fixture_v0\s*\(/.test(checkpoint),
    "fixture raw checkpoint bind is not test-only",
  );
  lockFunctionContract(checkpoint, "bind_prepared_poco_checkpoint_header_for_fixture_v0", [
    "prepared: PreparedPocoCheckpointHeaderV0",
    "exact_header: &BlockHeader",
    "exact_body: &BlockBodyV0",
    "exact_receipts: &ExecutionReceiptsV0",
  ], "Result<AuthorizedPocoCheckpointHeaderV0>", "fixture checkpoint bind");
  invariant(
    (checkpoint.match(/->\s*Result\s*<\s*AuthorizedPocoCheckpointHeaderV0\s*>/g) ?? []).length === 2,
    "non-durable checkpoint binder surface is not limited to private production plus test fixture",
  );
  invariant(!checkpoint.includes("into_authorized("), "durable checkpoint marker can be erased");
  invariant(
    /#\[derive\(Debug, Eq, PartialEq\)\]\s*#\[cfg_attr\(test, derive\(Clone\)\)\]\s*pub\(crate\) struct AuthorizedPocoCheckpointHeaderV0/.test(checkpoint),
    "raw checkpoint authorization is cloneable outside tests",
  );
  invariant(checkpoint.includes("pub(crate) struct AuthorizedPocoCheckpointHeaderV0"), "checkpoint capability visibility drift");
  invariant(!checkpoint.includes("pub struct AuthorizedPocoCheckpointHeaderV0"), "checkpoint capability became public");

  invariant(
    /#\[derive\(Debug\)\]\s*pub\(crate\) struct DurablyBoundPocoCheckpointHeaderV0\s*\{\s*authorized:\s*AuthorizedPocoCheckpointHeaderV0,\s*_reservation:\s*PocoPreparationReservationV0,\s*\}/s.test(checkpoint),
    "durably bound checkpoint wrapper shape drift",
  );
  const durableImpl = balancedDefinition(
    checkpoint,
    "impl DurablyBoundPocoCheckpointHeaderV0",
    "durably bound checkpoint impl",
  );
  const durableMethods = [...durableImpl.source.matchAll(/\bfn\s+([a-zA-Z0-9_]+)\s*\(/g)]
    .map((match) => match[1]);
  invariant(
    JSON.stringify(durableMethods) ===
      JSON.stringify(["authorized", "native_block_id", "authorization_id"]),
    "durably bound checkpoint method surface drift",
  );
  invariant(
    countLiteral(checkpoint, "DurablyBoundPocoCheckpointHeaderV0 {") === 3,
    "DurablyBoundPocoCheckpointHeaderV0 gained another declaration, impl, or construction point",
  );

  const reserve = lockFunctionContract(checkpoint, "reserve_prepared_poco_checkpoint_header_v0", [
    "journal: &PocoPreparationJournalV0",
    "prepared: PreparedPocoCheckpointHeaderV0",
  ], "Result<DurablyPreparedPocoCheckpointHeaderV0>", "durable checkpoint reserve");
  const reserveCall = "journal.reserve(&replay_record)?;";
  const preparedConstruction = "Ok(DurablyPreparedPocoCheckpointHeaderV0 {";
  const reserveCallIndex = reserve.body.indexOf(reserveCall);
  const preparedConstructionIndex = reserve.body.indexOf(preparedConstruction);
  invariant(
    countLiteral(reserve.body, reserveCall) === 1 &&
      reserveCallIndex < preparedConstructionIndex &&
      braceDepthBefore(reserve.body, reserveCallIndex, "durable checkpoint reserve call") === 0 &&
      braceDepthBefore(
        reserve.body,
        preparedConstructionIndex,
        "durable prepared checkpoint construction",
      ) === 0,
    "durable checkpoint preparation is constructed before successful journal.reserve",
  );

  const durableBind = lockFunctionContract(
    checkpoint,
    "bind_durably_prepared_poco_checkpoint_header_v0",
    [
      "journal: &PocoPreparationJournalV0",
      "durable: DurablyPreparedPocoCheckpointHeaderV0",
      "exact_header: &BlockHeader",
      "exact_body: &BlockBodyV0",
      "exact_receipts: &ExecutionReceiptsV0",
    ],
    "Result<DurablyBoundPocoCheckpointHeaderV0>",
    "durable checkpoint bind",
  );
  const journalBindCall = "journal.bind(&reservation, &bound_record)?;";
  const durableConstruction = "Ok(DurablyBoundPocoCheckpointHeaderV0 {";
  const journalBindCallIndex = durableBind.body.indexOf(journalBindCall);
  const durableConstructionIndex = durableBind.body.indexOf(durableConstruction);
  invariant(
    countLiteral(checkpoint, journalBindCall) === 1 &&
      countLiteral(checkpoint, durableConstruction) === 1,
    "durably bound checkpoint must have one journal.bind gate and one production construction",
  );
  invariant(
    journalBindCallIndex >= 0 &&
      journalBindCallIndex < durableConstructionIndex &&
      braceDepthBefore(
        durableBind.body,
        journalBindCallIndex,
        "durable checkpoint journal.bind",
      ) === 0 &&
      braceDepthBefore(
        durableBind.body,
        durableConstructionIndex,
        "durably bound checkpoint construction",
      ) === 0,
    "DurablyBoundPocoCheckpointHeaderV0 is constructed before journal.bind succeeds",
  );

  const authorize = functionSignature(joint, "authorize_poco_checkpoint_joint_handoff_v0", "joint source");
  lockConstructorParameters(authorize, [
    "checkpoint_header: DurablyBoundPocoCheckpointHeaderV0",
    "raw_checkpoint_parent_header_cev0: &[u8]",
    "raw_checkpoint_two_seal_finality_cev0: &[u8]",
    "raw_anchor_certificate_kernel_cev0: &[u8]",
  ], "joint raw consumer");
  invariant(
    !/pub\(crate\)\s+fn\s+authorize_poco_checkpoint_joint_handoff_v0\s*\(\s*checkpoint_header:\s*AuthorizedPocoCheckpointHeaderV0/.test(joint),
    "joint handoff accepts a non-durable checkpoint authorization",
  );
  invariant(
    !/pub\(crate\)\s+fn\s+authorize_poco_checkpoint_joint_handoff_from_authorized_v0\s*\(/.test(joint),
    "raw joint-handoff verification core is crate-visible",
  );
  invariant(
    /#\[cfg\(test\)\]\s*pub\(crate\)\s+fn\s+authorize_poco_checkpoint_joint_handoff_for_fixture_v0\s*\(/.test(joint),
    "fixture raw joint-handoff seam is not test-only",
  );
  invariant(!/verifier|timestamp|commitment|validator_set|parameters|root/i.test(authorize), "joint consumer accepts caller authority facts or verifier");
  invariant(joint.includes("decode_block_header_v0_exact"), "joint consumer lacks exact parent decode");
  invariant(joint.includes("decode_checkpoint_finality_proof_v0_exact"), "joint consumer lacks exact checkpoint finality decode");
  invariant(joint.includes("decode_epoch_anchor_authorization_kernel_v0_exact"), "joint consumer lacks exact handoff-kernel decode");
  invariant(joint.includes("&StrictEd25519Verifier"), "joint consumer lacks hard-coded strict verifier");
  invariant(joint.includes("trnm.poco-bft.authorized-checkpoint-joint-handoff.v0"), "private joint seal domain drift");
  invariant(joint.includes("pub(crate) struct AuthorizedPocoJointHandoffV0"), "joint capability visibility drift");
  invariant(!joint.includes("pub struct AuthorizedPocoJointHandoffV0"), "joint capability became public");
  invariant(!joint.includes("EpochAnchorQC"), "joint consumer emits EpochAnchorQC");
  invariant(nativeExecution.includes("pub(crate) struct AuthorizedNativeCheckpointExecutionV0"), "native execution authority missing");
  invariant(nativeExecution.includes("trnm.poco-bft.authorized-native-checkpoint-execution.v0"), "native execution seal domain drift");
  invariant(nativeExecution.includes("try_cev0_bytes"), "native execution authority does not bind exact CEV0");
  const authoritySources = `${checkpoint}\n${joint}`;
  invariant(
    !/\binto_authorized\s*\(/.test(authoritySources),
    "durable checkpoint authority gained an owned-marker erasure method",
  );
  const conversionImplHeaders = [
    ...authoritySources.matchAll(
      /\bimpl(?:\s*<[^{}]*>)?\s+(?:(?:std|core)::convert::)?(?:Try)?(?:From|Into)\s*<[^{}]*>\s+for\s+[^{}]+\{/g,
    ),
  ].map((match) => match[0]);
  for (const token of [
    "AuthorizedPocoCheckpointHeaderV0",
    "DurablyBoundPocoCheckpointHeaderV0",
  ]) {
    invariant(
      conversionImplHeaders.every((header) => !header.includes(token)),
      `${token}: From/TryFrom/Into/TryInto can erase or mint durable checkpoint authority`,
    );
  }
  for (const token of [
    "CheckpointTwoSealKernelV0",
    "JointHandoffKernelV0",
    "EpochAnchorAuthorizationKernelV0",
  ]) {
    invariant(
      !new RegExp(`impl\\s+(?:Try)?From<\\s*${token}`).test(authoritySources),
      `${token}: inert token gained From/TryFrom authority conversion`,
    );
  }
}

function rejectCometValues(value, label = "vector") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectCometValues(entry, `${label}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    const allowedNullMarker = label === "vector.compact_profile" && key === "comet_hash_mapping" && nested === null;
    invariant(allowedNullMarker || !/(?:comet|cometbft|request_hash|part_set)/i.test(key), `${label}.${key}: forbidden Comet hash/BlockID value field`);
    rejectCometValues(nested, `${label}.${key}`);
  }
}

const PROOF_KEYS = ["version", "root_hash_hex", "key_hex", "value_hex", "commitment_proof_hex"];

function validateMembershipProof(proof, cutoff, label) {
  exactKeys(proof, PROOF_KEYS, label);
  invariant(rustU64(proof.version, `${label}.version`) === PROFILE.cutoff_height, `${label}: version drift`);
  sameBuffer(exactHex(proof.root_hash_hex, 32, `${label}.root_hash_hex`), exactHex(cutoff.state_root_hex, 32, "cutoff.state_root_hex"), `${label}: root differs from cutoff state`);
  boundedHex(proof.key_hex, 1, 1 << 20, `${label}.key_hex`);
  boundedHex(proof.value_hex, 1, 8 << 20, `${label}.value_hex`);
  boundedHex(proof.commitment_proof_hex, 1, 8 << 20, `${label}.commitment_proof_hex`);
}

function validateCutoff(cutoff, label) {
  exactKeys(cutoff, [
    "height", "state_root_hex", "entries_root_hex", "entry_count",
    "scheduled_cutoff_authorization_id_hex", "cutoff_candidate_authorization_id_hex",
    "raw_cutoff_parent_header_cev0_hex", "raw_h1_finality_proof_cev0_hex", "h1_proof_id_hex", "raw_h2",
  ], label);
  invariant(rustU64(cutoff.height, `${label}.height`) === PROFILE.cutoff_height, `${label}: height drift`);
  exactHex(cutoff.state_root_hex, 32, `${label}.state_root_hex`);
  exactHex(cutoff.entries_root_hex, 32, `${label}.entries_root_hex`);
  const count = rustU32(cutoff.entry_count, `${label}.entry_count`);
  exactHex(cutoff.scheduled_cutoff_authorization_id_hex, 32, `${label}.scheduled_cutoff_authorization_id_hex`);
  exactHex(cutoff.cutoff_candidate_authorization_id_hex, 32, `${label}.cutoff_candidate_authorization_id_hex`);
  boundedHex(cutoff.raw_cutoff_parent_header_cev0_hex, 1, 1 << 20, `${label}.raw_cutoff_parent_header_cev0_hex`);
  boundedHex(cutoff.raw_h1_finality_proof_cev0_hex, 1, 16 << 20, `${label}.raw_h1_finality_proof_cev0_hex`);
  exactHex(cutoff.h1_proof_id_hex, 32, `${label}.h1_proof_id_hex`);
  exactKeys(cutoff.raw_h2, ["manifest_cev0_hex", "manifest_proof", "members", "absences"], `${label}.raw_h2`);
  boundedHex(cutoff.raw_h2.manifest_cev0_hex, 1, 1 << 20, `${label}.raw_h2.manifest_cev0_hex`);
  validateMembershipProof(cutoff.raw_h2.manifest_proof, cutoff, `${label}.raw_h2.manifest_proof`);
  invariant(Array.isArray(cutoff.raw_h2.members) && BigInt(cutoff.raw_h2.members.length) === count, `${label}: H2 member/count drift`);
  invariant(Array.isArray(cutoff.raw_h2.absences) && cutoff.raw_h2.absences.length === 0, `${label}: nonempty absence family is not authorized`);
  cutoff.raw_h2.members.forEach((member, index) => {
    const memberLabel = `${label}.raw_h2.members[${index}]`;
    exactKeys(member, ["kind", "logical_key_hex", "value_hex", "canonical_entry_cev0_hex", "proof"], memberLabel);
    rustU16(member.kind, `${memberLabel}.kind`);
    exactHex(member.logical_key_hex, 32, `${memberLabel}.logical_key_hex`);
    const value = boundedHex(member.value_hex, 1, 8 << 20, `${memberLabel}.value_hex`);
    boundedHex(member.canonical_entry_cev0_hex, 1, 8 << 20, `${memberLabel}.canonical_entry_cev0_hex`);
    validateMembershipProof(member.proof, cutoff, `${memberLabel}.proof`);
    sameBuffer(value, bytes(member.proof.value_hex, `${memberLabel}.proof.value_hex`), `${memberLabel}: proof value splice`);
    stats.h2MembersStructurallyBound += 1;
  });
}

function validatePreheader(preheader, label) {
  exactKeys(preheader, [
    "authorization_id_hex", "checkpoint_parent_header_cev0_hex", "checkpoint_parent_block_id_hex",
    "old_validator_set_cev0_hex", "old_parameters_cev0_hex", "new_validator_set_cev0_hex",
    "new_parameters_cev0_hex", "commitment_cev0_hex", "commitment_id_hex",
  ], label);
  exactHex(preheader.authorization_id_hex, 32, `${label}.authorization_id_hex`);
  boundedHex(preheader.checkpoint_parent_header_cev0_hex, 1, 1 << 20, `${label}.checkpoint_parent_header_cev0_hex`);
  exactHex(preheader.checkpoint_parent_block_id_hex, 32, `${label}.checkpoint_parent_block_id_hex`);
  for (const key of ["old_validator_set_cev0_hex", "new_validator_set_cev0_hex"]) boundedHex(preheader[key], 1, 16 << 20, `${label}.${key}`);
  for (const key of ["old_parameters_cev0_hex", "new_parameters_cev0_hex", "commitment_cev0_hex"]) boundedHex(preheader[key], 1, 1 << 20, `${label}.${key}`);
  exactHex(preheader.commitment_id_hex, 32, `${label}.commitment_id_hex`);
}

function validateCheckpoint(checkpoint, label) {
  exactKeys(checkpoint, [
    "native_execution_authorization_id_hex", "application_payload_cev0_hex", "execution_receipts_cev0_hex",
    "transaction_count", "receipt_count", "preparation_id_hex", "header_cev0_hex", "native_block_id_hex",
    "header_authorization_id_hex", "height", "view", "timestamp_ms", "payload_root_hex", "state_root_hex",
    "receipts_root_hex", "evidence_root_hex", "next_epoch_commitment_hash_hex",
  ], label);
  for (const key of [
    "native_execution_authorization_id_hex", "preparation_id_hex", "native_block_id_hex",
    "header_authorization_id_hex", "payload_root_hex", "state_root_hex", "receipts_root_hex",
    "evidence_root_hex", "next_epoch_commitment_hash_hex",
  ]) exactHex(checkpoint[key], 32, `${label}.${key}`);
  invariant(checkpoint.application_payload_cev0_hex === EMPTY_PAYLOAD_CEV0_HEX, `${label}: nonempty payload exceeds fixture claim`);
  invariant(checkpoint.execution_receipts_cev0_hex === EMPTY_RECEIPTS_CEV0_HEX, `${label}: nonempty receipts exceed fixture claim`);
  invariant(rustU32(checkpoint.transaction_count, `${label}.transaction_count`) === 0n, `${label}: transaction count must be zero`);
  invariant(rustU32(checkpoint.receipt_count, `${label}.receipt_count`) === 0n, `${label}: receipt count must be zero`);
  boundedHex(checkpoint.header_cev0_hex, 1, 1 << 20, `${label}.header_cev0_hex`);
  invariant(rustU64(checkpoint.height, `${label}.height`) === PROFILE.checkpoint_height, `${label}: height drift`);
  rustU64(checkpoint.view, `${label}.view`);
  rustU64(checkpoint.timestamp_ms, `${label}.timestamp_ms`);
  invariant(checkpoint.payload_root_hex === EMPTY_PAYLOAD_ROOT_HEX, `${label}: empty payload root drift`);
  invariant(checkpoint.receipts_root_hex === EMPTY_RECEIPTS_ROOT_HEX, `${label}: empty receipts root drift`);
  invariant(checkpoint.evidence_root_hex === EMPTY_EVIDENCE_ROOT_HEX, `${label}: empty evidence root drift`);
}

function validateCheckpointFinality(finality, label) {
  exactKeys(finality, [
    "raw_finality_proof_cev0_hex", "proof_id_hex", "checkpoint_block_id_hex",
    "seal_1_header_cev0_hex", "seal_1_block_id_hex", "seal_2_header_cev0_hex",
    "seal_2_block_id_hex", "terminal_qc_cev0_hex", "terminal_qc_id_hex",
  ], label);
  boundedHex(finality.raw_finality_proof_cev0_hex, 1, 32 << 20, `${label}.raw_finality_proof_cev0_hex`);
  for (const key of ["proof_id_hex", "checkpoint_block_id_hex", "seal_1_block_id_hex", "seal_2_block_id_hex", "terminal_qc_id_hex"]) exactHex(finality[key], 32, `${label}.${key}`);
  for (const key of ["seal_1_header_cev0_hex", "seal_2_header_cev0_hex", "terminal_qc_cev0_hex"]) boundedHex(finality[key], 1, 8 << 20, `${label}.${key}`);
}

function validateHandoff(handoff, label) {
  exactKeys(handoff, [
    "descriptor_cev0_hex", "descriptor_id_hex", "certificate_cev0_hex", "certificate_id_hex",
    "raw_anchor_certificate_kernel_cev0_hex", "old_signature_count", "new_signature_count",
  ], label);
  for (const key of ["descriptor_cev0_hex", "certificate_cev0_hex", "raw_anchor_certificate_kernel_cev0_hex"]) boundedHex(handoff[key], 1, 32 << 20, `${label}.${key}`);
  exactHex(handoff.descriptor_id_hex, 32, `${label}.descriptor_id_hex`);
  exactHex(handoff.certificate_id_hex, 32, `${label}.certificate_id_hex`);
  invariant(rustU32(handoff.old_signature_count, `${label}.old_signature_count`) === 4n, `${label}: old signature count drift`);
  invariant(rustU32(handoff.new_signature_count, `${label}.new_signature_count`) === 4n, `${label}: new signature count drift`);
}

const BOUND_KEYS = [
  "checkpoint_preparation_id_hex", "checkpoint_header_authorization_id_hex",
  "checkpoint_execution_authorization_id_hex", "commitment_authorization_id_hex",
  "scheduled_cutoff_authorization_id_hex", "checkpoint_finality_proof_id_hex",
  "handoff_certificate_id_hex", "joint_authorization_id_hex",
];

function validateBoundAuthority(bound, label) {
  exactKeys(bound, BOUND_KEYS, label);
  for (const key of BOUND_KEYS) exactHex(bound[key], 32, `${label}.${key}`);
}

function validateScenarioStructure(scenario, id, fallback, reason, label) {
  exactKeys(scenario, [
    "id", "fallback_used", "fallback_reason_code", "cutoff", "preheader", "checkpoint",
    "checkpoint_finality", "handoff", "bound_authority",
  ], label);
  invariant(scenario.id === id, `${label}: ID drift`);
  invariant(scenario.fallback_used === fallback, `${label}: fallback status drift`);
  invariant(rustU32(scenario.fallback_reason_code, `${label}.fallback_reason_code`) === BigInt(reason), `${label}: fallback reason drift`);
  validateCutoff(scenario.cutoff, `${label}.cutoff`);
  validatePreheader(scenario.preheader, `${label}.preheader`);
  validateCheckpoint(scenario.checkpoint, `${label}.checkpoint`);
  validateCheckpointFinality(scenario.checkpoint_finality, `${label}.checkpoint_finality`);
  validateHandoff(scenario.handoff, `${label}.handoff`);
  validateBoundAuthority(scenario.bound_authority, `${label}.bound_authority`);

  invariant(scenario.preheader.commitment_id_hex === scenario.checkpoint.next_epoch_commitment_hash_hex, `${label}: commitment/header splice`);
  invariant(scenario.checkpoint.native_block_id_hex === scenario.checkpoint_finality.checkpoint_block_id_hex, `${label}: checkpoint/finality ID splice`);
  invariant(scenario.checkpoint.preparation_id_hex === scenario.bound_authority.checkpoint_preparation_id_hex, `${label}: preparation/bound splice`);
  invariant(scenario.checkpoint.header_authorization_id_hex === scenario.bound_authority.checkpoint_header_authorization_id_hex, `${label}: header authorization splice`);
  invariant(scenario.checkpoint.native_execution_authorization_id_hex === scenario.bound_authority.checkpoint_execution_authorization_id_hex, `${label}: execution authorization splice`);
  invariant(scenario.preheader.authorization_id_hex === scenario.bound_authority.commitment_authorization_id_hex, `${label}: commitment authorization splice`);
  invariant(scenario.cutoff.scheduled_cutoff_authorization_id_hex === scenario.bound_authority.scheduled_cutoff_authorization_id_hex, `${label}: cutoff authorization splice`);
  invariant(scenario.checkpoint_finality.proof_id_hex === scenario.bound_authority.checkpoint_finality_proof_id_hex, `${label}: finality proof splice`);
  invariant(scenario.handoff.certificate_id_hex === scenario.bound_authority.handoff_certificate_id_hex, `${label}: handoff certificate splice`);
}

function validateVectorStructure(vector, candidateRaw, h3aRaw) {
  exactKeys(vector, [
    "schema", "schema_version", "fixture_scope", "candidate_vector_path", "candidate_vector_sha256_hex",
    "commitment_vector_path", "commitment_vector_sha256_hex", "compact_profile", "positive", "authenticated_fallback",
  ], "vector");
  invariant(vector.schema === FIXTURE_SCHEMA && rustU16(vector.schema_version, "vector.schema_version") === 0n, "vector identity/version");
  invariant(vector.fixture_scope === FIXTURE_SCOPE, "vector fixture scope drift");
  invariant(vector.candidate_vector_path === CANDIDATE_VECTOR_RELATIVE && vector.candidate_vector_sha256_hex === sha256(candidateRaw), "vector candidate source path/SHA drift");
  invariant(vector.commitment_vector_path === H3A_VECTOR_RELATIVE && vector.commitment_vector_sha256_hex === sha256(h3aRaw), "vector H3a source path/SHA drift");
  validateProfile(vector.compact_profile, "vector.compact_profile");
  rejectCometValues(vector);
  validateScenarioStructure(vector.positive, "authenticated_positive_checkpoint_handoff", false, 0, "vector.positive");
  validateScenarioStructure(vector.authenticated_fallback, "authenticated_fallback_checkpoint_handoff", true, 3, "vector.authenticated_fallback");
  invariant(vector.positive.bound_authority.joint_authorization_id_hex !== vector.authenticated_fallback.bound_authority.joint_authorization_id_hex, "positive/fallback joint authority splice");
}

function decodeScenarioRaw(scenario, label) {
  const oldParameters = decodeParameters(bytes(scenario.preheader.old_parameters_cev0_hex, `${label}.old_parameters`));
  const newParameters = decodeParameters(bytes(scenario.preheader.new_parameters_cev0_hex, `${label}.new_parameters`));
  const oldSet = decodeValidatorSet(bytes(scenario.preheader.old_validator_set_cev0_hex, `${label}.old_set`), oldParameters);
  const newSet = decodeValidatorSet(bytes(scenario.preheader.new_validator_set_cev0_hex, `${label}.new_set`), newParameters);
  const commitment = decodeCommitment(bytes(scenario.preheader.commitment_cev0_hex, `${label}.commitment`));
  const cutoffParent = decodeHeader(bytes(scenario.cutoff.raw_cutoff_parent_header_cev0_hex, `${label}.cutoff_parent`), oldParameters);
  const h1 = decodeFinality(bytes(scenario.cutoff.raw_h1_finality_proof_cev0_hex, `${label}.h1`), oldParameters);
  const checkpointParent = decodeHeader(bytes(scenario.preheader.checkpoint_parent_header_cev0_hex, `${label}.checkpoint_parent`), oldParameters);
  const checkpoint = decodeHeader(bytes(scenario.checkpoint.header_cev0_hex, `${label}.checkpoint`), oldParameters);
  const finality = decodeFinality(bytes(scenario.checkpoint_finality.raw_finality_proof_cev0_hex, `${label}.checkpoint_finality`), oldParameters);
  const seal1 = decodeHeader(bytes(scenario.checkpoint_finality.seal_1_header_cev0_hex, `${label}.seal1`), oldParameters);
  const seal2 = decodeHeader(bytes(scenario.checkpoint_finality.seal_2_header_cev0_hex, `${label}.seal2`), oldParameters);
  stats.rawRoundTrips += 11;
  return { oldParameters, newParameters, oldSet, newSet, commitment, cutoffParent, h1, checkpointParent, checkpoint, finality, seal1, seal2 };
}

function verifyFinalityChain(proof, set, parameters, parentHeader, commitmentId, expectedKinds, expectedHeights, label) {
  invariant(proof.genesis.equals(set.genesis) && proof.chain.equals(set.chain) && proof.protocol === set.protocol && proof.epoch === set.epoch, `${label}: outer context drift`);
  invariant(proof.setHash.equals(set.hash) && proof.parametersHash.equals(parameters.hash), `${label}: outer configuration drift`);
  const blocks = [proof.finalizedBlock, proof.child, proof.grandchild];
  blocks.forEach((certified, index) => {
    validateCertified(certified, set, parameters);
    stats.strictCertifiedHeaders += 1;
    invariant(certified.header.kind === expectedKinds[index] && certified.header.height === expectedHeights[index], `${label}[${index}]: kind/height drift`);
    if (commitmentId === null) invariant(certified.header.nextCommitment === null, `${label}[${index}]: unexpected commitment`);
    else sameBuffer(certified.header.nextCommitment, commitmentId, `${label}[${index}]: commitment drift`);
  });
  invariant(blocks[0].header.parentId.equals(parentHeader.id), `${label}: finalized parent ID drift`);
  invariant(blocks[1].header.parentId.equals(blocks[0].header.id), `${label}: child ancestry drift`);
  invariant(blocks[2].header.parentId.equals(blocks[1].header.id), `${label}: grandchild ancestry drift`);
  return blocks;
}

function recomputePrivateSeals(scenario, decoded, label) {
  const { checkpointParent, checkpoint, h1 } = decoded;
  const executionAuthorization = hashV1("trnm.poco-bft.authorized-native-checkpoint-execution.v0", [
    u(PROFILE.checkpoint_parent_height, 8),
    checkpointParent.stateRoot,
    u(PROFILE.checkpoint_height, 8),
    checkpoint.stateRoot,
    checkpoint.payloadRoot,
    checkpoint.receiptsRoot,
    bytes(scenario.checkpoint.application_payload_cev0_hex, `${label}.payload`),
    bytes(scenario.checkpoint.execution_receipts_cev0_hex, `${label}.receipts`),
  ]);
  sameBuffer(executionAuthorization, exactHex(scenario.checkpoint.native_execution_authorization_id_hex, 32, `${label}.execution_authorization`), `${label}: native execution authorization drift`);

  const preparation = hashV1("trnm.poco-bft.prepared-checkpoint-header.v0", [
    exactHex(scenario.preheader.authorization_id_hex, 32, `${label}.preheader_authorization`),
    executionAuthorization,
    h1.grandchild.raw,
    checkpoint.genesis,
    checkpoint.chain,
    u(checkpoint.protocol, 4),
    u(checkpoint.epoch, 8),
    u(checkpoint.view, 8),
    u(checkpoint.height, 8),
    checkpoint.parentId,
    checkpoint.proposerId,
    checkpoint.setHash,
    checkpoint.parametersHash,
    checkpoint.payloadRoot,
    checkpoint.stateRoot,
    checkpoint.receiptsRoot,
    checkpoint.evidenceRoot,
    u(checkpoint.timestamp, 8),
    checkpoint.nextCommitment,
    u(0, 4),
    u(0, 4),
  ]);
  sameBuffer(preparation, exactHex(scenario.checkpoint.preparation_id_hex, 32, `${label}.preparation_id`), `${label}: preparation ID drift`);

  const checkpointAuthorization = hashV1("trnm.poco-bft.authorized-checkpoint-header.v0", [
    preparation,
    checkpoint.raw,
    checkpoint.id,
  ]);
  sameBuffer(checkpointAuthorization, exactHex(scenario.checkpoint.header_authorization_id_hex, 32, `${label}.checkpoint_authorization`), `${label}: checkpoint authorization drift`);

  const jointAuthorization = hashV1("trnm.poco-bft.authorized-checkpoint-joint-handoff.v0", [
    executionAuthorization,
    preparation,
    checkpointAuthorization,
    exactHex(scenario.preheader.authorization_id_hex, 32, `${label}.preheader_authorization`),
    exactHex(scenario.cutoff.scheduled_cutoff_authorization_id_hex, 32, `${label}.cutoff_authorization`),
    checkpointParent.raw,
    checkpoint.raw,
    bytes(scenario.checkpoint_finality.raw_finality_proof_cev0_hex, `${label}.checkpoint_finality_raw`),
    decoded.oldSet.raw,
    decoded.oldParameters.raw,
    decoded.newSet.raw,
    decoded.newParameters.raw,
    decoded.commitment.raw,
    bytes(scenario.handoff.raw_anchor_certificate_kernel_cev0_hex, `${label}.anchor_kernel_raw`),
  ]);
  sameBuffer(jointAuthorization, exactHex(scenario.bound_authority.joint_authorization_id_hex, 32, `${label}.joint_authorization`), `${label}: joint authorization drift`);
  stats.privateSeals += 4;
}

function validateScenarioCrypto(scenario, label) {
  const decoded = decodeScenarioRaw(scenario, label);
  const { oldParameters, newParameters, oldSet, newSet, commitment, cutoffParent, h1, checkpointParent, checkpoint, finality, seal1, seal2 } = decoded;
  invariant(oldSet.epoch === PROFILE.old_epoch && newSet.epoch === PROFILE.new_epoch, `${label}: old/new epoch drift`);
  sameBuffer(oldSet.parametersHash, oldParameters.hash, `${label}: old parameter relation`);
  sameBuffer(newSet.parametersHash, newParameters.hash, `${label}: new parameter relation`);
  sameBuffer(commitment.id, exactHex(scenario.preheader.commitment_id_hex, 32, `${label}.commitment_id`), `${label}: commitment ID drift`);
  invariant(commitment.oldEpoch === PROFILE.old_epoch && commitment.newEpoch === PROFILE.new_epoch, `${label}: commitment epoch drift`);
  invariant(commitment.snapshotCutoffHeight === PROFILE.cutoff_height, `${label}: commitment cutoff drift`);
  sameBuffer(commitment.snapshotStateRoot, exactHex(scenario.cutoff.state_root_hex, 32, `${label}.cutoff_state_root`), `${label}: commitment cutoff state drift`);
  sameBuffer(commitment.newValidatorSetHash, newSet.hash, `${label}: commitment new-set drift`);
  sameBuffer(commitment.newParametersHash, newParameters.hash, `${label}: commitment new-parameters drift`);
  invariant(
    commitment.fallbackUsed === scenario.fallback_used &&
      BigInt(commitment.fallbackReason) === BigInt(scenario.fallback_reason_code),
    `${label}: commitment fallback drift`,
  );
  invariant(commitment.activationHeight === PROFILE.activation_height, `${label}: commitment activation context drift`);

  const h1Blocks = verifyFinalityChain(
    h1,
    oldSet,
    oldParameters,
    cutoffParent,
    null,
    [0, 0, 0],
    [25n, 26n, 27n],
    `${label}.h1`,
  );
  sameBuffer(h1.id, exactHex(scenario.cutoff.h1_proof_id_hex, 32, `${label}.h1_proof_id`), `${label}: H1 proof ID drift`);
  sameBuffer(h1Blocks[0].header.stateRoot, exactHex(scenario.cutoff.state_root_hex, 32, `${label}.cutoff_state_root`), `${label}: finalized cutoff state drift`);
  sameBuffer(h1Blocks[2].header.raw, checkpointParent.raw, `${label}: retained H1 checkpoint parent drift`);
  sameBuffer(checkpointParent.id, exactHex(scenario.preheader.checkpoint_parent_block_id_hex, 32, `${label}.parent_id`), `${label}: parent ID drift`);

  sameBuffer(checkpoint.id, exactHex(scenario.checkpoint.native_block_id_hex, 32, `${label}.checkpoint_id`), `${label}: checkpoint native ID drift`);
  invariant(checkpoint.kind === 1 && checkpoint.height === PROFILE.checkpoint_height, `${label}: checkpoint kind/height drift`);
  sameBuffer(checkpoint.parentId, checkpointParent.id, `${label}: checkpoint parent drift`);
  sameBuffer(checkpoint.payloadRoot, exactHex(scenario.checkpoint.payload_root_hex, 32, `${label}.payload_root`), `${label}: checkpoint payload root drift`);
  sameBuffer(checkpoint.stateRoot, exactHex(scenario.checkpoint.state_root_hex, 32, `${label}.state_root`), `${label}: checkpoint state root drift`);
  sameBuffer(checkpoint.receiptsRoot, exactHex(scenario.checkpoint.receipts_root_hex, 32, `${label}.receipts_root`), `${label}: checkpoint receipts root drift`);
  sameBuffer(checkpoint.evidenceRoot, exactHex(scenario.checkpoint.evidence_root_hex, 32, `${label}.evidence_root`), `${label}: checkpoint evidence root drift`);
  sameBuffer(checkpoint.nextCommitment, commitment.id, `${label}: checkpoint commitment drift`);

  const finalityBlocks = verifyFinalityChain(
    finality,
    oldSet,
    oldParameters,
    checkpointParent,
    commitment.id,
    [1, 2, 3],
    [28n, 29n, 30n],
    `${label}.checkpoint_finality`,
  );
  sameBuffer(finality.id, exactHex(scenario.checkpoint_finality.proof_id_hex, 32, `${label}.finality_id`), `${label}: checkpoint finality ID drift`);
  sameBuffer(finalityBlocks[0].header.raw, checkpoint.raw, `${label}: finalized checkpoint raw drift`);
  sameBuffer(finalityBlocks[1].header.raw, seal1.raw, `${label}: seal-1 raw drift`);
  sameBuffer(finalityBlocks[2].header.raw, seal2.raw, `${label}: seal-2 raw drift`);
  sameBuffer(seal1.id, exactHex(scenario.checkpoint_finality.seal_1_block_id_hex, 32, `${label}.seal1_id`), `${label}: seal-1 ID drift`);
  sameBuffer(seal2.id, exactHex(scenario.checkpoint_finality.seal_2_block_id_hex, 32, `${label}.seal2_id`), `${label}: seal-2 ID drift`);
  for (const [index, seal] of [seal1, seal2].entries()) {
    sameBuffer(seal.payloadRoot, exactHex(EMPTY_PAYLOAD_ROOT_HEX, 32, "empty payload root"), `${label}: seal-${index + 1} payload root drift`);
    sameBuffer(seal.receiptsRoot, exactHex(EMPTY_RECEIPTS_ROOT_HEX, 32, "empty receipts root"), `${label}: seal-${index + 1} receipts root drift`);
    sameBuffer(seal.evidenceRoot, exactHex(EMPTY_EVIDENCE_ROOT_HEX, 32, "empty evidence root"), `${label}: seal-${index + 1} evidence root drift`);
    sameBuffer(seal.stateRoot, checkpoint.stateRoot, `${label}: seal-${index + 1} state drift`);
  }
  sameBuffer(finalityBlocks[2].certifyingQc.raw, bytes(scenario.checkpoint_finality.terminal_qc_cev0_hex, `${label}.terminal_qc`), `${label}: terminal QC raw drift`);
  sameBuffer(finalityBlocks[2].certifyingQc.id, exactHex(scenario.checkpoint_finality.terminal_qc_id_hex, 32, `${label}.terminal_qc_id`), `${label}: terminal QC ID drift`);
  recomputePrivateSeals(scenario, decoded, label);
  stats.scenarios += 1;
  return decoded;
}

function verifyH3aPreheaderAuthority(scenario, sourceScenario, candidateVector, decoded, label) {
  const source = validateH3aScenario(sourceScenario, candidateVector, `${label}.h3a_source`);
  invariant(source.binding.fallbackUsed === scenario.fallback_used, `${label}: H3a fallback flag drift`);
  invariant(BigInt(source.binding.fallbackReason) === BigInt(scenario.fallback_reason_code), `${label}: H3a fallback reason drift`);

  sameBuffer(source.h1.parentRaw, bytes(scenario.cutoff.raw_cutoff_parent_header_cev0_hex, `${label}.cutoff_parent`), `${label}: H3a cutoff-parent splice`);
  sameBuffer(source.h1.proofRaw, bytes(scenario.cutoff.raw_h1_finality_proof_cev0_hex, `${label}.h1`), `${label}: H3a H1 splice`);
  sameBuffer(source.h1.proof.id, exactHex(scenario.cutoff.h1_proof_id_hex, 32, `${label}.h1_id`), `${label}: H3a H1 ID splice`);
  invariant(equivalentEvidence(sourceScenario.h2, scenario.cutoff.raw_h2), `${label}: H3a H2 transport splice`);
  sameBuffer(source.h2.root, exactHex(scenario.cutoff.state_root_hex, 32, `${label}.cutoff_root`), `${label}: H3a H2 cutoff root drift`);
  sameBuffer(source.h2.manifest.entriesRoot, exactHex(scenario.cutoff.entries_root_hex, 32, `${label}.entries_root`), `${label}: H3a H2 entries root drift`);
  invariant(source.h2.manifest.count === Number(rustU32(scenario.cutoff.entry_count, `${label}.entry_count`)), `${label}: H3a H2 entry count drift`);
  invariant(source.h2.absenceCount === 0, `${label}: H3a nonempty absence family`);

  sameBuffer(source.binding.oldSetRaw, decoded.oldSet.raw, `${label}: H3a old-set splice`);
  sameBuffer(source.binding.oldParametersRaw, decoded.oldParameters.raw, `${label}: H3a old-parameters splice`);
  sameBuffer(source.binding.newSetRaw, decoded.newSet.raw, `${label}: H3a new-set splice`);
  sameBuffer(source.binding.newParametersRaw, decoded.newParameters.raw, `${label}: H3a new-parameters splice`);
  sameBuffer(source.commitment.commitmentRaw, decoded.commitment.raw, `${label}: H3a commitment splice`);
  sameBuffer(source.h1.grandchild.header.raw, decoded.checkpointParent.raw, `${label}: H3a retained checkpoint-parent splice`);

  const chain = decoded.oldSet.chain;
  const scheduledCanonical = Buffer.concat([
    u(0, 2),
    decoded.oldSet.genesis,
    u(chain.length, 2),
    chain,
    decoded.oldParameters.hash,
    u(decoded.oldSet.protocol, 4),
    u(decoded.oldSet.epoch, 8),
    u(PROFILE.checkpoint_height, 8),
    u(PROFILE.cutoff_height, 8),
    exactHex(scenario.cutoff.state_root_hex, 32, `${label}.scheduled_cutoff_root`),
    exactHex(scenario.cutoff.entries_root_hex, 32, `${label}.scheduled_entries_root`),
    u(scenario.cutoff.entry_count, 4),
    decoded.oldSet.hash,
    decoded.oldParameters.hash,
  ]);
  const scheduledAuthorization = hashV1(
    "trnm.poco-bft.scheduled-cutoff-authorization.v0",
    [scheduledCanonical],
  );
  sameBuffer(
    scheduledAuthorization,
    exactHex(scenario.cutoff.scheduled_cutoff_authorization_id_hex, 32, `${label}.scheduled_cutoff_authorization`),
    `${label}: scheduled-cutoff authorization drift`,
  );

  const transcriptDigest = hashV1(
    "trnm.poco-bft.authenticated-candidate-transcript.v0",
    [source.candidate.transcriptRaw],
  );
  const resultDigest = hashV1(
    "trnm.poco-bft.authenticated-candidate-result.v0",
    [source.candidate.resultRaw],
  );
  const cutoffCandidateAuthorization = hashV1(
    "trnm.poco-bft.authenticated-cutoff-candidate-authorization.v0",
    [
      scheduledAuthorization,
      transcriptDigest,
      source.candidate.reconstructed.candidateParametersHash,
      resultDigest,
    ],
  );
  sameBuffer(
    cutoffCandidateAuthorization,
    exactHex(scenario.cutoff.cutoff_candidate_authorization_id_hex, 32, `${label}.cutoff_candidate_authorization`),
    `${label}: cutoff-only candidate authorization drift`,
  );

  const preheaderAuthorization = hashV1(
    "trnm.poco-bft.authorized-preheader-next-epoch-commitment.v0",
    [
      cutoffCandidateAuthorization,
      source.candidate.reconstructed.candidateParametersHash,
      source.h1.parentRaw,
      source.h1.proof.id,
      source.h1.finalized.header.id,
      source.h1.finalized.header.stateRoot,
      source.h2.manifest.entriesRoot,
      u(source.h2.manifest.count, 4),
      u(source.h2.absenceCount, 4),
      source.binding.oldSetRaw,
      source.binding.oldParametersRaw,
      source.binding.newSetRaw,
      source.binding.newParametersRaw,
      source.commitment.commitmentRaw,
    ],
  );
  sameBuffer(
    preheaderAuthorization,
    exactHex(scenario.preheader.authorization_id_hex, 32, `${label}.preheader_authorization`),
    `${label}: pre-header commitment authorization drift`,
  );
  stats.h2MembershipsVerified += sourceScenario.h2.members.length + 1;
  stats.privateSeals += 3;
}

function verifyB2fJointHandoff(scenario, decoded, label) {
  const bundle = {
    schema_version: 0,
    genesis_hash_hex: decoded.commitment.genesis.toString("hex"),
    chain_id: decoded.commitment.chain.toString("ascii"),
    old_consensus_parameters_cev0_hex: decoded.oldParameters.raw.toString("hex"),
    new_consensus_parameters_cev0_hex: decoded.newParameters.raw.toString("hex"),
    old_validator_set_cev0_hex: decoded.oldSet.raw.toString("hex"),
    new_validator_set_cev0_hex: decoded.newSet.raw.toString("hex"),
    next_epoch_commitment_cev0_hex: decoded.commitment.raw.toString("hex"),
    old_checkpoint_finality_cev0_hex: scenario.checkpoint_finality.raw_finality_proof_cev0_hex,
    epoch_anchor_authorization_kernel_cev0_hex: scenario.handoff.raw_anchor_certificate_kernel_cev0_hex,
    decode_authenticated_checkpoint_parent_timestamp_ms: decoded.checkpointParent.timestamp.toString(),
    composition_authenticated_checkpoint_parent_timestamp_ms: decoded.checkpointParent.timestamp.toString(),
    aggregate_digest_domain: null,
  };
  const facts = verifyBundle(bundle);
  invariant(facts.checkpoint_finality_proof_id_hex === scenario.checkpoint_finality.proof_id_hex, `${label}: B2-F finality proof ID drift`);
  invariant(facts.next_epoch_commitment_digest_hex === scenario.preheader.commitment_id_hex, `${label}: B2-F commitment ID drift`);
  invariant(facts.handoff_descriptor_digest_hex === scenario.handoff.descriptor_id_hex, `${label}: B2-F descriptor ID drift`);
  invariant(facts.handoff_certificate_digest_hex === scenario.handoff.certificate_id_hex, `${label}: B2-F certificate ID drift`);
  invariant(facts.old_epoch === PROFILE.old_epoch.toString() && facts.new_epoch === PROFILE.new_epoch.toString(), `${label}: B2-F epoch drift`);
  invariant(facts.old_validator_set_hash_hex === decoded.oldSet.hash.toString("hex"), `${label}: B2-F old-set drift`);
  invariant(facts.new_validator_set_hash_hex === decoded.newSet.hash.toString("hex"), `${label}: B2-F new-set drift`);
  invariant(facts.old_consensus_parameters_hash_hex === decoded.oldParameters.hash.toString("hex"), `${label}: B2-F old-parameters drift`);
  invariant(facts.new_consensus_parameters_hash_hex === decoded.newParameters.hash.toString("hex"), `${label}: B2-F new-parameters drift`);
  invariant(facts.checkpoint_height === PROFILE.checkpoint_height.toString(), `${label}: B2-F checkpoint height drift`);
  invariant(facts.checkpoint_block_id_hex === scenario.checkpoint.native_block_id_hex, `${label}: B2-F checkpoint ID drift`);
  invariant(facts.checkpoint_state_root_hex === scenario.checkpoint.state_root_hex, `${label}: B2-F checkpoint state drift`);
  invariant(facts.terminal_old_height === PROFILE.seal_2_height.toString(), `${label}: B2-F terminal height drift`);
  invariant(facts.terminal_old_block_id_hex === scenario.checkpoint_finality.seal_2_block_id_hex, `${label}: B2-F terminal block drift`);
  invariant(facts.terminal_old_qc_digest_hex === scenario.checkpoint_finality.terminal_qc_id_hex, `${label}: B2-F terminal QC drift`);
  invariant(facts.activation_height === PROFILE.activation_height.toString(), `${label}: B2-F activation context drift`);
  invariant(facts.epoch_anchor_qc_output === false && facts.aggregate_digest === null, `${label}: B2-F unauthorized output`);

  const authorization = parseAuthorization(
    bytes(scenario.handoff.raw_anchor_certificate_kernel_cev0_hex, `${label}.anchor_kernel`),
    decoded.oldSet,
    decoded.newSet,
  );
  sameBuffer(authorization.certificate.descriptor.raw, bytes(scenario.handoff.descriptor_cev0_hex, `${label}.descriptor`), `${label}: descriptor raw splice`);
  sameBuffer(authorization.certificate.raw, bytes(scenario.handoff.certificate_cev0_hex, `${label}.certificate`), `${label}: certificate raw splice`);
  sameBuffer(authorization.certificate.descriptor.id, exactHex(scenario.handoff.descriptor_id_hex, 32, `${label}.descriptor_id`), `${label}: descriptor ID splice`);
  sameBuffer(authorization.certificate.id, exactHex(scenario.handoff.certificate_id_hex, 32, `${label}.certificate_id`), `${label}: certificate ID splice`);
  invariant(authorization.certificate.oldSignatures.length === Number(rustU32(scenario.handoff.old_signature_count, `${label}.old_signature_count`)), `${label}: old signature count drift`);
  invariant(authorization.certificate.newSignatures.length === Number(rustU32(scenario.handoff.new_signature_count, `${label}.new_signature_count`)), `${label}: new signature count drift`);
  sameBuffer(authorization.terminalHeader.raw, decoded.finality.grandchild.header.raw, `${label}: exact terminal header substitution`);
  sameBuffer(authorization.terminalQc.raw, decoded.finality.grandchild.certifyingQc.raw, `${label}: exact terminal QC substitution`);
  stats.b2fBundles += 1;
  stats.handoffSignaturesVerified += authorization.certificate.oldSignatures.length + authorization.certificate.newSignatures.length;
}

function expectNamedNegative(id, operation, expectedMessage = null) {
  invariant(NEGATIVE_CASE_IDS.includes(id), `${id}: negative is not in the locked campaign`);
  invariant(!observedNegativeCaseIds.has(id), `${id}: duplicate named negative`);
  const snapshot = { ...stats };
  let rejection = null;
  try {
    operation();
  } catch (error) {
    rejection = error;
  } finally {
    for (const [key, value] of Object.entries(snapshot)) stats[key] = value;
  }
  invariant(rejection !== null, `${id}: negative was accepted`);
  if (expectedMessage !== null) {
    invariant(
      expectedMessage.test(String(rejection.message)),
      `${id}: rejected for the wrong reason: ${rejection.message}`,
    );
  }
  observedNegativeCaseIds.add(id);
  stats.negatives += 1;
}

function wholeChainRawEvidenceSplice(checkpointScenario, foreignEvidenceScenario) {
  return {
    preheader: checkpointScenario.preheader,
    checkpoint: checkpointScenario.checkpoint,
    checkpoint_finality: foreignEvidenceScenario.checkpoint_finality,
    handoff: foreignEvidenceScenario.handoff,
  };
}

function flipFirstByte(value, label) {
  const raw = exactHex(value, 32, label);
  raw[0] ^= 1;
  return raw.toString("hex");
}

function nativeExecutionAuthorizationForState(scenario, stateRootHex, label) {
  const stateRoot = exactHex(stateRootHex, 32, `${label}.state_root`);
  return hashV1("trnm.poco-bft.authorized-native-checkpoint-execution.v0", [
    u(PROFILE.checkpoint_parent_height, 8),
    stateRoot,
    u(PROFILE.checkpoint_height, 8),
    stateRoot,
    exactHex(scenario.checkpoint.payload_root_hex, 32, `${label}.payload_root`),
    exactHex(scenario.checkpoint.receipts_root_hex, 32, `${label}.receipts_root`),
    bytes(scenario.checkpoint.application_payload_cev0_hex, `${label}.payload`),
    bytes(scenario.checkpoint.execution_receipts_cev0_hex, `${label}.receipts`),
  ]).toString("hex");
}

function runNegativeSelfChecks(vector, positive, fallback) {
  // Both source scenarios have already completed H3a, B2-E, B2-F and private
  // seal verification. These two joins therefore splice whole, independently
  // valid raw finality+handoff objects; no proof, certificate or signature ID
  // is edited or left stale.
  expectNamedNegative(
    "whole_chain_positive_checkpoint_fallback_raw",
    () => verifyB2fJointHandoff(
      wholeChainRawEvidenceSplice(vector.positive, vector.authenticated_fallback),
      positive,
      "negative.whole_chain_positive_checkpoint_fallback_raw",
    ),
  );
  expectNamedNegative(
    "whole_chain_fallback_checkpoint_positive_raw",
    () => verifyB2fJointHandoff(
      wholeChainRawEvidenceSplice(vector.authenticated_fallback, vector.positive),
      fallback,
      "negative.whole_chain_fallback_checkpoint_positive_raw",
    ),
  );

  // The two compact profiles deliberately share one empty height-27 -> 28
  // execution and therefore have identical execution IDs. Derive a complete
  // foreign authorization preimage from the fallback scenario's independently
  // authenticated cutoff state instead of manufacturing an ID bitflip. Both
  // duplicated claims are replaced, so the structural relation stays intact;
  // the positive execution bytes/roots must still reject the foreign seal.
  const foreignExecutionAuthority = structuredClone(vector.positive);
  const foreignExecutionAuthorizationId = nativeExecutionAuthorizationForState(
    vector.positive,
    vector.authenticated_fallback.cutoff.state_root_hex,
    "negative.native_execution_authorization_cross_scenario",
  );
  invariant(
    foreignExecutionAuthorizationId !== vector.positive.checkpoint.native_execution_authorization_id_hex,
    "foreign execution authority unexpectedly equals the positive checkpoint execution authority",
  );
  foreignExecutionAuthority.checkpoint.native_execution_authorization_id_hex =
    foreignExecutionAuthorizationId;
  foreignExecutionAuthority.bound_authority.checkpoint_execution_authorization_id_hex =
    foreignExecutionAuthorizationId;
  expectNamedNegative(
    "native_execution_authorization_cross_scenario",
    () => validateScenarioCrypto(
      foreignExecutionAuthority,
      "negative.native_execution_authorization_cross_scenario",
    ),
    /native execution authorization drift/,
  );

  const flippedJointSeal = structuredClone(vector.positive);
  flippedJointSeal.bound_authority.joint_authorization_id_hex = flipFirstByte(
    flippedJointSeal.bound_authority.joint_authorization_id_hex,
    "negative.joint_private_seal_bitflip",
  );
  expectNamedNegative(
    "joint_private_seal_bitflip",
    () => validateScenarioCrypto(flippedJointSeal, "negative.joint_private_seal_bitflip"),
    /joint authorization drift/,
  );

  const foreignJointSeal = structuredClone(vector.positive);
  foreignJointSeal.bound_authority.joint_authorization_id_hex =
    vector.authenticated_fallback.bound_authority.joint_authorization_id_hex;
  expectNamedNegative(
    "joint_private_seal_cross_scenario",
    () => validateScenarioCrypto(foreignJointSeal, "negative.joint_private_seal_cross_scenario"),
    /joint authorization drift/,
  );

  expectNamedNegative(
    "recursive_comet_field_injection",
    () => rejectCometValues({
      checkpoint: {
        host_transport: {
          comet_block_id_hex: "00".repeat(32),
        },
      },
    }, "negative.recursive_comet_field_injection"),
    /forbidden Comet hash\/BlockID value field/,
  );

  invariant(
    JSON.stringify([...observedNegativeCaseIds]) === JSON.stringify(NEGATIVE_CASE_IDS),
    "named negative campaign order or coverage drift",
  );
}

function main() {
  const lossless = runLosslessNumberSelfTests();
  const candidateRaw = fs.readFileSync(CANDIDATE_VECTOR_PATH);
  const h3aRaw = fs.readFileSync(H3A_VECTOR_PATH);
  const candidateVector = parseLosslessUnsignedJson(candidateRaw, "authenticated candidate source vector");
  const h3aVector = parseLosslessUnsignedJson(h3aRaw, "authenticated H3a source vector");
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  validateSchema(schema, candidateRaw, h3aRaw);
  validatePrivateSourceSurface();

  if (process.argv.includes("--scaffold-only")) {
    process.stdout.write(`authenticated checkpoint-handoff scaffold ok (non-authoritative): schema/source/API locked, lossless_u64=${lossless}\n`);
    return;
  }
  invariant(fs.existsSync(VECTOR_PATH), `dedicated checkpoint-28 vector is absent at ${VECTOR_PATH}`);
  const vector = parseLosslessUnsignedJson(fs.readFileSync(VECTOR_PATH), "authenticated checkpoint-handoff vector");
  validateVectorStructure(vector, candidateRaw, h3aRaw);
  const positive = validateScenarioCrypto(vector.positive, "positive");
  const fallback = validateScenarioCrypto(vector.authenticated_fallback, "authenticated_fallback");

  if (process.argv.includes("--structural-only")) {
    process.stdout.write(
      `authenticated checkpoint-handoff structural/partial-crypto scaffold ok (non-authoritative): scenarios=${stats.scenarios}, raw_round_trips=${stats.rawRoundTrips}, strict_certified_headers=${stats.strictCertifiedHeaders}, private_seals=${stats.privateSeals}, h2_members_structurally_bound=${stats.h2MembersStructurallyBound}, lossless_u64=${lossless}\n`,
    );
    return;
  }
  verifyH3aPreheaderAuthority(
    vector.positive,
    h3aVector.positive,
    candidateVector,
    positive,
    "positive",
  );
  verifyH3aPreheaderAuthority(
    vector.authenticated_fallback,
    h3aVector.authenticated_fallback,
    candidateVector,
    fallback,
    "authenticated_fallback",
  );
  verifyB2fJointHandoff(vector.positive, positive, "positive");
  verifyB2fJointHandoff(vector.authenticated_fallback, fallback, "authenticated_fallback");
  runNegativeSelfChecks(vector, positive, fallback);
  process.stdout.write(
    `authenticated checkpoint-handoff gate ok: scenarios=${stats.scenarios}, raw_round_trips=${stats.rawRoundTrips}, strict_certified_headers=${stats.strictCertifiedHeaders}, private_seals=${stats.privateSeals}, h2_memberships=${stats.h2MembershipsVerified}, b2f_bundles=${stats.b2fBundles}, handoff_signatures=${stats.handoffSignaturesVerified}, negatives=${stats.negatives}, lossless_u64=${lossless}\n`,
  );
}

try {
  main();
} catch (error) {
  throw error;
}
