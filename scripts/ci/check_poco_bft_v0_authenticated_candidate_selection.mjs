#!/usr/bin/env node

/*
 * Independent B2-H3b2b2 evidence consumer.
 *
 * This checker deliberately starts at the retained physical history and the
 * raw namespace-8 cutoff projection.  It independently recomputes every
 * jmt 0.12.0 SHA-256 root and enumerates the complete physical PoCO namespace
 * at both cutoff and head.  It does not consume a Rust-normalized candidate
 * transcript, contribution list, eligibility bit, B2-G token, or verifier
 * choice.  The only signature verifier used below is Node's strict Ed25519
 * implementation over the exact PoP signing root.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  POP_DOMAIN,
  computeCase,
  decodePopExact,
  digest,
  fallbackName,
  fromHex,
  hex,
  publicKeyObject,
  uint,
} from "./check_poco_bft_v0_snapshot_candidate_schema.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCHEMA_PATH = path.join(
  ROOT,
  "docs/protocol/poco-bft-v0/schema/poco-authenticated-candidate-selection-v0.json",
);
const VECTOR_PATH = process.env.TRNM_POCO_AUTHENTICATED_CANDIDATE_VECTOR ?? path.join(
  ROOT,
  "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json",
);

const FIXTURE_SCHEMA = "trnm.poco-bft.authenticated-candidate-selection-fixture.v0";
const AUTHORITY_SCHEMA = "trnm_poco_application_authority_v0";
const AUTHORITY_IDENTITY = Buffer.from("trnm.poco.application-authority.v0", "ascii");
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const HASH_V1_PREFIX = Buffer.from("trnm.domain.hash.v1", "ascii");
const ENTRY_DOMAIN = "trnm.poco-bft.snapshot-entry.v0";
const ENTRY_NODE_DOMAIN = "trnm.poco-bft.snapshot-node.v0";
const ENTRY_ROOT_DOMAIN = "trnm.poco-bft.snapshot-root.v0";
const SEMANTIC_IDENTITY_DOMAIN = "trnm.poco-bft.snapshot-value-identity.v0";
const PARAMETERS_DOMAIN = "trnm.poco-bft.parameters.v0";
const VALIDATOR_SET_DOMAIN = "trnm.poco-bft.validator-set.v0";
const CERTIFICATE_DOMAIN = "trnm.poco.consumption-certificate.v0";
const CERTIFICATE_ID_DOMAIN = "trnm.poco.consumption-certificate-id.v0";
const REGISTRATION_POP_DIGEST_DOMAIN = "trnm.poco-bft.validator-registration-pop.v0";
const FUTURE_POP_DIGEST_DOMAIN = "trnm.poco-bft.future-candidate-pop.v0";
const REGISTRATION_HISTORY_DOMAIN = "trnm.poco-bft.registration-history.v0";
const CHECKPOINT_DOMAIN = "trnm.poco-bft.checkpoint-execution-id.v0";
const TRANSCRIPT_DOMAIN = "trnm.poco-bft.authenticated-candidate-transcript.v0";
const RESULT_DOMAIN = "trnm.poco-bft.authenticated-candidate-result.v0";
const AUTHORIZATION_DOMAIN = "trnm.poco-bft.authenticated-candidate-authorization.v0";
const AUTHENTICATED_KEY_DOMAIN = Buffer.from("trnm/authenticated-state/v4", "ascii");
const POCO_PHYSICAL_KEY_PREFIX = Buffer.concat([AUTHENTICATED_KEY_DOMAIN, Buffer.from([0, 8])]);
const JMT_PLACEHOLDER_HASH = Buffer.from("SPARSE_MERKLE_PLACEHOLDER_HASH__", "ascii");
const JMT_LEAF_DOMAIN = Buffer.from("JMT::LeafNode", "ascii");
// `Intrnal` is the consensus-frozen spelling in jmt 0.12.0.
const JMT_INTERNAL_DOMAIN = Buffer.from("JMT::IntrnalNode", "ascii");
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U128 = (1n << 128n) - 1n;
const ED25519_FIELD_MODULUS = (1n << 255n) - 19n;
const ED25519_SCALAR_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_SQRT_M1 = ed25519Pow(2n, (ED25519_FIELD_MODULUS - 1n) / 4n);
const ED25519_D = ed25519Mod(-121665n * ed25519Pow(121666n, ED25519_FIELD_MODULUS - 2n));
const ED25519_SMALL_ORDER_PUBLIC_KEY = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
const ED25519_BASEPOINT_COMPRESSED = Buffer.concat([Buffer.from([0x58]), Buffer.alloc(31, 0x66)]);
const ED25519_NONCANONICAL_R = littleEndianBytes(ED25519_FIELD_MODULUS, 32);
const FIXTURE_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const FUTURE_FIXTURE_KEY_PREFIX = Buffer.from("trnm.poco-bft.checkpoint-finality.private-fixture.v0:future-", "ascii");

// These are the exact serde field orders of every record nested below the
// kind-16 application-authority value.  JSON object order is consensus
// relevant here because Rust decodes with deny_unknown_fields and requires an
// exact byte-for-byte canonical re-encode before the value gains authority.
const AUTHORITY_NESTED_FIELD_ORDER = {
  consumer_keys: [
    "consumer_id_hex", "consumer_key_id_hex", "public_key_hex", "active_from_height",
    "authorization_decision_id_hex", "revoked_at_height", "revocation_decision_id_hex",
    "nonce_watermarks",
  ],
  consumer_nonce_watermarks: ["provider_id_hex", "max_accepted_nonce", "logical_key_hex"],
  meter_policies: [
    "meter_id_hex", "meter_version", "task_id_hex", "output_commitment_hex", "unit_scale",
    "evidence_policy", "per_certificate_cap", "rolling_cap", "rolling_epoch_span",
    "retention_blocks", "active_from_height", "retired_at_height",
  ],
  meter_usage: ["meter_id_hex", "meter_version", "window_epoch", "consumed_units"],
  consumer_provider_usage: ["consumer_id_hex", "provider_id_hex", "window_epoch", "consumed_units"],
  task_provider_usage: ["task_id_hex", "provider_id_hex", "window_epoch", "consumed_units"],
  provider_usage: ["provider_id_hex", "window_epoch", "consumed_units"],
  funded_unused_reservations: [
    "certificate_id_hex", "settlement_commitment_hex", "funding_decision_id_hex",
    "finalized_height", "reserved_units",
  ],
  active_certificates: [
    "certificate_id_hex", "consumer_id_hex", "consumer_key_id_hex", "provider_id_hex",
    "task_id_hex", "meter_id_hex", "meter_version", "settlement_commitment_hex",
    "settlement_finalized_height", "consumed_units", "evidence_root_hex",
    "relationship_class", "relationship_key_hex", "provider_consensus_key_hex",
    "provider_registration_nonce", "provider_proof_digest_hex",
    "provider_registration_decision_id_hex", "provider_registration_height",
    "provider_registration_history_head_hex", "acceptance_decision_id_hex",
    "funding_decision_id_hex", "meter_decision_id_hex", "evidence_decision_id_hex",
    "accepted_height", "finalized_epoch", "tuple_key_hex", "prunable_after_height",
    "lifecycle", "lifecycle_effective_height", "lifecycle_decision_id_hex", "semantic_keys",
  ],
  semantic_keys: ["kind", "logical_key_hex"],
  pending_challenges: [
    "challenge_id_hex", "certificate_id_hex", "opening_decision_id_hex", "opened_height",
  ],
  pending_governance_proposals: [
    "target_epoch", "proposal_decision_id_hex", "proposed_height", "phase",
    "parameters_hash_hex", "activation_height",
  ],
  finalized_governance_approvals: [
    "target_epoch", "phase", "proposal_decision_id_hex", "proposed_height", "decision_id_hex",
    "approval_height", "parameters_hash_hex", "activation_height",
  ],
  validator_registration_history: [
    "validator_id_hex", "history_head_hex", "max_registration_nonce", "consensus_key_hex",
    "current_proof_digest_hex", "previous_history_head_hex", "registration_decision_id_hex",
    "registration_height", "retired_key_count", "revoked_at_height",
    "revocation_decision_id_hex",
  ],
  future_candidate_registrations: [
    "validator_id_hex", "target_epoch", "consensus_key_hex", "registration_nonce",
    "previous_registration_nonce", "predecessor_history_head_hex", "proof_cev0_hex",
    "proof_digest_hex", "registration_decision_id_hex", "registration_height",
  ],
};

const AUTHORITY_HARD_CAPS = {
  consumer_keys: 4,
  nonce_watermarks_per_consumer_key: 8,
  total_nonce_watermarks: 8,
  meter_policies: 4,
  total_usage_buckets: 32,
  funded_unused_reservations: 4,
  active_certificates: 4,
  pending_challenges: 2,
  pending_governance_proposals: 2,
  finalized_governance_approvals: 2,
  validator_registration_history: 4,
  future_candidate_registrations: 4,
  total_authority_records_including_nonce_watermarks: 70,
};

const stats = {
  histories: 0,
  jmtRoots: 0,
  projections: 0,
  semanticEntries: 0,
  certificates: 0,
  candidates: 0,
  contributions: 0,
  popSignatures: 0,
  scenarios: 0,
  rejections: 0,
  boundaryControls: 0,
};

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sameJson(actual, expected, message) {
  invariant(canonicalJsonStringify(actual) === canonicalJsonStringify(expected), message);
}

// Rust's canonical kind-16 JSON admits every u64.  JSON.parse would round an
// unquoted integer above 2^53 - 1 before the byte-identical canonical check,
// so this narrow JSON parser preserves unsafe integers as BigInts and rejects
// every non-integer/noncanonical number spelling.
function parseLosslessUnsignedJson(input, label) {
  const text = Buffer.isBuffer(input) ? input.toString("utf8") : input;
  invariant(typeof text === "string", `${label}: JSON text required`);
  if (Buffer.isBuffer(input)) {
    invariant(Buffer.from(text, "utf8").equals(input), `${label}: invalid UTF-8`);
  }
  let offset = 0;
  const fail = (message) => {
    throw new Error(`${label}: ${message} at byte ${Buffer.byteLength(text.slice(0, offset), "utf8")}`);
  };
  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/.test(text[offset])) {
      offset += 1;
    }
  };
  const parseString = () => {
    if (text[offset] !== '"') fail("string required");
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        const token = text.slice(start, offset);
        try {
          const decoded = JSON.parse(token);
          if (typeof decoded !== "string") fail("invalid string");
          return decoded;
        } catch {
          fail("invalid string");
        }
      }
      if (character === "\\") {
        offset += 1;
        if (offset >= text.length) fail("truncated string escape");
        if (text[offset] === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(offset + 1, offset + 5))) {
            fail("invalid Unicode escape");
          }
          offset += 5;
        } else {
          offset += 1;
        }
        continue;
      }
      if (character.charCodeAt(0) < 0x20) fail("unescaped control character");
      offset += 1;
    }
    fail("unterminated string");
  };
  const parseUnsignedInteger = () => {
    const start = offset;
    while (
      offset < text.length &&
      !/[\u0009\u000a\u000d\u0020,\]}]/.test(text[offset])
    ) {
      offset += 1;
    }
    const token = text.slice(start, offset);
    if (!/^(0|[1-9][0-9]*)$/.test(token)) {
      fail("canonical unsigned integer required; floats, exponents, signs, and leading zeros are forbidden");
    }
    const decoded = BigInt(token);
    if (decoded > MAX_U64) fail("u64 overflow");
    return decoded <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(decoded) : decoded;
  };
  const parseValue = () => {
    skipWhitespace();
    if (offset >= text.length) fail("value required");
    if (text[offset] === '"') return parseString();
    if (text[offset] === "[") {
      offset += 1;
      skipWhitespace();
      const values = [];
      if (text[offset] === "]") {
        offset += 1;
        return values;
      }
      while (true) {
        values.push(parseValue());
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return values;
        }
        if (text[offset] !== ",") fail("array comma required");
        offset += 1;
      }
    }
    if (text[offset] === "{") {
      offset += 1;
      skipWhitespace();
      const value = Object.create(null);
      if (text[offset] === "}") {
        offset += 1;
        return value;
      }
      while (true) {
        skipWhitespace();
        const key = parseString();
        if (Object.prototype.hasOwnProperty.call(value, key)) fail("duplicate object key");
        skipWhitespace();
        if (text[offset] !== ":") fail("object colon required");
        offset += 1;
        value[key] = parseValue();
        skipWhitespace();
        if (text[offset] === "}") {
          offset += 1;
          return value;
        }
        if (text[offset] !== ",") fail("object comma required");
        offset += 1;
      }
    }
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    return parseUnsignedInteger();
  };
  const value = parseValue();
  skipWhitespace();
  if (offset !== text.length) fail("trailing JSON data");
  return value;
}

function canonicalJsonStringify(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    invariant(
      Number.isSafeInteger(value) && value >= 0,
      "canonical JSON number must be a safe unsigned integer",
    );
    return String(value);
  }
  if (typeof value === "bigint") {
    invariant(value >= 0n && value <= MAX_U64, "canonical JSON bigint exceeds u64");
    return value.toString();
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJsonStringify).join(",")}]`;
  invariant(typeof value === "object", "unsupported canonical JSON value");
  return `{${Object.keys(value)
    .map((key) => `${JSON.stringify(key)}:${canonicalJsonStringify(value[key])}`)
    .join(",")}}`;
}

function decodeCanonicalAuthorityJson(raw, label) {
  const value = parseLosslessUnsignedJson(raw, label);
  invariant(
    Buffer.from(canonicalJsonStringify(value), "utf8").equals(raw),
    `${label}: non-canonical JSON`,
  );
  return value;
}

function runLosslessJsonSelfTests() {
  const accepted = [
    ["9007199254740991", "number"],
    ["9007199254740992", "bigint"],
    ["18446744073709551615", "bigint"],
  ];
  for (const [literal, expectedType] of accepted) {
    const raw = Buffer.from(`{"value":${literal}}`, "utf8");
    const parsed = decodeCanonicalAuthorityJson(raw, `lossless self-test ${literal}`);
    invariant(typeof parsed.value === expectedType, `${literal}: decoded type drift`);
    invariant(String(parsed.value) === literal, `${literal}: decoded value drift`);
    invariant(canonicalJsonStringify(parsed) === raw.toString("utf8"), `${literal}: re-encode drift`);
  }
  const rejected = [
    `{"value":18446744073709551616}`,
    `{"value": 1}`,
    `{"value":01}`,
    `{"value":1.0}`,
    `{"value":1e0}`,
    `{"value":-1}`,
  ];
  for (const raw of rejected) {
    let rejectedAsRequired = false;
    try {
      decodeCanonicalAuthorityJson(Buffer.from(raw, "utf8"), "lossless rejection self-test");
    } catch {
      rejectedAsRequired = true;
    }
    invariant(rejectedAsRequired, `${raw}: malformed integer JSON accepted`);
  }
  return { accepted: accepted.length, rejected: rejected.length };
}

function exactKeys(value, expected, label) {
  invariant(value !== null && typeof value === "object" && !Array.isArray(value), `${label}: object required`);
  sameJson(Object.keys(value), expected, `${label}: field order drift`);
}

function compareCanonicalTuple(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}

function requireStrictOrder(records, key, label) {
  let prior = null;
  for (const [index, record] of records.entries()) {
    const current = key(record);
    invariant(
      prior === null || compareCanonicalTuple(prior, current) < 0,
      `${label}[${index}]: records are not strictly sorted and unique`,
    );
    prior = current;
  }
}

function requireRecordedHeight(value, lastTargetHeight, label) {
  const height = unsigned(value, MAX_U64, label);
  invariant(height > 0n && height <= BigInt(lastTargetHeight), `${label}: outside recorded authority height`);
  return height;
}

function exactHex(value, byteLength, label) {
  invariant(
    typeof value === "string" &&
      value.length === byteLength * 2 &&
      /^[0-9a-f]+$/.test(value),
    `${label}: expected ${byteLength}-byte lowercase hex`,
  );
  const decoded = Buffer.from(value, "hex");
  invariant(decoded.toString("hex") === value, `${label}: non-canonical hex`);
  return decoded;
}

function boundedHex(value, minimum, maximum, label) {
  invariant(typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value), `${label}: lowercase hex required`);
  const decoded = Buffer.from(value, "hex");
  invariant(decoded.length >= minimum && decoded.length <= maximum, `${label}: byte bound`);
  invariant(decoded.toString("hex") === value, `${label}: non-canonical hex`);
  return decoded;
}

function unsigned(value, maximum, label) {
  invariant(
    (typeof value === "string" || typeof value === "bigint" || Number.isSafeInteger(value)) &&
      /^(0|[1-9][0-9]*)$/.test(String(value)),
    `${label}: canonical unsigned integer required`,
  );
  const decoded = BigInt(value);
  invariant(decoded >= 0n && decoded <= maximum, `${label}: out of range`);
  return decoded;
}

function safeU64(value, label) {
  const decoded = unsigned(value, MAX_U64, label);
  return decoded <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(decoded) : decoded;
}

function canonicalU128(value, label) {
  return unsigned(value, MAX_U128, label).toString();
}

function authorityUnsignedJson(value, maximum, label) {
  invariant(
    typeof value === "number" || typeof value === "bigint",
    `${label}: Rust integer fields require an unquoted JSON number`,
  );
  return unsigned(value, maximum, label);
}

function authorityU64(value, label) {
  return authorityUnsignedJson(value, MAX_U64, label);
}

function authorityU32(value, label) {
  return Number(authorityUnsignedJson(value, (1n << 32n) - 1n, label));
}

function authorityU8(value, label) {
  return Number(authorityUnsignedJson(value, 255n, label));
}

function authorityCanonicalU128(value, label) {
  invariant(typeof value === "string", `${label}: CanonicalU128V0 requires a quoted decimal string`);
  return canonicalU128(value, label);
}

function boolByte(value, label) {
  invariant(value === 0 || value === 1, `${label}: invalid bool byte`);
  return value === 1;
}

function frame32(value) {
  return Buffer.concat([uint(value.length, 4), value]);
}

function frame64(value) {
  return Buffer.concat([uint(value.length, 8), value]);
}

function hashV1(domain, parts) {
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([HASH_V1_PREFIX, frame64(Buffer.from(domain, "ascii")), ...parts.map(frame64)]))
    .digest();
}

function domainHash(domain, encoded) {
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([HASH_PREFIX, Buffer.from(domain, "ascii"), encoded].map(frame32)))
    .digest();
}

function sha256(parts) {
  return crypto.createHash("sha256").update(Buffer.concat(parts)).digest();
}

function littleEndianInteger(raw) {
  let value = 0n;
  for (let index = raw.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(raw[index]);
  }
  return value;
}

function littleEndianBytes(value, width) {
  let remaining = BigInt(value);
  invariant(remaining >= 0n && remaining < (1n << BigInt(width * 8)), "little-endian integer width");
  const raw = Buffer.alloc(width);
  for (let index = 0; index < width; index += 1) {
    raw[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return raw;
}

function ed25519Mod(value) {
  const reduced = value % ED25519_FIELD_MODULUS;
  return reduced < 0n ? reduced + ED25519_FIELD_MODULUS : reduced;
}

function ed25519Pow(base, exponent) {
  let result = 1n;
  let factor = ed25519Mod(base);
  let remaining = BigInt(exponent);
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = ed25519Mod(result * factor);
    factor = ed25519Mod(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function decodeCanonicalEd25519Point(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) return null;
  const encoded = littleEndianInteger(raw);
  const sign = Number(encoded >> 255n);
  const y = encoded & ((1n << 255n) - 1n);
  if (y >= ED25519_FIELD_MODULUS) return null;
  const ySquared = ed25519Mod(y * y);
  const numerator = ed25519Mod(ySquared - 1n);
  const denominator = ed25519Mod(ED25519_D * ySquared + 1n);
  if (denominator === 0n) return null;
  const xSquared = ed25519Mod(numerator * ed25519Pow(denominator, ED25519_FIELD_MODULUS - 2n));
  let x = ed25519Pow(xSquared, (ED25519_FIELD_MODULUS + 3n) / 8n);
  if (ed25519Mod(x * x) !== xSquared) x = ed25519Mod(x * ED25519_SQRT_M1);
  if (ed25519Mod(x * x) !== xSquared || (x === 0n && sign === 1)) return null;
  if (Number(x & 1n) !== sign) x = ED25519_FIELD_MODULUS - x;
  return { x, y };
}

function addEd25519Points(left, right) {
  const product = ed25519Mod(left.x * right.x * left.y * right.y);
  const xDenominator = ed25519Mod(1n + ED25519_D * product);
  const yDenominator = ed25519Mod(1n - ED25519_D * product);
  invariant(xDenominator !== 0n && yDenominator !== 0n, "complete Ed25519 addition denominator");
  return {
    x: ed25519Mod(
      (left.x * right.y + left.y * right.x) *
        ed25519Pow(xDenominator, ED25519_FIELD_MODULUS - 2n),
    ),
    y: ed25519Mod(
      (left.y * right.y + left.x * right.x) *
        ed25519Pow(yDenominator, ED25519_FIELD_MODULUS - 2n),
    ),
  };
}

function isSmallOrderEd25519Point(point) {
  let multiple = point;
  for (let index = 0; index < 3; index += 1) multiple = addEd25519Points(multiple, multiple);
  return multiple.x === 0n && multiple.y === 1n;
}

function strictEd25519Verify(message, publicKey, signature) {
  if (!Buffer.isBuffer(message) || !Buffer.isBuffer(publicKey) || !Buffer.isBuffer(signature) ||
      publicKey.length !== 32 || signature.length !== 64) return false;
  const publicPoint = decodeCanonicalEd25519Point(publicKey);
  const signaturePoint = decodeCanonicalEd25519Point(signature.subarray(0, 32));
  if (publicPoint === null || signaturePoint === null ||
      isSmallOrderEd25519Point(publicPoint) || isSmallOrderEd25519Point(signaturePoint) ||
      littleEndianInteger(signature.subarray(32)) >= ED25519_SCALAR_ORDER) return false;
  try {
    return crypto.verify(null, message, publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}

function futureFixturePrivateKey(validatorIdHex, expectedPublicKeyHex, label) {
  const validatorId = boundedHex(validatorIdHex, 1, 128, `${label}.validator_id`);
  const seed = sha256([FUTURE_FIXTURE_KEY_PREFIX, validatorId]);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([FIXTURE_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const controlRoot = sha256([Buffer.from(`${label}:fixture-key-control`, "utf8")]);
  const controlSignature = crypto.sign(null, controlRoot, privateKey);
  invariant(
    strictEd25519Verify(
      controlRoot,
      exactHex(expectedPublicKeyHex, 32, `${label}.expected_public_key`),
      controlSignature,
    ),
    `${label}: deterministic fixture private-key mapping drift`,
  );
  return privateKey;
}

function orderedRoot(leafDomain, nodeDomain, rootDomain, values) {
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
  return domainHash(
    rootDomain,
    Buffer.concat([
      uint(0, 2),
      uint(values.length, 4),
      layer.length === 0 ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), layer[0]]),
    ]),
  );
}

function checkpointOrderedRoot(domain, values) {
  let layer = values.map((value, index) => hashV1(`${domain}.leaf`, [uint(index, 4), value]));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(hashV1(`${domain}.node`, [uint(level, 4), layer[index], layer[index + 1] ?? layer[index]]));
    }
    layer = next;
    level += 1;
  }
  return layer.length === 0
    ? hashV1(domain, [uint(values.length, 4), Buffer.from([0])])
    : hashV1(domain, [uint(values.length, 4), Buffer.from([1]), layer[0]]);
}

class Cursor {
  constructor(bytes, label) {
    this.bytes = bytes;
    this.offset = 0;
    this.label = label;
  }

  take(length, field = "bytes") {
    invariant(Number.isSafeInteger(length) && length >= 0 && this.offset + length <= this.bytes.length, `${this.label}.${field}: truncated`);
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  integer(width, field) {
    let value = 0n;
    for (const byte of this.take(width, field)) value = (value << 8n) | BigInt(byte);
    return value;
  }

  u8(field) { return Number(this.integer(1, field)); }
  u16(field) { return Number(this.integer(2, field)); }
  u32(field) { return Number(this.integer(4, field)); }
  u64(field) { return this.integer(8, field); }
  u128(field) { return this.integer(16, field); }

  bytes32(field, maximum = 65_536) {
    const length = this.u32(`${field}.length`);
    invariant(length <= maximum, `${this.label}.${field}: length bound`);
    return this.take(length, field);
  }

  bytes16(field, maximum = 128) {
    const length = this.u16(`${field}.length`);
    invariant(length >= 1 && length <= maximum, `${this.label}.${field}: length bound`);
    return this.take(length, field);
  }

  optionalU64(field) {
    const tag = this.u8(`${field}.tag`);
    invariant(tag === 0 || tag === 1, `${this.label}.${field}: invalid option tag`);
    return tag === 0 ? null : this.u64(field);
  }

  optionalFixed32(field) {
    const tag = this.u8(`${field}.tag`);
    invariant(tag === 0 || tag === 1, `${this.label}.${field}: invalid option tag`);
    return tag === 0 ? null : this.take(32, field);
  }

  finish() {
    invariant(this.offset === this.bytes.length, `${this.label}: trailing bytes at ${this.offset}`);
  }
}

function namespacedKey(namespace, components) {
  invariant(components.length >= 1 && components.length <= 0xffff, "authenticated key component count");
  return Buffer.concat([
    Buffer.from("trnm/authenticated-state/v4", "ascii"),
    Buffer.from([0, namespace]),
    uint(components.length, 2),
    ...components.map(frame32),
  ]);
}

function decodePocoPhysicalKey(key, label) {
  if (!key.subarray(0, POCO_PHYSICAL_KEY_PREFIX.length).equals(POCO_PHYSICAL_KEY_PREFIX)) return null;
  const cursor = new Cursor(key.subarray(POCO_PHYSICAL_KEY_PREFIX.length), label);
  const componentCount = cursor.u16("component_count");
  invariant(componentCount >= 1 && componentCount <= 3, `${label}: invalid component count`);
  const components = [];
  for (let index = 0; index < componentCount; index += 1) {
    const component = cursor.bytes32(`component_${index}`, 128);
    invariant(component.length > 0, `${label}: empty component`);
    components.push(component);
  }
  cursor.finish();
  if (components.length === 1 && components[0].equals(Buffer.from("manifest", "ascii"))) {
    invariant(key.equals(manifestKey()), `${label}: noncanonical manifest key`);
    return { type: "manifest" };
  }
  if (components.length === 3 && components[0].equals(Buffer.from("entry", "ascii"))) {
    invariant(components[1].length === 1, `${label}: entry kind is not u8`);
    const kind = components[1][0];
    invariant(kind >= 1 && kind <= 16, `${label}: unknown entry kind`);
    invariant(components[2].length >= 1 && components[2].length <= 128, `${label}: logical-key bound`);
    invariant(key.equals(entryPhysicalKey(kind, components[2])), `${label}: noncanonical entry key`);
    return { type: "entry", kind, logicalKey: components[2] };
  }
  throw new Error(`${label}: unknown PoCO physical key layout`);
}

function jmtLeaf(key, value) {
  const keyHash = sha256([key]);
  const valueHash = sha256([value]);
  return {
    keyHash,
    hash: sha256([JMT_LEAF_DOMAIN, keyHash, valueHash]),
    isLeaf: true,
  };
}

function jmtInternalHash(left, right) {
  return sha256([JMT_INTERNAL_DOMAIN, left, right]);
}

function keyNibble(keyHash, depth) {
  const byte = keyHash[Math.floor(depth / 2)];
  return depth % 2 === 0 ? byte >>> 4 : byte & 0x0f;
}

function jmtMerkleHash(children, start, width) {
  const present = [];
  for (let index = start; index < start + width; index += 1) {
    if (children[index] !== null) present.push(children[index]);
  }
  if (present.length === 0) return JMT_PLACEHOLDER_HASH;
  if (width === 1 || (present.length === 1 && present[0].isLeaf)) return present[0].hash;
  const half = width / 2;
  return jmtInternalHash(
    jmtMerkleHash(children, start, half),
    jmtMerkleHash(children, start + half, half),
  );
}

function jmtSubtree(leaves, depth) {
  invariant(leaves.length > 0, "JMT subtree cannot be empty");
  if (leaves.length === 1) return leaves[0];
  invariant(depth < 64, "SHA-256 authenticated-key collision");
  const groups = Array.from({ length: 16 }, () => []);
  for (const leaf of leaves) groups[keyNibble(leaf.keyHash, depth)].push(leaf);
  const children = groups.map((group) => group.length === 0 ? null : jmtSubtree(group, depth + 1));
  return { hash: jmtMerkleHash(children, 0, 16), isLeaf: false };
}

function jmtRoot(live) {
  if (live.size === 0) return JMT_PLACEHOLDER_HASH;
  const leaves = [...live.entries()].map(([keyHex, valueHex]) =>
    jmtLeaf(Buffer.from(keyHex, "hex"), Buffer.from(valueHex, "hex"))
  );
  return jmtSubtree(leaves, 0).hash;
}

function manifestKey() {
  return namespacedKey(8, [Buffer.from("manifest", "ascii")]);
}

function entryPhysicalKey(kind, logicalKey) {
  return namespacedKey(8, [Buffer.from("entry", "ascii"), Buffer.from([kind]), logicalKey]);
}

function canonicalEntry(kind, logicalKey, value) {
  return Buffer.concat([uint(0, 2), Buffer.from([kind]), frame32(logicalKey), frame32(value)]);
}

function semanticLogicalKey(kind, identity) {
  return domainHash(SEMANTIC_IDENTITY_DOMAIN, Buffer.concat([uint(0, 2), Buffer.from([kind]), frame32(identity)]));
}

function joinedIdentity(parts) {
  return Buffer.concat(parts.map(frame32));
}

function meterIdentity(meterId, meterVersion) {
  return Buffer.concat([frame32(meterId), uint(meterVersion, 4)]);
}

function consumptionTupleIdentity(certificate) {
  return Buffer.concat([
    joinedIdentity([
      boundedHex(certificate.consumer_id_hex, 1, 128, "tuple consumer ID"),
      boundedHex(certificate.provider_id_hex, 1, 128, "tuple provider ID"),
      boundedHex(certificate.task_id_hex, 1, 128, "tuple task ID"),
    ]),
    exactHex(certificate.output_commitment_hex, 32, "tuple output commitment"),
    uint(certificate.billing_start_height, 8),
    uint(certificate.billing_end_height, 8),
    uint(certificate.consumer_nonce, 8),
  ]);
}

function entryForIdentity(projection, kind, identity, label) {
  const key = semanticLogicalKey(kind, identity);
  const entry = projection.byKindKey.get(`${kind}:${key.toString("hex")}`);
  invariant(entry !== undefined, `${label}: application authority references absent semantic entry`);
  invariant(entry.envelope.identity.equals(identity), `${label}: semantic identity digest collision`);
  return entry;
}

function decodeManifest(bytes, label) {
  invariant(bytes.length === 47, `${label}: manifest length`);
  const cursor = new Cursor(bytes, label);
  invariant(cursor.u16("schema") === 0, `${label}: schema`);
  invariant(cursor.u8("namespace") === 8, `${label}: namespace`);
  const height = cursor.u64("height");
  const count = cursor.u32("count");
  const root = cursor.take(32, "root");
  cursor.finish();
  return { height, count, root };
}

function decodeSemanticEnvelope(entry, label) {
  const cursor = new Cursor(entry.value, label);
  invariant(cursor.u16("schema") === 0, `${label}: schema`);
  invariant(cursor.u8("kind") === entry.kind, `${label}: kind`);
  const revision = cursor.u64("revision");
  invariant(revision > 0n, `${label}: zero revision`);
  const identity = cursor.bytes32("identity", 128);
  invariant(identity.length >= 1, `${label}: empty identity`);
  const payload = cursor.bytes32("payload", 65_384);
  invariant(payload.length >= 1, `${label}: empty payload`);
  cursor.finish();
  invariant(semanticLogicalKey(entry.kind, identity).equals(entry.key), `${label}: identity/logical-key mismatch`);
  stats.semanticEntries += 1;
  return { revision, identity, payload };
}

function decodeParameters(raw, label) {
  invariant(raw.length === 341, `${label}: ConsensusParametersV0 must be 341 bytes`);
  const c = new Cursor(raw, label);
  const p = {
    schema_version: c.u16("schema_version"),
    protocol_version: c.u32("protocol_version"),
    production_activation: boolByte(c.u8("production_activation"), `${label}.production_activation`),
    max_chain_id_bytes: c.u16("max_chain_id_bytes"),
    max_validator_id_bytes: c.u16("max_validator_id_bytes"),
    max_block_bytes: c.u32("max_block_bytes"),
    max_consensus_message_bytes: c.u32("max_consensus_message_bytes"),
    min_validators: c.u32("min_validators"),
    max_validators: c.u32("max_validators"),
    quorum_numerator: c.u32("quorum_numerator"),
    quorum_denominator: c.u32("quorum_denominator"),
    quorum_addend: c.u32("quorum_addend"),
    finality_certified_chain_length: c.u8("finality_certified_chain_length"),
    max_total_voting_power: c.u64("max_total_voting_power").toString(),
    max_block_time_step_ms: c.u64("max_block_time_step_ms").toString(),
    leader_schedule: c.u8("leader_schedule"),
    require_full_payload_before_vote: boolByte(c.u8("require_full_payload_before_vote"), `${label}.require_full_payload_before_vote`),
    base_timeout_ms: c.u64("base_timeout_ms").toString(),
    timeout_multiplier_numerator: c.u32("timeout_multiplier_numerator"),
    timeout_multiplier_denominator: c.u32("timeout_multiplier_denominator"),
    timeout_max_ms: c.u64("timeout_max_ms").toString(),
    epoch_length_blocks: c.u64("epoch_length_blocks").toString(),
    epoch_seal_blocks: c.u8("epoch_seal_blocks"),
    snapshot_lead_blocks: c.u64("snapshot_lead_blocks").toString(),
    joint_handoff_old_quorum: boolByte(c.u8("joint_handoff_old_quorum"), `${label}.joint_handoff_old_quorum`),
    joint_handoff_new_quorum: boolByte(c.u8("joint_handoff_new_quorum"), `${label}.joint_handoff_new_quorum`),
    upgrade_notice_epochs: c.u64("upgrade_notice_epochs").toString(),
    max_protocol_version_jump: c.u32("max_protocol_version_jump"),
    scale_ppm: c.u64("scale_ppm").toString(),
    maturity_epochs: c.u64("maturity_epochs").toString(),
    max_certificate_age_epochs: c.u64("max_certificate_age_epochs").toString(),
    decay_step_ppm_per_epoch: c.u64("decay_step_ppm_per_epoch").toString(),
    per_certificate_unit_cap: c.u128("per_certificate_unit_cap").toString(),
    per_consumer_provider_epoch_unit_cap: c.u128("per_consumer_provider_epoch_unit_cap").toString(),
    per_task_provider_epoch_unit_cap: c.u128("per_task_provider_epoch_unit_cap").toString(),
    per_provider_epoch_unit_cap: c.u128("per_provider_epoch_unit_cap").toString(),
    units_per_power: c.u128("units_per_power").toString(),
    bond_atomic_units_per_power: c.u128("bond_atomic_units_per_power").toString(),
    min_validator_power: c.u64("min_validator_power").toString(),
    max_validator_power: c.u64("max_validator_power").toString(),
    max_validator_share_ppm: c.u64("max_validator_share_ppm").toString(),
    capped_weight_alpha_ppm: c.u64("capped_weight_alpha_ppm").toString(),
    full_weight_alpha_ppm: c.u64("full_weight_alpha_ppm").toString(),
    rollout_phase: c.u8("rollout_phase"),
    minimum_shadow_epochs: c.u64("minimum_shadow_epochs").toString(),
    minimum_eligibility_only_epochs: c.u64("minimum_eligibility_only_epochs").toString(),
    minimum_capped_weight_epochs: c.u64("minimum_capped_weight_epochs").toString(),
    automatic_promotion: boolByte(c.u8("automatic_promotion"), `${label}.automatic_promotion`),
    evidence_window_epochs: c.u64("evidence_window_epochs").toString(),
    unbonding_delay_epochs: c.u64("unbonding_delay_epochs").toString(),
    jail_duration_epochs: c.u64("jail_duration_epochs").toString(),
    trusting_period_epochs: c.u64("trusting_period_epochs").toString(),
    require_trusting_period_less_than_evidence: boolByte(c.u8("require_trusting_period_less_than_evidence"), `${label}.require_trusting_period_less_than_evidence`),
    require_evidence_window_le_unbonding_delay: boolByte(c.u8("require_evidence_window_le_unbonding_delay"), `${label}.require_evidence_window_le_unbonding_delay`),
  };
  c.finish();
  validateParameterSafety(p, label);
  return p;
}

function validateParameterSafety(p, label) {
  invariant(p.schema_version === 0 && p.protocol_version === 0, `${label}: version`);
  invariant(p.max_chain_id_bytes >= 1 && p.max_chain_id_bytes <= 128, `${label}: chain ID bound`);
  invariant(p.max_validator_id_bytes >= 1 && p.max_validator_id_bytes <= 128, `${label}: validator ID bound`);
  invariant(p.min_validators >= 4 && p.min_validators <= p.max_validators && p.max_validators <= 100, `${label}: validator bounds`);
  invariant(p.max_block_bytes > 0 && p.max_block_bytes <= p.max_consensus_message_bytes, `${label}: message bounds`);
  invariant(p.require_full_payload_before_vote, `${label}: full payload required`);
  invariant(p.quorum_numerator === 2 && p.quorum_denominator === 3 && p.quorum_addend === 1, `${label}: quorum`);
  invariant(p.finality_certified_chain_length === 3 && p.leader_schedule === 0, `${label}: finality/schedule`);
  invariant(p.timeout_multiplier_denominator > 0 && p.timeout_multiplier_numerator > p.timeout_multiplier_denominator, `${label}: timeout multiplier`);
  invariant(BigInt(p.base_timeout_ms) <= BigInt(p.timeout_max_ms), `${label}: timeout bound`);
  invariant(
    p.epoch_seal_blocks === 2 &&
      BigInt(p.snapshot_lead_blocks) >= BigInt(p.finality_certified_chain_length),
    `${label}: epoch seals/snapshot lead cannot finalize before checkpoint proposal`,
  );
  invariant(BigInt(p.epoch_length_blocks) > BigInt(p.snapshot_lead_blocks) + BigInt(p.epoch_seal_blocks), `${label}: epoch layout`);
  invariant(p.joint_handoff_old_quorum && p.joint_handoff_new_quorum, `${label}: joint handoff`);
  invariant(BigInt(p.upgrade_notice_epochs) >= 1n && p.max_protocol_version_jump === 1, `${label}: upgrade bounds`);
  invariant(BigInt(p.scale_ppm) > 0n, `${label}: scale`);
  const caps = [p.per_certificate_unit_cap, p.per_consumer_provider_epoch_unit_cap, p.per_task_provider_epoch_unit_cap, p.per_provider_epoch_unit_cap].map(BigInt);
  invariant(caps[0] > 0n && caps.every((value, index) => index === 0 || caps[index - 1] <= value), `${label}: unit caps`);
  invariant(BigInt(p.units_per_power) > 0n && BigInt(p.bond_atomic_units_per_power) > 0n, `${label}: capacity divisors`);
  invariant(BigInt(p.min_validator_power) > 0n && BigInt(p.min_validator_power) <= BigInt(p.max_validator_power), `${label}: power bounds`);
  invariant(BigInt(p.max_validator_share_ppm) > 0n && BigInt(p.max_validator_share_ppm) * 3n < BigInt(p.scale_ppm), `${label}: share bound`);
  invariant(BigInt(p.capped_weight_alpha_ppm) <= BigInt(p.scale_ppm) && BigInt(p.full_weight_alpha_ppm) === BigInt(p.scale_ppm), `${label}: rollout alpha`);
  invariant(p.rollout_phase >= 0 && p.rollout_phase <= 3 && !p.automatic_promotion, `${label}: rollout phase`);
  invariant(BigInt(p.min_validators) * BigInt(p.min_validator_power) <= BigInt(p.max_total_voting_power), `${label}: minimum set cannot fit`);
  invariant(BigInt(p.trusting_period_epochs) < BigInt(p.evidence_window_epochs) && BigInt(p.evidence_window_epochs) <= BigInt(p.unbonding_delay_epochs), `${label}: trusting/evidence/unbonding`);
  invariant(p.require_trusting_period_less_than_evidence && p.require_evidence_window_le_unbonding_delay, `${label}: relationship flags`);
}

function decodeValidatorSet(raw, label) {
  const c = new Cursor(raw, label);
  invariant(c.u16("schema") === 0, `${label}: schema`);
  const genesis = c.take(32, "genesis_hash");
  invariant(!genesis.equals(Buffer.alloc(32)), `${label}: zero genesis`);
  const chain = c.bytes16("chain_id", 128);
  const protocolVersion = c.u32("protocol_version");
  const epoch = c.u64("epoch");
  const parametersHash = c.take(32, "parameters_hash");
  const count = c.u32("validator_count");
  invariant(count >= 1 && count <= 100, `${label}: validator count`);
  const validators = [];
  const keys = new Set();
  let prior = null;
  for (let index = 0; index < count; index += 1) {
    const id = c.bytes32(`validators[${index}].id`, 128);
    invariant(id.length >= 1, `${label}: empty validator ID`);
    const key = c.take(32, `validators[${index}].key`);
    invariant(!key.equals(Buffer.alloc(32)), `${label}: zero validator key`);
    const power = c.u64(`validators[${index}].power`);
    invariant(power > 0n, `${label}: zero power`);
    invariant(prior === null || Buffer.compare(prior, id) < 0, `${label}: validator order/duplicate`);
    invariant(!keys.has(key.toString("hex")), `${label}: duplicate key`);
    prior = id;
    keys.add(key.toString("hex"));
    validators.push({
      validator_id_hex: id.toString("hex"),
      consensus_key_hex: key.toString("hex"),
      effective_weight: power.toString(),
    });
  }
  c.finish();
  return {
    genesis_hash_hex: genesis.toString("hex"),
    chain_id_ascii: chain.toString("ascii"),
    protocol_version: protocolVersion,
    epoch: epoch.toString(),
    consensus_parameters_hash_hex: parametersHash.toString("hex"),
    validators,
    cev0: raw,
    id: domainHash(VALIDATOR_SET_DOMAIN, raw),
  };
}

function decodeConsumptionCertificate(raw, label, countEvidence = true) {
  const c = new Cursor(raw, label);
  invariant(c.u16("schema") === 0, `${label}: schema`);
  const bodyStart = 0;
  const genesis = c.take(32, "genesis_hash");
  invariant(!genesis.equals(Buffer.alloc(32)), `${label}: zero genesis`);
  const chain = c.bytes16("chain_id", 128);
  const provider = c.bytes32("provider_id", 128);
  const consumer = c.bytes32("consumer_id", 128);
  const consumerKey = c.bytes32("consumer_key_id", 128);
  const task = c.bytes32("task_id", 128);
  invariant(provider.length && consumer.length && consumerKey.length && task.length, `${label}: empty opaque ID`);
  invariant(!provider.equals(consumer), `${label}: provider equals consumer`);
  const output = c.take(32, "output_commitment");
  const meter = c.bytes32("meter_id", 128);
  invariant(meter.length > 0, `${label}: empty meter ID`);
  const meterVersion = c.u32("meter_version");
  const consumedUnits = c.u128("consumed_units");
  invariant(consumedUnits > 0n, `${label}: zero consumed units`);
  const billingStart = c.u64("billing_start");
  const billingEnd = c.u64("billing_end");
  invariant(billingStart <= billingEnd, `${label}: invalid billing interval`);
  const nonce = c.u64("consumer_nonce");
  const settlement = c.take(32, "settlement_commitment");
  const evidence = c.optionalFixed32("measurement_evidence_root");
  const bodyEnd = c.offset;
  const signature = c.take(64, "consumer_signature");
  const certificateId = c.take(32, "certificate_id");
  c.finish();
  const body = raw.subarray(bodyStart, bodyEnd);
  const bodyRoot = domainHash(CERTIFICATE_DOMAIN, body);
  const expectedId = domainHash(CERTIFICATE_ID_DOMAIN, bodyRoot);
  invariant(expectedId.equals(certificateId), `${label}: certificate ID mismatch`);
  if (countEvidence) stats.certificates += 1;
  return {
    genesis_hash_hex: genesis.toString("hex"),
    chain_id_ascii: chain.toString("ascii"),
    provider_id_hex: provider.toString("hex"),
    consumer_id_hex: consumer.toString("hex"),
    consumer_key_id_hex: consumerKey.toString("hex"),
    task_id_hex: task.toString("hex"),
    output_commitment_hex: output.toString("hex"),
    meter_id_hex: meter.toString("hex"),
    meter_version: meterVersion,
    consumed_units: consumedUnits.toString(),
    billing_start_height: billingStart.toString(),
    billing_end_height: billingEnd.toString(),
    consumer_nonce: nonce.toString(),
    settlement_commitment_hex: settlement.toString("hex"),
    measurement_evidence_root_hex: evidence?.toString("hex") ?? null,
    signature_hex: signature.toString("hex"),
    certificate_id_hex: certificateId.toString("hex"),
    body_cev0: body,
    body_digest: bodyRoot,
  };
}

function decodeConsumerKey(payload, identity, label) {
  const identityCursor = new Cursor(identity, `${label}.identity`);
  const consumer = identityCursor.bytes32("consumer_id", 128);
  const consumerKey = identityCursor.bytes32("consumer_key_id", 128);
  identityCursor.finish();
  invariant(consumer.length > 0 && consumerKey.length > 0, `${label}: empty consumer/key identity`);
  const c = new Cursor(payload, label);
  invariant(c.bytes32("consumer_id", 128).equals(consumer), `${label}: consumer identity`);
  invariant(c.bytes32("consumer_key_id", 128).equals(consumerKey), `${label}: consumer-key identity`);
  const publicKey = c.take(32, "public_key");
  invariant(!publicKey.equals(Buffer.alloc(32)), `${label}: zero consumer public key`);
  const activeFrom = c.u64("active_from");
  const revokedAt = c.optionalU64("revoked_at");
  invariant(revokedAt === null || revokedAt > activeFrom, `${label}: invalid key interval`);
  c.finish();
  return {
    consumer_id_hex: consumer.toString("hex"),
    consumer_key_id_hex: consumerKey.toString("hex"),
    public_key_hex: publicKey.toString("hex"),
    active_from: activeFrom,
    revoked_at: revokedAt,
  };
}

function decodeConsumerNonce(payload, identity, label) {
  const identityCursor = new Cursor(identity, `${label}.identity`);
  const consumer = identityCursor.bytes32("consumer_id", 128);
  const consumerKey = identityCursor.bytes32("consumer_key_id", 128);
  const provider = identityCursor.bytes32("provider_id", 128);
  identityCursor.finish();
  invariant(!provider.equals(consumer), `${label}: nonce provider equals consumer`);
  const c = new Cursor(payload, label);
  invariant(c.bytes32("consumer_id", 128).equals(consumer), `${label}: consumer identity`);
  invariant(c.bytes32("consumer_key_id", 128).equals(consumerKey), `${label}: consumer-key identity`);
  invariant(c.bytes32("provider_id", 128).equals(provider), `${label}: provider identity`);
  const maxAcceptedNonce = c.u64("max_accepted_nonce");
  c.finish();
  return {
    consumer_id_hex: consumer.toString("hex"),
    consumer_key_id_hex: consumerKey.toString("hex"),
    provider_id_hex: provider.toString("hex"),
    max_accepted_nonce: maxAcceptedNonce,
  };
}

function decodeConsumptionTuple(payload, identity, label) {
  const identityCursor = new Cursor(identity, `${label}.identity`);
  const consumer = identityCursor.bytes32("consumer_id", 128);
  const provider = identityCursor.bytes32("provider_id", 128);
  const task = identityCursor.bytes32("task_id", 128);
  const output = identityCursor.take(32, "output_commitment");
  const billingStart = identityCursor.u64("billing_start");
  const billingEnd = identityCursor.u64("billing_end");
  const consumerNonce = identityCursor.u64("consumer_nonce");
  identityCursor.finish();
  invariant(!provider.equals(consumer), `${label}: tuple provider equals consumer`);
  invariant(billingStart <= billingEnd, `${label}: invalid tuple billing interval`);
  const c = new Cursor(payload, label);
  invariant(c.bytes32("consumer_id", 128).equals(consumer), `${label}: consumer identity`);
  invariant(c.bytes32("provider_id", 128).equals(provider), `${label}: provider identity`);
  invariant(c.bytes32("task_id", 128).equals(task), `${label}: task identity`);
  invariant(c.take(32, "output_commitment").equals(output), `${label}: output identity`);
  invariant(c.u64("billing_start") === billingStart, `${label}: billing-start identity`);
  invariant(c.u64("billing_end") === billingEnd, `${label}: billing-end identity`);
  invariant(c.u64("consumer_nonce") === consumerNonce, `${label}: nonce identity`);
  const certificateId = c.take(32, "certificate_id");
  const acceptedHeight = c.u64("accepted_height");
  invariant(acceptedHeight > billingEnd, `${label}: tuple acceptance does not follow billing interval`);
  c.finish();
  return {
    consumer_id_hex: consumer.toString("hex"),
    provider_id_hex: provider.toString("hex"),
    task_id_hex: task.toString("hex"),
    output_commitment_hex: output.toString("hex"),
    billing_start: billingStart,
    billing_end: billingEnd,
    consumer_nonce: consumerNonce,
    certificate_id_hex: certificateId.toString("hex"),
    accepted_height: acceptedHeight,
  };
}

function decodeMeter(payload, identity, label) {
  const identityCursor = new Cursor(identity, `${label}.identity`);
  const meter = identityCursor.bytes32("meter_id", 128);
  const meterVersion = identityCursor.u32("meter_version");
  identityCursor.finish();
  const c = new Cursor(payload, label);
  invariant(c.bytes32("meter_id", 128).equals(meter), `${label}: meter identity`);
  invariant(c.u32("meter_version") === meterVersion, `${label}: meter-version identity`);
  const unitScale = c.u128("unit_scale");
  invariant(unitScale > 0n, `${label}: zero meter unit scale`);
  const activeFrom = c.u64("active_from");
  const retiredAt = c.optionalU64("retired_at");
  invariant(retiredAt === null || retiredAt > activeFrom, `${label}: invalid meter interval`);
  c.finish();
  return {
    meter_id_hex: meter.toString("hex"),
    meter_version: meterVersion,
    unit_scale: unitScale,
    active_from: activeFrom,
    retired_at: retiredAt,
  };
}

function decodeSettlement(payload, identity, label) {
  invariant(identity.length === 32, `${label}: settlement identity width`);
  const c = new Cursor(payload, label);
  invariant(c.take(32, "certificate_id").equals(identity), `${label}: settlement certificate identity`);
  const commitment = c.take(32, "commitment");
  const state = c.u8("state");
  invariant(state >= 1 && state <= 3, `${label}: settlement state`);
  const finalizedHeight = c.u64("finalized_height");
  c.finish();
  return {
    certificate_id_hex: identity.toString("hex"),
    commitment_hex: commitment.toString("hex"),
    state,
    finalized_height: finalizedHeight,
  };
}

function decodeMeasurement(payload, identity, label) {
  invariant(identity.length === 32, `${label}: measurement identity width`);
  const c = new Cursor(payload, label);
  invariant(c.take(32, "certificate_id").equals(identity), `${label}: measurement certificate identity`);
  const evidenceRoot = c.optionalFixed32("evidence_root");
  const state = c.u8("state");
  invariant(state >= 1 && state <= 3, `${label}: measurement state`);
  c.finish();
  return {
    certificate_id_hex: identity.toString("hex"),
    evidence_root_hex: evidenceRoot?.toString("hex") ?? null,
    state,
  };
}

function verifyConsumptionCertificate(certificate, consumerPublicKeyHex, parameters, acceptedHeight, label) {
  invariant(BigInt(certificate.billing_end_height) < BigInt(acceptedHeight), `${label}: billing end must precede acceptance`);
  invariant(
    Buffer.from(certificate.chain_id_ascii, "ascii").length <= parameters.max_chain_id_bytes,
    `${label}: chain ID exceeds active parameter bound`,
  );
  for (const field of ["provider_id_hex", "consumer_id_hex", "consumer_key_id_hex", "task_id_hex", "meter_id_hex"]) {
    invariant(certificate[field].length / 2 <= parameters.max_validator_id_bytes, `${label}: ${field} exceeds active parameter bound`);
  }
  invariant(
    strictEd25519Verify(
      certificate.body_digest,
      exactHex(consumerPublicKeyHex, 32, `${label}.consumer_key`),
      exactHex(certificate.signature_hex, 64, `${label}.signature`),
    ),
    `${label}: invalid strict Ed25519 consumer signature`,
  );
}

function decodeRegistration(payload, identity, label) {
  const c = new Cursor(payload, label);
  const validator = c.bytes32("validator_id", 128);
  invariant(validator.equals(identity), `${label}: identity`);
  const key = c.take(32, "consensus_key");
  invariant(!key.equals(Buffer.alloc(32)), `${label}: zero key`);
  const nonce = c.u64("registration_nonce");
  const state = c.u8("state");
  invariant(state === 1 || state === 2, `${label}: state`);
  const proof = c.bytes32("proof", 65_384);
  c.finish();
  const decoded = decodePopExact(proof);
  invariant(decoded.fields.validator_id_hex === validator.toString("hex"), `${label}: PoP ID`);
  invariant(decoded.fields.public_key_hex === key.toString("hex"), `${label}: PoP key`);
  invariant(decoded.fields.registration_nonce === nonce.toString(), `${label}: PoP nonce`);
  return {
    validator_id_hex: validator.toString("hex"),
    consensus_key_hex: key.toString("hex"),
    registration_nonce: nonce,
    state,
    proof,
    proof_digest: domainHash(REGISTRATION_POP_DIGEST_DOMAIN, proof),
    pop: decoded,
  };
}

function verifyPop(decoded, expected, label) {
  invariant(decoded.fields.genesis_hash_hex === expected.genesis_hash_hex, `${label}: genesis scope`);
  invariant(decoded.fields.chain_id_ascii === expected.chain_id_ascii, `${label}: chain scope`);
  invariant(decoded.fields.target_epoch === String(expected.target_epoch), `${label}: target epoch`);
  invariant(decoded.fields.validator_id_hex === expected.validator_id_hex, `${label}: validator ID`);
  invariant(decoded.fields.public_key_hex === expected.public_key_hex, `${label}: public key`);
  invariant(decoded.fields.registration_nonce === String(expected.registration_nonce), `${label}: nonce`);
  const root = digest(POP_DOMAIN, decoded.signing);
  invariant(
    strictEd25519Verify(root, fromHex(decoded.fields.public_key_hex, `${label}.key`), decoded.signature),
    `${label}: invalid strict Ed25519 signature`,
  );
  stats.popSignatures += 1;
}

function registrationHistoryHead(history) {
  const encoded = Buffer.concat([
    uint(0, 2),
    exactHex(history.previous_history_head_hex, 32, "registration previous head"),
    frame32(boundedHex(history.validator_id_hex, 1, 128, "registration validator ID")),
    exactHex(history.consensus_key_hex, 32, "registration key"),
    uint(history.max_registration_nonce, 8),
    exactHex(history.current_proof_digest_hex, 32, "registration PoP digest"),
    exactHex(history.registration_decision_id_hex, 32, "registration decision"),
    uint(history.registration_height, 8),
  ]);
  return domainHash(REGISTRATION_HISTORY_DOMAIN, encoded);
}

function decodeBond(payload, identity, label) {
  const c = new Cursor(payload, label);
  invariant(c.bytes32("validator_id", 128).equals(identity), `${label}: identity`);
  const amount = c.u128("amount");
  invariant(amount > 0n, `${label}: zero amount`);
  const lockedUntil = c.u64("locked_until");
  const state = c.u8("state");
  invariant(state === 1 || state === 2, `${label}: state`);
  c.finish();
  return { amount, lockedUntil, state };
}

function decodeJail(payload, identity, label) {
  const c = new Cursor(payload, label);
  invariant(c.bytes32("validator_id", 128).equals(identity), `${label}: identity`);
  const jailedUntil = c.u64("jailed_until");
  const reason = c.u8("reason");
  invariant(reason >= 1 && reason <= 3, `${label}: reason`);
  c.finish();
  return { jailedUntil, reason };
}

function decodeRelationship(payload, identity, label) {
  const ic = new Cursor(identity, `${label}.identity`);
  const provider = ic.bytes32("provider", 128);
  const consumer = ic.bytes32("consumer", 128);
  const task = ic.bytes32("task", 128);
  ic.finish();
  const c = new Cursor(payload, label);
  invariant(c.bytes32("provider", 128).equals(provider), `${label}: provider`);
  invariant(c.bytes32("consumer", 128).equals(consumer), `${label}: consumer`);
  invariant(c.bytes32("task", 128).equals(task), `${label}: task`);
  const relationshipClass = c.u8("class");
  invariant(relationshipClass >= 1 && relationshipClass <= 4, `${label}: class`);
  const expiresAt = c.u64("expires_at");
  c.finish();
  return {
    provider_id_hex: provider.toString("hex"),
    consumer_id_hex: consumer.toString("hex"),
    task_id_hex: task.toString("hex"),
    relationship_class: relationshipClass,
    expires_at: expiresAt,
  };
}

function decodeLifecycle(payload, identity, label) {
  invariant(identity.length === 32, `${label}: certificate identity width`);
  const c = new Cursor(payload, label);
  invariant(c.take(32, "certificate_id").equals(identity), `${label}: certificate identity`);
  const state = c.u8("state");
  invariant(state >= 1 && state <= 5, `${label}: state`);
  const effectiveHeight = c.u64("effective_height");
  c.finish();
  return { certificate_id_hex: identity.toString("hex"), state, effectiveHeight };
}

function decodeGovernance(payload, identity, label) {
  invariant(identity.length === 8, `${label}: target epoch width`);
  const c = new Cursor(payload, label);
  const phase = c.u8("phase");
  invariant(phase >= 0 && phase <= 3, `${label}: phase`);
  const parametersHash = c.take(32, "parameters_hash");
  const activationHeight = c.u64("activation_height");
  invariant(activationHeight > 0n, `${label}: zero activation height`);
  const approval = c.u8("approval");
  invariant(approval === 0 || approval === 1, `${label}: approval`);
  c.finish();
  return {
    target_epoch: identity.readBigUInt64BE(0),
    phase,
    parameters_hash_hex: parametersHash.toString("hex"),
    activation_height: activationHeight,
    approval,
  };
}

function validateAuthorityJsonScalarTypes(state, label) {
  authorityU64(state.revision, `${label}.revision`);
  authorityU64(state.last_target_height, `${label}.last_target_height`);
  authorityU64(state.nullifier_count, `${label}.nullifier_count`);
  for (const [index, item] of state.consumer_keys.entries()) {
    authorityU64(item.active_from_height, `${label}.consumer_keys[${index}].active_from_height`);
    if (item.revoked_at_height !== null) authorityU64(item.revoked_at_height, `${label}.consumer_keys[${index}].revoked_at_height`);
    for (const [watermarkIndex, watermark] of item.nonce_watermarks.entries()) {
      authorityU64(watermark.max_accepted_nonce, `${label}.consumer_keys[${index}].nonce_watermarks[${watermarkIndex}].max_accepted_nonce`);
    }
  }
  for (const [index, item] of state.meter_policies.entries()) {
    authorityU32(item.meter_version, `${label}.meter_policies[${index}].meter_version`);
    authorityCanonicalU128(item.unit_scale, `${label}.meter_policies[${index}].unit_scale`);
    authorityCanonicalU128(item.per_certificate_cap, `${label}.meter_policies[${index}].per_certificate_cap`);
    authorityCanonicalU128(item.rolling_cap, `${label}.meter_policies[${index}].rolling_cap`);
    authorityU64(item.rolling_epoch_span, `${label}.meter_policies[${index}].rolling_epoch_span`);
    authorityU64(item.retention_blocks, `${label}.meter_policies[${index}].retention_blocks`);
    authorityU64(item.active_from_height, `${label}.meter_policies[${index}].active_from_height`);
    if (item.retired_at_height !== null) authorityU64(item.retired_at_height, `${label}.meter_policies[${index}].retired_at_height`);
  }
  for (const [field, hasMeterVersion] of [
    ["meter_usage", true], ["consumer_provider_usage", false],
    ["task_provider_usage", false], ["provider_usage", false],
  ]) {
    for (const [index, item] of state[field].entries()) {
      if (hasMeterVersion) authorityU32(item.meter_version, `${label}.${field}[${index}].meter_version`);
      authorityU64(item.window_epoch, `${label}.${field}[${index}].window_epoch`);
      authorityCanonicalU128(item.consumed_units, `${label}.${field}[${index}].consumed_units`);
    }
  }
  for (const [index, item] of state.funded_unused_reservations.entries()) {
    authorityU64(item.finalized_height, `${label}.funded_unused_reservations[${index}].finalized_height`);
    authorityCanonicalU128(item.reserved_units, `${label}.funded_unused_reservations[${index}].reserved_units`);
  }
  for (const [index, item] of state.active_certificates.entries()) {
    authorityU32(item.meter_version, `${label}.active_certificates[${index}].meter_version`);
    authorityU64(item.settlement_finalized_height, `${label}.active_certificates[${index}].settlement_finalized_height`);
    authorityCanonicalU128(item.consumed_units, `${label}.active_certificates[${index}].consumed_units`);
    authorityU8(item.relationship_class, `${label}.active_certificates[${index}].relationship_class`);
    authorityU64(item.provider_registration_nonce, `${label}.active_certificates[${index}].provider_registration_nonce`);
    authorityU64(item.provider_registration_height, `${label}.active_certificates[${index}].provider_registration_height`);
    authorityU64(item.accepted_height, `${label}.active_certificates[${index}].accepted_height`);
    authorityU64(item.finalized_epoch, `${label}.active_certificates[${index}].finalized_epoch`);
    authorityU64(item.prunable_after_height, `${label}.active_certificates[${index}].prunable_after_height`);
    authorityU64(item.lifecycle_effective_height, `${label}.active_certificates[${index}].lifecycle_effective_height`);
    for (const [keyIndex, key] of item.semantic_keys.entries()) {
      authorityU8(key.kind, `${label}.active_certificates[${index}].semantic_keys[${keyIndex}].kind`);
    }
  }
  for (const [index, item] of state.pending_challenges.entries()) {
    authorityU64(item.opened_height, `${label}.pending_challenges[${index}].opened_height`);
  }
  for (const [field, finalized] of [["pending_governance_proposals", false], ["finalized_governance_approvals", true]]) {
    for (const [index, item] of state[field].entries()) {
      authorityU64(item.target_epoch, `${label}.${field}[${index}].target_epoch`);
      authorityU8(item.phase, `${label}.${field}[${index}].phase`);
      authorityU64(item.proposed_height, `${label}.${field}[${index}].proposed_height`);
      if (finalized) authorityU64(item.approval_height, `${label}.${field}[${index}].approval_height`);
      authorityU64(item.activation_height, `${label}.${field}[${index}].activation_height`);
    }
  }
  for (const [index, item] of state.validator_registration_history.entries()) {
    authorityU64(item.max_registration_nonce, `${label}.validator_registration_history[${index}].max_registration_nonce`);
    authorityU64(item.registration_height, `${label}.validator_registration_history[${index}].registration_height`);
    authorityU64(item.retired_key_count, `${label}.validator_registration_history[${index}].retired_key_count`);
    if (item.revoked_at_height !== null) authorityU64(item.revoked_at_height, `${label}.validator_registration_history[${index}].revoked_at_height`);
  }
  for (const [index, item] of state.future_candidate_registrations.entries()) {
    authorityU64(item.target_epoch, `${label}.future_candidate_registrations[${index}].target_epoch`);
    authorityU64(item.registration_nonce, `${label}.future_candidate_registrations[${index}].registration_nonce`);
    if (item.previous_registration_nonce !== null) authorityU64(item.previous_registration_nonce, `${label}.future_candidate_registrations[${index}].previous_registration_nonce`);
    authorityU64(item.registration_height, `${label}.future_candidate_registrations[${index}].registration_height`);
  }
}

function decodeAuthority(payload, revision, label) {
  const state = decodeCanonicalAuthorityJson(payload, label);
  const required = [
    "schema", "revision", "last_target_height", "nullifier_root_hex", "nullifier_count",
    "consumer_keys", "meter_policies", "meter_usage", "consumer_provider_usage",
    "task_provider_usage", "provider_usage", "funded_unused_reservations",
    "active_certificates", "pending_challenges", "pending_governance_proposals",
    "finalized_governance_approvals", "validator_registration_history",
  ];
  const keys = Object.keys(state);
  const futureFamilyPresent = state.future_candidate_registrations !== undefined;
  const allowed = futureFamilyPresent ? [...required, "future_candidate_registrations"] : required;
  sameJson(keys, allowed, `${label}: field order`);
  invariant(state.schema === AUTHORITY_SCHEMA, `${label}: schema`);
  invariant(BigInt(state.revision) === revision && safeU64(state.revision, `${label}.revision`) > 0, `${label}: revision`);
  safeU64(state.last_target_height, `${label}.last_target_height`);
  exactHex(state.nullifier_root_hex, 32, `${label}.nullifier_root`);
  safeU64(state.nullifier_count, `${label}.nullifier_count`);
  for (const field of allowed.slice(5)) invariant(Array.isArray(state[field]), `${label}.${field}: array required`);
  invariant(
    !futureFamilyPresent || state.future_candidate_registrations.length > 0,
    `${label}.future_candidate_registrations: explicit empty family must be omitted`,
  );
  state.future_candidate_registrations ??= [];
  validateAuthorityJsonScalarTypes(state, label);

  for (const [field, records] of Object.entries(state)) {
    if (!Object.hasOwn(AUTHORITY_NESTED_FIELD_ORDER, field)) continue;
    for (const [index, record] of records.entries()) {
      exactKeys(record, AUTHORITY_NESTED_FIELD_ORDER[field], `${label}.${field}[${index}]`);
    }
  }
  let totalNonceWatermarks = 0;
  for (const [keyIndex, key] of state.consumer_keys.entries()) {
    invariant(Array.isArray(key.nonce_watermarks), `${label}.consumer_keys[${keyIndex}].nonce_watermarks: array required`);
    invariant(
      key.nonce_watermarks.length <= AUTHORITY_HARD_CAPS.nonce_watermarks_per_consumer_key,
      `${label}.consumer_keys[${keyIndex}]: nonce watermark cap`,
    );
    totalNonceWatermarks += key.nonce_watermarks.length;
    for (const [watermarkIndex, watermark] of key.nonce_watermarks.entries()) {
      exactKeys(
        watermark,
        AUTHORITY_NESTED_FIELD_ORDER.consumer_nonce_watermarks,
        `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}]`,
      );
    }
  }
  for (const [certificateIndex, certificate] of state.active_certificates.entries()) {
    invariant(Array.isArray(certificate.semantic_keys), `${label}.active_certificates[${certificateIndex}].semantic_keys: array required`);
    for (const [semanticIndex, semanticKey] of certificate.semantic_keys.entries()) {
      exactKeys(
        semanticKey,
        AUTHORITY_NESTED_FIELD_ORDER.semantic_keys,
        `${label}.active_certificates[${certificateIndex}].semantic_keys[${semanticIndex}]`,
      );
    }
  }

  invariant(state.consumer_keys.length <= AUTHORITY_HARD_CAPS.consumer_keys, `${label}: consumer-key cap`);
  invariant(totalNonceWatermarks <= AUTHORITY_HARD_CAPS.total_nonce_watermarks, `${label}: total nonce-watermark cap`);
  invariant(state.meter_policies.length <= AUTHORITY_HARD_CAPS.meter_policies, `${label}: meter-policy cap`);
  const totalUsageBuckets = state.meter_usage.length + state.consumer_provider_usage.length +
    state.task_provider_usage.length + state.provider_usage.length;
  invariant(totalUsageBuckets <= AUTHORITY_HARD_CAPS.total_usage_buckets, `${label}: aggregate usage-bucket cap`);
  for (const field of [
    "funded_unused_reservations", "active_certificates", "pending_challenges",
    "pending_governance_proposals", "finalized_governance_approvals",
    "validator_registration_history", "future_candidate_registrations",
  ]) {
    invariant(state[field].length <= AUTHORITY_HARD_CAPS[field], `${label}.${field}: record cap`);
  }
  const totalAuthorityRecords = state.consumer_keys.length + totalNonceWatermarks +
    state.meter_policies.length + totalUsageBuckets + state.funded_unused_reservations.length +
    state.active_certificates.length + state.pending_challenges.length +
    state.pending_governance_proposals.length + state.finalized_governance_approvals.length +
    state.validator_registration_history.length + state.future_candidate_registrations.length;
  invariant(
    totalAuthorityRecords <= AUTHORITY_HARD_CAPS.total_authority_records_including_nonce_watermarks,
    `${label}: total authority-record cap`,
  );
  return state;
}

// Rust's production projection constructor exact-decodes the kind-specific
// payload of every physical namespace-8 entry before any kind-16 companion or
// orphan analysis.  Keep that ordering here as well: an independently valid
// semantic role (for example an unreferenced relationship) may remain
// unaccompanied, but its raw payload is never allowed to bypass its decoder.
function decodeSemanticPayloadExact(kind, envelope, label) {
  const { identity, payload, revision } = envelope;
  switch (kind) {
    case 1: {
      invariant(identity.length === 32, `${label}: certificate identity width`);
      const certificate = decodeConsumptionCertificate(payload, label, false);
      invariant(certificate.certificate_id_hex === identity.toString("hex"), `${label}: certificate identity`);
      return certificate;
    }
    case 2: return decodeConsumerKey(payload, identity, label);
    case 3: return decodeConsumerNonce(payload, identity, label);
    case 4: return decodeConsumptionTuple(payload, identity, label);
    case 5: return decodeMeter(payload, identity, label);
    case 6: return decodeSettlement(payload, identity, label);
    case 7: return decodeMeasurement(payload, identity, label);
    case 8: return decodeRelationship(payload, identity, label);
    case 9: return decodeRegistration(payload, identity, label);
    case 10: return decodeBond(payload, identity, label);
    case 11: return decodeJail(payload, identity, label);
    case 12: return decodeLifecycle(payload, identity, label);
    case 13: {
      invariant(
        identity.length === 9 && (identity[0] === 1 || identity[0] === 2),
        `${label}: validator configuration identity must be role + epoch`,
      );
      const validatorSet = decodeValidatorSet(payload, label);
      invariant(
        BigInt(validatorSet.epoch) === identity.readBigUInt64BE(1),
        `${label}: validator set epoch identity`,
      );
      return validatorSet;
    }
    case 14:
      invariant(
        identity.length === 9 && (identity[0] === 1 || identity[0] === 2),
        `${label}: parameters identity must be role + target epoch`,
      );
      return decodeParameters(payload, label);
    case 15: return decodeGovernance(payload, identity, label);
    case 16:
      invariant(identity.equals(AUTHORITY_IDENTITY), `${label}: application authority identity`);
      return decodeAuthority(payload, revision, label);
    default: throw new Error(`${label}: unsupported semantic kind ${kind}`);
  }
}

function replayHistory(source, label) {
  exactKeys(source, ["head_version", "head_root_hex", "cutoff_version", "cutoff_root_hex", "history", "cutoff_projection", "head_projection"], label);
  const headVersion = safeU64(source.head_version, `${label}.head_version`);
  const cutoffVersion = safeU64(source.cutoff_version, `${label}.cutoff_version`);
  invariant(cutoffVersion <= headVersion, `${label}: cutoff after head`);
  exactHex(source.head_root_hex, 32, `${label}.head_root`);
  exactHex(source.cutoff_root_hex, 32, `${label}.cutoff_root`);
  invariant(Array.isArray(source.history) && source.history.length > 0, `${label}: empty history`);
  const live = new Map();
  let cutoffLive = null;
  let prior = null;
  for (const [index, item] of source.history.entries()) {
    exactKeys(item, ["version", "jmt_root_hex", "writes"], `${label}.history[${index}]`);
    const version = safeU64(item.version, `${label}.history[${index}].version`);
    invariant(prior === null ? version === 0 : version === prior + 1, `${label}: non-contiguous history`);
    prior = version;
    exactHex(item.jmt_root_hex, 32, `${label}.history[${index}].root`);
    invariant(Array.isArray(item.writes), `${label}: writes array`);
    const writeKeys = new Set();
    for (const [writeIndex, write] of item.writes.entries()) {
      exactKeys(write, ["physical_key_hex", "value_hex"], `${label}.history[${index}].writes[${writeIndex}]`);
      const key = boundedHex(write.physical_key_hex, 1, 1_048_576, `${label}.write.key`).toString("hex");
      invariant(!writeKeys.has(key), `${label}: duplicate physical write in version ${version}`);
      writeKeys.add(key);
      if (write.value_hex === null) live.delete(key);
      else {
        boundedHex(write.value_hex, 0, 8_388_608, `${label}.write.value`);
        live.set(key, write.value_hex);
      }
    }
    const recomputedRoot = jmtRoot(live).toString("hex");
    invariant(item.jmt_root_hex === recomputedRoot, `${label}: JMT root mismatch at version ${version}`);
    stats.jmtRoots += 1;
    if (version === cutoffVersion) {
      cutoffLive = new Map(live);
      invariant(item.jmt_root_hex === source.cutoff_root_hex, `${label}: cutoff history root`);
    }
  }
  invariant(prior === headVersion, `${label}: history/head version`);
  invariant(source.history.at(-1).jmt_root_hex === source.head_root_hex, `${label}: history/head root`);
  invariant(cutoffLive !== null, `${label}: cutoff absent from continuous history`);
  stats.histories += 1;
  return { cutoffLive, headLive: live, cutoffVersion, headVersion };
}

function validateProjection(raw, version, live, label) {
  exactKeys(raw, ["manifest_hex", "entries_root_hex", "entries"], label);
  invariant(Array.isArray(raw.entries) && raw.entries.length >= 1 && raw.entries.length <= 10_000, `${label}: entry count`);
  const entries = [];
  let prior = null;
  for (const [index, item] of raw.entries.entries()) {
    exactKeys(item, ["kind", "logical_key_hex", "value_hex", "canonical_entry_cev0_hex"], `${label}.entries[${index}]`);
    invariant(Number.isInteger(item.kind) && item.kind >= 1 && item.kind <= 16, `${label}: kind`);
    const key = exactHex(item.logical_key_hex, 32, `${label}.entries[${index}].key`);
    const value = boundedHex(item.value_hex, 1, 65_536, `${label}.entries[${index}].value`);
    const order = Buffer.concat([Buffer.from([item.kind]), key]);
    invariant(prior === null || Buffer.compare(prior, order) < 0, `${label}: entries not strictly sorted`);
    prior = order;
    const canonical = canonicalEntry(item.kind, key, value);
    invariant(canonical.toString("hex") === item.canonical_entry_cev0_hex, `${label}: canonical entry drift`);
    invariant(live.get(entryPhysicalKey(item.kind, key).toString("hex")) === item.value_hex, `${label}: entry absent from physical history`);
    const envelope = decodeSemanticEnvelope({ kind: item.kind, key, value }, `${label}.entries[${index}].envelope`);
    const exactPayload = decodeSemanticPayloadExact(
      item.kind,
      envelope,
      `${label}.entries[${index}].kind_${item.kind}`,
    );
    entries.push({ kind: item.kind, key, value, canonical, envelope, exactPayload, raw: item });
  }
  const root = orderedRoot(ENTRY_DOMAIN, ENTRY_NODE_DOMAIN, ENTRY_ROOT_DOMAIN, entries.map((entry) => entry.canonical));
  invariant(root.equals(exactHex(raw.entries_root_hex, 32, `${label}.entries_root`)), `${label}: entries root`);
  const manifestRaw = exactHex(raw.manifest_hex, 47, `${label}.manifest`);
  invariant(live.get(manifestKey().toString("hex")) === raw.manifest_hex, `${label}: manifest absent from physical history`);
  const manifest = decodeManifest(manifestRaw, `${label}.manifest`);
  invariant(manifest.height === BigInt(version), `${label}: manifest cutoff height`);
  invariant(manifest.count === entries.length && manifest.root.equals(root), `${label}: manifest tuple`);
  const expectedPhysicalKeys = new Set([
    manifestKey().toString("hex"),
    ...entries.map((entry) => entryPhysicalKey(entry.kind, entry.key).toString("hex")),
  ]);
  const actualPhysicalKeys = new Set();
  for (const keyHex of live.keys()) {
    const key = Buffer.from(keyHex, "hex");
    const decoded = decodePocoPhysicalKey(key, `${label}.physical[${keyHex}]`);
    if (decoded !== null) actualPhysicalKeys.add(keyHex);
  }
  invariant(
    actualPhysicalKeys.size === expectedPhysicalKeys.size &&
      [...actualPhysicalKeys].every((key) => expectedPhysicalKeys.has(key)),
    `${label}: physical namespace contains hidden, additional, duplicate, or missing leaves`,
  );
  stats.projections += 1;
  return { entries, root, manifest, byKindKey: new Map(entries.map((entry) => [`${entry.kind}:${entry.key.toString("hex")}`, entry])) };
}

function oneEntry(projection, kind, predicate, label) {
  const found = projection.entries.filter((entry) => entry.kind === kind && predicate(entry));
  invariant(found.length === 1, `${label}: expected exactly one entry, found ${found.length}`);
  return found[0];
}

function entryFromRef(projection, reference, label) {
  invariant(Number.isInteger(reference.kind) && reference.kind >= 1 && reference.kind <= 16, `${label}: kind`);
  exactHex(reference.logical_key_hex, 32, `${label}: key`);
  const entry = projection.byKindKey.get(`${reference.kind}:${reference.logical_key_hex}`);
  invariant(entry !== undefined, `${label}: referenced semantic companion missing`);
  return entry;
}

function reconstructAuthority(profile, projection, label) {
  const activeEpoch = BigInt(profile.active_epoch);
  const targetEpoch = BigInt(profile.target_epoch);
  invariant(targetEpoch === activeEpoch + 1n, `${label}: target epoch is not successor`);
  const activeSetEntry = oneEntry(
    projection,
    13,
    (entry) => entry.envelope.identity.length === 9 && entry.envelope.identity[0] === 1 && entry.envelope.identity.readBigUInt64BE(1) === activeEpoch,
    `${label}.active_validator_set`,
  );
  const oldSet = decodeValidatorSet(activeSetEntry.envelope.payload, `${label}.active_validator_set`);
  const activeParametersEntry = oneEntry(
    projection,
    14,
    (entry) => entry.envelope.identity.length === 9 && entry.envelope.identity[0] === 1 && entry.envelope.identity.readBigUInt64BE(1) === activeEpoch,
    `${label}.active_parameters`,
  );
  const oldParametersRaw = activeParametersEntry.envelope.payload;
  const oldParameters = decodeParameters(oldParametersRaw, `${label}.active_parameters`);
  const oldParametersHash = domainHash(PARAMETERS_DOMAIN, oldParametersRaw);
  invariant(oldSet.consensus_parameters_hash_hex === oldParametersHash.toString("hex"), `${label}: active set/parameters hash`);
  invariant(oldSet.epoch === activeEpoch.toString(), `${label}: active set epoch`);
  invariant(oldSet.genesis_hash_hex === profile.genesis_hash_hex && oldSet.chain_id_ascii === profile.chain_id_utf8, `${label}: set chain/genesis`);

  const authorityEntry = oneEntry(
    projection,
    16,
    (entry) => entry.envelope.identity.equals(AUTHORITY_IDENTITY),
    `${label}.authority`,
  );
  const authority = decodeAuthority(authorityEntry.envelope.payload, authorityEntry.envelope.revision, `${label}.authority`);
  invariant(
    (BigInt(authority.revision) === 1n) === (BigInt(authority.last_target_height) === 0n),
    `${label}: authority genesis revision/height mismatch`,
  );
  invariant(BigInt(authority.last_target_height) <= projection.manifest.height, `${label}: authority target height ahead of cutoff`);

  const referenced = new Set();
  const reference = (entry) => referenced.add(`${entry.kind}:${entry.key.toString("hex")}`);
  const consumerKeys = new Map();
  requireStrictOrder(
    authority.consumer_keys,
    (item) => [item.consumer_id_hex, item.consumer_key_id_hex],
    `${label}.authority.consumer_keys`,
  );
  for (const [keyIndex, item] of authority.consumer_keys.entries()) {
    const consumerId = boundedHex(item.consumer_id_hex, 1, 128, `${label}.consumer_keys[${keyIndex}].consumer_id`);
    const consumerKeyId = boundedHex(item.consumer_key_id_hex, 1, 128, `${label}.consumer_keys[${keyIndex}].consumer_key_id`);
    const publicKey = exactHex(item.public_key_hex, 32, `${label}.consumer_keys[${keyIndex}].public_key`);
    invariant(!publicKey.equals(Buffer.alloc(32)), `${label}: zero consumer public key`);
    const activeFrom = requireRecordedHeight(item.active_from_height, authority.last_target_height, `${label}.consumer_keys[${keyIndex}].active_from_height`);
    exactHex(item.authorization_decision_id_hex, 32, `${label}.consumer_keys[${keyIndex}].authorization_decision`);
    invariant(
      (item.revoked_at_height === null) === (item.revocation_decision_id_hex === null),
      `${label}: incomplete consumer-key revocation authority`,
    );
    if (item.revoked_at_height !== null) {
      const revokedAt = requireRecordedHeight(item.revoked_at_height, authority.last_target_height, `${label}.consumer_keys[${keyIndex}].revoked_at_height`);
      invariant(revokedAt > activeFrom, `${label}: non-monotonic consumer-key revocation`);
      exactHex(item.revocation_decision_id_hex, 32, `${label}.consumer_keys[${keyIndex}].revocation_decision`);
    }
    const identity = joinedIdentity([consumerId, consumerKeyId]);
    const entry = entryForIdentity(projection, 2, identity, `${label}.consumer_keys[${keyIndex}]`);
    const raw = decodeConsumerKey(entry.envelope.payload, entry.envelope.identity, `${label}.consumer_keys[${keyIndex}].kind2`);
    invariant(
      raw.public_key_hex === item.public_key_hex &&
        raw.active_from === BigInt(item.active_from_height) &&
        raw.revoked_at === (item.revoked_at_height === null ? null : BigInt(item.revoked_at_height)),
      `${label}: consumer-key authority diverges from exact kind-2 fact`,
    );
    reference(entry);
    requireStrictOrder(
      item.nonce_watermarks,
      (watermark) => [watermark.provider_id_hex],
      `${label}.consumer_keys[${keyIndex}].nonce_watermarks`,
    );
    const watermarks = new Map();
    for (const [watermarkIndex, watermark] of item.nonce_watermarks.entries()) {
      const providerId = boundedHex(watermark.provider_id_hex, 1, 128, `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}].provider_id`);
      const nonceIdentity = joinedIdentity([consumerId, consumerKeyId, providerId]);
      const nonceKey = semanticLogicalKey(3, nonceIdentity);
      invariant(nonceKey.toString("hex") === watermark.logical_key_hex, `${label}: nonce watermark logical-key drift`);
      const nonceEntry = entryForIdentity(projection, 3, nonceIdentity, `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}]`);
      const nonce = decodeConsumerNonce(nonceEntry.envelope.payload, nonceEntry.envelope.identity, `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}].kind3`);
      invariant(nonce.max_accepted_nonce === BigInt(watermark.max_accepted_nonce), `${label}: nonce watermark diverges from kind-3 fact`);
      reference(nonceEntry);
      watermarks.set(watermark.provider_id_hex, nonce);
    }
    consumerKeys.set(`${item.consumer_id_hex}:${item.consumer_key_id_hex}`, { item, raw, entry, watermarks });
  }

  const meterPolicies = new Map();
  requireStrictOrder(
    authority.meter_policies,
    (item) => [item.meter_id_hex, BigInt(item.meter_version)],
    `${label}.authority.meter_policies`,
  );
  for (const [policyIndex, policy] of authority.meter_policies.entries()) {
    const meterId = boundedHex(policy.meter_id_hex, 1, 128, `${label}.meter_policies[${policyIndex}].meter_id`);
    boundedHex(policy.task_id_hex, 1, 128, `${label}.meter_policies[${policyIndex}].task_id`);
    if (policy.output_commitment_hex !== null) exactHex(policy.output_commitment_hex, 32, `${label}.meter_policies[${policyIndex}].output`);
    const unitScale = BigInt(canonicalU128(policy.unit_scale, `${label}.meter_policies[${policyIndex}].unit_scale`));
    const perCertificateCap = BigInt(canonicalU128(policy.per_certificate_cap, `${label}.meter_policies[${policyIndex}].per_certificate_cap`));
    const rollingCap = BigInt(canonicalU128(policy.rolling_cap, `${label}.meter_policies[${policyIndex}].rolling_cap`));
    invariant(unitScale > 0n && perCertificateCap > 0n && rollingCap > 0n && perCertificateCap <= rollingCap, `${label}: invalid meter caps`);
    invariant(["required", "forbidden", "optional"].includes(policy.evidence_policy), `${label}: invalid meter evidence policy`);
    invariant(BigInt(policy.rolling_epoch_span) > 0n && BigInt(policy.retention_blocks) > 0n, `${label}: zero meter span/retention`);
    const activeFrom = requireRecordedHeight(policy.active_from_height, authority.last_target_height, `${label}.meter_policies[${policyIndex}].active_from_height`);
    if (policy.retired_at_height !== null) {
      const retiredAt = requireRecordedHeight(policy.retired_at_height, authority.last_target_height, `${label}.meter_policies[${policyIndex}].retired_at_height`);
      invariant(retiredAt > activeFrom, `${label}: invalid meter retirement interval`);
    }
    const identity = meterIdentity(meterId, policy.meter_version);
    const entry = entryForIdentity(projection, 5, identity, `${label}.meter_policies[${policyIndex}]`);
    const raw = decodeMeter(entry.envelope.payload, entry.envelope.identity, `${label}.meter_policies[${policyIndex}].kind5`);
    invariant(
      raw.unit_scale === unitScale && raw.active_from === BigInt(policy.active_from_height) &&
        raw.retired_at === (policy.retired_at_height === null ? null : BigInt(policy.retired_at_height)),
      `${label}: meter authority diverges from exact kind-5 fact`,
    );
    reference(entry);
    meterPolicies.set(`${policy.meter_id_hex}:${policy.meter_version}`, { policy, raw, entry });
  }

  requireStrictOrder(authority.meter_usage, (item) => [item.meter_id_hex, BigInt(item.meter_version), BigInt(item.window_epoch)], `${label}.authority.meter_usage`);
  for (const [index, usage] of authority.meter_usage.entries()) {
    const policy = meterPolicies.get(`${usage.meter_id_hex}:${usage.meter_version}`)?.policy;
    invariant(policy !== undefined, `${label}.meter_usage[${index}]: absent meter policy`);
    canonicalU128(usage.consumed_units, `${label}.meter_usage[${index}].consumed_units`);
    invariant(BigInt(usage.window_epoch) === activeEpoch / BigInt(policy.rolling_epoch_span), `${label}.meter_usage[${index}]: active window drift`);
  }
  for (const [field, tuple] of [
    ["consumer_provider_usage", (item) => [item.consumer_id_hex, item.provider_id_hex, BigInt(item.window_epoch)]],
    ["task_provider_usage", (item) => [item.task_id_hex, item.provider_id_hex, BigInt(item.window_epoch)]],
    ["provider_usage", (item) => [item.provider_id_hex, BigInt(item.window_epoch)]],
  ]) {
    requireStrictOrder(authority[field], tuple, `${label}.authority.${field}`);
    for (const [index, usage] of authority[field].entries()) {
      invariant(BigInt(usage.window_epoch) === activeEpoch, `${label}.${field}[${index}]: active window drift`);
      canonicalU128(usage.consumed_units, `${label}.${field}[${index}].consumed_units`);
      for (const idField of Object.keys(usage).filter((key) => key.endsWith("_id_hex"))) {
        boundedHex(usage[idField], 1, 128, `${label}.${field}[${index}].${idField}`);
      }
    }
  }

  requireStrictOrder(authority.funded_unused_reservations, (item) => [item.certificate_id_hex], `${label}.authority.funded_unused_reservations`);
  for (const [index, reservation] of authority.funded_unused_reservations.entries()) {
    const certificateId = exactHex(reservation.certificate_id_hex, 32, `${label}.reservations[${index}].certificate_id`);
    exactHex(reservation.settlement_commitment_hex, 32, `${label}.reservations[${index}].commitment`);
    exactHex(reservation.funding_decision_id_hex, 32, `${label}.reservations[${index}].funding_decision`);
    requireRecordedHeight(reservation.finalized_height, authority.last_target_height, `${label}.reservations[${index}].finalized_height`);
    invariant(BigInt(canonicalU128(reservation.reserved_units, `${label}.reservations[${index}].reserved_units`)) > 0n, `${label}: zero reservation units`);
    const entry = entryForIdentity(projection, 6, certificateId, `${label}.reservations[${index}]`);
    const settlement = decodeSettlement(entry.envelope.payload, entry.envelope.identity, `${label}.reservations[${index}].kind6`);
    invariant(
      settlement.state === 1 && settlement.commitment_hex === reservation.settlement_commitment_hex &&
        settlement.finalized_height === BigInt(reservation.finalized_height),
      `${label}: funded reservation diverges from exact settlement fact`,
    );
    reference(entry);
  }

  requireStrictOrder(authority.pending_governance_proposals, (item) => [BigInt(item.target_epoch)], `${label}.authority.pending_governance_proposals`);
  requireStrictOrder(authority.finalized_governance_approvals, (item) => [BigInt(item.target_epoch)], `${label}.authority.finalized_governance_approvals`);
  const governanceTargets = new Set();
  const governanceCompanions = new Map();
  const expectedActivationHeight = (activeEpoch + 1n) * BigInt(oldParameters.epoch_length_blocks) + 1n;
  const validateGovernanceRecord = (record, approval, recordLabel) => {
    const recordTarget = BigInt(record.target_epoch);
    invariant(recordTarget === targetEpoch && BigInt(record.activation_height) === expectedActivationHeight, `${recordLabel}: target/activation is not exact active successor`);
    invariant(!governanceTargets.has(recordTarget.toString()), `${recordLabel}: target is both pending/final or duplicated`);
    governanceTargets.add(recordTarget.toString());
    invariant(Number.isInteger(record.phase) && record.phase >= 0 && record.phase <= 3, `${recordLabel}: rollout phase`);
    exactHex(record.proposal_decision_id_hex, 32, `${recordLabel}.proposal_decision`);
    exactHex(record.parameters_hash_hex, 32, `${recordLabel}.parameters_hash`);
    const proposedHeight = requireRecordedHeight(record.proposed_height, authority.last_target_height, `${recordLabel}.proposed_height`);
    invariant(proposedHeight < BigInt(record.activation_height), `${recordLabel}: proposal does not precede activation`);
    if (approval === 1) {
      exactHex(record.decision_id_hex, 32, `${recordLabel}.decision_id`);
      const approvalHeight = requireRecordedHeight(record.approval_height, authority.last_target_height, `${recordLabel}.approval_height`);
      invariant(proposedHeight < approvalHeight && approvalHeight < BigInt(record.activation_height), `${recordLabel}: approval heights are not monotonic`);
    }
    const governanceEntry = entryForIdentity(projection, 15, uint(recordTarget, 8), `${recordLabel}.kind15`);
    const governance = decodeGovernance(governanceEntry.envelope.payload, governanceEntry.envelope.identity, `${recordLabel}.kind15`);
    invariant(
      governance.target_epoch === recordTarget && governance.phase === record.phase &&
        governance.parameters_hash_hex === record.parameters_hash_hex &&
        governance.activation_height === BigInt(record.activation_height) && governance.approval === approval,
      `${recordLabel}: governance companion drift`,
    );
    const parameterIdentity = Buffer.concat([Buffer.from([2]), uint(recordTarget, 8)]);
    const parameterEntry = entryForIdentity(projection, 14, parameterIdentity, `${recordLabel}.role2_parameters`);
    const parameters = decodeParameters(parameterEntry.envelope.payload, `${recordLabel}.role2_parameters`);
    invariant(domainHash(PARAMETERS_DOMAIN, parameterEntry.envelope.payload).toString("hex") === record.parameters_hash_hex, `${recordLabel}: role-2 parameter hash drift`);
    invariant(parameters.rollout_phase === record.phase, `${recordLabel}: rollout phase/parameters drift`);
    invariant(parameters.epoch_length_blocks === oldParameters.epoch_length_blocks, `${recordLabel}: epoch length drift`);
    reference(governanceEntry);
    reference(parameterEntry);
    governanceCompanions.set(recordTarget.toString(), { governanceEntry, parameterEntry, parameters });
  };
  for (const [index, proposal] of authority.pending_governance_proposals.entries()) {
    validateGovernanceRecord(proposal, 0, `${label}.pending_governance[${index}]`);
  }
  for (const [index, approval] of authority.finalized_governance_approvals.entries()) {
    validateGovernanceRecord(approval, 1, `${label}.finalized_governance[${index}]`);
  }

  const approvals = authority.finalized_governance_approvals.filter((entry) => BigInt(entry.target_epoch) === targetEpoch);
  invariant(approvals.length <= 1, `${label}: duplicate target approval`);
  let candidateParameters = oldParameters;
  let candidateParametersRaw = oldParametersRaw;
  if (approvals.length === 1) {
    const approval = approvals[0];
    const { parameterEntry, governanceEntry } = governanceCompanions.get(targetEpoch.toString());
    const governance = decodeGovernance(governanceEntry.envelope.payload, governanceEntry.envelope.identity, `${label}.finalized_governance`);
    invariant(governance.approval === 1 && governance.phase === approval.phase, `${label}: approval phase`);
    invariant(governance.parameters_hash_hex === approval.parameters_hash_hex, `${label}: approval parameter hash`);
    invariant(governance.activation_height === BigInt(approval.activation_height), `${label}: approval activation`);
    candidateParametersRaw = parameterEntry.envelope.payload;
    candidateParameters = decodeParameters(candidateParametersRaw, `${label}.candidate_parameters`);
    invariant(domainHash(PARAMETERS_DOMAIN, candidateParametersRaw).toString("hex") === approval.parameters_hash_hex, `${label}: candidate parameter preimage`);
    invariant(candidateParameters.rollout_phase === approval.phase, `${label}: rollout enum crosswalk`);
  }
  invariant(candidateParameters.epoch_length_blocks === oldParameters.epoch_length_blocks, `${label}: epoch length drift`);

  const registrations = new Map();
  const historicalKeys = new Set();
  let priorHistoryId = null;
  for (const history of authority.validator_registration_history) {
    const id = boundedHex(history.validator_id_hex, 1, 128, `${label}.history.id`);
    invariant(priorHistoryId === null || priorHistoryId < history.validator_id_hex, `${label}: registration histories not strictly sorted`);
    priorHistoryId = history.validator_id_hex;
    invariant(!registrations.has(history.validator_id_hex), `${label}: duplicate registration history`);
    invariant(!historicalKeys.has(history.consensus_key_hex), `${label}: registration key reused across histories`);
    historicalKeys.add(history.consensus_key_hex);
    exactHex(history.history_head_hex, 32, `${label}: registration history head`);
    exactHex(history.consensus_key_hex, 32, `${label}: registration consensus key`);
    exactHex(history.current_proof_digest_hex, 32, `${label}: registration proof digest`);
    exactHex(history.registration_decision_id_hex, 32, `${label}: registration decision`);
    requireRecordedHeight(history.registration_height, authority.last_target_height, `${label}: registration height`);
    invariant(registrationHistoryHead(history).toString("hex") === history.history_head_hex, `${label}: registration history head`);
    const previousHead = exactHex(history.previous_history_head_hex, 32, `${label}: previous history head`);
    invariant(
      (BigInt(history.retired_key_count) === 0n) === previousHead.equals(Buffer.alloc(32)),
      `${label}: predecessor head/retired-key count`,
    );
    invariant(
      (history.revoked_at_height === null) === (history.revocation_decision_id_hex === null),
      `${label}: incomplete registration revocation`,
    );
    if (history.revoked_at_height !== null) {
      invariant(
        BigInt(history.revoked_at_height) > BigInt(history.registration_height) &&
          BigInt(history.revoked_at_height) <= BigInt(authority.last_target_height),
        `${label}: invalid registration revocation height`,
      );
      exactHex(history.revocation_decision_id_hex, 32, `${label}: registration revocation decision`);
    }
    const raw = oneEntry(
      projection,
      9,
      (entry) => entry.envelope.identity.equals(id),
      `${label}.registration.${history.validator_id_hex}`,
    );
    const registration = decodeRegistration(raw.envelope.payload, raw.envelope.identity, `${label}.registration.${history.validator_id_hex}`);
    reference(raw);
    invariant(registration.consensus_key_hex === history.consensus_key_hex, `${label}: registration key companion`);
    invariant(registration.registration_nonce === BigInt(history.max_registration_nonce), `${label}: registration nonce companion`);
    invariant(registration.proof_digest.toString("hex") === history.current_proof_digest_hex, `${label}: registration proof digest`);
    invariant(registration.state === (history.revoked_at_height === null ? 1 : 2), `${label}: registration lifecycle`);
    verifyPop(registration.pop, {
      genesis_hash_hex: profile.genesis_hash_hex,
      chain_id_ascii: profile.chain_id_utf8,
      target_epoch: registration.pop.fields.target_epoch,
      validator_id_hex: history.validator_id_hex,
      public_key_hex: history.consensus_key_hex,
      registration_nonce: history.max_registration_nonce,
    }, `${label}.registration.${history.validator_id_hex}.pop`);
    const registrationEpoch = BigInt(registration.pop.fields.target_epoch);
    invariant(registrationEpoch <= activeEpoch, `${label}: active registration from future epoch`);
    const registrationStart = registrationEpoch * BigInt(oldParameters.epoch_length_blocks) + 1n;
    const registrationEnd = (registrationEpoch + 1n) * BigInt(oldParameters.epoch_length_blocks);
    invariant(
      BigInt(history.registration_height) >= registrationStart &&
        BigInt(history.registration_height) <= registrationEnd &&
        BigInt(history.registration_height) <= BigInt(authority.last_target_height),
      `${label}: registration height outside authenticated PoP epoch`,
    );
    registrations.set(history.validator_id_hex, { history, registration });
  }

  const bonds = new Map();
  const jails = new Map();
  for (const entry of projection.entries) {
    if (entry.kind === 10) {
      invariant(!bonds.has(entry.envelope.identity.toString("hex")), `${label}: duplicate bond`);
      bonds.set(entry.envelope.identity.toString("hex"), decodeBond(entry.envelope.payload, entry.envelope.identity, `${label}.bond`));
    } else if (entry.kind === 11) {
      invariant(!jails.has(entry.envelope.identity.toString("hex")), `${label}: duplicate jail`);
      jails.set(entry.envelope.identity.toString("hex"), decodeJail(entry.envelope.payload, entry.envelope.identity, `${label}.jail`));
    }
  }

  const coverageEnd = targetEpoch + BigInt(candidateParameters.evidence_window_epochs);
  invariant(coverageEnd <= MAX_U64, `${label}: bond evidence-window overflow`);
  const candidates = new Map();
  for (const validator of oldSet.validators) {
    const source = registrations.get(validator.validator_id_hex);
    if (!source || source.history.revoked_at_height !== null || source.history.consensus_key_hex !== validator.consensus_key_hex) continue;
    const bond = bonds.get(validator.validator_id_hex);
    const jail = jails.get(validator.validator_id_hex);
    candidates.set(validator.validator_id_hex, {
      validator_id_hex: validator.validator_id_hex,
      consensus_key_hex: validator.consensus_key_hex,
      active_slashable_bond: bond && bond.state === 1 && coverageEnd < bond.lockedUntil ? bond.amount.toString() : "0",
      jailed: jail ? targetEpoch < jail.jailedUntil : false,
      registration_valid: true,
      previous_registration_nonce: null,
      proof_fixture_id: null,
      proof_cev0_hex: null,
    });
  }

  const popById = new Map();
  const futureIds = new Set();
  const futureKeys = new Set();
  let priorFuture = null;
  for (const future of authority.future_candidate_registrations) {
    const ordering = `${String(future.target_epoch).padStart(20, "0")}:${future.validator_id_hex}`;
    invariant(priorFuture === null || priorFuture < ordering, `${label}: future registrations not strictly sorted`);
    priorFuture = ordering;
    invariant(!futureIds.has(future.validator_id_hex), `${label}: duplicate future candidate ID`);
    futureIds.add(future.validator_id_hex);
    invariant(!futureKeys.has(future.consensus_key_hex), `${label}: duplicate future candidate key`);
    invariant(!historicalKeys.has(future.consensus_key_hex), `${label}: future key reuses registration-history key`);
    const futureKey = exactHex(future.consensus_key_hex, 32, `${label}: future consensus key`);
    invariant(!futureKey.equals(Buffer.alloc(32)), `${label}: zero future consensus key`);
    invariant(
      oldSet.validators.every((validator) =>
        validator.validator_id_hex === future.validator_id_hex ||
          validator.consensus_key_hex !== future.consensus_key_hex
      ),
      `${label}: future candidate key belongs to another old validator`,
    );
    futureKeys.add(future.consensus_key_hex);
    invariant(BigInt(future.target_epoch) === targetEpoch, `${label}: future target`);
    const id = boundedHex(future.validator_id_hex, 1, 128, `${label}.future.id`);
    const proofRaw = boundedHex(future.proof_cev0_hex, 1, 65_384, `${label}.future.proof`);
    const proof = decodePopExact(proofRaw);
    invariant(domainHash(FUTURE_POP_DIGEST_DOMAIN, proofRaw).toString("hex") === future.proof_digest_hex, `${label}: future proof digest`);
    exactHex(future.registration_decision_id_hex, 32, `${label}: future registration decision`);
    verifyPop(proof, {
      genesis_hash_hex: profile.genesis_hash_hex,
      chain_id_ascii: profile.chain_id_utf8,
      target_epoch: targetEpoch.toString(),
      validator_id_hex: future.validator_id_hex,
      public_key_hex: future.consensus_key_hex,
      registration_nonce: future.registration_nonce,
    }, `${label}.future.${future.validator_id_hex}.pop`);
    const activeStart = activeEpoch * BigInt(oldParameters.epoch_length_blocks) + 1n;
    const activeEnd = (activeEpoch + 1n) * BigInt(oldParameters.epoch_length_blocks);
    invariant(
      BigInt(future.registration_height) >= activeStart &&
        BigInt(future.registration_height) <= activeEnd &&
        BigInt(future.registration_height) <= BigInt(authority.last_target_height),
      `${label}: future registration height outside source active epoch`,
    );
    const old = oldSet.validators.find((validator) => validator.validator_id_hex === future.validator_id_hex);
    const predecessorHead = exactHex(future.predecessor_history_head_hex, 32, `${label}: future predecessor history head`);
    if (old) {
      invariant(old.consensus_key_hex !== future.consensus_key_hex, `${label}: redundant same-key future registration`);
      const predecessor = registrations.get(future.validator_id_hex);
      invariant(predecessor && predecessor.history.revoked_at_height === null, `${label}: changed key lacks active predecessor`);
      invariant(
        predecessor.history.consensus_key_hex === old.consensus_key_hex &&
          future.previous_registration_nonce === predecessor.history.max_registration_nonce &&
          future.predecessor_history_head_hex === predecessor.history.history_head_hex,
        `${label}: changed-key predecessor old-key/nonce/history authority`,
      );
      invariant(BigInt(future.registration_nonce) > BigInt(future.previous_registration_nonce), `${label}: non-increasing future nonce`);
    } else {
      invariant(
        future.previous_registration_nonce === null && predecessorHead.equals(Buffer.alloc(32)),
        `${label}: new member has predecessor`,
      );
    }
    const fixtureId = `raw-future:${future.validator_id_hex}`;
    popById.set(fixtureId, { id: fixtureId, cev0_hex: future.proof_cev0_hex });
    const bond = bonds.get(future.validator_id_hex);
    const jail = jails.get(future.validator_id_hex);
    candidates.set(future.validator_id_hex, {
      validator_id_hex: future.validator_id_hex,
      consensus_key_hex: future.consensus_key_hex,
      active_slashable_bond: bond && bond.state === 1 && coverageEnd < bond.lockedUntil ? bond.amount.toString() : "0",
      jailed: jail ? targetEpoch < jail.jailedUntil : false,
      registration_valid: true,
      previous_registration_nonce: future.previous_registration_nonce === null ? null : String(future.previous_registration_nonce),
      proof_fixture_id: fixtureId,
      proof_cev0_hex: future.proof_cev0_hex,
    });
    invariant(id.toString("hex") === future.validator_id_hex, `${label}: future ID roundtrip`);
  }

  const candidateIds = new Set(candidates.keys());
  const contributions = [];
  const lifecycleCode = { accepted: 1, challenge_rejected: 4, challenge_sustained: 5 };
  let priorCertificateId = null;
  for (const certificate of authority.active_certificates) {
    invariant(
      priorCertificateId === null || priorCertificateId < certificate.certificate_id_hex,
      `${label}: active certificates not strictly sorted`,
    );
    priorCertificateId = certificate.certificate_id_hex;
    const certificateId = exactHex(certificate.certificate_id_hex, 32, `${label}: certificate ID`);
    for (const field of ["consumer_id_hex", "consumer_key_id_hex", "provider_id_hex", "task_id_hex", "meter_id_hex"]) {
      boundedHex(certificate[field], 1, 128, `${label}.certificate.${field}`);
    }
    for (const field of [
      "settlement_commitment_hex", "relationship_key_hex", "provider_consensus_key_hex",
      "provider_proof_digest_hex", "provider_registration_decision_id_hex",
      "provider_registration_history_head_hex", "acceptance_decision_id_hex",
      "funding_decision_id_hex", "meter_decision_id_hex", "evidence_decision_id_hex",
      "tuple_key_hex", "lifecycle_decision_id_hex",
    ]) exactHex(certificate[field], 32, `${label}.certificate.${field}`);
    if (certificate.evidence_root_hex !== null) exactHex(certificate.evidence_root_hex, 32, `${label}.certificate.evidence_root`);
    invariant(certificate.relationship_class >= 1 && certificate.relationship_class <= 4, `${label}: certificate relationship class`);
    invariant(["accepted", "challenge_rejected", "challenge_sustained"].includes(certificate.lifecycle), `${label}: certificate lifecycle enum`);
    const settlementFinalizedHeight = requireRecordedHeight(certificate.settlement_finalized_height, authority.last_target_height, `${label}: settlement finalized height`);
    const acceptedHeight = requireRecordedHeight(certificate.accepted_height, authority.last_target_height, `${label}: certificate accepted height`);
    const lifecycleHeight = requireRecordedHeight(certificate.lifecycle_effective_height, authority.last_target_height, `${label}: certificate lifecycle height`);
    const providerRegistrationHeight = requireRecordedHeight(certificate.provider_registration_height, authority.last_target_height, `${label}: provider registration height`);
    invariant(settlementFinalizedHeight <= acceptedHeight && providerRegistrationHeight <= acceptedHeight, `${label}: certificate predates settlement/provider authority`);
    invariant(BigInt(canonicalU128(certificate.consumed_units, `${label}: certificate consumed units`)) > 0n, `${label}: zero certificate units`);
    invariant(BigInt(certificate.prunable_after_height) > acceptedHeight, `${label}: certificate prune boundary does not follow acceptance`);
    if (certificate.lifecycle === "accepted") {
      invariant(lifecycleHeight === acceptedHeight && certificate.lifecycle_decision_id_hex === certificate.acceptance_decision_id_hex, `${label}: accepted lifecycle authority substitution`);
    } else {
      invariant(lifecycleHeight > acceptedHeight, `${label}: terminal lifecycle is not monotonic`);
    }

    const certificateEntry = entryForIdentity(projection, 1, certificateId, `${label}.certificate.${certificate.certificate_id_hex}.kind1`);
    const rawCertificate = decodeConsumptionCertificate(certificateEntry.envelope.payload, `${label}.certificate.${certificate.certificate_id_hex}`);
    invariant(certificateEntry.envelope.identity.toString("hex") === certificate.certificate_id_hex, `${label}: certificate identity`);
    for (const field of ["certificate_id_hex", "consumer_id_hex", "consumer_key_id_hex", "provider_id_hex", "task_id_hex", "meter_id_hex", "meter_version", "settlement_commitment_hex", "consumed_units"]) {
      invariant(String(rawCertificate[field]) === String(certificate[field]), `${label}: certificate ${field} companion`);
    }
    invariant(rawCertificate.genesis_hash_hex === profile.genesis_hash_hex && rawCertificate.chain_id_ascii === profile.chain_id_utf8, `${label}: certificate chain scope`);
    invariant(rawCertificate.measurement_evidence_root_hex === certificate.evidence_root_hex, `${label}: certificate evidence companion`);
    invariant(BigInt(certificate.accepted_height) > BigInt(rawCertificate.billing_end_height), `${label}: acceptance does not follow billing window`);

    const tupleIdentity = consumptionTupleIdentity(rawCertificate);
    const tupleEntry = entryForIdentity(projection, 4, tupleIdentity, `${label}.certificate.${certificate.certificate_id_hex}.kind4`);
    const settlementEntry = entryForIdentity(projection, 6, certificateId, `${label}.certificate.${certificate.certificate_id_hex}.kind6`);
    const measurementEntry = entryForIdentity(projection, 7, certificateId, `${label}.certificate.${certificate.certificate_id_hex}.kind7`);
    const lifecycleEntry = entryForIdentity(projection, 12, certificateId, `${label}.certificate.${certificate.certificate_id_hex}.kind12`);
    const expectedSemanticKeys = [certificateEntry, tupleEntry, settlementEntry, measurementEntry, lifecycleEntry]
      .map((entry) => `${entry.kind}:${entry.key.toString("hex")}`)
      .sort((left, right) => {
        const [leftKind, leftKey] = left.split(":");
        const [rightKind, rightKey] = right.split(":");
        return Number(leftKind) - Number(rightKind) || leftKey.localeCompare(rightKey);
      });
    requireStrictOrder(certificate.semantic_keys, (item) => [BigInt(item.kind), item.logical_key_hex], `${label}.certificate.${certificate.certificate_id_hex}.semantic_keys`);
    const actualSemanticKeys = certificate.semantic_keys.map((item, index) => {
      invariant([1, 4, 6, 7, 12].includes(item.kind), `${label}: retained semantic kind is not prune-authorized`);
      exactHex(item.logical_key_hex, 32, `${label}.certificate.semantic_keys[${index}].logical_key`);
      entryFromRef(projection, item, `${label}.certificate.semantic_keys[${index}]`);
      return `${item.kind}:${item.logical_key_hex}`;
    });
    sameJson(actualSemanticKeys, expectedSemanticKeys, `${label}: active certificate retained semantic set is substituted or incomplete`);
    for (const entry of [certificateEntry, tupleEntry, settlementEntry, measurementEntry, lifecycleEntry]) reference(entry);

    const consumerKey = consumerKeys.get(`${certificate.consumer_id_hex}:${certificate.consumer_key_id_hex}`);
    invariant(consumerKey !== undefined, `${label}: active certificate consumer-key authority is absent`);
    invariant(
      BigInt(rawCertificate.billing_start_height) >= consumerKey.raw.active_from && acceptedHeight >= consumerKey.raw.active_from &&
        (consumerKey.raw.revoked_at === null ||
          (BigInt(rawCertificate.billing_end_height) < consumerKey.raw.revoked_at && acceptedHeight < consumerKey.raw.revoked_at)),
      `${label}: active certificate consumer-key interval mismatch`,
    );
    verifyConsumptionCertificate(rawCertificate, consumerKey.item.public_key_hex, oldParameters, acceptedHeight, `${label}.certificate.${certificate.certificate_id_hex}`);
    const watermark = consumerKey.watermarks.get(certificate.provider_id_hex);
    invariant(watermark !== undefined && watermark.max_accepted_nonce >= BigInt(rawCertificate.consumer_nonce), `${label}: certificate nonce exceeds provider watermark`);

    const meter = meterPolicies.get(`${certificate.meter_id_hex}:${certificate.meter_version}`);
    invariant(meter !== undefined, `${label}: active certificate meter authority is absent`);
    invariant(
      meter.policy.task_id_hex === certificate.task_id_hex &&
        (meter.policy.output_commitment_hex === null || meter.policy.output_commitment_hex === rawCertificate.output_commitment_hex),
      `${label}: active certificate meter task/output authority mismatch`,
    );
    const tuple = decodeConsumptionTuple(tupleEntry.envelope.payload, tupleEntry.envelope.identity, `${label}.tuple.${certificate.certificate_id_hex}`);
    invariant(tupleEntry.key.toString("hex") === certificate.tuple_key_hex, `${label}: tuple key not derived from raw certificate`);
    invariant(tuple.certificate_id_hex === certificate.certificate_id_hex && tuple.accepted_height === acceptedHeight, `${label}: tuple certificate/accepted-height authority mismatch`);
    const settlement = decodeSettlement(settlementEntry.envelope.payload, settlementEntry.envelope.identity, `${label}.settlement.${certificate.certificate_id_hex}`);
    invariant(
      settlement.state === 2 && settlement.commitment_hex === certificate.settlement_commitment_hex &&
        settlement.finalized_height === settlementFinalizedHeight && settlement.finalized_height <= acceptedHeight,
      `${label}: active certificate settlement authority mismatch`,
    );
    const measurement = decodeMeasurement(measurementEntry.envelope.payload, measurementEntry.envelope.identity, `${label}.measurement.${certificate.certificate_id_hex}`);
    const evidenceMatches = measurement.evidence_root_hex === certificate.evidence_root_hex &&
      ((meter.policy.evidence_policy === "required" && certificate.evidence_root_hex !== null && measurement.state === 2) ||
        (meter.policy.evidence_policy === "forbidden" && certificate.evidence_root_hex === null && measurement.state === 1) ||
        (meter.policy.evidence_policy === "optional" &&
          ((certificate.evidence_root_hex === null && measurement.state === 1) ||
            (certificate.evidence_root_hex !== null && measurement.state === 2))));
    invariant(evidenceMatches, `${label}: measurement evidence does not satisfy meter policy`);

    const providerHistory = registrations.get(certificate.provider_id_hex);
    invariant(providerHistory !== undefined && providerHistory.history.revoked_at_height === null && providerHistory.registration.state === 1, `${label}: certificate lacks active provider registration history`);
    invariant(
      providerHistory.history.consensus_key_hex === certificate.provider_consensus_key_hex &&
        BigInt(providerHistory.history.max_registration_nonce) === BigInt(certificate.provider_registration_nonce) &&
        providerHistory.history.current_proof_digest_hex === certificate.provider_proof_digest_hex &&
        providerHistory.history.registration_decision_id_hex === certificate.provider_registration_decision_id_hex &&
        BigInt(providerHistory.history.registration_height) === BigInt(certificate.provider_registration_height) &&
        providerHistory.history.history_head_hex === certificate.provider_registration_history_head_hex,
      `${label}: certificate/provider registration provenance`,
    );
    invariant(providerHistory.registration.consensus_key_hex === certificate.provider_consensus_key_hex && providerHistory.registration.registration_nonce === BigInt(certificate.provider_registration_nonce), `${label}: provider registration raw fact drift`);
    const relationshipIdentity = joinedIdentity([
      boundedHex(certificate.provider_id_hex, 1, 128, `${label}: relationship provider`),
      boundedHex(certificate.consumer_id_hex, 1, 128, `${label}: relationship consumer`),
      boundedHex(certificate.task_id_hex, 1, 128, `${label}: relationship task`),
    ]);
    const relationshipEntry = entryForIdentity(projection, 8, relationshipIdentity, `${label}.relationship.${certificate.certificate_id_hex}`);
    const relationship = decodeRelationship(relationshipEntry.envelope.payload, relationshipEntry.envelope.identity, `${label}.relationship.${certificate.certificate_id_hex}`);
    invariant(relationship.provider_id_hex === certificate.provider_id_hex && relationship.consumer_id_hex === certificate.consumer_id_hex && relationship.task_id_hex === certificate.task_id_hex, `${label}: relationship tuple`);
    invariant(relationship.relationship_class === certificate.relationship_class, `${label}: relationship class`);
    invariant(relationshipEntry.key.toString("hex") === certificate.relationship_key_hex, `${label}: relationship logical-key authority`);
    invariant(relationship.expires_at > BigInt(rawCertificate.billing_end_height) && relationship.expires_at > acceptedHeight, `${label}: relationship expired before billing/acceptance`);
    const lifecycle = decodeLifecycle(lifecycleEntry.envelope.payload, lifecycleEntry.envelope.identity, `${label}.lifecycle.${certificate.certificate_id_hex}`);
    invariant(lifecycle.certificate_id_hex === certificate.certificate_id_hex, `${label}: lifecycle certificate`);
    const pendingChallenge = authority.pending_challenges.find(
      (challenge) => challenge.certificate_id_hex === certificate.certificate_id_hex,
    );
    const expectedLifecycleState = pendingChallenge ? 3 : lifecycleCode[certificate.lifecycle];
    const expectedLifecycleHeight = pendingChallenge
      ? BigInt(pendingChallenge.opened_height)
      : BigInt(certificate.lifecycle_effective_height);
    invariant(lifecycle.state === expectedLifecycleState, `${label}: lifecycle state`);
    invariant(lifecycle.effectiveHeight === expectedLifecycleHeight, `${label}: lifecycle height`);
    const derivedFinalizedEpoch = (BigInt(certificate.accepted_height) - 1n) / BigInt(oldParameters.epoch_length_blocks);
    invariant(derivedFinalizedEpoch === BigInt(certificate.finalized_epoch) && derivedFinalizedEpoch <= activeEpoch, `${label}: historical finalized epoch`);
    const eligible = contributionEligible(authority, candidateIds, certificate);
    contributions.push({
      certificate_id_hex: certificate.certificate_id_hex,
      provider_validator_id_hex: certificate.provider_id_hex,
      task_id_hex: certificate.task_id_hex,
      consumer_id_hex: certificate.consumer_id_hex,
      finalized_epoch: String(certificate.finalized_epoch),
      consumed_units: canonicalU128(certificate.consumed_units, `${label}: consumed units`),
      eligible,
    });
  }

  requireStrictOrder(authority.pending_challenges, (item) => [item.challenge_id_hex], `${label}.authority.pending_challenges`);
  const challengedCertificates = new Set();
  for (const [index, challenge] of authority.pending_challenges.entries()) {
    exactHex(challenge.challenge_id_hex, 32, `${label}.pending_challenges[${index}].challenge_id`);
    const certificateId = exactHex(challenge.certificate_id_hex, 32, `${label}.pending_challenges[${index}].certificate_id`);
    exactHex(challenge.opening_decision_id_hex, 32, `${label}.pending_challenges[${index}].opening_decision`);
    invariant(!challengedCertificates.has(challenge.certificate_id_hex), `${label}: certificate has multiple pending challenges`);
    challengedCertificates.add(challenge.certificate_id_hex);
    const certificate = authority.active_certificates.find((item) => item.certificate_id_hex === challenge.certificate_id_hex);
    invariant(certificate !== undefined && certificate.lifecycle === "accepted", `${label}: pending challenge lacks accepted certificate authority`);
    const openedHeight = requireRecordedHeight(challenge.opened_height, authority.last_target_height, `${label}.pending_challenges[${index}].opened_height`);
    invariant(openedHeight > BigInt(certificate.accepted_height), `${label}: pending challenge is not monotonic`);
    const lifecycleEntry = entryForIdentity(projection, 12, certificateId, `${label}.pending_challenges[${index}].kind12`);
    const lifecycle = decodeLifecycle(lifecycleEntry.envelope.payload, lifecycleEntry.envelope.identity, `${label}.pending_challenges[${index}].kind12`);
    invariant(lifecycle.state === 3 && lifecycle.effectiveHeight === openedHeight, `${label}: pending challenge lifecycle companion drift`);
  }

  for (const entry of projection.entries) {
    const authorityManaged = (entry.kind >= 1 && entry.kind <= 7) || entry.kind === 9 ||
      entry.kind === 12 || entry.kind === 15 ||
      (entry.kind === 14 && entry.envelope.identity.length >= 1 && entry.envelope.identity[0] === 2);
    invariant(
      !authorityManaged || referenced.has(`${entry.kind}:${entry.key.toString("hex")}`),
      `${label}: orphan authority-managed semantic entry lacks kind-16 companion`,
    );
  }

  const orderedCandidates = [...candidates.values()].sort((a, b) => a.validator_id_hex.localeCompare(b.validator_id_hex));
  const orderedContributions = contributions.sort((a, b) => a.certificate_id_hex.localeCompare(b.certificate_id_hex));
  stats.candidates += orderedCandidates.length;
  stats.contributions += orderedContributions.length;
  return {
    oldSet,
    oldParameters,
    oldParametersRaw,
    candidateParameters,
    candidateParametersRaw,
    candidateParametersHash: domainHash(PARAMETERS_DOMAIN, candidateParametersRaw),
    authority,
    popById,
    candidates: orderedCandidates,
    contributions: orderedContributions,
  };
}

function contributionEligible(authority, candidateIds, certificate) {
  const pending = authority.pending_challenges.some(
    (challenge) => challenge.certificate_id_hex === certificate.certificate_id_hex,
  );
  return candidateIds.has(certificate.provider_id_hex) && certificate.relationship_class === 1 &&
    (certificate.lifecycle === "challenge_rejected" ||
      (certificate.lifecycle === "accepted" && !pending));
}

function canonicalTranscript(transcript) {
  const chunks = [
    uint(0, 2),
    uint(transcript.snapshot_epoch, 8),
    uint(transcript.snapshot_height, 8),
    uint(transcript.committed_snapshot_cutoff, 8),
    uint(transcript.candidates.length, 4),
  ];
  for (const candidate of transcript.candidates) {
    chunks.push(
      frame32(boundedHex(candidate.validator_id_hex, 1, 128, "transcript candidate ID")),
      exactHex(candidate.consensus_key_hex, 32, "transcript candidate key"),
      uint(candidate.active_slashable_bond, 16),
      Buffer.from([candidate.jailed ? 1 : 0, candidate.registration_valid ? 1 : 0]),
    );
    if (candidate.previous_registration_nonce === null) chunks.push(Buffer.from([0]));
    else chunks.push(Buffer.from([1]), uint(candidate.previous_registration_nonce, 8));
    if (candidate.proof_cev0_hex === null) chunks.push(Buffer.from([0]));
    else chunks.push(Buffer.from([1]), frame32(boundedHex(candidate.proof_cev0_hex, 1, 65_384, "transcript PoP")));
  }
  chunks.push(uint(transcript.contributions.length, 4));
  for (const contribution of transcript.contributions) {
    chunks.push(
      exactHex(contribution.certificate_id_hex, 32, "transcript certificate ID"),
      frame32(boundedHex(contribution.provider_validator_id_hex, 1, 128, "transcript provider ID")),
      frame32(boundedHex(contribution.task_id_hex, 1, 128, "transcript task ID")),
      frame32(boundedHex(contribution.consumer_id_hex, 1, 128, "transcript consumer ID")),
      uint(contribution.finalized_epoch, 8),
      uint(contribution.consumed_units, 16),
      Buffer.from([contribution.eligible ? 1 : 0]),
    );
  }
  return Buffer.concat(chunks);
}

function encodeValidatorSet(set, parametersHash, epoch = set.epoch) {
  return Buffer.concat([
    uint(0, 2),
    exactHex(set.genesis_hash_hex, 32, "validator set genesis"),
    Buffer.concat([uint(Buffer.byteLength(set.chain_id_ascii, "ascii"), 2), Buffer.from(set.chain_id_ascii, "ascii")]),
    uint(set.protocol_version, 4),
    uint(epoch, 8),
    exactHex(parametersHash, 32, "validator set parameter hash"),
    uint(set.validators.length, 4),
    ...set.validators.flatMap((validator) => [
      frame32(boundedHex(validator.validator_id_hex, 1, 128, "validator set ID")),
      exactHex(validator.consensus_key_hex, 32, "validator set key"),
      uint(validator.effective_weight, 8),
    ]),
  ]);
}

function canonicalResult(outcome, oldSet, oldParametersRaw, candidateParametersRaw, candidateParametersHash, snapshotEpoch) {
  const targetEpoch = BigInt(snapshotEpoch) + 1n;
  const chunks = [
    uint(0, 2),
    uint(snapshotEpoch, 8),
    uint(targetEpoch, 8),
    Buffer.from([outcome.fallback_used ? 1 : 0]),
    uint(outcome.fallback_reason_code, 2),
    uint(outcome.computed_candidates.length, 4),
  ];
  for (const candidate of outcome.computed_candidates) {
    chunks.push(
      frame32(boundedHex(candidate.validator_id_hex, 1, 128, "result candidate ID")),
      exactHex(candidate.consensus_key_hex, 32, "result candidate key"),
      uint(candidate.decayed_units, 16),
      uint(candidate.poco_capacity, 16),
      uint(candidate.bond_capacity, 16),
      uint(candidate.raw_power, 8),
      Buffer.from([candidate.selected ? 1 : 0]),
    );
    if (candidate.rollout_weight === null) chunks.push(Buffer.from([0]));
    else chunks.push(Buffer.from([1]), uint(candidate.rollout_weight, 8));
    chunks.push(uint(candidate.consumer_cap_hits, 4), uint(candidate.task_cap_hits, 4), Buffer.from([candidate.provider_cap_hit ? 1 : 0]));
  }
  if (outcome.computed_candidate_validator_set === null) chunks.push(Buffer.from([0]));
  else {
    const computedSet = {
      genesis_hash_hex: oldSet.genesis_hash_hex,
      chain_id_ascii: oldSet.chain_id_ascii,
      protocol_version: oldSet.protocol_version,
      epoch: targetEpoch.toString(),
      validators: outcome.computed_candidate_validator_set,
    };
    chunks.push(Buffer.from([1]), frame32(encodeValidatorSet(computedSet, candidateParametersHash.toString("hex"), targetEpoch)));
  }
  const effectiveParametersRaw = outcome.fallback_used ? oldParametersRaw : candidateParametersRaw;
  let effectiveSet;
  let effectiveSetParametersHash;
  let effectiveEpoch;
  if (outcome.fallback_used || outcome.computed_candidate_validator_set === null) {
    effectiveSet = { ...oldSet, validators: outcome.effective_validator_set };
    effectiveSetParametersHash = outcome.fallback_used
      ? oldSet.consensus_parameters_hash_hex
      : candidateParametersHash.toString("hex");
    effectiveEpoch = targetEpoch;
  } else {
    effectiveSet = {
      genesis_hash_hex: oldSet.genesis_hash_hex,
      chain_id_ascii: oldSet.chain_id_ascii,
      protocol_version: oldSet.protocol_version,
      epoch: targetEpoch.toString(),
      validators: outcome.effective_validator_set,
    };
    effectiveSetParametersHash = candidateParametersHash.toString("hex");
    effectiveEpoch = targetEpoch;
  }
  chunks.push(
    frame32(encodeValidatorSet(effectiveSet, effectiveSetParametersHash, effectiveEpoch)),
    frame32(effectiveParametersRaw),
  );
  return Buffer.concat(chunks);
}

function checkpointCanonical(profile, scenario, source, reconstructed) {
  const checkpoint = scenario.checkpoint;
  const chain = Buffer.from(profile.chain_id_utf8, "ascii");
  invariant(chain.length >= 1 && chain.length <= 128, `${scenario.id}: checkpoint chain ID`);
  const canonical = Buffer.concat([
    uint(0, 2),
    exactHex(profile.genesis_hash_hex, 32, `${scenario.id}: checkpoint genesis`),
    Buffer.concat([uint(chain.length, 2), chain]),
    reconstructed.oldParametersHash,
    uint(reconstructed.oldSet.protocol_version, 4),
    uint(profile.active_epoch, 8),
    uint(checkpoint.block_height, 8),
    exactHex(checkpoint.block_hash_hex, 32, `${scenario.id}: checkpoint block hash`),
    uint(checkpoint.timestamp_ms, 8),
    uint(checkpoint.parent_height, 8),
    exactHex(checkpoint.parent_state_root_hex, 32, `${scenario.id}: parent root`),
    uint(source.cutoff_version, 8),
    exactHex(source.cutoff_root_hex, 32, `${scenario.id}: cutoff root`),
    exactHex(checkpoint.cutoff_entries_root_hex, 32, `${scenario.id}: cutoff entries root`),
    uint(checkpoint.cutoff_entry_count, 4),
    exactHex(checkpoint.payload_root_hex, 32, `${scenario.id}: payload root`),
    exactHex(checkpoint.receipts_root_hex, 32, `${scenario.id}: receipts root`),
    exactHex(checkpoint.next_state_root_hex, 32, `${scenario.id}: next root`),
    reconstructed.oldSet.id,
    reconstructed.oldParametersHash,
  ]);
  invariant(canonical.toString("hex") === checkpoint.checkpoint_execution_canonical_hex, `${scenario.id}: checkpoint canonical bytes`);
  invariant(hashV1(CHECKPOINT_DOMAIN, [canonical]).toString("hex") === checkpoint.execution_id_hex, `${scenario.id}: checkpoint execution ID`);
  return canonical;
}

function validateScenario(profile, scenario, label) {
  exactKeys(scenario, ["id", "expected_fallback_used", "expected_fallback_reason_code", "block_steps", "source", "checkpoint"], label);
  invariant(typeof scenario.id === "string" && scenario.id.length > 0, `${label}: ID`);
  invariant(typeof scenario.expected_fallback_used === "boolean", `${label}: fallback flag`);
  invariant(Number.isInteger(scenario.expected_fallback_reason_code) && scenario.expected_fallback_reason_code >= 0 && scenario.expected_fallback_reason_code <= 9, `${label}: fallback reason`);
  invariant(Array.isArray(scenario.block_steps) && scenario.block_steps.length > 0, `${label}: block steps`);
  let priorStep = null;
  for (const [index, step] of scenario.block_steps.entries()) {
    exactKeys(step, ["height", "purpose", "raw_operation_json_hexes"], `${label}.block_steps[${index}]`);
    const height = safeU64(step.height, `${label}.block_steps[${index}].height`);
    invariant(priorStep === null || priorStep < height, `${label}: block-step order`);
    priorStep = height;
    invariant(typeof step.purpose === "string" && step.purpose.length > 0, `${label}: step purpose`);
    invariant(Array.isArray(step.raw_operation_json_hexes), `${label}: step operations`);
    for (const raw of step.raw_operation_json_hexes) boundedHex(raw, 1, 1_048_576, `${label}: raw operation`);
  }

  const history = replayHistory(scenario.source, `${label}.source`);
  const cutoff = validateProjection(scenario.source.cutoff_projection, history.cutoffVersion, history.cutoffLive, `${label}.cutoff_projection`);
  // A no-op parent version preserves the scheduled cutoff manifest.  The
  // physical JMT head is v21 while the exact projection remains cutoff v20.
  const head = validateProjection(scenario.source.head_projection, history.cutoffVersion, history.headLive, `${label}.head_projection`);
  invariant(cutoff.root.equals(head.root), `${label}: post-cutoff projection content changed`);
  invariant(cutoff.manifest.count === head.manifest.count, `${label}: post-cutoff projection count changed`);
  const cutoffEntries = cutoff.entries.map((entry) => entry.canonical.toString("hex"));
  const headEntries = head.entries.map((entry) => entry.canonical.toString("hex"));
  sameJson(headEntries, cutoffEntries, `${label}: post-cutoff projection splice`);

  const reconstructed = reconstructAuthority(profile, cutoff, label);
  reconstructed.oldParametersHash = domainHash(PARAMETERS_DOMAIN, reconstructed.oldParametersRaw);
  const transcript = {
    snapshot_epoch: reconstructed.oldSet.epoch,
    snapshot_height: String(history.cutoffVersion),
    committed_snapshot_cutoff: String(history.cutoffVersion),
    candidates: reconstructed.candidates,
    contributions: reconstructed.contributions,
  };
  const caseRecord = {
    id: scenario.id,
    parameters_profile: "authenticated-cutoff",
    candidate_parameters: reconstructed.candidateParameters,
    transcript: {
      ...transcript,
      candidates: transcript.candidates.map(({ proof_cev0_hex: _proof, ...candidate }) => candidate),
    },
  };
  const context = {
    genesis_hash_hex: profile.genesis_hash_hex,
    chain_id_ascii: profile.chain_id_utf8,
    target_epoch: String(profile.target_epoch),
  };
  const outcome = computeCase(caseRecord, reconstructed.oldSet, reconstructed.oldParameters, reconstructed.popById, context);
  invariant(outcome.fallback_used === scenario.expected_fallback_used, `${label}: B2-G fallback flag`);
  invariant(outcome.fallback_reason_code === scenario.expected_fallback_reason_code, `${label}: B2-G fallback reason`);
  invariant(outcome.fallback_reason === fallbackName(scenario.expected_fallback_reason_code), `${label}: fallback taxonomy`);
  invariant(outcome.authorization_outputs === 0, `${label}: inert B2-G unexpectedly authorized`);

  const transcriptRaw = canonicalTranscript(transcript);
  const transcriptDigest = hashV1(TRANSCRIPT_DOMAIN, [transcriptRaw]);
  const resultRaw = canonicalResult(
    outcome,
    reconstructed.oldSet,
    reconstructed.oldParametersRaw,
    reconstructed.candidateParametersRaw,
    reconstructed.candidateParametersHash,
    transcript.snapshot_epoch,
  );
  const resultDigest = hashV1(RESULT_DOMAIN, [resultRaw]);
  const checkpointCanonicalRaw = checkpointCanonical(profile, scenario, scenario.source, reconstructed);
  const authorization = hashV1(AUTHORIZATION_DOMAIN, [
    checkpointCanonicalRaw,
    transcriptDigest,
    reconstructed.candidateParametersHash,
    resultDigest,
  ]);
  const checkpoint = scenario.checkpoint;
  exactKeys(checkpoint, [
    "block_height", "block_hash_hex", "timestamp_ms", "parent_height",
    "parent_state_root_hex", "next_state_root_hex", "cutoff_entries_root_hex",
    "cutoff_entry_count", "payload_root_hex", "receipts_root_hex",
    "checkpoint_execution_canonical_hex", "execution_id_hex", "authorization_id_hex",
    "transcript_canonical_hex", "transcript_digest_hex", "result_canonical_hex",
    "result_digest_hex", "candidate_parameters_hash_hex", "fallback_used",
    "fallback_reason_code", "computed_candidate_count", "computed_candidate_ids_hex",
    "effective_validator_set_cev0_hex",
  ], `${label}.checkpoint`);
  invariant(checkpoint.block_height === profile.checkpoint_height, `${label}: checkpoint height`);
  invariant(history.cutoffVersion === profile.cutoff_height, `${label}: profile/cutoff height`);
  invariant(checkpoint.parent_height === history.headVersion, `${label}: checkpoint parent version`);
  invariant(checkpoint.parent_state_root_hex === scenario.source.head_root_hex, `${label}: checkpoint parent root`);
  invariant(checkpoint.next_state_root_hex === scenario.source.head_root_hex, `${label}: read-only checkpoint next root`);
  invariant(checkpoint.cutoff_entries_root_hex === cutoff.root.toString("hex"), `${label}: cutoff entries root binding`);
  invariant(checkpoint.cutoff_entry_count === cutoff.entries.length, `${label}: cutoff entry count binding`);
  invariant(checkpoint.transcript_digest_hex === transcriptDigest.toString("hex"), `${label}: transcript seal`);
  invariant(checkpoint.transcript_canonical_hex === transcriptRaw.toString("hex"), `${label}: transcript canonical evidence`);
  invariant(checkpoint.result_digest_hex === resultDigest.toString("hex"), `${label}: result seal`);
  invariant(checkpoint.result_canonical_hex === resultRaw.toString("hex"), `${label}: result canonical evidence`);
  invariant(checkpoint.candidate_parameters_hash_hex === reconstructed.candidateParametersHash.toString("hex"), `${label}: candidate-parameters seal`);
  invariant(checkpoint.authorization_id_hex === authorization.toString("hex"), `${label}: authorization seal`);
  invariant(checkpoint.fallback_used === outcome.fallback_used && checkpoint.fallback_reason_code === outcome.fallback_reason_code, `${label}: checkpoint outcome telemetry drift`);
  invariant(checkpoint.computed_candidate_count === outcome.computed_candidates.length, `${label}: computed-candidate count telemetry drift`);
  sameJson(
    checkpoint.computed_candidate_ids_hex,
    outcome.computed_candidates.map((candidate) => candidate.validator_id_hex),
    `${label}: computed-candidate ID telemetry drift`,
  );
  const expectedEffectiveSet = canonicalResultEffectiveSet(outcome, reconstructed, transcript.snapshot_epoch);
  invariant(checkpoint.effective_validator_set_cev0_hex === expectedEffectiveSet.toString("hex"), `${label}: effective set evidence`);
  const emptyPayload = checkpointOrderedRoot("trnm.poco-bft.checkpoint-payload.v0", []);
  const emptyReceipts = checkpointOrderedRoot("trnm.poco-bft.checkpoint-receipts.v0", []);
  invariant(checkpoint.payload_root_hex === emptyPayload.toString("hex") && checkpoint.receipts_root_hex === emptyReceipts.toString("hex"), `${label}: fixture checkpoint body is not independently empty`);
  stats.scenarios += 1;
  return { history, cutoff, head, reconstructed, transcript, outcome, transcriptRaw, resultRaw, authorization };
}

function canonicalResultEffectiveSet(outcome, reconstructed, snapshotEpoch) {
  if (outcome.fallback_used || outcome.computed_candidate_validator_set === null) {
    return encodeValidatorSet(
      { ...reconstructed.oldSet, validators: outcome.effective_validator_set },
      outcome.fallback_used
        ? reconstructed.oldSet.consensus_parameters_hash_hex
        : reconstructed.candidateParametersHash.toString("hex"),
      BigInt(snapshotEpoch) + 1n,
    );
  }
  return encodeValidatorSet(
    {
      genesis_hash_hex: reconstructed.oldSet.genesis_hash_hex,
      chain_id_ascii: reconstructed.oldSet.chain_id_ascii,
      protocol_version: reconstructed.oldSet.protocol_version,
      validators: outcome.effective_validator_set,
    },
    reconstructed.candidateParametersHash.toString("hex"),
    BigInt(snapshotEpoch) + 1n,
  );
}

function validateProfile(profile) {
  exactKeys(profile, [
    "chain_id_utf8", "genesis_hash_hex", "epoch_length_blocks", "snapshot_lead_blocks",
    "maturity_epochs", "units_per_power", "bond_atomic_units_per_power",
    "evidence_window_epochs", "active_parameters_cev0_hex", "active_parameters_hash_hex",
    "active_epoch", "target_epoch", "boundary_height", "cutoff_height", "checkpoint_height",
  ], "compact_profile");
  invariant(typeof profile.chain_id_utf8 === "string" && /^[a-z0-9][a-z0-9._:-]{0,127}$/.test(profile.chain_id_utf8), "compact_profile: chain ID");
  exactHex(profile.genesis_hash_hex, 32, "compact_profile.genesis_hash");
  for (const field of ["epoch_length_blocks", "snapshot_lead_blocks", "maturity_epochs", "evidence_window_epochs", "active_epoch", "target_epoch", "boundary_height", "cutoff_height", "checkpoint_height"]) safeU64(profile[field], `compact_profile.${field}`);
  canonicalU128(profile.units_per_power, "compact_profile.units_per_power");
  canonicalU128(profile.bond_atomic_units_per_power, "compact_profile.bond_atomic_units_per_power");
  const raw = boundedHex(profile.active_parameters_cev0_hex, 341, 341, "compact_profile.active_parameters");
  const parameters = decodeParameters(raw, "compact_profile.active_parameters");
  invariant(domainHash(PARAMETERS_DOMAIN, raw).toString("hex") === profile.active_parameters_hash_hex, "compact_profile: parameter hash");
  for (const field of ["epoch_length_blocks", "snapshot_lead_blocks", "maturity_epochs", "units_per_power", "bond_atomic_units_per_power", "evidence_window_epochs"]) {
    invariant(String(parameters[field]) === String(profile[field]), `compact_profile: ${field}`);
  }
  invariant(
    profile.epoch_length_blocks === 10 && profile.snapshot_lead_blocks === 3 &&
      profile.active_epoch === 2 && profile.boundary_height === 21 &&
      profile.cutoff_height === 25 && profile.checkpoint_height === 28,
    "compact_profile: unified production-shaped 10/3/21/25/28 witness",
  );
  invariant(profile.target_epoch === profile.active_epoch + 1, "compact_profile: target epoch");
  invariant(profile.boundary_height === profile.active_epoch * profile.epoch_length_blocks + 1, "compact_profile: boundary geometry");
  invariant(profile.cutoff_height === (profile.active_epoch + 1) * profile.epoch_length_blocks - profile.snapshot_lead_blocks - 2, "compact_profile: cutoff geometry");
  invariant(profile.checkpoint_height === profile.cutoff_height + profile.snapshot_lead_blocks, "compact_profile: checkpoint geometry");
  return parameters;
}

function validateBoundary(vector) {
  const boundary = vector.boundary_contract;
  exactKeys(boundary, [
    "authority", "from_epoch", "to_epoch", "height", "usage_rollover", "cleared_meter_usage",
    "cleared_consumer_provider_usage", "cleared_task_provider_usage", "cleared_provider_usage",
    "preserved_certificate_ids_hex", "installed_bonds",
  ], "boundary_contract");
  invariant(boundary.authority === "fixture_only_bootstrap_not_application_or_core_transition", "boundary_contract: authority label");
  invariant(boundary.from_epoch === 0 && boundary.to_epoch === vector.compact_profile.active_epoch, "boundary_contract: epoch geometry");
  invariant(boundary.height === vector.compact_profile.boundary_height, "boundary_contract: height" );
  invariant(boundary.usage_rollover === "clear_epoch_zero_usage_buckets_preserve_certificate_authority", "boundary_contract: rollover rule");
  for (const field of ["cleared_meter_usage", "cleared_consumer_provider_usage", "cleared_task_provider_usage", "cleared_provider_usage"]) {
    invariant(Number.isInteger(boundary[field]) && boundary[field] >= 0, `boundary_contract: ${field}`);
  }
  invariant(Array.isArray(boundary.preserved_certificate_ids_hex) && boundary.preserved_certificate_ids_hex.length >= 4, "boundary_contract: retained certificates");
  for (const value of boundary.preserved_certificate_ids_hex) exactHex(value, 32, "boundary_contract certificate ID");
  invariant(Array.isArray(boundary.installed_bonds) && boundary.installed_bonds.length >= 4, "boundary_contract: bonds");
  for (const bond of boundary.installed_bonds) {
    exactKeys(bond, ["validator_id_hex", "amount", "locked_until", "state"], "boundary_contract.bond");
    boundedHex(bond.validator_id_hex, 1, 128, "boundary_contract bond ID");
    invariant(BigInt(canonicalU128(bond.amount, "boundary_contract bond amount")) > 0n, "boundary_contract: zero bond");
    safeU64(bond.locked_until, "boundary_contract bond locked_until");
    invariant(bond.state === "active_slashable", "boundary_contract: bond state");
  }
}

function encodeSemanticEnvelope(kind, revision, identity, payload) {
  return Buffer.concat([uint(0, 2), Buffer.from([kind]), uint(revision, 8), frame32(identity), frame32(payload)]);
}

function refreshRawProjection(raw, label) {
  raw.entries.sort((left, right) => left.kind - right.kind || left.logical_key_hex.localeCompare(right.logical_key_hex));
  const canonicals = [];
  for (const [index, item] of raw.entries.entries()) {
    const key = exactHex(item.logical_key_hex, 32, `${label}.entries[${index}].key`);
    const value = boundedHex(item.value_hex, 1, 65_536, `${label}.entries[${index}].value`);
    const canonical = canonicalEntry(item.kind, key, value);
    item.canonical_entry_cev0_hex = canonical.toString("hex");
    canonicals.push(canonical);
  }
  const root = orderedRoot(ENTRY_DOMAIN, ENTRY_NODE_DOMAIN, ENTRY_ROOT_DOMAIN, canonicals);
  raw.entries_root_hex = root.toString("hex");
  const oldManifest = decodeManifest(exactHex(raw.manifest_hex, 47, `${label}.manifest`), `${label}.manifest`);
  raw.manifest_hex = Buffer.concat([
    uint(0, 2), Buffer.from([8]), uint(oldManifest.height, 8), uint(raw.entries.length, 4), root,
  ]).toString("hex");
}

function replaceLastPhysicalWrite(source, physicalKeyHex, maximumVersion, nextValueHex, label) {
  let found = null;
  for (const item of source.history) {
    if (BigInt(item.version) > BigInt(maximumVersion)) break;
    for (const write of item.writes) {
      if (write.physical_key_hex === physicalKeyHex) found = write;
    }
  }
  invariant(found !== null, `${label}: prior physical write absent`);
  found.value_hex = nextValueHex;
}

function addPhysicalWriteAtVersion(source, version, physicalKeyHex, valueHex, label) {
  const item = source.history.find((candidate) => BigInt(candidate.version) === BigInt(version));
  invariant(item !== undefined, `${label}: target history version absent`);
  invariant(!item.writes.some((write) => write.physical_key_hex === physicalKeyHex), `${label}: physical key already written`);
  item.writes.push({ physical_key_hex: physicalKeyHex, value_hex: valueHex });
}

function recomputeExportedHistoryRoots(source, label) {
  const live = new Map();
  let cutoffRoot = null;
  for (const item of source.history) {
    for (const write of item.writes) {
      if (write.value_hex === null) live.delete(write.physical_key_hex);
      else live.set(write.physical_key_hex, write.value_hex);
    }
    item.jmt_root_hex = jmtRoot(live).toString("hex");
    if (BigInt(item.version) === BigInt(source.cutoff_version)) cutoffRoot = item.jmt_root_hex;
  }
  invariant(cutoffRoot !== null, `${label}: cutoff history version absent`);
  source.cutoff_root_hex = cutoffRoot;
  source.head_root_hex = source.history.at(-1).jmt_root_hex;
}

function rewriteAuthorityInSource(source, mutate, label) {
  let authorityKeyHex = null;
  let authorityValueHex = null;
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    const item = projection.entries.find((entry) => entry.kind === 16);
    invariant(item !== undefined, `${label}.${projectionName}: authority entry absent`);
    const raw = boundedHex(item.value_hex, 1, 65_536, `${label}.${projectionName}.authority`);
    const c = new Cursor(raw, `${label}.${projectionName}.authority`);
    invariant(c.u16("schema") === 0 && c.u8("kind") === 16, `${label}: authority envelope header`);
    const revision = c.u64("revision");
    const identity = c.bytes32("identity", 128);
    const payload = c.bytes32("payload", 65_384);
    c.finish();
    invariant(identity.equals(AUTHORITY_IDENTITY), `${label}: authority identity`);
    const state = decodeCanonicalAuthorityJson(payload, `${label}.${projectionName}.authority.payload`);
    mutate(state);
    const nextPayload = Buffer.from(canonicalJsonStringify(state), "utf8");
    const nextValue = encodeSemanticEnvelope(16, revision, identity, nextPayload);
    item.value_hex = nextValue.toString("hex");
    authorityKeyHex ??= item.logical_key_hex;
    authorityValueHex ??= item.value_hex;
    invariant(authorityKeyHex === item.logical_key_hex && authorityValueHex === item.value_hex, `${label}: cutoff/head mutation drift`);
    refreshRawProjection(projection, `${label}.${projectionName}`);
  }
  replaceLastPhysicalWrite(
    source,
    entryPhysicalKey(16, exactHex(authorityKeyHex, 32, `${label}.authority_key`)).toString("hex"),
    source.cutoff_version,
    authorityValueHex,
    `${label}.authority`,
  );
  replaceLastPhysicalWrite(source, manifestKey().toString("hex"), source.cutoff_version, source.cutoff_projection.manifest_hex, `${label}.manifest`);
  recomputeExportedHistoryRoots(source, label);
}

function setPhysicalWriteAtVersion(source, version, physicalKeyHex, valueHex, label) {
  const item = source.history.find((candidate) => BigInt(candidate.version) === BigInt(version));
  invariant(item !== undefined, `${label}: target history version absent`);
  const existing = item.writes.find((write) => write.physical_key_hex === physicalKeyHex);
  if (existing) existing.value_hex = valueHex;
  else item.writes.push({ physical_key_hex: physicalKeyHex, value_hex: valueHex });
}

function rewriteSemanticEntryInSource(source, kind, logicalKeyHex, mutatePayload, label, scope = "both") {
  invariant(scope === "both" || scope === "head_only", `${label}: invalid rewrite scope`);
  const projections = scope === "both" ? ["cutoff_projection", "head_projection"] : ["head_projection"];
  let nextValueHex = null;
  for (const projectionName of projections) {
    const projection = source[projectionName];
    const item = projection.entries.find((entry) => entry.kind === kind && entry.logical_key_hex === logicalKeyHex);
    invariant(item !== undefined, `${label}.${projectionName}: semantic entry absent`);
    const raw = boundedHex(item.value_hex, 1, 65_536, `${label}.${projectionName}.value`);
    const c = new Cursor(raw, `${label}.${projectionName}.envelope`);
    invariant(c.u16("schema") === 0 && c.u8("kind") === kind, `${label}: semantic envelope header`);
    const revision = c.u64("revision");
    const identity = c.bytes32("identity", 128);
    const payload = c.bytes32("payload", 65_384);
    c.finish();
    const nextPayload = mutatePayload(Buffer.from(payload), identity, projectionName);
    invariant(Buffer.isBuffer(nextPayload) && nextPayload.length >= 1 && nextPayload.length <= 65_384, `${label}: mutated payload bound`);
    const nextValue = encodeSemanticEnvelope(kind, revision, identity, nextPayload);
    item.value_hex = nextValue.toString("hex");
    nextValueHex ??= item.value_hex;
    invariant(nextValueHex === item.value_hex, `${label}: cutoff/head mutation drift`);
    refreshRawProjection(projection, `${label}.${projectionName}`);
  }
  const physicalKeyHex = entryPhysicalKey(kind, exactHex(logicalKeyHex, 32, `${label}.logical_key`)).toString("hex");
  if (scope === "both") {
    replaceLastPhysicalWrite(source, physicalKeyHex, source.cutoff_version, nextValueHex, `${label}.semantic`);
    replaceLastPhysicalWrite(source, manifestKey().toString("hex"), source.cutoff_version, source.cutoff_projection.manifest_hex, `${label}.manifest`);
  } else {
    setPhysicalWriteAtVersion(source, source.head_version, physicalKeyHex, nextValueHex, `${label}.semantic`);
    setPhysicalWriteAtVersion(source, source.head_version, manifestKey().toString("hex"), source.head_projection.manifest_hex, `${label}.manifest`);
  }
  recomputeExportedHistoryRoots(source, label);
}

function refreshCheckpointSourceBindings(profile, scenario, reconstructed, label) {
  const checkpoint = scenario.checkpoint;
  checkpoint.parent_state_root_hex = scenario.source.head_root_hex;
  checkpoint.next_state_root_hex = scenario.source.head_root_hex;
  checkpoint.cutoff_entries_root_hex = scenario.source.cutoff_projection.entries_root_hex;
  checkpoint.cutoff_entry_count = scenario.source.cutoff_projection.entries.length;
  const chain = Buffer.from(profile.chain_id_utf8, "ascii");
  const canonical = Buffer.concat([
    uint(0, 2),
    exactHex(profile.genesis_hash_hex, 32, `${label}.genesis`),
    Buffer.concat([uint(chain.length, 2), chain]),
    reconstructed.oldParametersHash,
    uint(reconstructed.oldSet.protocol_version, 4),
    uint(profile.active_epoch, 8),
    uint(checkpoint.block_height, 8),
    exactHex(checkpoint.block_hash_hex, 32, `${label}.block_hash`),
    uint(checkpoint.timestamp_ms, 8),
    uint(checkpoint.parent_height, 8),
    exactHex(checkpoint.parent_state_root_hex, 32, `${label}.parent_root`),
    uint(scenario.source.cutoff_version, 8),
    exactHex(scenario.source.cutoff_root_hex, 32, `${label}.cutoff_root`),
    exactHex(checkpoint.cutoff_entries_root_hex, 32, `${label}.entries_root`),
    uint(checkpoint.cutoff_entry_count, 4),
    exactHex(checkpoint.payload_root_hex, 32, `${label}.payload_root`),
    exactHex(checkpoint.receipts_root_hex, 32, `${label}.receipts_root`),
    exactHex(checkpoint.next_state_root_hex, 32, `${label}.next_root`),
    reconstructed.oldSet.id,
    reconstructed.oldParametersHash,
  ]);
  checkpoint.checkpoint_execution_canonical_hex = canonical.toString("hex");
  checkpoint.execution_id_hex = hashV1(CHECKPOINT_DOMAIN, [canonical]).toString("hex");
}

function refreshAuthorizationFromFrozenSeals(scenario, label) {
  const checkpoint = scenario.checkpoint;
  checkpoint.authorization_id_hex = hashV1(AUTHORIZATION_DOMAIN, [
    boundedHex(checkpoint.checkpoint_execution_canonical_hex, 1, 65_536, `${label}.checkpoint_canonical`),
    exactHex(checkpoint.transcript_digest_hex, 32, `${label}.transcript_digest`),
    exactHex(checkpoint.candidate_parameters_hash_hex, 32, `${label}.candidate_parameters_hash`),
    exactHex(checkpoint.result_digest_hex, 32, `${label}.result_digest`),
  ]).toString("hex");
}

function addSemanticEntryToSource(source, kind, identity, payload, revision, label) {
  const logicalKey = semanticLogicalKey(kind, identity);
  const value = encodeSemanticEnvelope(kind, revision, identity, payload);
  const rawEntry = {
    kind,
    logical_key_hex: logicalKey.toString("hex"),
    value_hex: value.toString("hex"),
    canonical_entry_cev0_hex: "",
  };
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    invariant(!projection.entries.some((entry) => entry.kind === kind && entry.logical_key_hex === rawEntry.logical_key_hex), `${label}: semantic key collision`);
    projection.entries.push(structuredClone(rawEntry));
    refreshRawProjection(projection, `${label}.${projectionName}`);
  }
  addPhysicalWriteAtVersion(
    source,
    source.cutoff_version,
    entryPhysicalKey(kind, logicalKey).toString("hex"),
    value.toString("hex"),
    label,
  );
  replaceLastPhysicalWrite(source, manifestKey().toString("hex"), source.cutoff_version, source.cutoff_projection.manifest_hex, `${label}.manifest`);
  recomputeExportedHistoryRoots(source, label);
  return logicalKey.toString("hex");
}

function retargetCutoffVersionInSource(source, nextVersion, label) {
  const cutoffVersion = safeU64(nextVersion, `${label}.cutoff_version`);
  invariant(BigInt(cutoffVersion) < BigInt(source.cutoff_version), `${label}: cutoff mutation must move backward`);
  invariant(
    source.history.some((item) => BigInt(item.version) === BigInt(cutoffVersion)),
    `${label}: substituted cutoff version absent`,
  );
  let manifestHex = null;
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    const root = exactHex(projection.entries_root_hex, 32, `${label}.${projectionName}.entries_root`);
    const nextManifest = Buffer.concat([
      uint(0, 2),
      Buffer.from([8]),
      uint(cutoffVersion, 8),
      uint(projection.entries.length, 4),
      root,
    ]).toString("hex");
    projection.manifest_hex = nextManifest;
    manifestHex ??= nextManifest;
    invariant(manifestHex === nextManifest, `${label}: cutoff/head manifest mutation drift`);
  }
  const physicalManifestKey = manifestKey().toString("hex");
  setPhysicalWriteAtVersion(source, cutoffVersion, physicalManifestKey, manifestHex, `${label}.cutoff_manifest`);
  for (const item of source.history) {
    if (BigInt(item.version) <= BigInt(cutoffVersion)) continue;
    const manifestWrite = item.writes.find((write) => write.physical_key_hex === physicalManifestKey);
    if (manifestWrite !== undefined) manifestWrite.value_hex = manifestHex;
  }
  source.cutoff_version = cutoffVersion;
  recomputeExportedHistoryRoots(source, label);
}

function rewriteManifestTupleInSource(source, mutate, label) {
  let manifestHex = null;
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    const manifest = decodeManifest(
      exactHex(projection.manifest_hex, 47, `${label}.${projectionName}.manifest`),
      `${label}.${projectionName}.manifest`,
    );
    const next = mutate({
      height: manifest.height,
      count: manifest.count,
      root: Buffer.from(manifest.root),
    });
    invariant(
      next !== null && typeof next === "object" && Number.isInteger(next.count) && Buffer.isBuffer(next.root),
      `${label}: invalid manifest mutation result`,
    );
    const nextManifest = Buffer.concat([
      uint(0, 2), Buffer.from([8]), uint(next.height, 8), uint(next.count, 4), next.root,
    ]).toString("hex");
    projection.manifest_hex = nextManifest;
    manifestHex ??= nextManifest;
    invariant(manifestHex === nextManifest, `${label}: cutoff/head manifest mutation drift`);
  }
  replaceLastPhysicalWrite(
    source,
    manifestKey().toString("hex"),
    source.cutoff_version,
    manifestHex,
    `${label}.manifest`,
  );
  recomputeExportedHistoryRoots(source, label);
}

function duplicateSemanticEntryInSource(source, kind, logicalKeyHex, label) {
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    const item = projection.entries.find(
      (entry) => entry.kind === kind && entry.logical_key_hex === logicalKeyHex,
    );
    invariant(item !== undefined, `${label}.${projectionName}: duplicate source entry absent`);
    projection.entries.push(structuredClone(item));
    refreshRawProjection(projection, `${label}.${projectionName}`);
  }
  replaceLastPhysicalWrite(
    source,
    manifestKey().toString("hex"),
    source.cutoff_version,
    source.cutoff_projection.manifest_hex,
    `${label}.manifest`,
  );
  recomputeExportedHistoryRoots(source, label);
}

function futurePopOffsets(raw, label) {
  const c = new Cursor(raw, label);
  c.u16("schema");
  const genesisHash = c.offset;
  c.take(32, "genesis_hash");
  const chainLength = c.u16("chain_id.length");
  invariant(chainLength >= 1 && chainLength <= 128, `${label}: chain ID length`);
  const chainId = c.offset;
  c.take(chainLength, "chain_id");
  const targetEpoch = c.offset;
  c.u64("target_epoch");
  const validatorLength = c.u32("validator_id.length");
  invariant(validatorLength >= 1 && validatorLength <= 128, `${label}: validator ID length`);
  const validatorId = c.offset;
  c.take(validatorLength, "validator_id");
  const publicKey = c.offset;
  c.take(32, "public_key");
  const registrationNonce = c.offset;
  c.u64("registration_nonce");
  const signature = c.offset;
  c.take(64, "signature");
  c.finish();
  return {
    genesisHash,
    chainId,
    chainLength,
    targetEpoch,
    validatorId,
    validatorLength,
    publicKey,
    registrationNonce,
    signature,
  };
}

function addOrphanConsumerKeyToSource(source, label) {
  const consumer = Buffer.from("orphan-consumer", "ascii");
  const consumerKey = Buffer.from("orphan-key", "ascii");
  const identity = joinedIdentity([consumer, consumerKey]);
  const payload = Buffer.concat([
    frame32(consumer), frame32(consumerKey), Buffer.alloc(32, 0x42), uint(1, 8), Buffer.from([0]),
  ]);
  const logicalKey = semanticLogicalKey(2, identity);
  const value = encodeSemanticEnvelope(2, 1, identity, payload);
  const rawEntry = {
    kind: 2,
    logical_key_hex: logicalKey.toString("hex"),
    value_hex: value.toString("hex"),
    canonical_entry_cev0_hex: "",
  };
  for (const projectionName of ["cutoff_projection", "head_projection"]) {
    const projection = source[projectionName];
    invariant(!projection.entries.some((entry) => entry.kind === 2 && entry.logical_key_hex === rawEntry.logical_key_hex), `${label}: orphan key collision`);
    projection.entries.push(structuredClone(rawEntry));
    refreshRawProjection(projection, `${label}.${projectionName}`);
  }
  addPhysicalWriteAtVersion(
    source,
    source.cutoff_version,
    entryPhysicalKey(2, logicalKey).toString("hex"),
    value.toString("hex"),
    `${label}.orphan`,
  );
  replaceLastPhysicalWrite(source, manifestKey().toString("hex"), source.cutoff_version, source.cutoff_projection.manifest_hex, `${label}.manifest`);
  recomputeExportedHistoryRoots(source, label);
}

function runNegativeSelfChecks(vector, positive, fallback) {
  const cases = [
    ["cutoff root", /cutoff history root/, (draft) => { draft.positive.source.cutoff_root_hex = "ff".repeat(32); }],
    ["history JMT root", /JMT root mismatch/, (draft) => {
      draft.positive.source.history.at(-1).writes.push({
        physical_key_hex: namespacedKey(7, [Buffer.from("jmt-root-negative", "ascii")]).toString("hex"),
        value_hex: "00",
      });
    }],
    ["entry omission", /entries root/, (draft) => { draft.positive.source.cutoff_projection.entries.pop(); }],
    ["manifest count", /checkpoint canonical bytes/, (draft) => { draft.positive.checkpoint.cutoff_entry_count += 1; }],
    ["authorization substitution", /authorization seal/, (draft) => { draft.positive.checkpoint.authorization_id_hex = "ff".repeat(32); }],
  ];
  const authorityIndex = positive.cutoff.entries.findIndex((entry) => entry.kind === 16);
  invariant(authorityIndex >= 0, "negative self-check lacks authority entry");
  for (const [name, expectedError, mutate] of cases) {
    const draft = structuredClone(vector);
    mutate(draft);
    assert.throws(
      () => validateScenario(draft.compact_profile, draft.positive, `negative.${name}`),
      expectedError,
      `${name} mutation did not reach its frozen first-error family`,
    );
    stats.rejections += 1;
  }

  const resultSeal = structuredClone(vector);
  resultSeal.positive.checkpoint.result_digest_hex = "fe".repeat(32);
  assert.throws(
    () => validateScenario(resultSeal.compact_profile, resultSeal.positive, "negative.result_seal"),
    /result seal/,
    "explicit result-digest substitution was accepted",
  );
  stats.rejections += 1;

  const candidateParametersSeal = structuredClone(vector);
  candidateParametersSeal.positive.checkpoint.candidate_parameters_hash_hex = "fd".repeat(32);
  assert.throws(
    () => validateScenario(
      candidateParametersSeal.compact_profile,
      candidateParametersSeal.positive,
      "negative.candidate_parameters_seal",
    ),
    /candidate-parameters seal/,
    "explicit candidate-parameters-hash substitution was accepted",
  );
  stats.rejections += 1;

  const fallbackResultSeal = structuredClone(vector);
  fallbackResultSeal.authenticated_fallback.checkpoint.result_digest_hex = "fc".repeat(32);
  assert.throws(
    () => validateScenario(
      fallbackResultSeal.compact_profile,
      fallbackResultSeal.authenticated_fallback,
      "negative.fallback_result_seal",
    ),
    /result seal/,
    "authenticated fallback result-digest substitution was accepted",
  );
  stats.rejections += 1;

  const cutoffVersion = structuredClone(vector);
  retargetCutoffVersionInSource(
    cutoffVersion.positive.source,
    BigInt(cutoffVersion.positive.source.cutoff_version) - 1n,
    "negative.cutoff_version",
  );
  refreshCheckpointSourceBindings(
    cutoffVersion.compact_profile,
    cutoffVersion.positive,
    positive.reconstructed,
    "negative.cutoff_version",
  );
  assert.throws(
    () => validateScenario(cutoffVersion.compact_profile, cutoffVersion.positive, "negative.cutoff_version"),
    /profile\/cutoff height/,
    "root-consistent cutoff-version substitution was accepted",
  );
  stats.rejections += 1;

  const manifestRoot = structuredClone(vector);
  rewriteManifestTupleInSource(
    manifestRoot.positive.source,
    (manifest) => {
      manifest.root[0] ^= 1;
      return manifest;
    },
    "negative.manifest_entries_root",
  );
  assert.throws(
    () => validateScenario(manifestRoot.compact_profile, manifestRoot.positive, "negative.manifest_entries_root"),
    /manifest tuple/,
    "physical/JMT-consistent manifest entries-root substitution was accepted",
  );
  stats.rejections += 1;

  const manifestCount = structuredClone(vector);
  rewriteManifestTupleInSource(
    manifestCount.positive.source,
    (manifest) => ({ ...manifest, count: manifest.count + 1 }),
    "negative.manifest_entry_count",
  );
  assert.throws(
    () => validateScenario(manifestCount.compact_profile, manifestCount.positive, "negative.manifest_entry_count"),
    /manifest tuple/,
    "physical/JMT-consistent manifest entry-count substitution was accepted",
  );
  stats.rejections += 1;

  const duplicateEntry = structuredClone(vector);
  duplicateSemanticEntryInSource(
    duplicateEntry.positive.source,
    16,
    positive.cutoff.entries[authorityIndex].key.toString("hex"),
    "negative.semantic_entry_duplicate",
  );
  assert.throws(
    () => validateScenario(duplicateEntry.compact_profile, duplicateEntry.positive, "negative.semantic_entry_duplicate"),
    /entries not strictly sorted/,
    "root-consistent duplicate semantic entry was accepted",
  );
  stats.rejections += 1;

  // Keep the mutated JMT root internally consistent so this reaches the
  // independent physical-namespace completeness check rather than failing on
  // a stale exported root.  A valid but unmanifested namespace-8 entry must
  // still be rejected at the head projection.
  const hiddenDraft = structuredClone(vector);
  const hiddenLogicalKey = Buffer.alloc(32, 0xfe);
  const hiddenPhysicalKey = entryPhysicalKey(1, hiddenLogicalKey).toString("hex");
  invariant(!positive.history.headLive.has(hiddenPhysicalKey), "hidden-leaf negative key collision");
  hiddenDraft.positive.source.history.at(-1).writes.push({
    physical_key_hex: hiddenPhysicalKey,
    value_hex: "00",
  });
  const hiddenLive = new Map(positive.history.headLive);
  hiddenLive.set(hiddenPhysicalKey, "00");
  const hiddenRootHex = jmtRoot(hiddenLive).toString("hex");
  hiddenDraft.positive.source.history.at(-1).jmt_root_hex = hiddenRootHex;
  hiddenDraft.positive.source.head_root_hex = hiddenRootHex;
  assert.throws(
    () => validateScenario(hiddenDraft.compact_profile, hiddenDraft.positive, "negative.hidden_namespace_leaf"),
    /physical namespace contains hidden, additional, duplicate, or missing leaves/,
    "hidden namespace-8 physical leaf was accepted",
  );
  stats.rejections += 1;

  // This bypasses the physical-root mutations on purpose and exercises the
  // exact nested kind-16 decoder itself.  A canonical JSON payload containing
  // an unknown field in a nested semantic-key companion must fail at that
  // nested record rather than being ignored by JavaScript object access.
  const nestedUnknown = structuredClone(positive.reconstructed.authority);
  invariant(
    nestedUnknown.active_certificates.length > 0 &&
      nestedUnknown.active_certificates[0].semantic_keys.length > 0,
    "nested unknown-field negative lacks a semantic-key companion",
  );
  nestedUnknown.active_certificates[0].semantic_keys[0].unknown_field = 1;
  assert.throws(
    () => decodeAuthority(
      Buffer.from(JSON.stringify(nestedUnknown)),
      BigInt(nestedUnknown.revision),
      "negative.nested_unknown_field",
    ),
    /semantic_keys\[0\]: field order drift/,
    "nested kind-16 unknown field was accepted",
  );
  stats.rejections += 1;

  const overCap = structuredClone(positive.reconstructed.authority);
  invariant(overCap.active_certificates.length === AUTHORITY_HARD_CAPS.active_certificates, "authority-cap negative lacks a full certificate family");
  overCap.active_certificates.push(structuredClone(overCap.active_certificates[0]));
  assert.throws(
    () => decodeAuthority(
      Buffer.from(JSON.stringify(overCap)),
      BigInt(overCap.revision),
      "negative.authority_record_cap",
    ),
    /active_certificates: record cap/,
    "over-cap kind-16 authority was accepted",
  );
  stats.rejections += 1;

  // Rewrite the canonical kind-16 value, both projections, the manifest and
  // every affected JMT/source root so this mutation cannot be dismissed as a
  // stale-root error.  It must reach the provider-provenance companion join.
  const provenanceDraft = structuredClone(vector);
  rewriteAuthorityInSource(
    provenanceDraft.positive.source,
    (state) => {
      invariant(state.active_certificates.length > 0, "provider-provenance negative lacks certificate authority");
      state.active_certificates[0].provider_registration_decision_id_hex = "ab".repeat(32);
    },
    "negative.provider_provenance",
  );
  assert.throws(
    () => validateScenario(provenanceDraft.compact_profile, provenanceDraft.positive, "negative.provider_provenance"),
    /certificate\/provider registration provenance/,
    "kind-16 provider-provenance substitution was accepted",
  );
  stats.rejections += 1;

  // Add a fully canonical kind-2 value and corresponding physical leaf, then
  // recompute the ordered projection root, manifest and JMT roots.  The raw
  // fact is valid on its own but has no kind-16 companion, so only the reverse
  // authority-managed orphan sweep may reject it.
  const orphanDraft = structuredClone(vector);
  addOrphanConsumerKeyToSource(orphanDraft.positive.source, "negative.orphan_consumer_key");
  assert.throws(
    () => validateScenario(orphanDraft.compact_profile, orphanDraft.positive, "negative.orphan_consumer_key"),
    /orphan authority-managed semantic entry lacks kind-16 companion/,
    "orphan authority-managed kind-2 semantic entry was accepted",
  );
  stats.rejections += 1;

  // Independent kind-8 facts are not kind-16 orphans, but Rust still exact-
  // decodes every physical semantic payload before authority reconstruction.
  // Add a canonical envelope and valid relationship identity, append one byte
  // to an otherwise valid payload, and refresh every projection/JMT/checkpoint
  // source seal so the only first error is the raw kind-8 payload decoder.
  const malformedIndependentRelationship = structuredClone(vector);
  const relationshipProvider = Buffer.from("independent-provider", "ascii");
  const relationshipConsumer = Buffer.from("independent-consumer", "ascii");
  const relationshipTask = Buffer.from("independent-task", "ascii");
  const relationshipIdentity = joinedIdentity([
    relationshipProvider,
    relationshipConsumer,
    relationshipTask,
  ]);
  const relationshipPayload = Buffer.concat([
    frame32(relationshipProvider),
    frame32(relationshipConsumer),
    frame32(relationshipTask),
    Buffer.from([1]),
    uint(malformedIndependentRelationship.compact_profile.checkpoint_height + 10, 8),
    Buffer.from([0]),
  ]);
  addSemanticEntryToSource(
    malformedIndependentRelationship.positive.source,
    8,
    relationshipIdentity,
    relationshipPayload,
    1,
    "negative.independent_relationship_payload",
  );
  refreshCheckpointSourceBindings(
    malformedIndependentRelationship.compact_profile,
    malformedIndependentRelationship.positive,
    positive.reconstructed,
    "negative.independent_relationship_payload",
  );
  refreshAuthorizationFromFrozenSeals(
    malformedIndependentRelationship.positive,
    "negative.independent_relationship_payload",
  );
  assert.throws(
    () => validateScenario(
      malformedIndependentRelationship.compact_profile,
      malformedIndependentRelationship.positive,
      "negative.independent_relationship_payload",
    ),
    /kind_8: trailing bytes/,
    "root-consistent malformed independent kind-8 payload was accepted",
  );
  stats.rejections += 1;

  const changedFuture = positive.reconstructed.authority.future_candidate_registrations.find(
    (item) => item.previous_registration_nonce !== null,
  );
  const newFuture = positive.reconstructed.authority.future_candidate_registrations.find(
    (item) => item.previous_registration_nonce === null,
  );
  invariant(changedFuture && newFuture, "retained mutation campaign lacks changed/new future registrations");

  const explicitEmptyFuture = structuredClone(vector);
  rewriteAuthorityInSource(
    explicitEmptyFuture.positive.source,
    (state) => { state.future_candidate_registrations = []; },
    "negative.explicit_empty_future_family",
  );
  assert.throws(
    () => validateScenario(explicitEmptyFuture.compact_profile, explicitEmptyFuture.positive, "negative.explicit_empty_future_family"),
    /explicit empty family must be omitted/,
    "explicit empty future-registration family was accepted",
  );
  stats.rejections += 1;

  const quotedU64 = structuredClone(vector);
  rewriteAuthorityInSource(
    quotedU64.positive.source,
    (state) => { state.revision = String(state.revision); },
    "negative.quoted_authority_u64",
  );
  assert.throws(
    () => validateScenario(quotedU64.compact_profile, quotedU64.positive, "negative.quoted_authority_u64"),
    /Rust integer fields require an unquoted JSON number/,
    "quoted kind-16 u64 was accepted",
  );
  stats.rejections += 1;

  const unquotedU128 = structuredClone(vector);
  rewriteAuthorityInSource(
    unquotedU128.positive.source,
    (state) => { state.active_certificates[0].consumed_units = 1; },
    "negative.unquoted_authority_u128",
  );
  assert.throws(
    () => validateScenario(unquotedU128.compact_profile, unquotedU128.positive, "negative.unquoted_authority_u128"),
    /CanonicalU128V0 requires a quoted decimal string/,
    "unquoted kind-16 CanonicalU128V0 was accepted",
  );
  stats.rejections += 1;

  const shortNewPredecessor = structuredClone(vector);
  rewriteAuthorityInSource(
    shortNewPredecessor.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === newFuture.validator_id_hex);
      item.predecessor_history_head_hex = "0";
    },
    "negative.short_new_predecessor_head",
  );
  assert.throws(
    () => validateScenario(shortNewPredecessor.compact_profile, shortNewPredecessor.positive, "negative.short_new_predecessor_head"),
    /expected 32-byte lowercase hex/,
    "short all-zero new-member predecessor head was accepted",
  );
  stats.rejections += 1;

  const wrongPopDomain = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopDomain.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-domain PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-domain PoP");
      const decoded = decodePopExact(proof);
      const publicKey = exactHex(item.consensus_key_hex, 32, "negative wrong-domain PoP key");
      const privateKey = futureFixturePrivateKey(
        item.validator_id_hex,
        item.consensus_key_hex,
        "negative wrong-domain PoP",
      );
      const wrongDomainRoot = digest("trnm.poco-bft.validator-key-pop.v1", decoded.signing);
      const wrongDomainSignature = crypto.sign(null, wrongDomainRoot, privateKey);
      invariant(
        strictEd25519Verify(wrongDomainRoot, publicKey, wrongDomainSignature),
        "negative wrong-domain PoP is not valid under the substituted domain",
      );
      invariant(
        !strictEd25519Verify(digest(POP_DOMAIN, decoded.signing), publicKey, wrongDomainSignature),
        "negative wrong-domain PoP unexpectedly verifies under the frozen v0 domain",
      );
      wrongDomainSignature.copy(proof, offsets.signature);
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_domain",
  );
  assert.throws(
    () => validateScenario(wrongPopDomain.compact_profile, wrongPopDomain.positive, "negative.future_pop_wrong_domain"),
    /invalid strict Ed25519 signature/,
    "future PoP signed under the wrong domain was accepted",
  );
  stats.rejections += 1;

  const wrongPopGenesis = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopGenesis.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-genesis PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-genesis PoP");
      proof[offsets.genesisHash] ^= 1;
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_genesis",
  );
  assert.throws(
    () => validateScenario(wrongPopGenesis.compact_profile, wrongPopGenesis.positive, "negative.future_pop_wrong_genesis"),
    /genesis scope/,
    "future PoP genesis substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopChain = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopChain.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-chain PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-chain PoP");
      proof[offsets.chainId] = proof[offsets.chainId] === 0x61 ? 0x62 : 0x61;
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_chain",
  );
  assert.throws(
    () => validateScenario(wrongPopChain.compact_profile, wrongPopChain.positive, "negative.future_pop_wrong_chain"),
    /chain scope/,
    "future PoP chain substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopValidatorId = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopValidatorId.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-validator-ID PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-validator-ID PoP");
      proof[offsets.validatorId + offsets.validatorLength - 1] ^= 1;
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_validator_id",
  );
  assert.throws(
    () => validateScenario(
      wrongPopValidatorId.compact_profile,
      wrongPopValidatorId.positive,
      "negative.future_pop_wrong_validator_id",
    ),
    /validator ID/,
    "future PoP validator-ID substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopTarget = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopTarget.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-target PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-target PoP");
      uint(BigInt(item.target_epoch) + 1n, 8).copy(proof, offsets.targetEpoch);
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_target",
  );
  assert.throws(
    () => validateScenario(wrongPopTarget.compact_profile, wrongPopTarget.positive, "negative.future_pop_wrong_target"),
    /target epoch/,
    "future PoP target substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopKey = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopKey.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-key PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-key PoP");
      proof[offsets.publicKey] ^= 1;
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_key",
  );
  assert.throws(
    () => validateScenario(wrongPopKey.compact_profile, wrongPopKey.positive, "negative.future_pop_wrong_key"),
    /public key/,
    "future PoP public-key substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopNonce = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopNonce.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-nonce PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-nonce PoP");
      uint(BigInt(item.registration_nonce) + 1n, 8).copy(proof, offsets.registrationNonce);
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_nonce",
  );
  assert.throws(
    () => validateScenario(wrongPopNonce.compact_profile, wrongPopNonce.positive, "negative.future_pop_wrong_nonce"),
    /nonce/,
    "future PoP nonce substitution was accepted",
  );
  stats.rejections += 1;

  const wrongPopSignature = structuredClone(vector);
  rewriteAuthorityInSource(
    wrongPopSignature.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative wrong-signature PoP");
      const offsets = futurePopOffsets(proof, "negative wrong-signature PoP");
      proof[offsets.signature] ^= 1;
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_wrong_signature",
  );
  assert.throws(
    () => validateScenario(wrongPopSignature.compact_profile, wrongPopSignature.positive, "negative.future_pop_wrong_signature"),
    /invalid strict Ed25519 signature/,
    "future PoP signature substitution was accepted",
  );
  stats.rejections += 1;

  const noncanonicalPopScalar = structuredClone(vector);
  rewriteAuthorityInSource(
    noncanonicalPopScalar.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative noncanonical-S PoP");
      const offsets = futurePopOffsets(proof, "negative noncanonical-S PoP");
      const scalarOffset = offsets.signature + 32;
      const scalar = littleEndianInteger(proof.subarray(scalarOffset, scalarOffset + 32));
      invariant(scalar < ED25519_SCALAR_ORDER, "canonical fixture PoP has a noncanonical scalar");
      const noncanonicalScalar = scalar + ED25519_SCALAR_ORDER;
      invariant(noncanonicalScalar < (1n << 256n), "noncanonical-S mutation overflow");
      littleEndianBytes(noncanonicalScalar, 32).copy(proof, scalarOffset);
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_noncanonical_s",
  );
  assert.throws(
    () => validateScenario(
      noncanonicalPopScalar.compact_profile,
      noncanonicalPopScalar.positive,
      "negative.future_pop_noncanonical_s",
    ),
    /invalid strict Ed25519 signature/,
    "future PoP with noncanonical S was accepted",
  );
  stats.rejections += 1;

  const noncanonicalPopPoint = structuredClone(vector);
  rewriteAuthorityInSource(
    noncanonicalPopPoint.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative noncanonical-R PoP");
      const offsets = futurePopOffsets(proof, "negative noncanonical-R PoP");
      ED25519_NONCANONICAL_R.copy(proof, offsets.signature);
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_pop_noncanonical_r",
  );
  assert.throws(
    () => validateScenario(
      noncanonicalPopPoint.compact_profile,
      noncanonicalPopPoint.positive,
      "negative.future_pop_noncanonical_r",
    ),
    /invalid strict Ed25519 signature/,
    "future PoP with noncanonical R was accepted",
  );
  stats.rejections += 1;

  const smallOrderFutureKey = structuredClone(vector);
  rewriteAuthorityInSource(
    smallOrderFutureKey.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      const proof = boundedHex(item.proof_cev0_hex, 1, 65_384, "negative small-order future key PoP");
      const offsets = futurePopOffsets(proof, "negative small-order future key PoP");
      ED25519_SMALL_ORDER_PUBLIC_KEY.copy(proof, offsets.publicKey);
      item.consensus_key_hex = ED25519_SMALL_ORDER_PUBLIC_KEY.toString("hex");
      const forgedSignature = Buffer.alloc(64);
      ED25519_BASEPOINT_COMPRESSED.copy(forgedSignature, 0);
      forgedSignature[32] = 1;
      forgedSignature.copy(proof, offsets.signature);
      const decoded = decodePopExact(proof);
      invariant(
        isSmallOrderEd25519Point(decodeCanonicalEd25519Point(ED25519_SMALL_ORDER_PUBLIC_KEY)),
        "small-order future-key fixture is not small order",
      );
      invariant(
        !strictEd25519Verify(
          digest(POP_DOMAIN, decoded.signing),
          ED25519_SMALL_ORDER_PUBLIC_KEY,
          forgedSignature,
        ),
        "strict Ed25519 accepted a small-order future key",
      );
      item.proof_cev0_hex = proof.toString("hex");
      item.proof_digest_hex = domainHash(FUTURE_POP_DIGEST_DOMAIN, proof).toString("hex");
    },
    "negative.future_small_order_key",
  );
  assert.throws(
    () => validateScenario(
      smallOrderFutureKey.compact_profile,
      smallOrderFutureKey.positive,
      "negative.future_small_order_key",
    ),
    /invalid strict Ed25519 signature/,
    "small-order future candidate key was accepted",
  );
  stats.rejections += 1;

  const predecessorNonce = structuredClone(vector);
  rewriteAuthorityInSource(
    predecessorNonce.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      item.previous_registration_nonce += 1;
    },
    "negative.predecessor_nonce",
  );
  assert.throws(
    () => validateScenario(predecessorNonce.compact_profile, predecessorNonce.positive, "negative.predecessor_nonce"),
    /changed-key predecessor old-key\/nonce\/history authority/,
    "changed-key predecessor nonce substitution was accepted",
  );
  stats.rejections += 1;

  const predecessorHistoryHead = structuredClone(vector);
  rewriteAuthorityInSource(
    predecessorHistoryHead.positive.source,
    (state) => {
      const item = state.future_candidate_registrations.find((candidate) => candidate.validator_id_hex === changedFuture.validator_id_hex);
      item.predecessor_history_head_hex = "cd".repeat(32);
    },
    "negative.predecessor_history_head",
  );
  assert.throws(
    () => validateScenario(predecessorHistoryHead.compact_profile, predecessorHistoryHead.positive, "negative.predecessor_history_head"),
    /changed-key predecessor old-key\/nonce\/history authority/,
    "changed-key predecessor history-head substitution was accepted",
  );
  stats.rejections += 1;

  const predecessorOldKey = structuredClone(vector);
  const activeSetEntry = positive.cutoff.entries.find((entry) => entry.kind === 13);
  invariant(activeSetEntry !== undefined, "predecessor old-key negative lacks active validator set");
  rewriteSemanticEntryInSource(
    predecessorOldKey.positive.source,
    13,
    activeSetEntry.key.toString("hex"),
    (payload) => {
      const c = new Cursor(payload, "negative.predecessor_old_key.validator_set");
      c.u16("schema"); c.take(32, "genesis"); c.bytes16("chain"); c.u32("protocol"); c.u64("epoch"); c.take(32, "parameters_hash");
      const count = c.u32("count");
      let mutated = false;
      for (let index = 0; index < count; index += 1) {
        const id = c.bytes32(`validator_${index}.id`, 128);
        const keyOffset = c.offset;
        c.take(32, `validator_${index}.key`);
        c.u64(`validator_${index}.power`);
        if (id.toString("hex") === changedFuture.validator_id_hex) {
          Buffer.alloc(32, 0x7d).copy(payload, keyOffset);
          mutated = true;
        }
      }
      c.finish();
      invariant(mutated, "predecessor old-key validator absent");
      return payload;
    },
    "negative.predecessor_old_key",
  );
  assert.throws(
    () => validateScenario(predecessorOldKey.compact_profile, predecessorOldKey.positive, "negative.predecessor_old_key"),
    /changed-key predecessor old-key\/nonce\/history authority/,
    "changed-key predecessor history from a non-old key was accepted",
  );
  stats.rejections += 1;

  const sourceSplice = structuredClone(vector);
  sourceSplice.positive.source = structuredClone(vector.authenticated_fallback.source);
  sourceSplice.positive.expected_fallback_used = true;
  sourceSplice.positive.expected_fallback_reason_code = 3;
  refreshCheckpointSourceBindings(sourceSplice.compact_profile, sourceSplice.positive, positive.reconstructed, "negative.source_splice");
  assert.throws(
    () => validateScenario(sourceSplice.compact_profile, sourceSplice.positive, "negative.source_splice"),
    /transcript seal/,
    "positive checkpoint/fallback source splice was accepted",
  );
  stats.rejections += 1;

  const retainedCertificate = positive.reconstructed.authority.active_certificates[0];
  const relationshipExpiry = structuredClone(vector);
  rewriteSemanticEntryInSource(
    relationshipExpiry.positive.source,
    8,
    retainedCertificate.relationship_key_hex,
    (payload) => {
      uint(retainedCertificate.accepted_height, 8).copy(payload, payload.length - 8);
      return payload;
    },
    "negative.relationship_expiry",
  );
  assert.throws(
    () => validateScenario(relationshipExpiry.compact_profile, relationshipExpiry.positive, "negative.relationship_expiry"),
    /relationship expired before billing\/acceptance/,
    "expired raw relationship companion was accepted",
  );
  stats.rejections += 1;

  const fallbackCertificateId = fallback.reconstructed.authority.pending_challenges[0].certificate_id_hex;
  const fallbackCertificate = fallback.reconstructed.authority.active_certificates.find((item) => item.certificate_id_hex === fallbackCertificateId);
  const fallbackLifecycleKey = fallbackCertificate.semantic_keys.find((item) => item.kind === 12).logical_key_hex;
  const lifecycleDrift = structuredClone(vector);
  rewriteSemanticEntryInSource(
    lifecycleDrift.authenticated_fallback.source,
    12,
    fallbackLifecycleKey,
    (payload) => { payload[32] = 1; return payload; },
    "negative.lifecycle_pending_drift",
  );
  assert.throws(
    () => validateScenario(lifecycleDrift.compact_profile, lifecycleDrift.authenticated_fallback, "negative.lifecycle_pending_drift"),
    /lifecycle state/,
    "pending-challenge lifecycle drift was accepted",
  );
  stats.rejections += 1;

  const governancePendingFinalizedDrift = structuredClone(vector);
  const governanceTarget = BigInt(vector.compact_profile.target_epoch);
  const governanceActivation = governanceTarget * BigInt(vector.compact_profile.epoch_length_blocks) + 1n;
  const governanceDecisionId = "bc".repeat(32);
  rewriteAuthorityInSource(
    governancePendingFinalizedDrift.positive.source,
    (state) => {
      invariant(state.pending_governance_proposals.length === 0, "governance pending/finalized negative requires no prior pending proposal");
      state.pending_governance_proposals.push({
        target_epoch: vector.compact_profile.target_epoch,
        proposal_decision_id_hex: governanceDecisionId,
        proposed_height: state.last_target_height,
        phase: positive.reconstructed.oldParameters.rollout_phase,
        parameters_hash_hex: vector.compact_profile.active_parameters_hash_hex,
        activation_height: Number(governanceActivation),
      });
    },
    "negative.governance_pending_finalized_drift",
  );
  const governancePayload = Buffer.concat([
    Buffer.from([positive.reconstructed.oldParameters.rollout_phase]),
    exactHex(vector.compact_profile.active_parameters_hash_hex, 32, "negative governance parameters hash"),
    uint(governanceActivation, 8),
    Buffer.from([1]),
  ]);
  addSemanticEntryToSource(
    governancePendingFinalizedDrift.positive.source,
    15,
    uint(governanceTarget, 8),
    governancePayload,
    1,
    "negative.governance_pending_finalized_drift",
  );
  assert.throws(
    () => validateScenario(
      governancePendingFinalizedDrift.compact_profile,
      governancePendingFinalizedDrift.positive,
      "negative.governance_pending_finalized_drift",
    ),
    /governance companion drift/,
    "pending kind-16 governance record accepted a finalized raw companion",
  );
  stats.rejections += 1;

  const bondEquality = structuredClone(vector);
  const bondedId = retainedCertificate.provider_id_hex;
  const bondKey = semanticLogicalKey(10, boundedHex(bondedId, 1, 128, "negative bond validator ID")).toString("hex");
  const coverageEnd = BigInt(vector.compact_profile.target_epoch) + BigInt(vector.compact_profile.evidence_window_epochs);
  rewriteSemanticEntryInSource(
    bondEquality.positive.source,
    10,
    bondKey,
    (payload) => {
      const c = new Cursor(payload, "negative.bond_equality");
      c.bytes32("validator_id", 128); c.u128("amount");
      const lockedUntilOffset = c.offset;
      c.u64("locked_until"); c.u8("state"); c.finish();
      uint(coverageEnd, 8).copy(payload, lockedUntilOffset);
      return payload;
    },
    "negative.bond_equality",
  );
  bondEquality.positive.expected_fallback_used = true;
  bondEquality.positive.expected_fallback_reason_code = 3;
  refreshCheckpointSourceBindings(bondEquality.compact_profile, bondEquality.positive, positive.reconstructed, "negative.bond_equality");
  assert.throws(
    () => validateScenario(bondEquality.compact_profile, bondEquality.positive, "negative.bond_equality"),
    /transcript seal/,
    "bond coverage equality did not invalidate the frozen transcript",
  );
  stats.rejections += 1;

  const jailEquality = structuredClone(vector);
  const jailIdentity = boundedHex(bondedId, 1, 128, "negative jail validator ID");
  const jailPayload = Buffer.concat([frame32(jailIdentity), uint(vector.compact_profile.target_epoch, 8), Buffer.from([2])]);
  const jailKey = addSemanticEntryToSource(jailEquality.positive.source, 11, jailIdentity, jailPayload, 1, "boundary.jail_equality");
  refreshCheckpointSourceBindings(jailEquality.compact_profile, jailEquality.positive, positive.reconstructed, "boundary.jail_equality");
  refreshAuthorizationFromFrozenSeals(jailEquality.positive, "boundary.jail_equality");
  validateScenario(jailEquality.compact_profile, jailEquality.positive, "boundary.jail_equality");

  const jailOneBefore = structuredClone(jailEquality);
  rewriteSemanticEntryInSource(
    jailOneBefore.positive.source,
    11,
    jailKey,
    (payload) => {
      const c = new Cursor(payload, "negative.jail_one_before");
      c.bytes32("validator_id", 128);
      const jailedUntilOffset = c.offset;
      c.u64("jailed_until"); c.u8("reason"); c.finish();
      uint(BigInt(vector.compact_profile.target_epoch) + 1n, 8).copy(payload, jailedUntilOffset);
      return payload;
    },
    "negative.jail_one_before",
  );
  jailOneBefore.positive.expected_fallback_used = true;
  jailOneBefore.positive.expected_fallback_reason_code = 3;
  refreshCheckpointSourceBindings(jailOneBefore.compact_profile, jailOneBefore.positive, positive.reconstructed, "negative.jail_one_before");
  assert.throws(
    () => validateScenario(jailOneBefore.compact_profile, jailOneBefore.positive, "negative.jail_one_before"),
    /transcript seal/,
    "jail one-before boundary did not invalidate the frozen transcript",
  );
  stats.rejections += 1;

  const currentHeadSubstitution = structuredClone(vector);
  rewriteSemanticEntryInSource(
    currentHeadSubstitution.positive.source,
    8,
    retainedCertificate.relationship_key_hex,
    (payload) => { payload[payload.length - 1] ^= 1; return payload; },
    "negative.current_head_substitution",
    "head_only",
  );
  assert.throws(
    () => validateScenario(currentHeadSubstitution.compact_profile, currentHeadSubstitution.positive, "negative.current_head_substitution"),
    /post-cutoff projection content changed/,
    "self-consistent post-cutoff current-head semantic substitution was accepted",
  );
  stats.rejections += 1;

  // A retained certificate for a provider removed from the reconstructed
  // candidate universe must become ineligible, not malformed B2-G input.
  const retained = positive.reconstructed.authority.active_certificates[0];
  const withoutProvider = new Set(positive.reconstructed.candidates.map((candidate) => candidate.validator_id_hex));
  withoutProvider.delete(retained.provider_id_hex);
  invariant(
    contributionEligible(positive.reconstructed.authority, withoutProvider, retained) === false,
    "retained non-candidate provider was not projected eligible=false",
  );
  stats.boundaryControls += 1;
}

function validateProductionSourceSurface() {
  const checkpointSource = fs.readFileSync(
    path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/poco_checkpoint.rs"),
    "utf8",
  );
  const candidateSource = fs.readFileSync(
    path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/poco_authenticated_candidate.rs"),
    "utf8",
  );
  const combined = checkpointSource.match(
    /pub\(crate\) fn authorize_poco_checkpoint_candidate_selection_v0\s*\(([\s\S]*?)\)\s*->[^{]+\{/,
  );
  invariant(combined !== null, "combined production candidate constructor missing");
  const inner = candidateSource.match(
    /pub\(crate\) fn authorize_authenticated_poco_candidate_selection_v0\s*\(([\s\S]*?)\)\s*->[^{]+\{/,
  );
  invariant(inner !== null, "authenticated candidate constructor missing");
  for (const [name, parameters] of [["combined", combined[1]], ["inner", inner[1]]]) {
    for (const forbidden of [
      "SignatureVerifier", "CandidateSelectionKernelV0", "UnauthenticatedCandidateSelectionTranscriptV0",
      "status", "event",
    ]) invariant(!parameters.includes(forbidden), `${name} constructor accepts forbidden ${forbidden} input`);
  }
  invariant(
    candidateSource.includes("&StrictEd25519Verifier") &&
      candidateSource.includes("compute_candidate_selection_kernel_v0("),
    "production reconstruction does not hard-code fresh strict B2-G",
  );
  invariant(
    candidateSource.includes("candidate_ids.contains(&provider_validator_id)") &&
      candidateSource.includes("eligible = candidate_ids.contains"),
    "production non-candidate retained-certificate projection drift",
  );
  invariant(
    !candidateSource.includes("impl From<CandidateSelectionKernelV0>") &&
      !candidateSource.includes("impl From<&CandidateSelectionKernelV0>"),
    "old inert B2-G token gained an authenticated conversion",
  );
}

function validateSchema(schema) {
  invariant(schema.schema === "trnm.poco-bft.authenticated-candidate-selection.v0" && schema.schema_version === 0, "authenticated-candidate schema identity/version");
  sameJson(schema.authority_flow, [
    "one exact retained production JMT cutoff projection",
    "complete physical and bidirectional kind-16 application audit",
    "internal canonical B2-G transcript reconstruction",
    "hard-coded StrictEd25519Verifier",
    "fresh compute_candidate_selection_kernel_v0",
    "private checkpoint-and-selection capability",
  ], "schema authority flow");
  sameJson(schema.compact_timing_contract, {
    epoch_length_blocks: 10,
    finality_certified_chain_length: 3,
    snapshot_lead_blocks: 3,
    active_epoch: 2,
    boundary_height: 21,
    future_registration_height: 22,
    final_semantic_height: 24,
    cutoff_height: 25,
    checkpoint_parent_height: 27,
    checkpoint_height: 28,
    lead_two_status: "rejected by consensus-parameter validation and retained only as a negative regression",
  }, "schema compact timing contract");
  invariant(schema.fixture_evidence.schema === FIXTURE_SCHEMA, "schema fixture ID");
  sameJson(
    schema.kind16_nested_contract.exact_field_order,
    AUTHORITY_NESTED_FIELD_ORDER,
    "schema kind-16 nested field order",
  );
  sameJson(
    schema.kind16_nested_contract.hard_caps,
    AUTHORITY_HARD_CAPS,
    "schema kind-16 hard caps",
  );
  invariant(
    schema.kind16_nested_contract.canonicality.includes("omitted when empty") &&
      schema.kind16_nested_contract.numeric_types.includes("canonical unquoted JSON integers") &&
      schema.kind16_nested_contract.numeric_types.includes("CanonicalU128V0 fields alone"),
    "schema kind-16 omission/numeric type contract drift",
  );
  sameJson(schema.bidirectional_projection_contract.exact_raw_decoders, [
    "kind 1 consumption certificate",
    "kind 2 consumer-key authorization",
    "kind 3 consumer/provider nonce watermark",
    "kind 4 unique consumption tuple",
    "kind 5 meter definition",
    "kind 6 settlement",
    "kind 7 measurement evidence",
    "kind 8 relationship classification",
    "kind 9 validator registration",
    "kind 10 active bond",
    "kind 11 jail status",
    "kind 12 revocation/challenge lifecycle",
    "kind 13 validator configuration",
    "kind 14 consensus parameters",
    "kind 15 rollout/governance",
    "kind 16 application authority state",
  ], "schema exact raw companion decoders");
  sameJson(schema.bidirectional_projection_contract.reverse_orphan_rejection, [
    "kind 1 consumption certificate",
    "kind 2 consumer-key authorization",
    "kind 3 consumer nonce",
    "kind 4 unique consumption tuple",
    "kind 5 meter definition",
    "kind 6 settlement",
    "kind 7 measurement evidence",
    "kind 9 validator registration",
    "kind 12 lifecycle",
    "kind 15 governance",
    "role-2 kind 14 candidate parameters",
  ], "schema reverse authority-managed orphan set");
  invariant(
    schema.bidirectional_projection_contract.active_certificate_join.includes("strict consumer Ed25519 signature") &&
      schema.bidirectional_projection_contract.active_certificate_join.includes("{1,4,6,7,12}") &&
      schema.bidirectional_projection_contract.exact_decode_order.includes("before kind-16 companion reconstruction") &&
      schema.bidirectional_projection_contract.relationship_exception.includes("not globally orphan-rejected") &&
      schema.bidirectional_projection_contract.relationship_exception.includes("still kind-specific exact-decoded"),
    "schema bidirectional active-certificate/relationship contract drift",
  );
  invariant(
    schema.fixture_evidence.independent_consumer.includes("recomputes every jmt 0.12.0 SHA-256 root") &&
      schema.fixture_evidence.independent_consumer.includes("exact namespace-8 physical completeness") &&
      schema.fixture_evidence.independent_consumer.includes("exact-decodes every kind 1 through 16 payload"),
    "schema overstates or drops the independent JMT/physical consumer boundary",
  );
  invariant(
    schema.fixture_evidence.rust_consumer.includes("ProcessProposal and FinalizeBlock") &&
      schema.fixture_evidence.rust_consumer.includes("SQLite restart") &&
      schema.fixture_evidence.rust_consumer.includes("cache miss and hit") &&
      schema.fixture_evidence.rust_consumer.includes("V3 parent restore") &&
      schema.fixture_evidence.rust_consumer.includes("V4 cutoff-25 restore") &&
      schema.fixture_evidence.rust_consumer.includes("zero-hash rejection preserves head, pending state, and retained cutoff state") &&
      schema.fixture_evidence.rust_consumer.includes("physically deletes the SQLite height-25 root") &&
      schema.fixture_evidence.rust_consumer.includes("does not establish normal scheduled pruning") &&
      schema.fixture_evidence.fixture_only_boundary.includes("height-24") &&
      schema.fixture_evidence.fixture_only_boundary.includes("test-only"),
    "schema Rust production replay or fixture-only boundary drift",
  );
  invariant(
    schema.node_retained_mutation_campaign.covered.length >= 21 &&
      schema.node_retained_mutation_campaign.gate_statistics ===
        "43 fail-closed rejection mutations and 1 non-rejecting retained-provider eligibility boundary control" &&
      schema.node_retained_mutation_campaign.source_recomposition.includes("every affected JMT root") &&
      schema.node_retained_mutation_campaign.strict_ed25519_boundary.includes("canonical compressed public-key and signature-R points") &&
      schema.node_retained_mutation_campaign.strict_ed25519_boundary.includes("small-order public-key/R points") &&
      schema.node_retained_mutation_campaign.strict_ed25519_boundary.includes("scalar order") &&
      schema.node_retained_mutation_campaign.not_claimed_by_node.includes("retained-history prune/pruned-cutoff rejection are Rust production-path evidence") &&
      schema.node_retained_mutation_campaign.not_claimed_by_node.includes("not simulated by Node") &&
      schema.node_retained_mutation_campaign.not_claimed_by_node.includes("does not establish normal scheduled pruning"),
    "schema retained mutation evidence boundary drift",
  );
  sameJson(schema.rejection_contract.closure_required_families, [
    "cutoff version/root/manifest/count substitution",
    "checkpoint/projection splice",
    "entry omission/addition/duplicate",
    "kind-16 companion drift",
    "current-head substitution",
    "PoP domain/chain/genesis/target/id/key/nonce/signature substitution",
    "predecessor nonce/history substitution",
    "bond, jail, lifecycle, relationship, and governance boundary substitution",
    "old B2-G token, generic verifier, status, and event injection",
    "cache hit/miss, restart, and retained-history prune",
  ], "schema normative rejection families");
  invariant(
    schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("domain, chain, genesis, target, validator-ID, public-key, nonce, and signature")) &&
      schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("noncanonical R/S and small-order")) &&
      schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("governance pending/finalized")) &&
      schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("authenticated-fallback result-digest")) &&
      schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("raw manifest entries-root/count")) &&
      schema.rejection_contract.landed_rejection_evidence.node_campaign.some((item) => item.includes("kind 1 through 16 exact payload decoding")) &&
      schema.rejection_contract.landed_rejection_evidence.rust_production_replay.some((item) => item.includes("SQLite restart")) &&
      schema.rejection_contract.landed_rejection_evidence.rust_production_replay.some((item) => item.includes("physically deletes the SQLite height-25 root")) &&
      !schema.rejection_contract.remaining_rejection_evidence.some((item) => item.includes("retained-history prune")) &&
      !schema.rejection_contract.remaining_rejection_evidence.some((item) => item.includes("future PoP")) &&
      !schema.rejection_contract.remaining_rejection_evidence.some((item) => item.includes("raw projection manifest")) &&
      schema.rejection_contract.evidence_partition_note.includes("does not imply execution") &&
      schema.rejection_contract.evidence_partition_note.includes("does not count older H3b2b1 contracts"),
    "schema landed/open rejection-evidence partition drift",
  );
  invariant(
    schema.fixture_evidence.lossless_integer_policy ===
      "kind-16 canonical JSON uses unquoted u64 decimal integers over the full 0..2^64-1 range; Node preserves unsafe values as BigInt, emits them unquoted for byte-identical re-encoding, and rejects floats, exponents, signs, leading zeros, overflow, or reformatting",
    "schema kind-16 lossless integer policy drift",
  );
  invariant(schema.canonical_seals.transcript_domain === TRANSCRIPT_DOMAIN && schema.canonical_seals.result_domain === RESULT_DOMAIN && schema.canonical_seals.authorization_domain === AUTHORIZATION_DOMAIN, "schema seal domains");
  invariant(schema.does_not_establish.includes("H1 finalized-cutoff proof or cutoff block ID authority"), "schema hides finalized-cutoff nonclaim");
}

function main() {
  const losslessJsonSelfTests = runLosslessJsonSelfTests();
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  const vector = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
  validateSchema(schema);
  exactKeys(vector, ["schema", "schema_version", "fixture_scope", "compact_profile", "boundary_contract", "positive", "authenticated_fallback"], "vector");
  invariant(vector.schema === FIXTURE_SCHEMA && vector.schema_version === 0, "vector identity/version");
  invariant(vector.fixture_scope === "application_authenticated_candidate_reconstruction_not_core_epoch_transition", "vector fixture scope");
  validateProductionSourceSurface();
  validateProfile(vector.compact_profile);
  validateBoundary(vector);
  const positive = validateScenario(vector.compact_profile, vector.positive, "positive");
  const fallback = validateScenario(vector.compact_profile, vector.authenticated_fallback, "authenticated_fallback");
  invariant(!positive.outcome.fallback_used && positive.outcome.fallback_reason_code === 0, "positive is not reason-zero");
  invariant(positive.transcript.candidates.length >= 4 && positive.transcript.contributions.filter((entry) => entry.eligible).length >= 4, "positive lacks four authenticated mature candidate chains");
  invariant(fallback.outcome.fallback_used && fallback.outcome.fallback_reason_code === 3, "authenticated fallback taxonomy drift");
  invariant(!positive.authorization.equals(fallback.authorization), "positive/fallback authorization splice");
  runNegativeSelfChecks(vector, positive, fallback);
  process.stdout.write(
    `authenticated candidate gate ok: histories=${stats.histories}, jmt_roots=${stats.jmtRoots}, projections=${stats.projections}, semantic_entries=${stats.semanticEntries}, certificates=${stats.certificates}, candidates=${stats.candidates}, contributions=${stats.contributions}, strict_pop=${stats.popSignatures}, scenarios=${stats.scenarios}, rejections=${stats.rejections}, boundary_controls=${stats.boundaryControls}, lossless_u64=${losslessJsonSelfTests.accepted}/${losslessJsonSelfTests.rejected}\n`,
  );
}

export {
  parseLosslessUnsignedJson,
  strictEd25519Verify,
  validateBoundary,
  validateProductionSourceSurface,
  validateProfile,
  validateScenario,
  validateSchema,
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
