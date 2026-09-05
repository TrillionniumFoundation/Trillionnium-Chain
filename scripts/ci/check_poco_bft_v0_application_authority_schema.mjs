import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relative) =>
  JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
const schema = readJson(
  "docs/protocol/poco-bft-v0/schema/poco-application-authority-v0.json",
);
const vector = readJson(
  "docs/protocol/poco-bft-v0/vectors/poco-application-authority-v0.json",
);
const transitionSchema = readJson(
  "docs/protocol/poco-bft-v0/schema/poco-snapshot-transition-v0.json",
);
const businessSchema = readJson(
  "docs/protocol/poco-bft-v0/schema/poco-business-semantics-v0.json",
);
const parameterVector = readJson(
  "docs/protocol/poco-bft-v0/vectors/parameters-v0.json",
);
const authenticatedCandidateVector = readJson(
  "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json",
);

const invariant = (condition, message) => {
  if (!condition) throw new Error(message);
};
const sameJson = (actual, expected, message) =>
  invariant(
    canonicalJsonStringify(actual) === canonicalJsonStringify(expected),
    `${message}: ${canonicalJsonStringify(actual)}`,
  );
const exactKeys = (value, expected, label) => {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label}: object required`,
  );
  sameJson(Object.keys(value), expected, `${label}: field order`);
};
const unique = (values, message) =>
  invariant(new Set(values).size === values.length, message);
const exactHex = (value, bytes, label) => {
  invariant(
    typeof value === "string" &&
      value.length === bytes * 2 &&
      /^[0-9a-f]+$/.test(value),
    `${label}: exact lowercase hex`,
  );
  return Buffer.from(value, "hex");
};
const boundedHex = (value, minimumBytes, maximumBytes, label) => {
  invariant(
    typeof value === "string" &&
      value.length % 2 === 0 &&
      value.length >= minimumBytes * 2 &&
      value.length <= maximumBytes * 2 &&
      /^[0-9a-f]+$/.test(value),
    `${label}: bounded lowercase hex`,
  );
  return Buffer.from(value, "hex");
};
const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;
const U32_MAX = (1n << 32n) - 1n;
const U8_MAX = (1n << 8n) - 1n;
const MAX_SAFE_INTEGER_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

// Exact serde field order for every record nested below the kind-16
// application-authority value.  Rust uses deny_unknown_fields and admits a
// value only after byte-identical canonical re-encode, so checking only the
// top-level array names would leave a false JavaScript authorization surface.
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

// serde_json's Rust integer types and the transparent CanonicalU128V0 string
// are distinct JSON contracts.  Keep that distinction explicit for every
// kind-16 field: accepting a quoted u64 (or an unquoted u128) here would let
// JavaScript authorize bytes that PocoApplicationAuthorityStateV0 rejects.
const AUTHORITY_NUMERIC_FIELD_TYPES = {
  top_level: {
    u64_unquoted: ["revision", "last_target_height", "nullifier_count"],
  },
  consumer_keys: {
    u64_unquoted: ["active_from_height"],
    optional_u64_unquoted: ["revoked_at_height"],
  },
  consumer_nonce_watermarks: {
    u64_unquoted: ["max_accepted_nonce"],
  },
  meter_policies: {
    u32_unquoted: ["meter_version"],
    u64_unquoted: ["rolling_epoch_span", "retention_blocks", "active_from_height"],
    optional_u64_unquoted: ["retired_at_height"],
    u128_decimal_strings: ["unit_scale", "per_certificate_cap", "rolling_cap"],
  },
  meter_usage: {
    u32_unquoted: ["meter_version"],
    u64_unquoted: ["window_epoch"],
    u128_decimal_strings: ["consumed_units"],
  },
  consumer_provider_usage: {
    u64_unquoted: ["window_epoch"],
    u128_decimal_strings: ["consumed_units"],
  },
  task_provider_usage: {
    u64_unquoted: ["window_epoch"],
    u128_decimal_strings: ["consumed_units"],
  },
  provider_usage: {
    u64_unquoted: ["window_epoch"],
    u128_decimal_strings: ["consumed_units"],
  },
  funded_unused_reservations: {
    u64_unquoted: ["finalized_height"],
    u128_decimal_strings: ["reserved_units"],
  },
  active_certificates: {
    u32_unquoted: ["meter_version"],
    u64_unquoted: [
      "settlement_finalized_height", "provider_registration_nonce",
      "provider_registration_height", "accepted_height", "finalized_epoch",
      "prunable_after_height", "lifecycle_effective_height",
    ],
    u8_unquoted: ["relationship_class"],
    u128_decimal_strings: ["consumed_units"],
  },
  semantic_keys: {
    u8_unquoted: ["kind"],
  },
  pending_challenges: {
    u64_unquoted: ["opened_height"],
  },
  pending_governance_proposals: {
    u64_unquoted: ["target_epoch", "proposed_height", "activation_height"],
    u8_unquoted: ["phase"],
  },
  finalized_governance_approvals: {
    u64_unquoted: ["target_epoch", "proposed_height", "approval_height", "activation_height"],
    u8_unquoted: ["phase"],
  },
  validator_registration_history: {
    u64_unquoted: ["max_registration_nonce", "registration_height", "retired_key_count"],
    optional_u64_unquoted: ["revoked_at_height"],
  },
  future_candidate_registrations: {
    u64_unquoted: ["target_epoch", "registration_nonce", "registration_height"],
    optional_u64_unquoted: ["previous_registration_nonce"],
  },
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

// Kind-16 payloads are canonical JSON, but serde_json accepts the complete
// u64 domain.  JSON.parse would silently round integers above 2^53 - 1 before
// the canonical byte check.  Keep safe integers as Numbers for the existing
// checker surface and preserve larger integers as BigInts.
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
    if (decoded > U64_MAX) fail("u64 overflow");
    return decoded <= MAX_SAFE_INTEGER_BIGINT ? Number(decoded) : decoded;
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
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    invariant(
      Number.isSafeInteger(value) && value >= 0,
      "canonical JSON number must be a safe unsigned integer",
    );
    return String(value);
  }
  if (typeof value === "bigint") {
    invariant(value >= 0n && value <= U64_MAX, "canonical JSON bigint exceeds u64");
    return value.toString();
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJsonStringify).join(",")}]`;
  }
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

const asUnsigned = (value, maximum, label) => {
  invariant(
    (typeof value === "string" || typeof value === "bigint" || Number.isSafeInteger(value)) &&
      /^(0|[1-9][0-9]*)$/.test(String(value)),
    `${label}: canonical unsigned decimal`,
  );
  const decoded = BigInt(value);
  invariant(decoded >= 0n && decoded <= maximum, `${label}: range`);
  return decoded;
};
const strictJsonUnsigned = (value, maximum, typeName, label) => {
  invariant(
    typeof value === "bigint" ||
      (typeof value === "number" && Number.isSafeInteger(value) && value >= 0),
    `${label}: unquoted ${typeName} JSON integer required`,
  );
  const decoded = BigInt(value);
  invariant(decoded <= maximum, `${label}: ${typeName} range`);
  return decoded;
};
const strictJsonU64 = (value, label) => strictJsonUnsigned(value, U64_MAX, "u64", label);
const strictJsonU32 = (value, label) => strictJsonUnsigned(value, U32_MAX, "u32", label);
const strictJsonU8 = (value, label) => strictJsonUnsigned(value, U8_MAX, "u8", label);
const strictJsonCanonicalU128 = (value, label) => {
  invariant(
    typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value),
    `${label}: canonical u128 decimal string required`,
  );
  const decoded = BigInt(value);
  invariant(decoded <= U128_MAX, `${label}: u128 range`);
  return decoded;
};
const uint = (value, bytes) => {
  let decoded = BigInt(value);
  invariant(decoded >= 0n, "negative unsigned integer");
  const output = Buffer.alloc(bytes);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    output[index] = Number(decoded & 0xffn);
    decoded >>= 8n;
  }
  invariant(decoded === 0n, "unsigned integer overflow");
  return output;
};
const losslessJsonSelfTests = runLosslessJsonSelfTests();
const frame = (value) => Buffer.concat([uint(value.length, 4), value]);
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0");
let hashCalls = 0;
const domainHash = (domain, encoded) => {
  hashCalls += 1;
  return crypto
    .createHash("sha256")
    .update(
      Buffer.concat(
        [HASH_PREFIX, Buffer.from(domain), encoded].map((value) => frame(value)),
      ),
    )
    .digest();
};
const lifecycleHashDomain = (domain, parts) =>
  crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from("trnm.domain.hash.v1"),
        uint(Buffer.byteLength(domain), 8),
        Buffer.from(domain),
        ...parts.flatMap((part) => [uint(part.length, 8), part]),
      ]),
    )
    .digest();

invariant(schema.schema === "trnm.poco-bft.application-authority.v0", "schema id drift");
invariant(schema.schema_version === 0, "schema version drift");
invariant(
  schema.status ===
    "B2-H3b2b1-authenticated-application-authority-and-atomic-cross-entry-planner",
  "schema status drift",
);
invariant(vector.schema === "trnm.poco-bft.application-authority.vector.v0", "vector id drift");
invariant(vector.schema_version === 0, "vector version drift");
invariant(
  schema.authenticated_signer_commitment.prefix_ascii === "trnm.domain.hash.v1" &&
    schema.authenticated_signer_commitment.domain_ascii ===
      "trnm.poco-bft.application-governance-signer.v0",
  "authenticated signer commitment domain drift",
);
sameJson(schema.decision_preimage.field_order, [
  "schema_version:u16",
  "genesis_hash:Bytes",
  "chain_id:Bytes",
  "source_version:u64",
  "source_root:Hash32",
  "target_height:u64",
  "active_epoch:u64",
  "active_parameters_hash:Hash32",
  "authority_signer_commitment:Hash32",
  "normalized_operation:Bytes",
], "decision preimage field order drift");

// H3b2b1 is append-only. The H3a/H3b2b0 contracts must remain honest about
// their fifteen-kind, non-authorizing boundary.
invariant(
  transitionSchema.value_envelope.fields.find((field) => field.name === "kind")
    .maximum === 15,
  "H3a kind maximum was rewritten",
);
invariant(transitionSchema.kinds.length === 15, "H3a kind table was rewritten");
invariant(
  businessSchema.mutation_contract.record_rules.length === 15,
  "H3b2b0 record table was rewritten",
);
invariant(
  businessSchema.external_authority_blockers.length === 7,
  "H3b2b0 blockers were hidden instead of composed",
);
invariant(
  businessSchema.mutation_contract.record_rules.every((entry) => entry.delete === "reject"),
  "generic H3b2b0 delete was opened",
);
sameJson(schema.composition.legacy_kinds, {
  minimum: 1,
  maximum: 15,
  wire_change: false,
  semantic_change: false,
  note: "H3b2b0 remains an honest pure-semantic kernel; no old value becomes authority by reinterpretation.",
}, "legacy kind contract drift");
invariant(schema.composition.appended_kind.kind === 16, "kind 16 drift");
invariant(schema.composition.appended_kind.namespace === 8, "kind 16 namespace drift");
invariant(
  schema.composition.appended_kind.identity_ascii ===
    "trnm.poco.application-authority.v0",
  "authority identity drift",
);
invariant(
  Buffer.byteLength(schema.composition.appended_kind.identity_ascii) === 34,
  "authority identity length drift",
);
sameJson(schema.composition.optional_payload_extension, {
  milestone: "B2-H3b2b2a",
  field: "future_candidate_registrations",
  position: "trailing after validator_registration_history",
  compatibility: "pre-release v0 append-only optional extension: an empty vector is omitted, so every frozen H3b2b1 payload byte remains valid; when non-empty the field is present exactly once in the trailing position",
  authority_boundary: "future target candidate registration only; the existing active-provider kind-9 registration is not reinterpreted",
}, "future-candidate payload extension drift");
sameJson(schema.operation_extension, {
  kind: "register_future_candidate",
  body_field_order: [
    "kind",
    "validator_id_hex",
    "target_epoch",
    "previous_registration_nonce",
    "predecessor_history_head_hex",
    "proof_cev0_hex",
    "registration_decision_id_hex",
  ],
  semantic_changes: 0,
  nullifier_non_membership_checks: 0,
  nullifier_insertions: [
    { family: 8, name: "registration_decision", identifier: "derived registration_decision_id" },
    { family: 13, name: "validator_consensus_key", identifier: "exact future consensus key" },
  ],
  target_epoch: "exact checked active_epoch + 1",
  strict_pop: "exact CEV0 ValidatorKeyProofOfPossessionV0 verified by production StrictEd25519Verifier and bound to authenticated genesis hash, chain ID, exact successor target epoch, validator ID, consensus key, and registration nonce",
  changed_key_predecessor: "an old-set validator changing key supplies previous_registration_nonce equal to the exact active validator-registration history max_registration_nonce and predecessor_history_head_hex equal to its exact non-revoked history_head_hex; the new nonce is strictly greater",
  new_validator_predecessor: "a validator absent from the old set supplies null previous_registration_nonce and the all-zero predecessor_history_head_hex",
  unchanged_key: "reject; an old-set validator carrying the same key uses the proof-free canonical candidate path instead",
  persistence: "writes only the trailing kind-16 future_candidate_registrations companion; it neither creates nor rewrites a kind-9 active-provider fact",
}, "future-candidate operation extension drift");
sameJson(schema.authority_value.payload.field_order, [
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
  "future_candidate_registrations",
], "authority JSON field order drift");
sameJson(
  schema.authority_value.payload.optional_trailing_fields,
  ["future_candidate_registrations"],
  "authority optional trailing field drift",
);
invariant(
  schema.authority_value.payload.optional_trailing_field_rule ===
    "future_candidate_registrations is absent if and only if empty; when present it is a non-empty array in the exact final position, so payloads omitting the empty extension retain their original canonical bytes",
  "authority optional trailing rule drift",
);
invariant(
  schema.authority_value.payload.active_certificate_record ===
    "the exact field order is certificate_id_hex, consumer_id_hex, consumer_key_id_hex, provider_id_hex, task_id_hex, meter_id_hex, meter_version, settlement_commitment_hex, settlement_finalized_height, consumed_units, evidence_root_hex, relationship_class, relationship_key_hex, provider_consensus_key_hex, provider_registration_nonce, provider_proof_digest_hex, provider_registration_decision_id_hex, provider_registration_height, provider_registration_history_head_hex, acceptance_decision_id_hex, funding_decision_id_hex, meter_decision_id_hex, evidence_decision_id_hex, accepted_height, finalized_epoch, tuple_key_hex, prunable_after_height, lifecycle, lifecycle_effective_height, lifecycle_decision_id_hex, semantic_keys; every companion field is re-derived from the authenticated certificate/key/provider/meter/settlement/evidence/relationship/lifecycle projection",
  "active-certificate provenance field order drift",
);
sameJson(schema.authority_value.payload.record_families, [
  { name: "consumer_keys", canonical_key: ["consumer_id_hex", "consumer_key_id_hex"], maximum_records: 4 },
  { name: "meter_policies", canonical_key: ["meter_id_hex", "meter_version"], maximum_records: 4 },
  { name: "meter_usage", canonical_key: ["meter_id_hex", "meter_version", "window_epoch"], maximum_records: 32 },
  { name: "consumer_provider_usage", canonical_key: ["consumer_id_hex", "provider_id_hex", "window_epoch"], maximum_records: 32 },
  { name: "task_provider_usage", canonical_key: ["task_id_hex", "provider_id_hex", "window_epoch"], maximum_records: 32 },
  { name: "provider_usage", canonical_key: ["provider_id_hex", "window_epoch"], maximum_records: 32 },
  { name: "funded_unused_reservations", canonical_key: ["certificate_id_hex"], maximum_records: 4 },
  { name: "active_certificates", canonical_key: ["certificate_id_hex"], maximum_records: 4 },
  { name: "pending_challenges", canonical_key: ["challenge_id_hex"], maximum_records: 2 },
  { name: "pending_governance_proposals", canonical_key: ["target_epoch"], maximum_records: 2 },
  { name: "finalized_governance_approvals", canonical_key: ["target_epoch"], maximum_records: 2 },
  { name: "validator_registration_history", canonical_key: ["validator_id_hex"], maximum_records: 4 },
  { name: "future_candidate_registrations", canonical_key: ["target_epoch", "validator_id_hex"], maximum_records: 4 },
], "authority record-family caps drift");
invariant(
  schema.authority_value.payload.integer_policy ===
    "u64 values are unquoted canonical decimal JSON integers over the full 0..2^64-1 range; independent consumers parse them losslessly and reject floats, exponents, signs, leading zeros, overflow, and any byte-changing reformat; u128 business quantities remain canonical decimal strings parsed by BigInt",
  "authority integer policy drift",
);
sameJson(
  schema.authority_value.payload.numeric_field_types,
  AUTHORITY_NUMERIC_FIELD_TYPES,
  "authority numeric-field type table drift",
);
sameJson(schema.authority_value.payload.future_candidate_record, {
  field_order: [
    "validator_id_hex",
    "target_epoch",
    "consensus_key_hex",
    "registration_nonce",
    "previous_registration_nonce",
    "predecessor_history_head_hex",
    "proof_cev0_hex",
    "proof_digest_hex",
    "registration_decision_id_hex",
    "registration_height",
  ],
  maximum_records: 4,
  target_epoch: "exact checked active epoch successor",
  proof: "exact CEV0 ValidatorKeyProofOfPossessionV0 verified by production StrictEd25519Verifier",
  proof_digest_domain_ascii: "trnm.poco-bft.future-candidate-pop.v0",
  changed_key_predecessor: "exact non-revoked active history max_registration_nonce and history_head_hex, with a strictly larger new nonce",
  new_validator_predecessor: "null previous_registration_nonce and all-zero predecessor_history_head_hex",
  rejections: "same-key old validator, reused key, stale epoch, noncanonical or invalid proof, or substituted predecessor, decision, digest, or registration height",
}, "future-candidate record contract drift");
sameJson(
  schema.authority_value.payload.nested_record_field_order,
  AUTHORITY_NESTED_FIELD_ORDER,
  "authority nested-record field order drift",
);
sameJson(
  schema.authority_value.payload.hard_caps,
  AUTHORITY_HARD_CAPS,
  "authority nested/family hard caps drift",
);
invariant(
  schema.authority_value.payload.nested_canonicality ===
    "every nested object is exact-order and deny-unknown; the four usage arrays share one aggregate cap, nonce watermarks have per-key and aggregate caps, and the total cap counts nested nonce watermarks",
  "authority nested canonicality rule drift",
);

const expectedFamilies = [
  [1, "certificate"],
  [2, "tuple"],
  [3, "settlement_decision"],
  [4, "meter_decision"],
  [5, "evidence_decision"],
  [6, "challenge_decision"],
  [7, "governance_decision"],
  [8, "registration_decision"],
  [9, "consumer_key_decision"],
  [10, "consumer_key_identity"],
  [11, "consumer_nonce_summary"],
  [12, "meter_identity"],
  [13, "validator_consensus_key"],
  [14, "validator_identity"],
];
sameJson(
  schema.nullifier_accumulator.families.map((entry) => [entry.tag, entry.name]),
  expectedFamilies,
  "nullifier family table drift",
);
invariant(schema.nullifier_accumulator.depth === 256, "nullifier depth drift");
invariant(schema.nullifier_accumulator.proof.encoded_bytes === 8230, "proof length drift");
sameJson(schema.nullifier_accumulator.domains, {
  key: "trnm.poco-bft.nullifier-key.v0",
  empty_leaf: "trnm.poco-bft.nullifier-empty-leaf.v0",
  occupied_leaf: "trnm.poco-bft.nullifier-occupied-leaf.v0",
  node: "trnm.poco-bft.nullifier-node.v0",
}, "nullifier domains drift");
sameJson(schema.hard_bounds, {
  operations_per_block: 32,
  operation_bytes_each: 1048576,
  semantic_changes_per_operation: 32,
  total_usage_buckets: 32,
  nullifier_non_membership_checks_per_operation: 16,
  nullifier_insertions_per_operation: 16,
  authority_payload_bytes: 65384,
  namespace_entries: 10000,
  aggregate_projection_bytes: 8388608,
  ordering: "source projection plus operation count/bytes are checked with checked arithmetic before operation decode or overlay clone; operation-internal semantic/nullifier counts are checked before semantic planning, while exact nullifier shape validation necessarily decodes each bounded 8,230-byte proof",
}, "hard-bound table drift");
sameJson(vector.constants.hard_bounds, {
  operations_per_block: 32,
  operation_bytes_each: 1048576,
  semantic_changes_per_operation: 32,
  total_usage_buckets: 32,
  nullifier_non_membership_checks_per_operation: 16,
  nullifier_insertions_per_operation: 16,
  authority_payload_bytes: 65384,
  namespace_entries: 10000,
  aggregate_projection_bytes: 8388608,
}, "vector hard-bound table drift");
sameJson(schema.additional_bounds, {
  semantic_changes_minimum: {
    default: 1,
    register_future_candidate: 0,
  },
  opaque_id_bytes_minimum: 1,
  opaque_id_bytes_maximum: 128,
  nonce_watermarks_per_consumer_key: 8,
  total_nonce_watermarks: 8,
  total_authority_records: 70,
  future_candidate_registrations: 4,
  retired_registration_keys: "represented only by checked retired_key_count; every concrete retired key remains permanently protected by its family-13 nullifier",
}, "additional-bound table drift");
invariant(
  schema.application_rules.target_bound_fields.at(-1) ===
    "future candidate registration height",
  "future-candidate target-bound height drift",
);
invariant(
  schema.application_rules.future_candidate_registration ===
    "register_future_candidate is an append-only kind-16-only operation for exact active_epoch + 1; it admits zero semantic changes and zero caller non-membership checks, strictly verifies the exact PoP, consumes fresh family-8 decision and family-13 key nullifiers, rejects an unchanged old key, and requires either the exact active predecessor nonce/head for an old-set key change or null/all-zero predecessor authority for a new validator",
  "future-candidate application rule drift",
);
invariant(
  schema.required_rejections.includes(
    "future candidate wrong target epoch, malformed or noncanonical PoP, wrong chain/genesis/validator/key/nonce/signature, reused key, unchanged old key, substituted predecessor nonce/head, or more than four retained future registrations",
  ),
  "future-candidate rejection matrix drift",
);
sameJson(schema.operation_sequence_authoring, {
  script: "scripts/ci/author_poco_bft_v0_application_sequences.mjs",
  draft_schema: "trnm.poco-bft.application-operation-sequence-draft.v0",
  rust_genesis_schema: "trnm.poco-bft.application-full-genesis-export.v0",
  final_schema: "trnm.poco-bft.application-operation-sequences.vector.v0",
  commands: ["init", "append", "derive", "derive-negative", "merge", "check", "finalize", "check-final", "scaffold-required", "self-test"],
  stdout_only: true,
  completion_authority: "there is no status field: a step is complete only when its exact fixed Rust event validates source export/request digests, scope, context, source and target heads, ordered raw operations/IDs/root, canonical mutations/root, full target projection/manifest, authority/nullifier successor, persistence evidence, and next production context",
  root_discipline: "Node never invents a JMT root: every source and target root is imported from exact retained Rust evidence, while Node independently rehashes all content committed by that root",
  independent_node_work: "Node derives every operation-local decision ID and proof plan, enforces sorted unique semantic/proof arrays, checks all absence proofs against one initial root and insertions sequentially, and recomputes operation/mutation/entry roots plus the exact 47-byte manifest",
  partial_rule: "check reports partial=true whenever any required automaton block or required negative is absent or any present record awaits its fixed Rust event; within each sequence no later positive step may be appended until the current event is fully revalidated",
  finalization_rule: "finalize strips private authoring metadata only after all nine exact automata and actual negatives validate; check-final reconstructs source/nullifier/decision/proof/root/scope/subject continuity from retained raw source exports and finalized raw records",
  scaffold_rule: "scaffold-required requires one real full-store source and four scoped isolated-source exports and emits all nine complete next-block field-order skeletons with exact source digests; every marker is non-authorizing and derive rejects it",
  self_test_rule: "self-test executes a valid success and actual negative merge, finalizes and independently check-finals it, and proves rejection of status/root/mutation/manifest/source/scope/context/sort/type/signature/persistence/classifier/subject/proof tampering; missing or unknown commands exit nonzero",
}, "operation-sequence authoring contract drift");
sameJson(schema.shared_operation_sequences.final_top_level_fields, ["schema", "schema_version", "source_exports_sha256_hex", "source_exports", "required_automata", "sequences"], "final operation vector field order drift");
sameJson(schema.shared_operation_sequences.sequence_fields, ["id", "execution_scope", "activation_prerequisite", "source_export_sha256_hex", "subjects", "initial", "steps", "negatives"], "operation sequence field order drift");
sameJson(schema.shared_operation_sequences.step_fields, ["id", "context", "operations", "operation_root_hex", "operation_count", "rust_event"], "operation block field order drift");
sameJson(schema.shared_operation_sequences.operation_record_fields, ["id", "operation_kind", "raw_operation_json_hex", "operation_id_hex"], "operation record field order drift");
sameJson(schema.shared_operation_sequences.context_fields, ["chain_id_utf8", "genesis_hash_hex", "source_version", "source_root_hex", "target_height", "active_epoch", "active_parameters_cev0_hex", "active_parameters_hash_hex", "authority_signer_commitment_hex"], "production context field order drift");
sameJson(schema.shared_operation_sequences.step_request_fields, ["schema", "schema_version", "source_export_sha256_hex", "sequence_id", "step_id", "execution_scope", "activation_prerequisite", "context", "raw_operation_json_hexes", "operation_ids_hex", "operation_root_hex", "operation_count"], "step request field order drift");
sameJson(schema.shared_operation_sequences.negative_request_fields, ["schema", "schema_version", "source_export_sha256_hex", "sequence_id", "negative_id", "execution_scope", "context", "source", "base_positive", "fault_model", "raw_operation_json_hexes", "expected_reject", "expected_writes", "expected_unchanged"], "negative request field order drift");
sameJson(schema.shared_operation_sequences.full_scope_evidence_fields, ["kind", "ordered_signed_tx_hexes", "process_proposal", "finalize_block", "sqlite_commit", "sqlite_restart", "snapshot_v3_restore", "snapshot_v4_restore", "sqlite_failpoint_outcomes"], "full-store evidence field order drift");
sameJson(schema.shared_operation_sequences.sqlite_failpoint_contract, [["before_sql_commit", "source"], ["after_sql_commit_before_status", "target"]], "SQLite failpoint outcome contract drift");
sameJson(schema.shared_operation_sequences.negative_fields, ["id", "context", "base_positive", "fault_model", "raw_operation_json_hexes", "source", "expected_reject", "expected_writes", "expected_unchanged", "rust_event"], "negative record field order drift");
sameJson(schema.shared_operation_sequences.actual_rejection_fields, ["stage", "error_code", "classifier_priority", "error_chain_sha256_hex", "rejected_nullifier"], "actual rejection field order drift");
sameJson(schema.shared_operation_sequences.full_negative_execution_fields, ["kind", "ordered_signed_tx_hexes", "process_proposal_status", "process_executor_actual", "independent_executor_actual", "finalize_block_not_invoked_after_reject", "pending_after_reject", "sqlite_restart"], "negative production execution field order drift");
sameJson(Object.keys(schema.shared_operation_sequences), [
  "vector_path", "final_top_level_fields", "source_export_registry_fields", "source_export_rule",
  "full_source_export_fields", "isolated_source_export_fields", "lineage_base_intent_fields", "business_intent_normalization",
  "sequence_fields", "initial_fields", "active_genesis_fields", "named_genesis_record_fields",
  "active_parameter_fields", "active_genesis", "history_entry_fields", "history_write_fields",
  "projection_fields", "projection_entry_fields", "step_fields", "operation_record_fields",
  "context_fields", "step_request_fields", "negative_request_fields", "rust_step_event_fields", "event_operation_fields", "full_scope_evidence_fields",
  "state_fingerprint_fields", "sqlite_failpoint_contract", "mutation_fields", "target_fields",
  "negative_fields", "negative_base_fields", "negative_fault_fields", "rust_negative_event_fields",
  "actual_rejection_fields", "rejected_nullifier_fields", "full_negative_execution_fields",
  "isolated_negative_execution_fields", "required_full_store_sequences", "required_kernel_sequences",
  "scope_rule", "semantic_delete_rule", "negative_rule", "independence", "side_fact_rule",
], "shared operation-sequence schema surface drift");
sameJson(schema.shared_operation_sequences.source_export_registry_fields, ["sha256_hex", "raw_json_hex"], "source registry fields drift");
sameJson(schema.shared_operation_sequences.full_source_export_fields, ["schema", "schema_version", "initial", "authoring_nullifier_state"], "full source export fields drift");
sameJson(schema.shared_operation_sequences.isolated_source_export_fields, ["schema", "schema_version", "lineage_base_intent", "initial", "authoring_nullifier_state"], "isolated source export fields drift");
sameJson(schema.shared_operation_sequences.lineage_base_intent_fields, ["operation_kind", "normalized_business_intent_digest_hex", "subjects"], "lineage intent fields drift");
sameJson(Object.keys(schema.shared_operation_sequences.business_intent_normalization), ["domain", "preimage_fields", "decision_rule", "target_bound_omissions", "semantic_intent", "omission_boundary"], "business intent normalization surface drift");
invariant(schema.shared_operation_sequences.business_intent_normalization.domain === "trnm.poco-bft.application-business-intent.v1", "business intent domain drift");
sameJson(schema.shared_operation_sequences.business_intent_normalization.preimage_fields, ["operation_kind", "body", "semantic_intent"], "business intent preimage fields drift");
invariant(schema.shared_operation_sequences.business_intent_normalization.decision_rule === "replace every operation-kind decision binding with exactly 32 zero bytes before canonical JSON hashing", "business intent decision rule drift");
sameJson(schema.shared_operation_sequences.business_intent_normalization.target_bound_omissions, {
  authorize_consumer_key: ["/body/active_from_height"],
  define_meter_policy: ["/body/policy/active_from_height"],
  register_validator: ["/body/target_epoch"],
}, "business intent target-bound omission drift");
const semanticIntentContract = schema.shared_operation_sequences.business_intent_normalization.semantic_intent;
sameJson(Object.keys(semanticIntentContract), ["item_fields", "actions", "put_kind_by_operation", "fact_fields", "validator_proof_fields", "integer_rule", "normalization_rule"], "semantic intent contract surface drift");
sameJson(semanticIntentContract.item_fields, ["kind", "logical_key_hex", "action", "identity_hex", "fact"], "semantic intent item fields drift");
sameJson(semanticIntentContract.actions, ["put", "delete"], "semantic intent actions drift");
sameJson(semanticIntentContract.put_kind_by_operation, {
  authorize_consumer_key: 2,
  define_meter_policy: 5,
  fund_settlement: 6,
  register_validator: 9,
  rotate_validator: 9,
  resolve_challenge: 12,
  approve_governance: 15,
}, "semantic intent operation-kind map drift");
sameJson(semanticIntentContract.fact_fields, {
  "2": ["consumer_id_hex", "consumer_key_id_hex", "public_key_hex", "state"],
  "5": ["meter_id_hex", "meter_version", "unit_scale", "state"],
  "6": ["certificate_id_hex", "commitment_hex", "state"],
  "9": ["validator_id_hex", "consensus_key_hex", "registration_nonce", "proof", "state"],
  "12": ["state"],
  "15": ["target_epoch", "phase", "parameters_hash_hex", "activation_height", "approved"],
}, "semantic intent fact fields drift");
sameJson(semanticIntentContract.validator_proof_fields, ["schema_version", "genesis_hash_hex", "chain_id_utf8", "validator_id_hex", "public_key_hex", "registration_nonce"], "semantic intent validator proof fields drift");
invariant(semanticIntentContract.integer_rule === "u64/u128 facts are canonical decimal strings; u32 and u8 wire discriminants are JSON numbers; governance approved is boolean", "semantic intent integer rule drift");
invariant(semanticIntentContract.normalization_rule === "Node and Rust exact-decode each nondelete value through the sole semantic envelope/payload layouts, rederive the raw identity and logical key, omit envelope revision and only the explicitly target-bound semantic heights, and for validator PoP retain schema/genesis/chain/validator/key/nonce while omitting target_epoch and signature; delete binds kind/key/action with null identity/fact, unknown nondelete kinds fail closed, and volatile sparse-Merkle proofs are never part of lineage", "semantic intent normalization rule drift");
invariant(schema.shared_operation_sequences.business_intent_normalization.omission_boundary === "only the three named body fields, envelope revision, target-bound semantic heights, validator-PoP target_epoch/signature, and volatile sparse-Merkle proofs are omitted from lineage/base-positive hashing; exact semantic identity/key/content, production operation bytes, target context, decision preimage, semantic validation, and subjects remain unchanged", "business intent omission boundary drift");
sameJson(schema.shared_operation_sequences.initial_fields, ["version", "jmt_root_hex", "active_genesis", "production_context", "history", "projection"], "source initial fields drift");
sameJson(schema.shared_operation_sequences.active_genesis_fields, ["chain_id_utf8", "genesis_hash_hex", "validator_lifecycle", "poco_authority_config", "active_parameters", "other_apphash_writes"], "active genesis fields drift");
sameJson(schema.shared_operation_sequences.named_genesis_record_fields, ["physical_key_hex", "value_hex"], "named genesis record fields drift");
sameJson(schema.shared_operation_sequences.active_parameter_fields, ["physical_key_hex", "value_hex", "cev0_hex", "hash_hex"], "active parameter fields drift");
sameJson(schema.shared_operation_sequences.history_entry_fields, ["version", "jmt_root_hex", "writes"], "history entry fields drift");
sameJson(schema.shared_operation_sequences.history_write_fields, ["physical_key_hex", "value_hex"], "history write fields drift");
sameJson(schema.shared_operation_sequences.projection_fields, ["manifest_hex", "entries_root_hex", "entries"], "projection fields drift");
sameJson(schema.shared_operation_sequences.projection_entry_fields, ["kind", "logical_key_hex", "value_hex", "canonical_entry_cev0_hex"], "projection entry fields drift");
sameJson(schema.shared_operation_sequences.rust_step_event_fields, ["schema", "schema_version", "source_export_sha256_hex", "draft_request_sha256_hex", "sequence_id", "step_id", "execution_scope", "context", "source", "operation", "scope_evidence", "mutations", "target", "next_production_context"], "Rust step event fields drift");
sameJson(schema.shared_operation_sequences.event_operation_fields, ["raw_json_hexes", "operation_ids_hex", "operation_root_hex", "operation_count"], "event operation fields drift");
sameJson(schema.shared_operation_sequences.state_fingerprint_fields, ["version", "jmt_root_hex", "manifest_hex", "entries_root_hex", "authority_envelope_hex"], "state fingerprint fields drift");
sameJson(schema.shared_operation_sequences.mutation_fields, ["kind", "logical_key_hex", "expected_value_hex", "next_value_hex", "canonical_cev0_hex"], "mutation fields drift");
sameJson(schema.shared_operation_sequences.target_fields, ["version", "jmt_root_hex", "manifest_hex", "entries_root_hex", "entries", "authority"], "target fields drift");
sameJson(schema.shared_operation_sequences.negative_base_fields, ["source", "step_id", "operation_index", "normalized_business_intent_digest_hex"], "negative base fields drift");
sameJson(schema.shared_operation_sequences.negative_fault_fields, ["kind", "authenticated_source_relation", "expected_first_error_stage", "expected_first_error_code"], "negative fault fields drift");
sameJson(schema.shared_operation_sequences.rust_negative_event_fields, ["schema", "schema_version", "source_export_sha256_hex", "draft_request_sha256_hex", "sequence_id", "negative_id", "execution_scope", "context", "source", "raw_operation_json_hexes", "actual_rejection", "execution_evidence", "writes", "target_after"], "Rust negative event fields drift");
sameJson(schema.shared_operation_sequences.rejected_nullifier_fields, ["family", "identifier_hex", "key_hex", "proof_source_root_hex"], "rejected nullifier fields drift");
sameJson(schema.shared_operation_sequences.isolated_negative_execution_fields, ["kind", "kernel"], "isolated negative execution fields drift");
sameJson(schema.shared_operation_sequences.required_full_store_sequences, ["certificate_challenge_rejected", "certificate_challenge_sustained", "governance_propose_approve", "validator_register_rotate", "release_refund_replay"], "required full-store automata drift");
sameJson(schema.shared_operation_sequences.required_kernel_sequences, ["certificate_prune_replay", "consumer_key_prune_replay", "meter_prune_replay", "validator_prune_replay"], "required isolated automata drift");
invariant(schema.shared_operation_sequences.vector_path === "operation_sequences", "operation sequence vector path drift");
invariant(schema.shared_operation_sequences.source_export_rule === "sorted unique registry retains every exact Rust export byte, including whitespace; Node rehashes raw_json_hex, exact-parses the scope-specific source export, and every sequence references the matching digest", "source export rule drift");
invariant(schema.shared_operation_sequences.active_genesis === "exact validator-lifecycle, genesis PocoAuthorityConfig, active-parameter raw bytes/hash, and every remaining genesis AppHash leaf needed to reconstruct version zero; each named physical key/value must appear byte-for-byte in version-zero history, other_apphash_writes are strictly sorted unique and disjoint from named records, later authenticated history may supersede dynamic PoCO genesis leaves, and no synthetic parameter leaf is permitted when the production store embeds parameters in another authenticated object", "active genesis rule drift");
invariant(schema.shared_operation_sequences.scope_rule === "full_application_store binds the same ordered signed transactions through independent ProcessProposal and FinalizeBlock executions plus SQLite commit/restart, V3/V4 restore, and both durable failpoint outcomes; isolated_prune_transition_kernel is explicitly non-production evidence gated by the named activation prerequisite", "operation scope rule drift");
invariant(schema.shared_operation_sequences.semantic_delete_rule === "Node permits null semantic successors only for private prune_* operations or for release_settlement deleting exactly one kind-6 logical key re-derived from the same certificate ID; Rust production evidence must additionally prove every exact source fact, permanent nullifier, and complete authorized delete set", "operation semantic delete rule drift");
invariant(schema.shared_operation_sequences.negative_rule === "each required negative is a state_dependent_same_subject_replay tied to one successful same-kind business-intent digest or an exact Rust isolated-source lineage; proof-stage replay additionally requires that exact family/subject/key to be occupied in the current authenticated nullifier set and the rejected proof source root to differ from the current authority root; Rust exports an actual stable classifier result and nonzero error-chain digest, while rejected ProcessProposal never invokes FinalizeBlock", "negative evidence rule drift");
invariant(schema.shared_operation_sequences.independence === "Node independently exact-decodes raw JSON and CEV0, derives decision IDs and subjects, verifies every sparse proof against the authenticated initial/sequential root, recomputes operation/mutation/entry roots and manifests, validates persistence fingerprints, and provides an independent check-final after authoring metadata is stripped", "operation evidence independence rule drift");
invariant(schema.shared_operation_sequences.side_fact_rule === "status strings, normalized summaries, telemetry IDs, expected-error echoes, and caller context/proofs are never completion or application authority", "side-fact rule drift");

const NULLIFIER_KEY_DOMAIN = "trnm.poco-bft.nullifier-key.v0";
const EMPTY_LEAF_DOMAIN = "trnm.poco-bft.nullifier-empty-leaf.v0";
const OCCUPIED_LEAF_DOMAIN = "trnm.poco-bft.nullifier-occupied-leaf.v0";
const NULLIFIER_NODE_DOMAIN = "trnm.poco-bft.nullifier-node.v0";
const emptyLeafHash = () => domainHash(EMPTY_LEAF_DOMAIN, uint(0, 2));
const occupiedLeafHash = (key) =>
  domainHash(OCCUPIED_LEAF_DOMAIN, Buffer.concat([uint(0, 2), key]));
const nullifierNodeHash = (level, left, right) =>
  domainHash(
    NULLIFIER_NODE_DOMAIN,
    Buffer.concat([uint(0, 2), uint(level, 4), left, right]),
  );
const deriveNullifierKey = (family, identifier) =>
  domainHash(
    NULLIFIER_KEY_DOMAIN,
    Buffer.concat([uint(0, 2), uint(family, 1), identifier]),
  );
const defaultHashes = [emptyLeafHash()];
for (let level = 0; level < 256; level += 1) {
  defaultHashes.push(
    nullifierNodeHash(level, defaultHashes[level], defaultHashes[level]),
  );
}
const selectedDefaults = vector.nullifier.default_hashes;
for (const level of [0, 1, 2, 17, 255]) {
  invariant(
    defaultHashes[level].toString("hex") === selectedDefaults[`level_${level}_hex`],
    `default hash level ${level} drift`,
  );
}
invariant(
  defaultHashes[256].toString("hex") ===
    selectedDefaults.level_256_empty_root_hex,
  "empty sparse root drift",
);

const pathBitLsbFirst = (key, level) =>
  ((key[31 - Math.floor(level / 8)] >> (level % 8)) & 1) === 1;
const rootFromLeaf = (key, siblings, leaf) => {
  let current = leaf;
  for (let level = 0; level < 256; level += 1) {
    current = pathBitLsbFirst(key, level)
      ? nullifierNodeHash(level, siblings[level], current)
      : nullifierNodeHash(level, current, siblings[level]);
  }
  return current;
};

class ProofError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const readU16 = (bytes, offset) => bytes.readUInt16BE(offset);
const decodeProofExact = (bytes) => {
  if (bytes.length !== 8230) throw new ProofError("proof_length");
  if (readU16(bytes, 0) !== 0) throw new ProofError("proof_schema");
  if (readU16(bytes, 2) !== 0) throw new ProofError("proof_version");
  if (readU16(bytes, 4) !== 256) throw new ProofError("proof_depth");
  const key = bytes.subarray(6, 38);
  const siblings = [];
  for (let level = 0; level < 256; level += 1) {
    const start = 38 + level * 32;
    siblings.push(bytes.subarray(start, start + 32));
  }
  return { key, siblings };
};
const verifyNonMembership = (fixture, raw, familyOverride = fixture.family) => {
  const proof = decodeProofExact(raw);
  const identifier = exactHex(fixture.identifier_hex, 32, `${fixture.id}.identifier`);
  const expectedKey = deriveNullifierKey(familyOverride, identifier);
  if (!proof.key.equals(expectedKey)) throw new ProofError("proof_key");
  const sourceRoot = exactHex(fixture.source_root_hex, 32, `${fixture.id}.source root`);
  if (!rootFromLeaf(proof.key, proof.siblings, emptyLeafHash()).equals(sourceRoot)) {
    throw new ProofError("proof_root");
  }
  const sourceCount = asUnsigned(fixture.source_count, U64_MAX, `${fixture.id}.source count`);
  if (sourceCount === U64_MAX) throw new ProofError("proof_count_exhausted");
  return { proof, expectedKey, sourceCount };
};
const verifyInsertion = (fixture, raw, familyOverride = fixture.family) => {
  const { proof, expectedKey, sourceCount } = verifyNonMembership(
    fixture,
    raw,
    familyOverride,
  );
  const targetRoot = rootFromLeaf(
    proof.key,
    proof.siblings,
    occupiedLeafHash(proof.key),
  );
  invariant(
    targetRoot.toString("hex") === fixture.target_root_hex,
    `${fixture.id}: target root drift`,
  );
  invariant(
    sourceCount + 1n === asUnsigned(fixture.target_count, U64_MAX, `${fixture.id}.target count`),
    `${fixture.id}: target count drift`,
  );
  return { key: expectedKey, targetRoot };
};

unique(
  vector.nullifier.derived_family_keys.map((entry) => entry.family),
  "duplicate nullifier family vector",
);
for (const fixture of vector.nullifier.derived_family_keys) {
  invariant(fixture.family >= 1 && fixture.family <= 14, "unknown nullifier family fixture");
  const identifier = exactHex(fixture.identifier_hex, 32, "family identifier");
  invariant(
    deriveNullifierKey(fixture.family, identifier).toString("hex") === fixture.key_hex,
    `family ${fixture.family}: key drift`,
  );
}
const fundSubjectAbsence = vector.nullifier.fund_subject_absence;
const fundSubjectProof = exactHex(
  fundSubjectAbsence.proof_hex,
  8230,
  "fund-subject absence proof",
);
invariant(
  crypto.createHash("sha256").update(fundSubjectProof).digest("hex") ===
    fundSubjectAbsence.proof_sha256_hex,
  "fund-subject absence proof digest drift",
);
verifyNonMembership(fundSubjectAbsence, fundSubjectProof);
let previousTarget = null;
for (const fixture of vector.nullifier.sequential_insertions) {
  const raw = exactHex(fixture.proof_hex, 8230, `${fixture.id}.proof`);
  invariant(
    crypto.createHash("sha256").update(raw).digest("hex") === fixture.proof_sha256_hex,
    `${fixture.id}: raw proof digest drift`,
  );
  if (previousTarget !== null) {
    invariant(fixture.source_root_hex === previousTarget.root, `${fixture.id}: root chain drift`);
    invariant(fixture.source_count === previousTarget.count, `${fixture.id}: count chain drift`);
  }
  verifyInsertion(fixture, raw);
  previousTarget = { root: fixture.target_root_hex, count: fixture.target_count };
}

const proofById = new Map(
  vector.nullifier.sequential_insertions.map((fixture) => [fixture.id, fixture]),
);
for (const negative of vector.nullifier.negative_mutations) {
  const fixture = proofById.get(negative.base);
  invariant(fixture !== undefined, `${negative.id}: missing base proof`);
  let raw = Buffer.from(fixture.proof_hex, "hex");
  let family = fixture.family;
  switch (negative.action) {
    case "xor":
      raw = Buffer.from(raw);
      raw[negative.offset] ^= negative.mask;
      break;
    case "append":
      raw = Buffer.concat([raw, Buffer.from(negative.hex, "hex")]);
      break;
    case "truncate":
      raw = raw.subarray(0, raw.length - negative.bytes);
      break;
    case "family":
      family = negative.family;
      break;
    default:
      throw new Error(`${negative.id}: unknown proof mutation`);
  }
  let code = null;
  try {
    verifyInsertion(fixture, raw, family);
  } catch (error) {
    if (error instanceof ProofError) code = error.code;
    else throw error;
  }
  invariant(code === negative.expected_error, `${negative.id}: rejection drift ${code}`);
}

class Cursor {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }
  fixed(length) {
    invariant(this.offset + length <= this.bytes.length, "truncated exact value");
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
  u8() { return this.fixed(1)[0]; }
  u16() { return this.fixed(2).readUInt16BE(0); }
  u32() { return this.fixed(4).readUInt32BE(0); }
  u64() { return this.fixed(8).readBigUInt64BE(0); }
  bytesValue() { return this.fixed(this.u32()); }
  finish() { invariant(this.offset === this.bytes.length, "trailing exact value bytes"); }
}
const logicalKey = (kind, identity) =>
  domainHash(
    "trnm.poco-bft.snapshot-value-identity.v0",
    Buffer.concat([uint(0, 2), uint(kind, 1), frame(identity)]),
  );
const validateAuthorityNumericRecord = (record, contract, label) => {
  for (const field of contract.u64_unquoted ?? []) {
    strictJsonU64(record[field], `${label}.${field}`);
  }
  for (const field of contract.optional_u64_unquoted ?? []) {
    if (record[field] !== null) {
      strictJsonU64(record[field], `${label}.${field}`);
    }
  }
  for (const field of contract.u32_unquoted ?? []) {
    strictJsonU32(record[field], `${label}.${field}`);
  }
  for (const field of contract.u8_unquoted ?? []) {
    strictJsonU8(record[field], `${label}.${field}`);
  }
  for (const field of contract.u128_decimal_strings ?? []) {
    strictJsonCanonicalU128(record[field], `${label}.${field}`);
  }
};
const validateAuthorityNumericFieldTypes = (state, hasExtension, label) => {
  validateAuthorityNumericRecord(state, AUTHORITY_NUMERIC_FIELD_TYPES.top_level, label);
  for (const [family, contract] of Object.entries(AUTHORITY_NUMERIC_FIELD_TYPES)) {
    if (
      family === "top_level" ||
      family === "consumer_nonce_watermarks" ||
      family === "semantic_keys"
    ) {
      continue;
    }
    const records = family === "future_candidate_registrations" && !hasExtension
      ? []
      : state[family];
    for (const [index, record] of records.entries()) {
      validateAuthorityNumericRecord(record, contract, `${label}.${family}[${index}]`);
    }
  }
  for (const [keyIndex, consumerKey] of state.consumer_keys.entries()) {
    for (const [watermarkIndex, watermark] of consumerKey.nonce_watermarks.entries()) {
      validateAuthorityNumericRecord(
        watermark,
        AUTHORITY_NUMERIC_FIELD_TYPES.consumer_nonce_watermarks,
        `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}]`,
      );
    }
  }
  for (const [certificateIndex, certificate] of state.active_certificates.entries()) {
    for (const [semanticIndex, semanticKey] of certificate.semantic_keys.entries()) {
      validateAuthorityNumericRecord(
        semanticKey,
        AUTHORITY_NUMERIC_FIELD_TYPES.semantic_keys,
        `${label}.active_certificates[${certificateIndex}].semantic_keys[${semanticIndex}]`,
      );
    }
  }
};
const validateAuthorityStateShape = (state, label) => {
  const fullOrder = schema.authority_value.payload.field_order;
  const extensionField = schema.authority_value.payload.optional_trailing_fields[0];
  invariant(fullOrder.at(-1) === extensionField, `${label}: optional extension is not trailing`);
  const hasExtension = Object.prototype.hasOwnProperty.call(state, extensionField);
  sameJson(
    Object.keys(state),
    hasExtension ? fullOrder : fullOrder.slice(0, -1),
    `${label}: field order`,
  );

  const familyCaps = new Map(
    schema.authority_value.payload.record_families.map((family) => [family.name, family.maximum_records]),
  );
  let authorityRecordCount = 0;
  for (const [family, maximum] of familyCaps) {
    const records = family === extensionField && !hasExtension ? [] : state[family];
    invariant(Array.isArray(records), `${label}.${family}: record array required`);
    invariant(records.length <= maximum, `${label}.${family}: record cap`);
    authorityRecordCount += records.length;
  }
  const usageCount = [
    "meter_usage", "consumer_provider_usage", "task_provider_usage", "provider_usage",
  ].reduce((total, family) => total + state[family].length, 0);
  invariant(usageCount <= schema.hard_bounds.total_usage_buckets, `${label}: aggregate usage cap`);
  let nonceWatermarkCount = 0;
  for (const [index, consumerKey] of state.consumer_keys.entries()) {
    invariant(
      Array.isArray(consumerKey.nonce_watermarks) &&
        consumerKey.nonce_watermarks.length <= schema.additional_bounds.nonce_watermarks_per_consumer_key,
      `${label}.consumer_keys[${index}]: nonce-watermark cap`,
    );
    nonceWatermarkCount += consumerKey.nonce_watermarks.length;
  }
  invariant(
    nonceWatermarkCount <= schema.additional_bounds.total_nonce_watermarks,
    `${label}: total nonce-watermark cap`,
  );
  authorityRecordCount += nonceWatermarkCount;
  invariant(
    authorityRecordCount <= schema.additional_bounds.total_authority_records,
    `${label}: aggregate authority-record cap`,
  );

  for (const [family, fieldOrder] of Object.entries(AUTHORITY_NESTED_FIELD_ORDER)) {
    if (family === "consumer_nonce_watermarks" || family === "semantic_keys") continue;
    const records = family === extensionField && !hasExtension ? [] : state[family];
    for (const [index, record] of records.entries()) {
      exactKeys(record, fieldOrder, `${label}.${family}[${index}]`);
    }
  }
  for (const [keyIndex, consumerKey] of state.consumer_keys.entries()) {
    for (const [watermarkIndex, watermark] of consumerKey.nonce_watermarks.entries()) {
      exactKeys(
        watermark,
        AUTHORITY_NESTED_FIELD_ORDER.consumer_nonce_watermarks,
        `${label}.consumer_keys[${keyIndex}].nonce_watermarks[${watermarkIndex}]`,
      );
    }
  }
  for (const [certificateIndex, certificate] of state.active_certificates.entries()) {
    invariant(
      Array.isArray(certificate.semantic_keys),
      `${label}.active_certificates[${certificateIndex}].semantic_keys: array required`,
    );
    for (const [semanticIndex, semanticKey] of certificate.semantic_keys.entries()) {
      exactKeys(
        semanticKey,
        AUTHORITY_NESTED_FIELD_ORDER.semantic_keys,
        `${label}.active_certificates[${certificateIndex}].semantic_keys[${semanticIndex}]`,
      );
    }
  }
  validateAuthorityNumericFieldTypes(state, hasExtension, label);
  if (!hasExtension) return;

  const records = state.future_candidate_registrations;
  invariant(Array.isArray(records) && records.length > 0, `${label}: empty future extension must be omitted`);
  invariant(
    records.length <= schema.authority_value.payload.future_candidate_record.maximum_records,
    `${label}: future candidate registration cap`,
  );
  const lastTargetHeight = asUnsigned(
    state.last_target_height,
    U64_MAX,
    `${label}.last_target_height`,
  );
  const histories = new Map(
    state.validator_registration_history.map((history) => [history.validator_id_hex, history]),
  );
  const historicalConsensusKeys = new Set(
    state.validator_registration_history.map((history) => history.consensus_key_hex),
  );
  let previous = null;
  const consensusKeys = new Set();
  for (const [index, record] of records.entries()) {
    const recordLabel = `${label}.future_candidate_registrations[${index}]`;
    exactKeys(
      record,
      schema.authority_value.payload.future_candidate_record.field_order,
      recordLabel,
    );
    const validatorId = boundedHex(record.validator_id_hex, 1, 128, `${recordLabel}.validator_id_hex`);
    const targetEpoch = asUnsigned(record.target_epoch, U64_MAX, `${recordLabel}.target_epoch`);
    invariant(targetEpoch > 0n, `${recordLabel}: zero target epoch`);
    const consensusKey = exactHex(record.consensus_key_hex, 32, `${recordLabel}.consensus_key_hex`);
    invariant(!consensusKey.equals(Buffer.alloc(32)), `${recordLabel}: zero consensus key`);
    invariant(!consensusKeys.has(record.consensus_key_hex), `${recordLabel}: reused consensus key`);
    invariant(
      !historicalConsensusKeys.has(record.consensus_key_hex),
      `${recordLabel}: consensus key reuses registration history`,
    );
    consensusKeys.add(record.consensus_key_hex);
    const registrationNonce = asUnsigned(
      record.registration_nonce,
      U64_MAX,
      `${recordLabel}.registration_nonce`,
    );
    invariant(
      record.previous_registration_nonce === null ||
        typeof record.previous_registration_nonce === "bigint" ||
        Number.isSafeInteger(record.previous_registration_nonce),
      `${recordLabel}: predecessor nonce representation`,
    );
    const previousNonce = record.previous_registration_nonce === null
      ? null
      : asUnsigned(
          record.previous_registration_nonce,
          U64_MAX,
          `${recordLabel}.previous_registration_nonce`,
        );
    const predecessor = exactHex(
      record.predecessor_history_head_hex,
      32,
      `${recordLabel}.predecessor_history_head_hex`,
    );
    invariant(
      previousNonce === null
        ? predecessor.equals(Buffer.alloc(32))
        : !predecessor.equals(Buffer.alloc(32)) && registrationNonce > previousNonce,
      `${recordLabel}: predecessor nonce/head contract`,
    );
    if (previousNonce !== null) {
      const history = histories.get(record.validator_id_hex);
      invariant(history !== undefined, `${recordLabel}: missing predecessor history`);
      invariant(history.revoked_at_height === null, `${recordLabel}: revoked predecessor history`);
      invariant(
        asUnsigned(history.max_registration_nonce, U64_MAX, `${recordLabel}.history_nonce`) ===
          previousNonce &&
          history.history_head_hex === record.predecessor_history_head_hex,
        `${recordLabel}: substituted predecessor authority`,
      );
    }
    const proof = boundedHex(record.proof_cev0_hex, 1, 65_384, `${recordLabel}.proof_cev0_hex`);
    invariant(
      domainHash(schema.authority_value.payload.future_candidate_record.proof_digest_domain_ascii, proof)
        .equals(exactHex(record.proof_digest_hex, 32, `${recordLabel}.proof_digest_hex`)),
      `${recordLabel}: proof digest`,
    );
    exactHex(record.registration_decision_id_hex, 32, `${recordLabel}.registration_decision_id_hex`);
    const registrationHeight = asUnsigned(
      record.registration_height,
      U64_MAX,
      `${recordLabel}.registration_height`,
    );
    invariant(registrationHeight > 0n, `${recordLabel}: zero registration height`);
    invariant(
      registrationHeight <= lastTargetHeight,
      `${recordLabel}: registration height exceeds authority watermark`,
    );
    invariant(
      previous === null ||
        targetEpoch > previous.targetEpoch ||
        (targetEpoch === previous.targetEpoch &&
          Buffer.compare(validatorId, previous.validatorId) > 0),
      `${recordLabel}: canonical ordering`,
    );
    previous = { targetEpoch, validatorId };
  }
};
const decodeAuthorityEnvelope = (raw, expectedLogicalKey) => {
  invariant(raw.length <= 65536, "authority envelope exceeds value bound");
  const cursor = new Cursor(raw);
  invariant(cursor.u16() === 0, "authority envelope schema drift");
  invariant(cursor.u8() === 16, "authority envelope kind drift");
  const revision = cursor.u64();
  invariant(revision > 0n, "zero authority revision");
  const identity = cursor.bytesValue();
  invariant(identity.toString() === "trnm.poco.application-authority.v0", "authority identity mismatch");
  const payload = cursor.bytesValue();
  cursor.finish();
  invariant(payload.length > 0 && payload.length <= 65384, "authority payload bound");
  invariant(logicalKey(16, identity).equals(expectedLogicalKey), "authority logical key mismatch");
  const state = decodeCanonicalAuthorityJson(payload, "authority state");
  validateAuthorityStateShape(state, "authority state");
  invariant(BigInt(state.revision) === revision, "authority envelope/state revision mismatch");
  invariant(
    (revision === 1n) === (BigInt(state.last_target_height) === 0n),
    "authority genesis revision/height mismatch",
  );
  exactHex(state.nullifier_root_hex, 32, "authority nullifier root");
  asUnsigned(state.nullifier_count, U64_MAX, "authority nullifier count");
  return { revision, identity, payload, state };
};
const validateFutureCandidateGeometry = (state, profile, label) => {
  const activeEpoch = asUnsigned(profile.active_epoch, U64_MAX, `${label}.active_epoch`);
  const targetEpoch = asUnsigned(profile.target_epoch, U64_MAX, `${label}.target_epoch`);
  const epochLength = asUnsigned(
    profile.epoch_length_blocks,
    U64_MAX,
    `${label}.epoch_length_blocks`,
  );
  invariant(targetEpoch === activeEpoch + 1n, `${label}: target is not active successor`);
  invariant(epochLength > 0n, `${label}: zero epoch length`);
  const firstHeight = activeEpoch * epochLength + 1n;
  const lastHeight = (activeEpoch + 1n) * epochLength;
  for (const [index, record] of state.future_candidate_registrations.entries()) {
    const registrationHeight = asUnsigned(
      record.registration_height,
      U64_MAX,
      `${label}[${index}].registration_height`,
    );
    invariant(
      asUnsigned(record.target_epoch, U64_MAX, `${label}[${index}].target_epoch`) ===
        targetEpoch,
      `${label}[${index}]: target epoch drift`,
    );
    invariant(
      registrationHeight >= firstHeight && registrationHeight <= lastHeight,
      `${label}[${index}]: registration outside source active epoch`,
    );
  }
};

const canonicalEntry = (kind, key, value) =>
  Buffer.concat([uint(0, 2), uint(kind, 1), frame(key), frame(value)]);
const orderedRoot = (leafDomain, nodeDomain, rootDomain, values) => {
  let layer = values.map((value) => domainHash(leafDomain, value));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index];
      const right = layer[index + 1] ?? left;
      next.push(
        domainHash(
          nodeDomain,
          Buffer.concat([uint(0, 2), uint(level, 4), left, right]),
        ),
      );
    }
    layer = next;
    level += 1;
  }
  return domainHash(
    rootDomain,
    Buffer.concat([
      uint(0, 2),
      uint(values.length, 4),
      layer.length === 0 ? uint(0, 1) : Buffer.concat([uint(1, 1), layer[0]]),
    ]),
  );
};
const decodeManifest = (raw) => {
  invariant(raw.length === 47, "manifest length drift");
  const cursor = new Cursor(raw);
  invariant(cursor.u16() === 0 && cursor.u8() === 8, "manifest header drift");
  const height = cursor.u64();
  const count = cursor.u32();
  const rootHash = cursor.fixed(32);
  cursor.finish();
  return { height, count, rootHash };
};

const successor = vector.authority_successor;
const authorityKey = exactHex(successor.source.logical_key_hex, 32, "authority key");
const sourceJmtRoot = exactHex(successor.source.jmt_root_hex, 32, "source JMT root");
const targetJmtRoot = exactHex(successor.target.jmt_root_hex, 32, "target JMT root");
invariant(
  !sourceJmtRoot.equals(Buffer.alloc(32)) &&
    !targetJmtRoot.equals(Buffer.alloc(32)) &&
    !targetJmtRoot.equals(sourceJmtRoot),
  "production JMT root chain is zero or unchanged",
);
invariant(successor.target.logical_key_hex === successor.source.logical_key_hex, "authority key changed");
for (const [label, fixture] of [["source", successor.source], ["target", successor.target]]) {
  const canonicalPayload = Buffer.from(canonicalJsonStringify(fixture.state));
  invariant(canonicalPayload.toString("hex") === fixture.canonical_json_hex, `${label}: canonical state drift`);
  const decoded = decodeAuthorityEnvelope(Buffer.from(fixture.envelope_hex, "hex"), authorityKey);
  invariant(decoded.payload.equals(canonicalPayload), `${label}: envelope payload drift`);
  sameJson(decoded.state, fixture.state, `${label}: state decode drift`);
}
const richAuthorityEntry = authenticatedCandidateVector.positive.source.cutoff_projection.entries.find(
  (entry) => entry.kind === 16,
);
invariant(richAuthorityEntry !== undefined, "authenticated-candidate kind-16 witness missing");
const richAuthorityState = decodeAuthorityEnvelope(
  Buffer.from(richAuthorityEntry.value_hex, "hex"),
  exactHex(richAuthorityEntry.logical_key_hex, 32, "authenticated-candidate authority key"),
).state;
invariant(
  richAuthorityState.consumer_keys.length > 0 &&
    richAuthorityState.consumer_keys[0].nonce_watermarks.length > 0 &&
    richAuthorityState.active_certificates.length > 0 &&
    richAuthorityState.active_certificates[0].semantic_keys.length > 0,
  "nested unknown-field self-test lacks rich authority companions",
);
const nestedUnknownFieldMutations = [
  ["record", (state) => { state.consumer_keys[0].unknown_field = 0; }],
  ["nonce_watermark", (state) => {
    state.consumer_keys[0].nonce_watermarks[0].unknown_field = 0;
  }],
  ["semantic_key", (state) => {
    state.active_certificates[0].semantic_keys[0].unknown_field = 0;
  }],
];
let authorityNestedUnknownNegatives = 0;
for (const [name, mutate] of nestedUnknownFieldMutations) {
  const drifted = structuredClone(richAuthorityState);
  mutate(drifted);
  let rejected = false;
  try {
    validateAuthorityStateShape(drifted, `unknown_nested.${name}`);
  } catch (error) {
    invariant(
      error instanceof Error && error.message.includes("field order"),
      `unknown_nested.${name}: wrong rejection ${String(error)}`,
    );
    rejected = true;
  }
  invariant(rejected, `unknown_nested.${name}: unknown field accepted`);
  authorityNestedUnknownNegatives += 1;
}
const authorityJsonTypeMutations = [
  ["quoted_revision", "unquoted u64", (state) => {
    state.revision = String(state.revision);
  }],
  ["quoted_nested_height", "unquoted u64", (state) => {
    state.consumer_keys[0].active_from_height =
      String(state.consumer_keys[0].active_from_height);
  }],
  ["quoted_nested_optional_height", "unquoted u64", (state) => {
    state.consumer_keys[0].revoked_at_height = "1";
  }],
  ["quoted_nested_nonce", "unquoted u64", (state) => {
    state.consumer_keys[0].nonce_watermarks[0].max_accepted_nonce =
      String(state.consumer_keys[0].nonce_watermarks[0].max_accepted_nonce);
  }],
  ["quoted_nested_u32", "unquoted u32", (state) => {
    state.active_certificates[0].meter_version =
      String(state.active_certificates[0].meter_version);
  }],
  ["quoted_nested_enum", "unquoted u8", (state) => {
    state.active_certificates[0].relationship_class =
      String(state.active_certificates[0].relationship_class);
  }],
  ["unquoted_nested_u128", "canonical u128 decimal string", (state) => {
    state.active_certificates[0].consumed_units = 1;
  }],
];
let authorityJsonTypeNegatives = 0;
for (const [name, expectedError, mutate] of authorityJsonTypeMutations) {
  const drifted = structuredClone(richAuthorityState);
  mutate(drifted);
  let rejected = false;
  try {
    validateAuthorityStateShape(drifted, `numeric_type.${name}`);
  } catch (error) {
    invariant(
      error instanceof Error && error.message.includes(expectedError),
      `numeric_type.${name}: wrong rejection ${String(error)}`,
    );
    rejected = true;
  }
  invariant(rejected, `numeric_type.${name}: wrong JSON numeric type accepted`);
  authorityJsonTypeNegatives += 1;
}
let authorityCapacityNegatives = 0;
for (const family of schema.authority_value.payload.record_families) {
  const over = structuredClone(successor.target.state);
  over[family.name] = Array.from({ length: family.maximum_records + 1 }, () => ({}));
  invariant(
    (() => {
      try {
        validateAuthorityStateShape(over, `capacity.${family.name}`);
        return false;
      } catch {
        return true;
      }
    })(),
    `${family.name}: cap+1 state accepted`,
  );
  authorityCapacityNegatives += 1;
}
{
  const over = structuredClone(successor.target.state);
  over.meter_usage = Array.from({ length: 32 }, () => ({}));
  over.consumer_provider_usage = [{}];
  invariant(
    (() => {
      try {
        validateAuthorityStateShape(over, "capacity.aggregate_usage");
        return false;
      } catch {
        return true;
      }
    })(),
    "aggregate usage cap+1 state accepted",
  );
  authorityCapacityNegatives += 1;
}
{
  const over = structuredClone(successor.target.state);
  over.consumer_keys = [
    { nonce_watermarks: Array.from({ length: 5 }, () => ({})) },
    { nonce_watermarks: Array.from({ length: 4 }, () => ({})) },
  ];
  invariant(
    (() => {
      try {
        validateAuthorityStateShape(over, "capacity.total_nonce_watermarks");
        return false;
      } catch {
        return true;
      }
    })(),
    "total nonce-watermark cap+1 state accepted",
  );
  authorityCapacityNegatives += 1;
}

const futureStep = authenticatedCandidateVector.positive.block_steps.find(
  (step) => step.purpose === "strict_successor_epoch_changed_and_new_candidate_pop",
);
invariant(futureStep !== undefined, "future-candidate production operation step missing");
invariant(
  futureStep.raw_operation_json_hexes.length === 2,
  "future-candidate operation witness count drift",
);
const decodeFutureCandidatePopConsensusKey = (raw, label) => {
  const cursor = new Cursor(raw);
  invariant(cursor.u16() === 0, `${label}: PoP schema drift`);
  invariant(!cursor.fixed(32).equals(Buffer.alloc(32)), `${label}: zero PoP genesis hash`);
  const chainLength = cursor.u16();
  invariant(chainLength >= 1 && chainLength <= 128, `${label}: PoP chain ID length`);
  cursor.fixed(chainLength);
  cursor.u64();
  const validatorId = cursor.bytesValue();
  invariant(
    validatorId.length >= 1 && validatorId.length <= 128,
    `${label}: PoP validator ID length`,
  );
  const consensusKey = cursor.fixed(32);
  invariant(!consensusKey.equals(Buffer.alloc(32)), `${label}: zero PoP consensus key`);
  cursor.u64();
  cursor.fixed(64);
  cursor.finish();
  return consensusKey;
};
const validateFutureCandidateRawOperation = (raw, label) => {
  const operation = JSON.parse(raw.toString("utf8"));
  sameJson(Object.keys(operation), [
    "schema", "target_height", "expected_state_revision", "body", "semantic_changes",
    "nullifier_non_membership_checks", "nullifier_insertions",
  ], `${label}: field order`);
  invariant(
    operation.schema === "trnm_poco_application_operation_v0" &&
      Buffer.from(JSON.stringify(operation)).equals(raw),
    `${label}: noncanonical JSON/schema`,
  );
  sameJson(Object.keys(operation.body), [
    "kind", "validator_id_hex", "target_epoch", "previous_registration_nonce",
    "predecessor_history_head_hex", "proof_cev0_hex", "registration_decision_id_hex",
  ], `${label}: body field order`);
  invariant(operation.body.kind === "register_future_candidate", `${label}: kind`);
  invariant(operation.semantic_changes.length === 0, `${label}: semantic changes`);
  invariant(
    operation.nullifier_non_membership_checks.length === 0,
    `${label}: caller non-membership checks`,
  );
  invariant(operation.nullifier_insertions.length === 2, `${label}: insertion count`);
  sameJson(
    operation.nullifier_insertions.map((insertion) => insertion.family),
    [8, 13],
    `${label}: insertion families`,
  );
  for (const [insertionIndex, insertion] of operation.nullifier_insertions.entries()) {
    sameJson(
      Object.keys(insertion),
      ["family", "identifier_hex", "proof_hex"],
      `${label}: insertion ${insertionIndex} field order`,
    );
    const identifier = exactHex(
      insertion.identifier_hex,
      32,
      `${label}: insertion ${insertionIndex} identifier`,
    );
    const proof = decodeProofExact(
      exactHex(insertion.proof_hex, 8_230, `${label}: insertion ${insertionIndex} proof`),
    );
    invariant(
      proof.key.equals(deriveNullifierKey(insertion.family, identifier)),
      `${label}: insertion ${insertionIndex} sparse proof key`,
    );
  }
  invariant(
    operation.nullifier_insertions[0].identifier_hex ===
      operation.body.registration_decision_id_hex,
    `${label}: decision nullifier subject`,
  );
  const consensusKey = decodeFutureCandidatePopConsensusKey(
    boundedHex(operation.body.proof_cev0_hex, 1, 65_384, `${label}: PoP`),
    label,
  );
  invariant(
    operation.nullifier_insertions[1].identifier_hex === consensusKey.toString("hex"),
    `${label}: consensus-key nullifier subject`,
  );
  return operation;
};
const expectFutureOperationReject = (operation, label) => {
  let rejected = false;
  try {
    validateFutureCandidateRawOperation(Buffer.from(JSON.stringify(operation)), label);
  } catch {
    rejected = true;
  }
  invariant(rejected, `${label}: mutation accepted`);
};
let futureOperationBindingNegatives = 0;
for (const [index, rawHex] of futureStep.raw_operation_json_hexes.entries()) {
  const label = `future operation ${index}`;
  const raw = boundedHex(rawHex, 1, 1_048_576, label);
  const operation = validateFutureCandidateRawOperation(raw, label);

  const wrongSubject = structuredClone(operation);
  const substitutedKey = Buffer.from(
    wrongSubject.nullifier_insertions[1].identifier_hex,
    "hex",
  );
  substitutedKey[0] ^= 1;
  wrongSubject.nullifier_insertions[1].identifier_hex = substitutedKey.toString("hex");
  expectFutureOperationReject(wrongSubject, `${label} substituted consensus-key subject`);
  futureOperationBindingNegatives += 1;

  for (const insertionIndex of [0, 1]) {
    const wrongProofKey = structuredClone(operation);
    const proof = Buffer.from(
      wrongProofKey.nullifier_insertions[insertionIndex].proof_hex,
      "hex",
    );
    // Six bytes of sparse-proof header precede its exact 32-byte key.
    proof[6] ^= 1;
    wrongProofKey.nullifier_insertions[insertionIndex].proof_hex = proof.toString("hex");
    expectFutureOperationReject(
      wrongProofKey,
      `${label} insertion ${insertionIndex} substituted sparse key`,
    );
    futureOperationBindingNegatives += 1;
  }
}
const futureAuthorityEntry =
  authenticatedCandidateVector.positive.source.cutoff_projection.entries.find(
    (entry) => entry.kind === 16,
  );
invariant(futureAuthorityEntry !== undefined, "future authority projection entry missing");
const futureAuthority = decodeAuthorityEnvelope(
  Buffer.from(futureAuthorityEntry.value_hex, "hex"),
  exactHex(futureAuthorityEntry.logical_key_hex, 32, "future authority logical key"),
).state;
invariant(
  futureAuthority.future_candidate_registrations.length === 2,
  "nonempty future authority extension witness count drift",
);
validateFutureCandidateGeometry(
  futureAuthority,
  authenticatedCandidateVector.compact_profile,
  "future authority geometry",
);
{
  const badGeometry = structuredClone(futureAuthority);
  badGeometry.future_candidate_registrations[0].registration_height =
    Number(authenticatedCandidateVector.compact_profile.boundary_height) - 1;
  invariant(
    (() => {
      try {
        validateFutureCandidateGeometry(
          badGeometry,
          authenticatedCandidateVector.compact_profile,
          "future authority bad geometry",
        );
        return false;
      } catch {
        return true;
      }
    })(),
    "future registration outside source active epoch was accepted",
  );
}
invariant(
  BigInt(successor.target.state.revision) === BigInt(successor.source.state.revision) + 1n,
  "state revision is not an exact successor",
);
invariant(
  BigInt(successor.target.state.last_target_height) === BigInt(successor.target_height),
  "state target-height watermark drift",
);
invariant(
  BigInt(successor.source_version) + 1n === BigInt(successor.target_height),
  "block target is not exact source successor",
);
invariant(
  successor.target.state.nullifier_root_hex ===
    vector.nullifier.sequential_insertions[0].target_root_hex &&
    String(successor.target.state.nullifier_count) ===
      vector.nullifier.sequential_insertions[0].target_count,
  "authority state did not commit sequential nullifier result",
);

const sourceEntry = canonicalEntry(16, authorityKey, Buffer.from(successor.source.envelope_hex, "hex"));
invariant(sourceEntry.toString("hex") === successor.source.entry_cev0_hex, "source entry drift");
const settlementKey = exactHex(successor.target.settlement_logical_key_hex, 32, "settlement key");
const settlementValue = Buffer.from(successor.target.settlement_value_hex, "hex");
const targetEntries = [
  canonicalEntry(6, settlementKey, settlementValue),
  canonicalEntry(16, authorityKey, Buffer.from(successor.target.envelope_hex, "hex")),
];
invariant(targetEntries[0].toString("hex") === successor.target.settlement_entry_cev0_hex, "settlement entry drift");
invariant(targetEntries[1].toString("hex") === successor.target.authority_entry_cev0_hex, "target authority entry drift");
const sourceEntriesRoot = orderedRoot(
  "trnm.poco-bft.snapshot-entry.v0",
  "trnm.poco-bft.snapshot-node.v0",
  "trnm.poco-bft.snapshot-root.v0",
  [sourceEntry],
);
const targetEntriesRoot = orderedRoot(
  "trnm.poco-bft.snapshot-entry.v0",
  "trnm.poco-bft.snapshot-node.v0",
  "trnm.poco-bft.snapshot-root.v0",
  targetEntries,
);
invariant(sourceEntriesRoot.toString("hex") === successor.source.entries_root_hex, "source entries root drift");
invariant(targetEntriesRoot.toString("hex") === successor.target.entries_root_hex, "target entries root drift");
const sourceManifest = decodeManifest(Buffer.from(successor.source.manifest_hex, "hex"));
const targetManifest = decodeManifest(Buffer.from(successor.target.manifest_hex, "hex"));
invariant(sourceManifest.height === 0n && sourceManifest.count === 1, "source manifest coordinate drift");
invariant(sourceManifest.rootHash.equals(sourceEntriesRoot), "source manifest root drift");
invariant(targetManifest.height === 2n && targetManifest.count === 2, "target manifest coordinate drift");
invariant(targetManifest.rootHash.equals(targetEntriesRoot), "target manifest root drift");
invariant(successor.manifest_write_count === 1, "application plan must write one manifest");

const optionalBytes = (value) =>
  value === null
    ? uint(0, 1)
    : Buffer.concat([uint(1, 1), frame(value)]);
const canonicalMutation = (entry) =>
  Buffer.concat([
    uint(0, 2),
    uint(entry.kind, 1),
    frame(Buffer.from(entry.logical_key_hex, "hex")),
    optionalBytes(entry.expected_value_hex === null ? null : Buffer.from(entry.expected_value_hex, "hex")),
    optionalBytes(entry.next_value_hex === null ? null : Buffer.from(entry.next_value_hex, "hex")),
  ]);
const mutationBytes = successor.mutations.map((entry) => {
  const canonical = canonicalMutation(entry);
  invariant(canonical.toString("hex") === entry.canonical_cev0_hex, `kind ${entry.kind}: mutation drift`);
  return canonical;
});
sameJson(successor.mutations.map((entry) => entry.kind), [6, 16], "mutation order drift");
invariant(successor.mutation_count === mutationBytes.length, "mutation count drift");
invariant(
  orderedRoot(
    "trnm.poco-bft.application-mutation.v0",
    "trnm.poco-bft.application-mutation-node.v0",
    "trnm.poco-bft.application-mutation-root.v0",
    mutationBytes,
  ).toString("hex") === successor.mutation_root_hex,
  "application mutation root drift",
);

const operationRaw = Buffer.from(successor.operation.canonical_json_hex, "hex");
invariant(Buffer.from(JSON.stringify(successor.operation.value)).equals(operationRaw), "operation JSON drift");
const decodedOperation = JSON.parse(operationRaw.toString("utf8"));
invariant(Buffer.from(JSON.stringify(decodedOperation)).equals(operationRaw), "operation JSON is not canonical");
invariant(decodedOperation.target_height === 2, "operation target-height drift");
invariant(decodedOperation.expected_state_revision === 1, "operation source revision drift");
invariant(decodedOperation.semantic_changes.length === 1, "operation semantic-change count drift");
invariant(decodedOperation.nullifier_non_membership_checks.length === 1, "fund operation certificate-absence count drift");
invariant(decodedOperation.nullifier_insertions.length === 1, "operation nullifier count drift");
invariant(decodedOperation.semantic_changes[0].kind === 6, "operation did not create settlement kind 6");
invariant(decodedOperation.semantic_changes[0].logical_key_hex === successor.target.settlement_logical_key_hex, "operation settlement key drift");
invariant(decodedOperation.semantic_changes[0].next_value_hex === successor.target.settlement_value_hex, "operation settlement value drift");
invariant(decodedOperation.body.reserved_units === "7", "operation reserved-units fixture drift");
sameJson(
  decodedOperation.nullifier_non_membership_checks[0],
  {
    family: 1,
    identifier_hex: decodedOperation.body.certificate_id_hex,
    proof_hex: fundSubjectAbsence.proof_hex,
  },
  "fund operation certificate subject absence drift",
);
verifyNonMembership(
  fundSubjectAbsence,
  Buffer.from(decodedOperation.nullifier_non_membership_checks[0].proof_hex, "hex"),
);
invariant(
  successor.target.state.funded_unused_reservations[0].reserved_units ===
    decodedOperation.body.reserved_units,
  "reservation did not retain exact reserved units",
);
invariant(decodedOperation.nullifier_insertions[0].proof_hex === vector.nullifier.sequential_insertions[0].proof_hex, "operation proof substitution");
verifyInsertion(
  vector.nullifier.sequential_insertions[0],
  Buffer.from(decodedOperation.nullifier_insertions[0].proof_hex, "hex"),
);

const authenticatedContext = vector.authenticated_context;
invariant(
  authenticatedContext.source_root_hex === successor.source.jmt_root_hex,
  "authenticated context/source JMT root drift",
);
invariant(
  authenticatedContext.active_parameters_hash_hex === parameterVector.digest_hex,
  "active parameter hash differs from the frozen reference profile",
);
invariant(
  authenticatedContext.active_parameters_source ===
    "docs/protocol/poco-bft-v0/vectors/parameters-v0.json" &&
    authenticatedContext.active_parameters_cev0_hex === parameterVector.cev0_hex,
  "active parameter raw bytes differ from the frozen reference profile",
);
invariant(
  typeof authenticatedContext.governance_signer_id_utf8 === "string" &&
    authenticatedContext.governance_signer_id_utf8.length > 0 &&
    authenticatedContext.governance_signer_id_utf8 ===
      authenticatedContext.governance_signer_id_utf8.trim() &&
    Buffer.byteLength(authenticatedContext.governance_signer_id_utf8) <= 256,
  "governance signer ID is not canonical",
);
exactHex(
  authenticatedContext.authorized_signers_hash_hex_ascii,
  32,
  "authorized signer policy hash",
);
const authoritySignerCommitment = lifecycleHashDomain(
  "trnm.poco-bft.application-governance-signer.v0",
  [
    Buffer.from(authenticatedContext.governance_signer_id_utf8),
    Buffer.from(authenticatedContext.authorized_signers_hash_hex_ascii),
  ],
);
invariant(
  authoritySignerCommitment.toString("hex") ===
    authenticatedContext.authority_signer_commitment_hex &&
    !authoritySignerCommitment.equals(Buffer.alloc(32)),
  "AppHash governance signer commitment drift",
);
const normalizedOperation = structuredClone(decodedOperation);
normalizedOperation.nullifier_non_membership_checks = [];
normalizedOperation.nullifier_insertions = [];
normalizedOperation.body.funding_decision_id_hex = "0".repeat(64);
const normalizedOperationBytes = Buffer.from(JSON.stringify(normalizedOperation));
invariant(
  normalizedOperationBytes.toString("hex") ===
    authenticatedContext.normalized_decision_operation_json_hex,
  "normalized decision operation drift",
);
const decisionPreimageFor = (signerCommitment) =>
  domainHash(
    "trnm.poco-bft.application-decision-preimage.v0",
    Buffer.concat([
    uint(0, 2),
    frame(exactHex(authenticatedContext.genesis_hash_hex, 32, "context genesis hash")),
    frame(Buffer.from(authenticatedContext.chain_id_utf8)),
    uint(asUnsigned(authenticatedContext.source_version, U64_MAX, "context source version"), 8),
    exactHex(authenticatedContext.source_root_hex, 32, "context source root"),
    uint(asUnsigned(authenticatedContext.target_height, U64_MAX, "context target height"), 8),
    uint(asUnsigned(authenticatedContext.active_epoch, U64_MAX, "context active epoch"), 8),
    exactHex(authenticatedContext.active_parameters_hash_hex, 32, "context parameter hash"),
    signerCommitment,
    frame(normalizedOperationBytes),
    ]),
  );
const decisionPreimage = decisionPreimageFor(authoritySignerCommitment);
invariant(
  decisionPreimage.toString("hex") === authenticatedContext.decision_preimage_hex,
  "authenticated decision preimage drift",
);
const decisionId = domainHash(
  "trnm.poco-bft.application-decision-id.v0",
  Buffer.concat([
    uint(0, 2),
    frame(Buffer.from(authenticatedContext.decision_label_ascii)),
    decisionPreimage,
  ]),
);
invariant(
  authenticatedContext.negative_signer_contexts.length ===
    vector.expected_counts.signer_context_negative,
  "negative signer-context count drift",
);
for (const negative of authenticatedContext.negative_signer_contexts) {
  exactHex(negative.authorized_signers_hash_hex_ascii, 32, `${negative.id}.policy hash`);
  const substitutedCommitment = lifecycleHashDomain(
    "trnm.poco-bft.application-governance-signer.v0",
    [
      Buffer.from(negative.governance_signer_id_utf8),
      Buffer.from(negative.authorized_signers_hash_hex_ascii),
    ],
  );
  const substitutedPreimage = decisionPreimageFor(substitutedCommitment);
  const substitutedDecision = domainHash(
    "trnm.poco-bft.application-decision-id.v0",
    Buffer.concat([
      uint(0, 2),
      frame(Buffer.from(authenticatedContext.decision_label_ascii)),
      substitutedPreimage,
    ]),
  );
  invariant(
    !substitutedCommitment.equals(authoritySignerCommitment) &&
      !substitutedPreimage.equals(decisionPreimage) &&
      !substitutedDecision.equals(decisionId),
    `${negative.id}: signer substitution did not alter decision authority`,
  );
  invariant(
    ["authority_signer_commitment_mismatch", "authority_signer_changed_within_block"]
      .includes(negative.expected_error),
    `${negative.id}: unexpected signer rejection`,
  );
}
invariant(
  decisionId.toString("hex") === authenticatedContext.derived_decision_id_hex &&
    decodedOperation.body.funding_decision_id_hex === authenticatedContext.derived_decision_id_hex &&
    decodedOperation.nullifier_insertions[0].identifier_hex === authenticatedContext.derived_decision_id_hex,
  "derived settlement decision binding drift",
);
invariant(
  domainHash("trnm.poco-bft.application-operation.v0", operationRaw).toString("hex") ===
    successor.operation.operation_id_hex,
  "operation ID drift",
);
invariant(
  orderedRoot(
    "trnm.poco-bft.application-operation.v0",
    "trnm.poco-bft.application-operation-node.v0",
    "trnm.poco-bft.application-operation-root.v0",
    [operationRaw],
  ).toString("hex") === successor.operation.ordered_operation_root_hex,
  "ordered operation root drift",
);

const evaluate = (test) => {
  const f = test.facts;
  switch (test.rule) {
    case "target": {
      const parent = asUnsigned(f[0], U64_MAX, test.id);
      const target = asUnsigned(f[1], U64_MAX, test.id);
      const bound = asUnsigned(f[2], U64_MAX, test.id);
      if (parent === U64_MAX) return [false, "target_height_overflow"];
      if (target !== parent + 1n) return [false, "target_not_exact_successor"];
      if (bound !== target) return [false, "target_bound_field_mismatch"];
      return [true, null];
    }
    case "state": {
      const sourceRevision = asUnsigned(f[0], U64_MAX, test.id);
      const expectedRevision = asUnsigned(f[1], U64_MAX, test.id);
      const targetRevision = asUnsigned(f[2], U64_MAX, test.id);
      const sourceCount = asUnsigned(f[5], U64_MAX, test.id);
      const targetCount = asUnsigned(f[6], U64_MAX, test.id);
      if (sourceRevision !== expectedRevision) return [false, "stale_authority_revision"];
      if (sourceRevision === U64_MAX || targetRevision !== sourceRevision + 1n) return [false, "revision_not_exact_successor"];
      if (f[3] !== f[4]) return [false, "source_root_mismatch"];
      if (targetCount !== sourceCount + 1n) return [false, "target_nullifier_count_mismatch"];
      if (f[7] !== f[8]) return [false, "target_nullifier_root_mismatch"];
      return [true, null];
    }
    case "decision":
      if (f[0] !== f[1]) return [false, "decision_role_substitution"];
      if (f[2] !== f[3]) return [false, "decision_subject_substitution"];
      if (f[4] !== f[5]) return [false, "decision_payload_substitution"];
      if (f[6]) return [false, "decision_replay"];
      return [true, null];
    case "authority_signer":
      if (f[0] !== f[1]) return [false, "authority_signer_commitment_mismatch"];
      if (!f[2]) return [false, "authority_signer_changed_within_block"];
      return [true, null];
    case "consumer_key_nullifier":
      if (!["authorize", "revoke"].includes(f[0]) || f[1] !== f[2]) {
        return [false, "consumer_key_nullifier_family"];
      }
      if (!f[3]) return [false, "consumer_key_nullifier_proof"];
      if (!f[4]) return [false, "consumer_key_decision_replay"];
      if (!f[5]) return [false, "consumer_key_decision_subject"];
      if (f[0] === "authorize" && f[6] !== 10) {
        return [false, "consumer_key_identity_family"];
      }
      if (f[0] === "authorize" && !f[7]) {
        return [false, "consumer_key_identity_replay"];
      }
      return [true, null];
    case "reserved_units": {
      const canonical = (value) =>
        typeof value === "string" &&
        /^(0|[1-9][0-9]*)$/.test(value) &&
        BigInt(value) <= U128_MAX;
      if (!f[2] || !canonical(f[0]) || !canonical(f[1])) {
        return [false, "reserved_units_noncanonical_u128"];
      }
      const reserved = BigInt(f[0]);
      const consumed = BigInt(f[1]);
      if (reserved === 0n) return [false, "reserved_units_zero"];
      if (reserved !== consumed) return [false, "reserved_units_mismatch"];
      return [true, null];
    }
    case "usage_caps": {
      if (!f[7]) return [false, "cross_meter_usage_not_aggregated"];
      if (!f[8]) return [false, "usage_u128_overflow"];
      const previous = [0, 1, 2].map((index) => asUnsigned(f[index], U128_MAX, test.id));
      const delta = asUnsigned(f[3], U128_MAX, test.id);
      const caps = [4, 5, 6].map((index) => asUnsigned(f[index], U128_MAX, test.id));
      if (previous.some((value) => value + delta > U128_MAX)) {
        return [false, "usage_u128_overflow"];
      }
      if (previous[0] + delta > caps[0]) return [false, "consumer_provider_cap_exceeded"];
      if (previous[1] + delta > caps[1]) return [false, "task_provider_cap_exceeded"];
      if (previous[2] + delta > caps[2]) return [false, "provider_cap_exceeded"];
      return [true, null];
    }
    case "provider_tuple":
      if (!f[0]) return [false, "provider_registration_missing"];
      if (f[1] !== "active") return [false, "provider_registration_inactive"];
      if (f[2] !== f[3]) return [false, "provider_registration_identity"];
      if (f[4] !== f[5]) return [false, "tuple_certificate_mismatch"];
      if (BigInt(f[6]) !== BigInt(f[7])) return [false, "tuple_accepted_height_mismatch"];
      return [true, null];
    case "projection_integrity":
      if (f[5] !== 0) return [false, "projection_failure_wrote_state"];
      if (!f[0]) return [false, "projection_active_certificate_drift"];
      if (!f[1]) return [false, "projection_reservation_settlement_drift"];
      if (!f[2]) return [false, "projection_challenge_lifecycle_drift"];
      if (!f[3]) return [false, "projection_registration_history_drift"];
      if (!f[4]) return [false, "projection_governance_rollout_drift"];
      if (f[6] === false) return [false, "projection_orphan_authority"];
      if (f[7] === false) return [false, "projection_orphan_semantic"];
      return [true, null];
    case "meter": {
      if (f[0] !== f[1]) return [false, "meter_task_mismatch"];
      if (f[2] !== f[3]) return [false, "meter_output_mismatch"];
      const units = asUnsigned(f[4], U128_MAX, test.id);
      const perCap = asUnsigned(f[5], U128_MAX, test.id);
      const used = asUnsigned(f[6], U128_MAX, test.id);
      const rollingCap = asUnsigned(f[7], U128_MAX, test.id);
      if (!f[10] || used + units > U128_MAX) return [false, "meter_u128_overflow"];
      if (units > perCap) return [false, "per_certificate_cap_exceeded"];
      if (used + units > rollingCap) return [false, "rolling_cap_exceeded"];
      if (f[8] === "required" && !f[9]) return [false, "required_evidence_missing"];
      if (f[8] === "forbidden" && f[9]) return [false, "forbidden_evidence_present"];
      return [true, null];
    }
    case "settlement":
      if (f[0] === "missing") return [false, "settlement_not_funded_unused"];
      if (f[0] !== "funded_unused") return [false, "settlement_terminal"];
      if (f[1] !== f[2]) return [false, "settlement_certificate_mismatch"];
      if (f[3] !== f[4]) return [false, "settlement_commitment_mismatch"];
      if (!f[5]) return [false, "settlement_decision_missing"];
      if (f[6]) return [false, "settlement_decision_replay"];
      if (f[7]) return [false, "settlement_decision_competing_use"];
      return [true, null];
    case "challenge": {
      if (f[2] !== f[3]) return [false, "challenge_id_mismatch"];
      if (f[4]) return [false, "challenge_decision_replay"];
      if (["rejected", "sustained"].includes(f[0])) return [false, "challenge_terminal_update"];
      const allowed = (f[0] === "accepted" && f[1] === "pending") ||
        (f[0] === "pending" && ["rejected", "sustained"].includes(f[1]));
      return allowed ? [true, null] : [false, "challenge_transition_invalid"];
    }
    case "governance":
      if (!f[0]) return [false, "governance_proposal_missing"];
      if (f[1]) return [false, "governance_terminal_update"];
      if (f[2]) return [false, "governance_decision_replay"];
      if (BigInt(f[3]) !== BigInt(f[4])) return [false, "governance_height_mismatch"];
      if (f[5] !== f[6]) return [false, "governance_parameter_substitution"];
      return [true, null];
    case "registration": {
      if (f[8]) return [false, "registration_decision_replay"];
      if (!f[0]) return BigInt(f[3]) > 0n ? [true, null] : [false, "registration_nonce_not_increasing"];
      const previous = asUnsigned(f[1], U64_MAX, test.id);
      const supplied = asUnsigned(f[2], U64_MAX, test.id);
      const next = asUnsigned(f[3], U64_MAX, test.id);
      if (previous === U64_MAX) return [false, "registration_nonce_exhausted"];
      if (supplied !== previous) return [false, "registration_predecessor_mismatch"];
      if (f[4] !== f[5]) return [false, "registration_history_mismatch"];
      if (f[6] !== f[7]) return [false, "registration_key_owner_mismatch"];
      if (next <= previous) return [false, "registration_nonce_not_increasing"];
      return [true, null];
    }
    case "prune":
      if (!f[8]) return [false, "prune_private_authority_required"];
      if (!f[0]) return [false, "prune_live_record"];
      if (f[1]) return [false, "prune_pending_challenge"];
      if (f[2]) return [false, "prune_funded_unused"];
      if (BigInt(f[3]) <= BigInt(f[4])) return [false, "prune_not_mature"];
      if (f[5] !== f[6]) return [false, "prune_nullifier_omission"];
      if (!f[7]) return [false, "prune_partial_record_group"];
      return [true, null];
    case "consumer_key_prune":
      if (!f[9]) return [false, "consumer_key_prune_private_authority"];
      if (!f[0]) return [false, "consumer_key_prune_active"];
      if (BigInt(f[1]) <= BigInt(f[2])) return [false, "consumer_key_prune_retention"];
      if (f[3]) return [false, "consumer_key_prune_active_reference"];
      if (f[4] > 32) return [false, "consumer_key_prune_watermark_bound"];
      if (f[4] !== f[5]) return [false, "consumer_key_prune_delete_set"];
      if (f[6] !== f[7] || f[7] !== 11) return [false, "consumer_key_prune_summary_family"];
      if (!f[8]) return [false, "consumer_key_prune_summary_replay"];
      return [true, null];
    case "meter_prune":
      if (!f[8]) return [false, "meter_prune_private_authority"];
      if (!f[0]) return [false, "meter_prune_active"];
      if (BigInt(f[1]) <= [BigInt(f[2]), BigInt(f[3])].reduce((a, b) => a > b ? a : b)) {
        return [false, "meter_prune_retention"];
      }
      if (f[4]) return [false, "meter_prune_active_reference"];
      if (f[5]) return [false, "meter_prune_retained_usage"];
      if (!f[6]) return [false, "meter_prune_delete_set"];
      if (f[7] !== 0) return [false, "meter_prune_nullifier_insertion"];
      return [true, null];
    case "validator_prune":
      if (!f[6]) return [false, "validator_prune_private_authority"];
      if (!f[0]) return [false, "validator_prune_active"];
      if (BigInt(f[1]) <= BigInt(f[2])) return [false, "validator_prune_retention"];
      if (f[3]) return [false, "validator_prune_active_reference"];
      if (!f[4]) return [false, "validator_prune_delete_set"];
      if (f[5] !== 0) return [false, "validator_prune_nullifier_insertion"];
      return [true, null];
    case "fund_subject":
      if (f[0] !== 1) return [false, "fund_subject_absence_count"];
      if (f[1] !== 1) return [false, "fund_subject_absence_family"];
      if (!f[2]) return [false, "fund_subject_absence_proof"];
      if (!f[3]) return [false, "fund_subject_replay"];
      if (!f[4]) return [false, "fund_decision_replay"];
      if (!f[5]) return [false, "fund_reservation_exists"];
      if (!f[6]) return [false, "fund_active_certificate_exists"];
      return [true, null];
    case "release_tombstone":
      if (!f[0]) return [false, "release_reservation_substitution"];
      if (!f[1]) return [false, "release_delete_set"];
      if (f[2] !== "1,3") return [false, "release_nullifier_family_set"];
      if (!f[3]) return [false, "release_certificate_proof"];
      if (!f[4]) return [false, "release_decision_proof"];
      if (!f[5]) return [false, "release_certificate_replay"];
      if (!f[6]) return [false, "release_decision_replay"];
      return [true, null];
    case "lifecycle_provenance":
      if (!["accepted", "challenge_rejected", "challenge_sustained"].includes(f[0])) {
        return [false, "lifecycle_state_invalid"];
      }
      if (BigInt(f[1]) !== BigInt(f[2])) return [false, "lifecycle_effective_height_substitution"];
      if (f[3] !== f[4]) return [false, "lifecycle_decision_substitution"];
      if (!f[5]) return [false, "lifecycle_semantic_drift"];
      if (!f[6]) return [false, "lifecycle_authority_orphan"];
      return [true, null];
    case "governance_finalized_provenance": {
      if (f[0] !== f[1]) return [false, "governance_finalized_phase_substitution"];
      if (f[2] !== f[3]) return [false, "governance_proposal_decision_substitution"];
      const proposed = BigInt(f[4]);
      const approved = BigInt(f[5]);
      const activation = BigInt(f[6]);
      if (proposed === 0n || !(proposed < approved && approved < activation)) {
        return [false, "governance_provenance_height_order"];
      }
      if (!f[7]) return [false, "governance_finalized_projection_drift"];
      if (!f[8]) return [false, "governance_finalized_orphan"];
      return [true, null];
    }
    case "validator_history_provenance":
      if (f[0] !== f[1]) return [false, "validator_current_proof_substitution"];
      if (f[2] !== f[3]) return [false, "validator_registration_decision_substitution"];
      if (BigInt(f[4]) === 0n || BigInt(f[4]) > BigInt(f[5])) {
        return [false, "validator_registration_height_invalid"];
      }
      if (!f[6]) return [false, "validator_retired_key_count_drift"];
      if (!f[7]) return [false, "validator_history_projection_drift"];
      if (!f[8]) return [false, "validator_history_orphan"];
      return [true, null];
    case "usage_bucket_bound": {
      if (!f[4]) return [false, "usage_bucket_count_overflow"];
      const total = f.slice(0, 4).reduce((sum, count) => sum + count, 0);
      return total <= 32
        ? [true, null]
        : [false, "usage_bucket_total_exceeded"];
    }
    case "batch":
      if (f[1] !== f[0]) return [false, "atomic_mutation_omission"];
      if (f[2] !== 0) return [false, "atomic_extra_write"];
      if (!f[3]) return [false, "atomic_duplicate_mutation"];
      if (!f[4]) return [false, "atomic_noncanonical_order"];
      if (f[5] !== 1) return [false, "atomic_manifest_count"];
      if (!f[6]) return [false, "atomic_operation_failure"];
      if (!f[7]) return [false, "atomic_source_cas_mismatch"];
      return [true, null];
    case "bounds": {
      const limits = [32, 1048576, 32, 16, 16, 65384, 10000, 8388608];
      const failed = f.findIndex((value, index) => value > limits[index]);
      if (failed === -1) return [true, null];
      return failed === 3
        ? [false, "bounds_before_semantic_planning"]
        : [false, "bounds_before_clone_sort_proof_decode_hash"];
    }
    case "canonical_state": {
      const revision = asUnsigned(f[0], U64_MAX, test.id);
      const lastTargetHeight = asUnsigned(f[1], U64_MAX, test.id);
      const accepted = (revision === 1n) === (lastTargetHeight === 0n);
      return accepted
        ? [true, null]
        : [false, "genesis_revision_height_mismatch"];
    }
    default:
      throw new Error(`${test.id}: unknown truth rule ${test.rule}`);
  }
};

const flatCases = [];
for (const [category, cases] of Object.entries(vector.truth_cases)) {
  invariant(cases.length === vector.expected_counts.categories[category], `${category}: count drift`);
  unique(cases.map((test) => test.id), `${category}: duplicate case id`);
  for (const test of cases) {
    const [accepted, errorCode] = evaluate(test);
    invariant(accepted === test.expected, `${category}/${test.id}: expectation drift`);
    invariant(errorCode === test.error_code, `${category}/${test.id}: error-code drift ${errorCode}`);
    flatCases.push(test);
  }
}
invariant(flatCases.length === vector.expected_counts.total, "truth total drift");
invariant(flatCases.filter((test) => test.expected).length === vector.expected_counts.accepted, "accepted count drift");
invariant(flatCases.filter((test) => !test.expected).length === vector.expected_counts.rejected, "rejected count drift");
invariant(vector.nullifier.sequential_insertions.length === vector.expected_counts.proof_positive, "proof-positive count drift");
invariant(vector.nullifier.negative_mutations.length === vector.expected_counts.proof_negative, "proof-negative count drift");
invariant(vector.nullifier.derived_family_keys.length === vector.expected_counts.family_keys, "family-key count drift");

// Allocation/crypto ordering is observable: rejected over-bound cases must
// return before this synthetic clone/sort/proof-decode/hash continuation.
const admitBeforeHeavyWork = (test) => {
  const beforeHashes = hashCalls;
  let heavyCalls = 0;
  const [accepted, errorCode] = evaluate(test);
  if (accepted) {
    heavyCalls += 1;
    domainHash("trnm.poco-bft.bound-order-witness.v0", Buffer.from(test.id));
  }
  if (!accepted) {
    invariant(heavyCalls === 0, `${test.id}: heavy work preceded bounds`);
    invariant(hashCalls === beforeHashes, `${test.id}: hashing preceded bounds`);
  }
  return [accepted, errorCode];
};
for (const test of vector.truth_cases.bounds) admitBeforeHeavyWork(test);

sameJson(vector.authority_boundary, {
  private_prune_only: true,
  generic_delete: "reject",
  writes_on_any_failure: 0,
  source_head_unchanged_on_any_failure: true,
  candidate_outputs: 0,
  handoff_outputs: 0,
  activation_outputs: 0,
  core_transition_outputs: 0,
  old_unauthenticated_b2g_token_rebinding: "forbidden",
}, "authority boundary drift");

console.log(
  `PoCO-BFT v0 application-authority gate passed: ${vector.expected_counts.proof_positive} raw sparse proofs, ` +
    `${vector.expected_counts.proof_negative} proof negatives, ${vector.expected_counts.family_keys} family keys, ` +
    `${vector.expected_counts.total} authority/atomicity cases (${vector.expected_counts.accepted} accept, ` +
    `${vector.expected_counts.rejected} reject), ${authorityCapacityNegatives} authority capacity negatives, ` +
    `${authorityNestedUnknownNegatives} nested unknown-field negatives, ` +
    `${authorityJsonTypeNegatives} JSON numeric-type negatives, ` +
    `${futureStep.raw_operation_json_hexes.length} zero-change future operations and ` +
    `${futureOperationBindingNegatives} future binding negatives, one exact state successor, ` +
    `two ordered mutations, one manifest, and ${losslessJsonSelfTests.accepted} full-u64 / ` +
    `${losslessJsonSelfTests.rejected} malformed-JSON self-tests`,
);
