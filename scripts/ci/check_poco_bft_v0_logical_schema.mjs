#!/usr/bin/env node

// Independent B2-A certificate-kernel CEV0 decoder and schema/projection gate.
// Standard-library only. Deliberately does not import or execute the B1 Python
// encoder, Rust crates, protobuf generators, or generated transport code.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "../..");
const SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-v0.json",
);
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/cev0-parser-certificate-kernel-v0.json",
);
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const ED25519_FIELD = (1n << 255n) - 19n;
const ED25519_GROUP_ORDER =
  (1n << 252n) + 27742317777372353535851937790883648493n;

class GateError extends Error {
  constructor(code, offset, message) {
    super(`${code} at byte ${offset}: ${message}`);
    this.name = "GateError";
    this.code = code;
    this.offset = offset;
  }
}

function fail(code, offset, message) {
  throw new GateError(code, offset, message);
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, "utf8"));
}

function decimal(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    fail("schema_manifest_invalid", 0, `${label} must be canonical decimal text`);
  }
  return BigInt(value);
}

function safeNumber(value, label) {
  const parsed = decimal(value, label);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("schema_manifest_invalid", 0, `${label} exceeds Number safe range`);
  }
  return Number(parsed);
}

function bytesEqual(first, second) {
  return Buffer.isBuffer(first) && Buffer.isBuffer(second) && first.equals(second);
}

function compareBytes(first, second) {
  return Buffer.compare(first, second);
}

function canonicalHex(value, label) {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]*$/.test(value)
  ) {
    fail("schema_manifest_invalid", 0, `${label} is not lowercase hexadecimal`);
  }
  const decoded = Buffer.from(value, "hex");
  if (decoded.toString("hex") !== value) {
    fail("schema_manifest_invalid", 0, `${label} is not canonical hexadecimal`);
  }
  return decoded;
}

function cloneValue(value) {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }
  if (Array.isArray(value)) {
    return value.map(cloneValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneValue(item)]),
    );
  }
  return value;
}

function frame(value) {
  if (value.length > 0xffffffff) {
    fail("length_limit_exceeded", 0, "digest frame exceeds u32");
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(value.length);
  return Buffer.concat([prefix, value]);
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

function fieldMod(value) {
  const reduced = value % ED25519_FIELD;
  return reduced >= 0n ? reduced : reduced + ED25519_FIELD;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let factor = ((base % modulus) + modulus) % modulus;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = (result * factor) % modulus;
    }
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

const ED25519_D = fieldMod(
  -121665n * modPow(121666n, ED25519_FIELD - 2n, ED25519_FIELD),
);
const ED25519_SQRT_MINUS_ONE = modPow(
  2n,
  (ED25519_FIELD - 1n) / 4n,
  ED25519_FIELD,
);
const ED25519_IDENTITY = [0n, 1n, 1n, 0n];

function pointAdd(first, second) {
  const [x1, y1, z1, t1] = first;
  const [x2, y2, z2, t2] = second;
  const a = fieldMod((y1 - x1) * (y2 - x2));
  const b = fieldMod((y1 + x1) * (y2 + x2));
  const c = fieldMod(2n * ED25519_D * t1 * t2);
  const d = fieldMod(2n * z1 * z2);
  const e = fieldMod(b - a);
  const f = fieldMod(d - c);
  const g = fieldMod(d + c);
  const h = fieldMod(b + a);
  return [
    fieldMod(e * f),
    fieldMod(g * h),
    fieldMod(f * g),
    fieldMod(e * h),
  ];
}

function pointDouble(point) {
  const [x, y, z] = point;
  const a = fieldMod(x * x);
  const b = fieldMod(y * y);
  const c = fieldMod(2n * z * z);
  const d = fieldMod(-a);
  const e = fieldMod((x + y) * (x + y) - a - b);
  const g = fieldMod(d + b);
  const f = fieldMod(g - c);
  const h = fieldMod(d - b);
  return [
    fieldMod(e * f),
    fieldMod(g * h),
    fieldMod(f * g),
    fieldMod(e * h),
  ];
}

function scalarMultiply(point, scalar) {
  let result = ED25519_IDENTITY;
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) {
      result = pointAdd(result, addend);
    }
    addend = pointDouble(addend);
    remaining >>= 1n;
  }
  return result;
}

function pointsEqual(first, second) {
  return (
    fieldMod(first[0] * second[2] - second[0] * first[2]) === 0n &&
    fieldMod(first[1] * second[2] - second[1] * first[2]) === 0n
  );
}

function recoverX(y, sign) {
  const numerator = fieldMod(y * y - 1n);
  const denominator = fieldMod(ED25519_D * y * y + 1n);
  const xSquared = fieldMod(
    numerator * modPow(denominator, ED25519_FIELD - 2n, ED25519_FIELD),
  );
  let x = modPow(
    xSquared,
    (ED25519_FIELD + 3n) / 8n,
    ED25519_FIELD,
  );
  if (fieldMod(x * x - xSquared) !== 0n) {
    x = fieldMod(x * ED25519_SQRT_MINUS_ONE);
  }
  if (fieldMod(x * x - xSquared) !== 0n || (x === 0n && sign === 1n)) {
    return null;
  }
  if ((x & 1n) !== sign) {
    x = ED25519_FIELD - x;
  }
  return x;
}

function littleEndianInteger(bytes) {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(bytes[index]);
  }
  return result;
}

function littleEndianBytes(value, length) {
  const result = Buffer.alloc(length);
  let remaining = value;
  for (let index = 0; index < length; index += 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function decodeEd25519Point(encoded) {
  if (encoded.length !== 32) {
    return null;
  }
  const value = littleEndianInteger(encoded);
  const sign = value >> 255n;
  const y = value & ((1n << 255n) - 1n);
  if (y >= ED25519_FIELD) {
    return null;
  }
  const x = recoverX(y, sign);
  if (x === null) {
    return null;
  }
  const point = [x, y, 1n, fieldMod(x * y)];
  if (pointsEqual(scalarMultiply(point, 8n), ED25519_IDENTITY)) {
    return null;
  }
  return point;
}

const ED25519_BASE_Y = fieldMod(
  4n * modPow(5n, ED25519_FIELD - 2n, ED25519_FIELD),
);
const ED25519_BASE_X = recoverX(ED25519_BASE_Y, 0n);
if (ED25519_BASE_X === null) {
  throw new Error("failed to construct RFC8032 base point");
}
const ED25519_BASE_POINT = [
  ED25519_BASE_X,
  ED25519_BASE_Y,
  1n,
  fieldMod(ED25519_BASE_X * ED25519_BASE_Y),
];

function manifestIndex(manifest) {
  return {
    aliases: new Map(manifest.aliases.map((item) => [item.name, item])),
    enums: new Map(manifest.enums.map((item) => [item.name, item])),
    objects: new Map(manifest.objects.map((item) => [item.name, item])),
    domains: new Map(manifest.domains.map((item) => [item.id, item])),
  };
}

const INTEGER_WIDTHS = new Map([
  ["u8", 1],
  ["u16", 2],
  ["u32", 4],
  ["u64", 8],
  ["u128", 16],
]);

class Decoder {
  constructor(buffer, index) {
    this.buffer = buffer;
    this.index = index;
    this.offset = 0;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0) {
      fail("length_limit_exceeded", this.offset, "invalid byte length");
    }
    if (length > this.buffer.length - this.offset) {
      fail("unexpected_eof", this.offset, `need ${length} bytes`);
    }
    const start = this.offset;
    this.offset += length;
    return this.buffer.subarray(start, this.offset);
  }

  unsigned(width) {
    const raw = this.take(width);
    if (width === 1) {
      return raw[0];
    }
    if (width === 2) {
      return raw.readUInt16BE(0);
    }
    if (width === 4) {
      return raw.readUInt32BE(0);
    }
    let value = 0n;
    for (const byte of raw) {
      value = (value << 8n) | BigInt(byte);
    }
    return value;
  }

  decode(type, constraints = {}) {
    if (typeof type === "object" && type?.kind === "list") {
      const countOffset = this.offset;
      const count = this.unsigned(4);
      const max = safeNumber(type.max_count, "list max_count");
      if (count > max) {
        fail(
          "count_limit_exceeded",
          countOffset,
          `list count ${count} exceeds hard maximum ${max}`,
        );
      }
      // Count is checked before allocating the result array.
      const result = new Array(count);
      for (let index = 0; index < count; index += 1) {
        result[index] = this.decode(type.item);
      }
      return result;
    }

    if (INTEGER_WIDTHS.has(type)) {
      return this.unsigned(INTEGER_WIDTHS.get(type));
    }
    if (type === "Bytes") {
      const lengthOffset = this.offset;
      const length = this.unsigned(4);
      const minimum = constraints.min_bytes
        ? safeNumber(constraints.min_bytes, "Bytes min_bytes")
        : 0;
      const maximum = constraints.max_bytes
        ? safeNumber(constraints.max_bytes, "Bytes max_bytes")
        : 0xffffffff;
      if (length < minimum || length > maximum) {
        fail(
          "length_limit_exceeded",
          lengthOffset,
          `Bytes length ${length} is outside ${minimum}..${maximum}`,
        );
      }
      // Length is checked before exposing/slicing the value.
      return this.take(length);
    }
    if (type === "ConsensusString") {
      const lengthOffset = this.offset;
      const length = this.unsigned(2);
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

    const alias = this.index.aliases.get(type);
    if (alias) {
      return this.take(alias.bytes);
    }
    const enumeration = this.index.enums.get(type);
    if (enumeration) {
      const valueOffset = this.offset;
      const value = this.unsigned(INTEGER_WIDTHS.get(enumeration.encoding));
      if (!enumeration.variants.some((variant) => variant.value === value)) {
        fail(
          "invalid_message_kind",
          valueOffset,
          `${type} has unknown discriminant ${value}`,
        );
      }
      return value;
    }
    const object = this.index.objects.get(type);
    if (object) {
      const result = {};
      for (const field of object.fields) {
        const value = this.decode(field.type, field);
        if (field.aggregate_item_field) {
          const maximum = safeNumber(
            field.aggregate_max_count,
            `${object.name}.${field.name} aggregate_max_count`,
          );
          let aggregate = 0;
          for (const item of value) {
            const nested = item[field.aggregate_item_field];
            if (!Array.isArray(nested)) {
              fail(
                "schema_manifest_invalid",
                this.offset,
                `${field.aggregate_item_field} is not a list`,
              );
            }
            aggregate += nested.length;
            if (aggregate > maximum) {
              fail(
                "aggregate_limit_exceeded",
                this.offset,
                `aggregate nested count exceeds ${maximum}`,
              );
            }
          }
        }
        result[field.name] = value;
      }
      return result;
    }
    fail("schema_manifest_invalid", this.offset, `unknown logical type ${type}`);
  }
}

function encodeUnsigned(value, width) {
  const bigint = typeof value === "bigint" ? value : BigInt(value);
  const maximum = 1n << BigInt(width * 8);
  if (bigint < 0n || bigint >= maximum) {
    fail("schema_manifest_invalid", 0, `integer does not fit ${width} bytes`);
  }
  const result = Buffer.alloc(width);
  let remaining = bigint;
  for (let index = width - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function encodeValue(type, value, index) {
  if (typeof type === "object" && type?.kind === "list") {
    return Buffer.concat([
      encodeUnsigned(value.length, 4),
      ...value.map((item) => encodeValue(type.item, item, index)),
    ]);
  }
  if (INTEGER_WIDTHS.has(type)) {
    return encodeUnsigned(value, INTEGER_WIDTHS.get(type));
  }
  if (type === "Bytes") {
    return Buffer.concat([encodeUnsigned(value.length, 4), value]);
  }
  if (type === "ConsensusString") {
    return Buffer.concat([encodeUnsigned(value.length, 2), value]);
  }
  const alias = index.aliases.get(type);
  if (alias) {
    if (!Buffer.isBuffer(value) || value.length !== alias.bytes) {
      fail("schema_manifest_invalid", 0, `${type} has the wrong byte length`);
    }
    return value;
  }
  const enumeration = index.enums.get(type);
  if (enumeration) {
    return encodeUnsigned(value, INTEGER_WIDTHS.get(enumeration.encoding));
  }
  const object = index.objects.get(type);
  if (object) {
    return Buffer.concat(
      object.fields.map((field) => encodeValue(field.type, value[field.name], index)),
    );
  }
  fail("schema_manifest_invalid", 0, `cannot encode unknown logical type ${type}`);
}

function decodeExact(type, buffer, index) {
  const decoder = new Decoder(buffer, index);
  const value = decoder.decode(type);
  if (decoder.offset !== buffer.length) {
    fail(
      "trailing_bytes",
      decoder.offset,
      `${buffer.length - decoder.offset} unconsumed bytes`,
    );
  }
  return value;
}

function typeReferences(type) {
  if (typeof type === "object" && type?.kind === "list") {
    return [type.item];
  }
  return [type];
}

function validateManifest(manifest) {
  if (
    manifest.schema !== "trnm_poco_bft_cev0_logical_schema_v0" ||
    manifest.schema_version !== 0 ||
    manifest.scope !== "B2-A certificate kernel only"
  ) {
    fail("schema_manifest_invalid", 0, "unexpected manifest identity or scope");
  }
  const expectedHashConstruction = {
    algorithm: "sha256",
    hash_prefix_ascii: "trnm.cev0.hash.v0",
    preimage_fields: [
      "Frame(hash_prefix)",
      "Frame(domain_ascii)",
      "Frame(CEV0(logical_value))",
    ],
    frame_length: "u32_be",
  };
  if (
    JSON.stringify(manifest.hash_construction) !==
    JSON.stringify(expectedHashConstruction)
  ) {
    fail("schema_manifest_invalid", 0, "hash construction drifted");
  }
  const expectedPrimitives = [
    { name: "u8", encoding: "unsigned_big_endian", bytes: 1 },
    { name: "u16", encoding: "unsigned_big_endian", bytes: 2 },
    { name: "u32", encoding: "unsigned_big_endian", bytes: 4 },
    { name: "u64", encoding: "unsigned_big_endian", bytes: 8 },
    { name: "u128", encoding: "unsigned_big_endian", bytes: 16 },
    { name: "bool", encoding: "u8_discriminant", values: [0, 1] },
    { name: "FixedBytes<N>", encoding: "exactly_N_raw_bytes" },
    { name: "Bytes", encoding: "u32_be_length_then_raw_bytes" },
    {
      name: "ConsensusString",
      encoding: "u16_be_length_then_restricted_ascii",
      grammar: "[a-z0-9][a-z0-9._:-]{0,127}",
      hard_max_bytes: "128",
    },
    { name: "List<T>", encoding: "u32_be_count_then_concatenated_items" },
    {
      name: "Optional<T>",
      encoding: "u8_presence_then_value_when_present",
      presence_values: [0, 1],
    },
  ];
  if (
    !Array.isArray(manifest.primitives) ||
    JSON.stringify(manifest.primitives) !== JSON.stringify(expectedPrimitives)
  ) {
    fail("schema_manifest_invalid", 0, "CEV0 primitive table drifted");
  }
  const expectedAliases = [
    ["Hash32", "fixed_bytes", 32],
    ["PublicKey32", "fixed_bytes", 32],
    ["Signature64", "fixed_bytes", 64],
  ];
  if (
    manifest.aliases.length !== expectedAliases.length ||
    manifest.aliases.some(
      (item, position) =>
        item.name !== expectedAliases[position][0] ||
        item.type !== expectedAliases[position][1] ||
        item.bytes !== expectedAliases[position][2],
    )
  ) {
    fail("schema_manifest_invalid", 0, "fixed-byte alias table drifted");
  }

  const expectedLimits = {
    max_chain_id_bytes: "128",
    max_validator_id_bytes: "128",
    max_validator_count: "100",
    max_qc_signature_count: "100",
    max_tc_entry_count: "100",
    max_tc_reference_count: "100",
    max_tc_aggregate_qc_signature_count: "10000",
  };
  for (const [name, expected] of Object.entries(expectedLimits)) {
    if (manifest.hard_limits[name] !== expected) {
      fail("schema_manifest_invalid", 0, `${name} is not frozen to ${expected}`);
    }
    decimal(manifest.hard_limits[name], `hard_limits.${name}`);
  }
  if (
    BigInt(manifest.hard_limits.max_tc_reference_count) *
      BigInt(manifest.hard_limits.max_qc_signature_count) !==
    BigInt(manifest.hard_limits.max_tc_aggregate_qc_signature_count)
  ) {
    fail("schema_manifest_invalid", 0, "TC aggregate hard limit is inconsistent");
  }

  const index = manifestIndex(manifest);
  const requiredObjects = [
    "CommonConsensusContextV0",
    "ValidatorV0",
    "ValidatorSetV0",
    "SignatureShareV0",
    "VoteSignV0",
    "QuorumCertificateV0",
    "HighQCSummaryV0",
    "TimeoutSignV0",
    "TimeoutEntryV0",
    "TimeoutCertificateV0",
  ];
  if (
    manifest.objects.length !== requiredObjects.length ||
    requiredObjects.some((name) => !index.objects.has(name))
  ) {
    fail("schema_manifest_invalid", 0, "certificate-kernel object scope drifted");
  }
  if (!index.enums.has("MessageKindV0")) {
    fail("schema_manifest_invalid", 0, "MessageKindV0 is missing");
  }
  const messageKinds = index.enums.get("MessageKindV0");
  const expectedKinds = [
    ["proposal", 0],
    ["vote", 1],
    ["timeout", 2],
    ["old_set_handoff_vote", 3],
    ["new_set_handoff_vote", 4],
  ];
  if (
    messageKinds.encoding !== "u8" ||
    messageKinds.variants.length !== expectedKinds.length ||
    messageKinds.variants.some(
      (item, position) =>
        item.name !== expectedKinds[position][0] ||
        item.value !== expectedKinds[position][1],
    )
  ) {
    fail("schema_manifest_invalid", 0, "MessageKindV0 table drifted");
  }

  const knownTypes = new Set([
    ...INTEGER_WIDTHS.keys(),
    "Bytes",
    "ConsensusString",
    ...index.aliases.keys(),
    ...index.enums.keys(),
    ...index.objects.keys(),
  ]);
  const graph = new Map();
  for (const object of manifest.objects) {
    if (object.coverage !== "closed" || !Array.isArray(object.fields)) {
      fail("schema_manifest_invalid", 0, `${object.name} is not a closed field array`);
    }
    const names = new Set();
    const edges = [];
    for (const field of object.fields) {
      if (names.has(field.name)) {
        fail("schema_manifest_invalid", 0, `${object.name}.${field.name} is duplicated`);
      }
      names.add(field.name);
      for (const reference of typeReferences(field.type)) {
        if (!knownTypes.has(reference)) {
          fail(
            "schema_manifest_invalid",
            0,
            `${object.name}.${field.name} references unknown ${reference}`,
          );
        }
        if (index.objects.has(reference)) {
          edges.push(reference);
        }
      }
      if (typeof field.type === "object" && field.type.kind === "list") {
        decimal(field.type.max_count, `${object.name}.${field.name}.max_count`);
      }
      if (
        ["schema_version", "protocol_version"].includes(field.name) &&
        field.equals !== "0"
      ) {
        fail(
          "schema_manifest_invalid",
          0,
          `${object.name}.${field.name} must freeze equality to zero`,
        );
      }
      if (
        field.name === "validator_id" &&
        (field.min_bytes !== "1" || field.max_bytes !== "128")
      ) {
        fail("schema_manifest_invalid", 0, `${object.name}.validator_id bounds drifted`);
      }
    }
    graph.set(object.name, edges);
  }
  if (
    index.objects.get("VoteSignV0").fields[0].required_message_kind !== "vote" ||
    index.objects.get("TimeoutSignV0").fields[0].required_message_kind !== "timeout"
  ) {
    fail("schema_manifest_invalid", 0, "signing-value message-kind binding drifted");
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(name) {
    if (visiting.has(name)) {
      fail("schema_manifest_invalid", 0, `logical object cycle through ${name}`);
    }
    if (visited.has(name)) {
      return;
    }
    visiting.add(name);
    for (const child of graph.get(name)) {
      visit(child);
    }
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of graph.keys()) {
    visit(name);
  }

  const requiredDomains = new Map([
    ["validator_set", "trnm.poco-bft.validator-set.v0"],
    ["vote", "trnm.poco-bft.vote.v0"],
    ["qc", "trnm.poco-bft.qc.v0"],
    ["timeout", "trnm.poco-bft.timeout.v0"],
    ["tc", "trnm.poco-bft.tc.v0"],
  ]);
  if (manifest.domains.length !== requiredDomains.size) {
    fail("schema_manifest_invalid", 0, "certificate-kernel domain scope drifted");
  }
  for (const [id, ascii] of requiredDomains) {
    const domain = index.domains.get(id);
    if (!domain || domain.ascii !== ascii || !index.objects.has(domain.logical_object)) {
      fail("schema_manifest_invalid", 0, `domain ${id} is invalid`);
    }
  }

  const roles = new Set(["canonical", "redundant", "derived", "sidecar"]);
  const projectedObjects = new Set();
  const projectionIds = new Set();
  for (const projection of manifest.transport_projections) {
    if (!index.objects.has(projection.logical_object)) {
      fail(
        "schema_manifest_invalid",
        0,
        `${projection.proto_message} names unknown logical object`,
      );
    }
    projectedObjects.add(projection.logical_object);
    if (projection.projection_id) {
      if (projectionIds.has(projection.projection_id)) {
        fail("schema_manifest_invalid", 0, "duplicate transport projection id");
      }
      projectionIds.add(projection.projection_id);
    }
    if (!Array.isArray(projection.fields)) {
      fail("schema_manifest_invalid", 0, "transport fields must be an array");
    }
    const logical = index.objects.get(projection.logical_object);
    const logicalFields = new Set(logical.fields.map((field) => field.name));
    const fieldNumbers = new Set();
    const fieldNames = new Set();
    for (const field of projection.fields) {
      if (
        fieldNumbers.has(field.number) ||
        fieldNames.has(field.name) ||
        !roles.has(field.role) ||
        !["singular", "repeated"].includes(field.cardinality)
      ) {
        fail(
          "schema_manifest_invalid",
          0,
          `${projection.proto_message}.${field.name} mapping is invalid`,
        );
      }
      fieldNumbers.add(field.number);
      fieldNames.add(field.name);
      if (field.role === "canonical") {
        if (!field.logical_field || !logicalFields.has(field.logical_field)) {
          fail(
            "schema_manifest_invalid",
            0,
            `${projection.proto_message}.${field.name} lacks a valid logical field`,
          );
        }
      } else if (field.role === "redundant" && !field.binding) {
        fail("schema_manifest_invalid", 0, `${field.name} lacks redundant binding`);
      } else if (field.role === "derived" && !field.derivation) {
        fail("schema_manifest_invalid", 0, `${field.name} lacks derivation`);
      } else if (field.role === "sidecar" && !field.binding) {
        fail("schema_manifest_invalid", 0, `${field.name} lacks sidecar binding`);
      }
    }
    const canonicalFields = projection.fields
      .filter((field) => field.role === "canonical")
      .map((field) => field.logical_field);
    if (
      new Set(canonicalFields).size !== canonicalFields.length ||
      canonicalFields.length !== logical.fields.length ||
      logical.fields.some((field) => !canonicalFields.includes(field.name))
    ) {
      fail(
        "schema_manifest_invalid",
        0,
        `${projection.proto_message}/${projection.logical_object} canonical mapping is not a logical-field bijection`,
      );
    }
  }
  for (const object of requiredObjects) {
    if (!projectedObjects.has(object)) {
      fail(
        "schema_manifest_invalid",
        0,
        `${object} has neither a transport projection nor internal-only declaration`,
      );
    }
  }
  for (const projection of manifest.transport_projections) {
    const logical = index.objects.get(projection.logical_object);
    for (const field of projection.fields.filter((item) => item.item_projection_id)) {
      const target = manifest.transport_projections.find(
        (item) => item.projection_id === field.item_projection_id,
      );
      const logicalField = logical.fields.find((item) => item.name === field.logical_field);
      if (
        !target ||
        target.proto_message !== field.proto_type ||
        typeof logicalField?.type !== "object" ||
        logicalField.type.kind !== "list" ||
        logicalField.type.item !== target.logical_object
      ) {
        fail(
          "schema_manifest_invalid",
          0,
          `${projection.proto_message}.${field.name} has an invalid item projection`,
        );
      }
    }
  }
  const expectedImplementationMappings = [
    {
      implementation: "Rust trnm_consensus_types::QcRef",
      logical_object: "HighQCSummaryV0",
      fields: [
        {
          implementation_field: "qc_id",
          role: "canonical",
          logical_field: "qc_digest",
        },
        {
          implementation_field: "epoch",
          role: "canonical",
          logical_field: "qc_epoch",
        },
        {
          implementation_field: "view",
          role: "canonical",
          logical_field: "qc_view",
        },
        {
          implementation_field: "height",
          role: "canonical",
          logical_field: "qc_height",
        },
        {
          implementation_field: "block_id",
          role: "canonical",
          logical_field: "qc_block_id",
        },
        {
          implementation_field: "validator_set_id",
          role: "derived",
          derivation:
            "enclosing consensus context validator_set_hash; not encoded in HighQCSummaryV0",
        },
      ],
    },
  ];
  if (
    JSON.stringify(manifest.implementation_mappings) !==
    JSON.stringify(expectedImplementationMappings)
  ) {
    fail("schema_manifest_invalid", 0, "Rust QcRef implementation mapping drifted");
  }

  const errorCodes = [
    ...manifest.decoder_error_codes,
    ...manifest.admission_error_codes,
  ].map((item) => item.code);
  if (new Set(errorCodes).size !== errorCodes.length) {
    fail("schema_manifest_invalid", 0, "stable error code is duplicated");
  }
  return index;
}

function validateRustErrorVocabulary(manifest) {
  const filename = path.join(
    REPO_ROOT,
    "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs",
  );
  const source = fs.readFileSync(filename, "utf8");
  const marker = source.indexOf("pub const fn as_str");
  if (marker < 0) {
    fail("schema_manifest_invalid", 0, "Rust DecodeErrorCode::as_str is missing");
  }
  const opening = source.indexOf("{", marker);
  let depth = 1;
  let closing = -1;
  for (let index = opening + 1; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) {
      closing = index;
      break;
    }
  }
  if (closing < 0) {
    fail("schema_manifest_invalid", 0, "Rust DecodeErrorCode::as_str is malformed");
  }
  const rustCodes = [
    ...source.slice(opening, closing).matchAll(/Self::[A-Za-z0-9_]+\s*=>\s*"([a-z0-9_]+)"/g),
  ].map((match) => match[1]);
  const manifestCodes = manifest.decoder_error_codes.map((item) => item.code);
  const expectedExclusions = [
    "invalid_block_kind",
    "invalid_optional_tag",
    "invalid_block_header",
    "invalid_handoff_descriptor",
    "invalid_handoff_certificate",
    "invalid_epoch_anchor_relations",
    "invalid_boolean",
    "invalid_rollout_phase",
    "invalid_fallback_reason",
    "invalid_next_epoch_commitment",
    "invalid_utf8",
    "noncanonical_event_attribute_order",
    "invalid_double_vote_evidence",
    "invalid_leader_schedule",
    "invalid_consensus_parameters",
    "invalid_finality_proof",
    "invalid_checkpoint_two_seal",
    "invalid_sign_intent_tag",
    "invalid_sign_intent",
    "invalid_handoff_sign_intent_role",
    "invalid_handoff_sign_intent",
  ];
  const exclusions = manifest.rust_decoder_error_exclusions ?? [];
  const exclusionCodes = exclusions.map((item) => item.code);
  if (
    new Set(rustCodes).size !== rustCodes.length ||
    new Set(manifestCodes).size !== manifestCodes.length ||
    new Set(exclusionCodes).size !== exclusionCodes.length ||
    JSON.stringify(exclusionCodes) !== JSON.stringify(expectedExclusions) ||
    exclusions.some((item, index) => {
      const expectedScope = index < 6
        ? "B2-B block/handoff endpoint only"
        : index < 10
          ? "B2-C NextEpochCommitmentV0 endpoint only"
          : index < 13
            ? "B2-D ordinary block body endpoint only"
          : index < 17
            ? "B2-E checkpoint finality endpoint only"
            : "node-local signer-intent endpoint only";
      return item.scope !== expectedScope;
    }) ||
    exclusionCodes.some((code) => !rustCodes.includes(code)) ||
    exclusionCodes.some((code) => manifestCodes.includes(code)) ||
    JSON.stringify(rustCodes.filter((code) => !exclusionCodes.includes(code))) !==
      JSON.stringify(manifestCodes)
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "B2-A scoped error codes plus explicit B2-B/B2-C/B2-D/B2-E and node-local exclusions differ from Rust DecodeErrorCode::as_str",
    );
  }
}

function stripProtoComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

function protoBlock(source, keyword, name) {
  const expression = new RegExp(`\\b${keyword}\\s+${name}\\s*\\{`, "m");
  const match = expression.exec(source);
  if (!match) {
    fail("proto_projection_drift", 0, `${keyword} ${name} is missing`);
  }
  const opening = source.indexOf("{", match.index);
  let depth = 1;
  for (let index = opening + 1; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(opening + 1, index);
  }
  fail("proto_projection_drift", 0, `${keyword} ${name} is unterminated`);
}

function protoMessageFields(source, name) {
  const body = protoBlock(stripProtoComments(source), "message", name);
  const fields = [];
  const expression = /\b(repeated\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([a-z_][A-Za-z0-9_]*)\s*=\s*([0-9]+)\s*(?:\[[^\]]*\])?\s*;/g;
  for (let match = expression.exec(body); match; match = expression.exec(body)) {
    fields.push({
      cardinality: match[1] ? "repeated" : "singular",
      proto_type: match[2],
      name: match[3],
      number: Number(match[4]),
    });
  }
  return fields.sort((first, second) => first.number - second.number);
}

function protoEnumVariants(source, name) {
  const body = protoBlock(stripProtoComments(source), "enum", name);
  const variants = [];
  const expression = /\b([A-Z][A-Z0-9_]*)\s*=\s*([0-9]+)\s*;/g;
  for (let match = expression.exec(body); match; match = expression.exec(body)) {
    variants.push({ proto_name: match[1], value: Number(match[2]) });
  }
  return variants;
}

function validateProtoProjections(manifest) {
  const sources = new Map();
  function sourceFor(filename) {
    if (!sources.has(filename)) {
      sources.set(filename, fs.readFileSync(path.join(REPO_ROOT, filename), "utf8"));
    }
    return sources.get(filename);
  }

  for (const projection of manifest.transport_projections) {
    const actual = protoMessageFields(
      sourceFor(projection.proto_file),
      projection.proto_message,
    );
    const expected = projection.fields
      .map(({ number, name, proto_type, cardinality }) => ({
        number,
        name,
        proto_type,
        cardinality,
      }))
      .sort((first, second) => first.number - second.number);
    const signature = (field) =>
      `${field.number}:${field.cardinality}:${field.proto_type}:${field.name}`;
    if (
      actual.length !== expected.length ||
      actual.some((field, item) => signature(field) !== signature(expected[item]))
    ) {
      fail(
        "proto_projection_drift",
        0,
        `${projection.proto_message} field projection differs from ${projection.proto_file}`,
      );
    }
  }

  for (const projection of manifest.transport_enums) {
    const actual = protoEnumVariants(
      sourceFor(projection.proto_file),
      projection.proto_enum,
    );
    const expected = projection.variants.map(({ proto_name, value }) => ({
      proto_name,
      value,
    }));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail(
        "proto_projection_drift",
        0,
        `${projection.proto_enum} enum projection drifted`,
      );
    }
  }
}

function validateSchemaVersion(value) {
  if (value.schema_version !== 0) {
    fail("invalid_schema_version", 0, "schema_version must equal zero");
  }
  if (value.protocol_version !== 0) {
    fail("invalid_protocol_version", 0, "protocol_version must equal zero");
  }
}

function isZero(value) {
  return value.every((byte) => byte === 0);
}

function sameScope(value, environment) {
  return (
    bytesEqual(value.genesis_hash, environment.genesisHash) &&
    bytesEqual(value.chain_id, environment.chainId) &&
    value.protocol_version === environment.protocolVersion &&
    value.epoch === environment.epoch &&
    bytesEqual(value.validator_set_hash, environment.validatorSetHash)
  );
}

function validateValidatorSet(value, environment = null) {
  validateSchemaVersion(value);
  if (isZero(value.genesis_hash)) {
    fail("zero_genesis_hash", 0, "validator set genesis hash is all zero");
  }
  if (value.validators.length === 0) {
    fail("empty_validator_set", 0, "validator set is empty");
  }
  if (
    environment &&
    (!bytesEqual(value.genesis_hash, environment.genesisHash) ||
      !bytesEqual(value.chain_id, environment.chainId) ||
      value.protocol_version !== environment.protocolVersion ||
      value.epoch !== environment.epoch ||
      !bytesEqual(
        value.consensus_parameters_hash,
        environment.consensusParametersHash,
      ))
  ) {
    fail("context_mismatch", 0, "validator set scope does not match the corpus");
  }
  let previous = null;
  const keys = new Set();
  for (const validator of value.validators) {
    if (previous !== null) {
      const comparison = compareBytes(previous, validator.validator_id);
      if (comparison === 0) {
        fail("duplicate_validator_id", 0, "validator ID is duplicated");
      }
      if (comparison > 0) {
        fail("noncanonical_validator_order", 0, "validator IDs are not sorted");
      }
    }
    previous = validator.validator_id;
    if (isZero(validator.consensus_public_key)) {
      fail("zero_public_key", 0, "validator public key is all zero");
    }
    const key = validator.consensus_public_key.toString("hex");
    if (keys.has(key)) {
      fail("duplicate_public_key", 0, "validator public key is duplicated");
    }
    keys.add(key);
    if (validator.effective_weight === 0n) {
      fail("zero_voting_power", 0, "validator effective weight is zero");
    }
  }
}

function commonContext(value, view, messageKind) {
  return {
    schema_version: value.schema_version,
    genesis_hash: value.genesis_hash,
    chain_id: value.chain_id,
    protocol_version: value.protocol_version,
    epoch: value.epoch,
    validator_set_hash: value.validator_set_hash,
    view,
    message_kind: messageKind,
  };
}

function qcVoteSign(qc) {
  return {
    context: commonContext(qc, qc.view, 1),
    height: qc.height,
    block_id: qc.block_id,
  };
}

function qcSummary(qc, qcDigest) {
  return {
    qc_digest: qcDigest,
    qc_epoch: qc.epoch,
    qc_view: qc.view,
    qc_height: qc.height,
    qc_block_id: qc.block_id,
  };
}

function timeoutSign(tc, summary) {
  return {
    context: commonContext(tc, tc.timed_out_view, 2),
    high_qc: summary,
  };
}

function validateSigningValue(type, value) {
  validateSchemaVersion(value.context);
  const required = type === "VoteSignV0" ? 1 : 2;
  if (value.context.message_kind !== required) {
    fail(
      "invalid_message_kind",
      0,
      `${type} has message kind ${value.context.message_kind}, expected ${required}`,
    );
  }
}

function verifyEd25519(publicKey, message, signature) {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  const encodedR = signature.subarray(0, 32);
  const scalar = littleEndianInteger(signature.subarray(32));
  if (scalar >= ED25519_GROUP_ORDER) {
    return false;
  }
  const publicPoint = decodeEd25519Point(publicKey);
  const rPoint = decodeEd25519Point(encodedR);
  if (publicPoint === null || rPoint === null) {
    return false;
  }
  const challenge =
    littleEndianInteger(
      crypto
        .createHash("sha512")
        .update(Buffer.concat([encodedR, publicKey, message]))
        .digest(),
    ) % ED25519_GROUP_ORDER;
  return pointsEqual(
    scalarMultiply(ED25519_BASE_POINT, scalar),
    pointAdd(rPoint, scalarMultiply(publicPoint, challenge)),
  );
}

function strictEd25519SelfTest() {
  const publicKey = Buffer.from(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "hex",
  );
  const signature = Buffer.from(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "hex",
  );
  if (!verifyEd25519(publicKey, Buffer.alloc(0), signature)) {
    throw new Error("strict Ed25519 verifier failed RFC8032 test 1");
  }
  if (verifyEd25519(publicKey, Buffer.from([0]), signature)) {
    throw new Error("strict Ed25519 verifier accepted the wrong message");
  }
  const mutated = Buffer.from(signature);
  mutated[0] ^= 1;
  if (verifyEd25519(publicKey, Buffer.alloc(0), mutated)) {
    throw new Error("strict Ed25519 verifier accepted a mutated signature");
  }
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const identityForgery = Buffer.alloc(64);
  identity.copy(identityForgery, 0);
  if (verifyEd25519(identity, Buffer.from("any message"), identityForgery)) {
    throw new Error("strict Ed25519 verifier accepted an identity-point forgery");
  }
  const nonCanonicalScalar = Buffer.from(signature);
  littleEndianBytes(ED25519_GROUP_ORDER, 32).copy(nonCanonicalScalar, 32);
  if (verifyEd25519(publicKey, Buffer.alloc(0), nonCanonicalScalar)) {
    throw new Error("strict Ed25519 verifier accepted S >= L");
  }
  const nonCanonicalPoint = littleEndianBytes(ED25519_FIELD, 32);
  if (verifyEd25519(nonCanonicalPoint, Buffer.alloc(0), signature)) {
    throw new Error("strict Ed25519 verifier accepted noncanonical public-key y");
  }
  const nonCanonicalR = Buffer.from(signature);
  nonCanonicalPoint.copy(nonCanonicalR, 0);
  if (verifyEd25519(publicKey, Buffer.alloc(0), nonCanonicalR)) {
    throw new Error("strict Ed25519 verifier accepted noncanonical R");
  }
}

function validateScope(value, environment) {
  validateSchemaVersion(value);
  if (!sameScope(value, environment)) {
    fail("context_mismatch", 0, "certificate scope does not match validator set");
  }
}

function validateOrderedSigners(shares, environment, signingRoot) {
  let previous = null;
  let signedPower = 0n;
  for (const share of shares) {
    if (previous !== null) {
      const comparison = compareBytes(previous, share.validator_id);
      if (comparison === 0) {
        fail("duplicate_signer", 0, "certificate signer is duplicated");
      }
      if (comparison > 0) {
        fail("noncanonical_signer_order", 0, "certificate signers are not sorted");
      }
    }
    previous = share.validator_id;
    const validator = environment.validators.get(share.validator_id.toString("hex"));
    if (!validator) {
      fail("unknown_signer", 0, "certificate signer is not in the validator set");
    }
    if (!verifyEd25519(validator.publicKey, signingRoot, share.signature)) {
      fail("invalid_signature", 0, "strict Ed25519 verification failed");
    }
    signedPower += validator.power;
  }
  return signedPower;
}

function validateOrdinaryQc(value, environment, index) {
  validateScope(value, environment);
  if (value.signatures.length === 0 || value.view === 0n) {
    fail(
      "unauthorized_synthetic_qc",
      0,
      "ordinary QC admission rejects empty-signature or view-zero anchors",
    );
  }
  const vote = qcVoteSign(value);
  validateSigningValue("VoteSignV0", vote);
  const voteRoot = digest(
    environment.domains.get("vote").ascii,
    encodeValue("VoteSignV0", vote, index),
  );
  const signedPower = validateOrderedSigners(
    value.signatures,
    environment,
    voteRoot,
  );
  if (signedPower < environment.quorumPower) {
    fail("insufficient_quorum", 0, "QC signed power is below quorum");
  }
}

function tupleGreater(first, second) {
  if (first.view !== second.view) {
    return first.view > second.view;
  }
  const block = compareBytes(first.blockId, second.blockId);
  if (block !== 0) {
    return block > 0;
  }
  return compareBytes(first.digest, second.digest) > 0;
}

function summaryMatches(summary, reference) {
  return (
    bytesEqual(summary.qc_digest, reference.digest) &&
    summary.qc_epoch === reference.qc.epoch &&
    summary.qc_view === reference.qc.view &&
    summary.qc_height === reference.qc.height &&
    bytesEqual(summary.qc_block_id, reference.qc.block_id)
  );
}

function validateTimeoutCertificate(value, environment, index) {
  validateScope(value, environment);
  if (value.entries.length === 0 || value.referenced_qcs.length === 0) {
    fail("empty_tc", 0, "TC needs entries and full referenced QCs");
  }
  const aggregate = value.referenced_qcs.reduce(
    (total, qc) => total + qc.signatures.length,
    0,
  );
  if (aggregate > 10000) {
    fail("aggregate_limit_exceeded", 0, "TC nested QC signatures exceed 10000");
  }

  const references = [];
  let previousDigest = null;
  const viewCoordinates = new Map();
  const blockCoordinates = new Map();
  for (const qc of value.referenced_qcs) {
    try {
      validateOrdinaryQc(qc, environment, index);
    } catch (error) {
      if (error instanceof GateError) {
        if (error.code === "invalid_signature") {
          throw error;
        }
        fail("invalid_referenced_qc", error.offset, `invalid TC reference: ${error.code}`);
      }
      throw error;
    }
    const qcDigest = digest(
      environment.domains.get("qc").ascii,
      encodeValue("QuorumCertificateV0", qc, index),
    );
    if (previousDigest !== null) {
      const comparison = compareBytes(previousDigest, qcDigest);
      if (comparison === 0) {
        fail("duplicate_reference", 0, "TC referenced QC is duplicated");
      }
      if (comparison > 0) {
        fail("noncanonical_reference_order", 0, "TC references are not digest sorted");
      }
    }
    previousDigest = qcDigest;
    if (qc.view > value.timed_out_view) {
      fail("future_reference_view", 0, "TC reference is from a future view");
    }
    const viewKey = `${qc.epoch}:${qc.view}`;
    const coordinate = `${qc.height}:${qc.block_id.toString("hex")}`;
    const priorCoordinate = viewCoordinates.get(viewKey);
    if (priorCoordinate !== undefined && priorCoordinate !== coordinate) {
      fail("conflicting_same_view_qc", 0, "same epoch/view has conflicting QC coordinates");
    }
    viewCoordinates.set(viewKey, coordinate);
    const blockKey = qc.block_id.toString("hex");
    const blockCoordinate = `${qc.epoch}:${qc.view}:${qc.height}`;
    const priorBlockCoordinate = blockCoordinates.get(blockKey);
    if (
      priorBlockCoordinate !== undefined &&
      priorBlockCoordinate !== blockCoordinate
    ) {
      fail(
        "same_block_different_coordinates",
        0,
        "one block ID is bound to different QC coordinates",
      );
    }
    blockCoordinates.set(blockKey, blockCoordinate);
    references.push({ qc, digest: qcDigest });
  }

  let previousSigner = null;
  let signedPower = 0n;
  const used = new Set();
  let maximum = null;
  for (const entry of value.entries) {
    if (previousSigner !== null) {
      const comparison = compareBytes(previousSigner, entry.validator_id);
      if (comparison === 0) {
        fail("duplicate_signer", 0, "TC signer is duplicated");
      }
      if (comparison > 0) {
        fail("noncanonical_signer_order", 0, "TC signers are not sorted");
      }
    }
    previousSigner = entry.validator_id;
    const validator = environment.validators.get(entry.validator_id.toString("hex"));
    if (!validator) {
      fail("unknown_signer", 0, "TC signer is not in the validator set");
    }
    const matches = [];
    references.forEach((reference, referenceIndex) => {
      if (summaryMatches(entry.high_qc, reference)) {
        matches.push(referenceIndex);
      }
    });
    if (matches.length !== 1) {
      fail("reference_summary_mismatch", 0, "timeout summary has no unique full QC");
    }
    used.add(matches[0]);
    const reference = references[matches[0]];
    const candidate = {
      view: reference.qc.view,
      blockId: reference.qc.block_id,
      digest: reference.digest,
    };
    if (maximum === null || tupleGreater(candidate, maximum)) {
      maximum = candidate;
    }
    const signingValue = timeoutSign(value, entry.high_qc);
    validateSigningValue("TimeoutSignV0", signingValue);
    const root = digest(
      environment.domains.get("timeout").ascii,
      encodeValue("TimeoutSignV0", signingValue, index),
    );
    if (!verifyEd25519(validator.publicKey, root, entry.signature)) {
      fail("invalid_signature", 0, "TC timeout signature is invalid");
    }
    signedPower += validator.power;
  }
  if (used.size !== references.length) {
    fail("unreferenced_qc", 0, "TC contains an unused referenced QC");
  }
  if (maximum === null || !bytesEqual(value.selected_high_qc_digest, maximum.digest)) {
    fail("selected_not_maximum", 0, "TC selected digest is not the maximum");
  }
  if (signedPower < environment.quorumPower) {
    fail("insufficient_quorum", 0, "TC signed power is below quorum");
  }
}

function validateAdmitted(type, value, environment, index) {
  if (type === "ValidatorSetV0") {
    validateValidatorSet(value, environment);
  } else if (type === "QuorumCertificateV0") {
    validateOrdinaryQc(value, environment, index);
  } else if (type === "TimeoutCertificateV0") {
    validateTimeoutCertificate(value, environment, index);
  } else {
    fail("schema_manifest_invalid", 0, `no admission function for ${type}`);
  }
}

function jsonPointer(document, pointer) {
  if (pointer === "") return document;
  if (!pointer.startsWith("/")) {
    fail("schema_manifest_invalid", 0, `invalid JSON pointer ${pointer}`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce((value, part) => {
      if (value === null || typeof value !== "object" || !(part in value)) {
        fail("schema_manifest_invalid", 0, `JSON pointer ${pointer} is missing`);
      }
      return value[part];
    }, document);
}

function expectError(expected, action, label) {
  try {
    action();
  } catch (error) {
    if (error instanceof GateError && error.code === expected) {
      return;
    }
    throw new Error(
      `${label}: expected ${expected}, received ${error?.code ?? error?.message ?? error}`,
      { cause: error },
    );
  }
  throw new Error(`${label}: expected ${expected}, received success`);
}

function environmentFromB1(b1, validatorSet, validatorSetHash, manifest) {
  const validators = new Map();
  let totalPower = 0n;
  for (const validator of validatorSet.validators) {
    validators.set(validator.validator_id.toString("hex"), {
      publicKey: validator.consensus_public_key,
      power: validator.effective_weight,
    });
    totalPower += validator.effective_weight;
  }
  const quorumPower = (2n * totalPower) / 3n + 1n;
  if (
    BigInt(b1.validator_set.total_power) !== totalPower ||
    BigInt(b1.validator_set.quorum_power) !== quorumPower
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "B1 declared total/quorum power differs from decoded validator weights",
    );
  }
  const contextSetHash = canonicalHex(
    b1.context.validator_set_id_hex,
    "B1 context validator-set hash",
  );
  if (!contextSetHash.equals(validatorSetHash)) {
    fail(
      "digest_mismatch",
      0,
      "B1 context validator-set hash differs from decoded set digest",
    );
  }
  return {
    genesisHash: canonicalHex(b1.context.genesis_hash_hex, "B1 genesis hash"),
    chainId: Buffer.from(b1.context.chain_id, "ascii"),
    protocolVersion: b1.context.protocol_version,
    epoch: BigInt(b1.context.epoch),
    validatorSetHash,
    consensusParametersHash: canonicalHex(
      b1.context.consensus_parameters_hash_hex,
      "B1 parameters hash",
    ),
    validators,
    totalPower,
    quorumPower,
    domains: new Map(manifest.domains.map((domain) => [domain.id, domain])),
  };
}

function loadValidRawObjects(corpus, b1, index, manifest) {
  const result = new Map();
  let environment = null;
  for (const source of corpus.valid_raw_objects) {
    const fixture = jsonPointer(b1, source.json_pointer);
    const raw = canonicalHex(fixture.cev0_hex, `${source.id}.cev0_hex`);
    const decoded = decodeExact(source.object_type, raw, index);
    const reencoded = encodeValue(source.object_type, decoded, index);
    if (!raw.equals(reencoded)) {
      throw new Error(`${source.id}: parse/re-encode is not byte-identical`);
    }
    const domain = index.domains.get(source.domain);
    if (!domain || domain.logical_object !== source.object_type) {
      fail("schema_manifest_invalid", 0, `${source.id} has the wrong digest domain`);
    }
    const actualDigest = digest(domain.ascii, raw);
    const expectedDigest = canonicalHex(
      fixture[source.digest_field],
      `${source.id}.${source.digest_field}`,
    );
    if (!actualDigest.equals(expectedDigest)) {
      fail("digest_mismatch", 0, `${source.id} digest differs from B1`);
    }
    if (source.object_type === "ValidatorSetV0") {
      validateValidatorSet(decoded);
      environment = environmentFromB1(b1, decoded, actualDigest, manifest);
      validateValidatorSet(decoded, environment);
    } else {
      if (!environment) {
        fail("schema_manifest_invalid", 0, "validator set must precede certificates");
      }
      validateAdmitted(source.object_type, decoded, environment, index);
    }
    result.set(source.id, { ...source, fixture, raw, decoded });
  }
  return { validObjects: result, environment };
}

function validateCorpus(corpus, manifest) {
  if (
    corpus.schema !==
      "trnm_poco_bft_cev0_parser_certificate_kernel_vectors_v0" ||
    corpus.schema_version !== 0
  ) {
    fail("schema_manifest_invalid", 0, "unexpected parser corpus identity");
  }
  const stableCodes = new Set(
    [...manifest.decoder_error_codes, ...manifest.admission_error_codes].map(
      (item) => item.code,
    ),
  );
  const ids = new Set();
  for (const group of [
    corpus.valid_raw_objects,
    corpus.raw_shape_cases,
    corpus.boundary_cases,
    corpus.generated_semantic_cases,
    corpus.imported_b1_semantic_cases,
  ]) {
    if (!Array.isArray(group)) {
      fail("schema_manifest_invalid", 0, "every corpus case group must be an array");
    }
    for (const item of group) {
      const id = item.id ?? item.source_case_id;
      if (!id || ids.has(id)) {
        fail("schema_manifest_invalid", 0, `duplicate or absent corpus case ID ${id}`);
      }
      ids.add(id);
      if (item.expected_error_code && !stableCodes.has(item.expected_error_code)) {
        fail(
          "schema_manifest_invalid",
          0,
          `${id} names unknown stable error ${item.expected_error_code}`,
        );
      }
    }
  }
}

function runRawShapeCases(corpus, validObjects, index) {
  for (const test of corpus.raw_shape_cases) {
    if (test.operation === "all_noncomplete_prefixes") {
      for (const source of validObjects.values()) {
        for (let length = 0; length < source.raw.length; length += 1) {
          const prefix = source.raw.subarray(0, length);
          expectError(
            test.expected_error_code,
            () => decodeExact(source.object_type, prefix, index),
            `${test.id}:${source.id}:prefix-${length}`,
          );
        }
      }
    } else if (test.operation === "append_hex") {
      const suffix = canonicalHex(test.hex, `${test.id}.hex`);
      for (const source of validObjects.values()) {
        expectError(
          test.expected_error_code,
          () =>
            decodeExact(
              source.object_type,
              Buffer.concat([source.raw, suffix]),
              index,
            ),
          `${test.id}:${source.id}`,
        );
      }
    } else if (test.operation === "truncate_last_byte") {
      const source = validObjects.get(test.source);
      expectError(
        test.expected_error_code,
        () => decodeExact(source.object_type, source.raw.subarray(0, -1), index),
        test.id,
      );
    } else if (test.operation === "standalone_list_count") {
      const count = decimal(test.count, `${test.id}.count`);
      const encoded = encodeUnsigned(count, 4);
      expectError(
        test.expected_error_code,
        () => {
          const decoder = new Decoder(encoded, index);
          decoder.decode({ kind: "list", item: "u8", max_count: test.max_count });
        },
        test.id,
      );
    } else if (test.operation === "qc_view_zero_then_truncate") {
      const source = validObjects.get(test.source);
      const mutated = cloneValue(source.decoded);
      mutated.view = 0n;
      const raw = encodeValue("QuorumCertificateV0", mutated, index);
      expectError(
        test.expected_error_code,
        () => decodeExact("QuorumCertificateV0", raw.subarray(0, -1), index),
        test.id,
      );
    } else if (test.operation === "qc_empty_signatures_then_trailing") {
      const source = validObjects.get(test.source);
      const mutated = cloneValue(source.decoded);
      mutated.signatures = [];
      const raw = Buffer.concat([
        encodeValue("QuorumCertificateV0", mutated, index),
        Buffer.from([0]),
      ]);
      expectError(
        test.expected_error_code,
        () => decodeExact("QuorumCertificateV0", raw, index),
        test.id,
      );
    } else {
      fail("schema_manifest_invalid", 0, `unknown raw operation ${test.operation}`);
    }
  }
}

function makeValidator(index) {
  const id = Buffer.from(`v${index.toString().padStart(3, "0")}`, "ascii");
  const key = Buffer.alloc(32);
  key.writeUInt32BE(index + 1, 28);
  return {
    validator_id: id,
    consensus_public_key: key,
    effective_weight: 1n,
  };
}

function makeSignatureShare(index) {
  const id = Buffer.from(`s${index.toString().padStart(3, "0")}`, "ascii");
  const signature = Buffer.alloc(64);
  signature.writeUInt32BE(index + 1, 60);
  return { validator_id: id, signature };
}

function qcDigestForSort(qc, environment, index) {
  return digest(
    environment.domains.get("qc").ascii,
    encodeValue("QuorumCertificateV0", qc, index),
  );
}

function generatedSameViewConflict(environment, index) {
  const keyRecords = ["a", "b", "c", "d"].map((suffix) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    return {
      validatorId: Buffer.from(`generated-${suffix}`, "ascii"),
      publicKey: publicDer.subarray(publicDer.length - 32),
      privateKey,
    };
  });
  const validatorSet = {
    schema_version: 0,
    genesis_hash: environment.genesisHash,
    chain_id: environment.chainId,
    protocol_version: environment.protocolVersion,
    epoch: environment.epoch,
    consensus_parameters_hash: environment.consensusParametersHash,
    validators: keyRecords.map((record) => ({
      validator_id: record.validatorId,
      consensus_public_key: record.publicKey,
      effective_weight: 1n,
    })),
  };
  validateValidatorSet(validatorSet);
  const validatorSetHash = digest(
    environment.domains.get("validator_set").ascii,
    encodeValue("ValidatorSetV0", validatorSet, index),
  );
  const generatedEnvironment = {
    ...environment,
    validatorSetHash,
    validators: new Map(
      keyRecords.map((record) => [
        record.validatorId.toString("hex"),
        { publicKey: record.publicKey, power: 1n },
      ]),
    ),
    totalPower: 4n,
    quorumPower: 3n,
  };
  function makeQc(fill, view) {
    const qc = {
      schema_version: 0,
      genesis_hash: generatedEnvironment.genesisHash,
      chain_id: generatedEnvironment.chainId,
      protocol_version: generatedEnvironment.protocolVersion,
      epoch: generatedEnvironment.epoch,
      validator_set_hash: generatedEnvironment.validatorSetHash,
      view,
      height: 20n,
      block_id: Buffer.alloc(32, fill),
      signatures: [],
    };
    const voteRoot = digest(
      generatedEnvironment.domains.get("vote").ascii,
      encodeValue("VoteSignV0", qcVoteSign(qc), index),
    );
    qc.signatures = keyRecords.slice(0, 3).map((record) => ({
      validator_id: record.validatorId,
      signature: crypto.sign(null, voteRoot, record.privateKey),
    }));
    return qc;
  }
  function makeTc(qcs) {
    const referencedQcs = qcs.sort((first, second) =>
      compareBytes(
        qcDigestForSort(first, generatedEnvironment, index),
        qcDigestForSort(second, generatedEnvironment, index),
      ),
    );
    const referenceData = referencedQcs.map((qc) => ({
      qc,
      digest: qcDigestForSort(qc, generatedEnvironment, index),
    }));
    const selected = referenceData.reduce((maximum, item) => {
      const candidate = {
        view: item.qc.view,
        blockId: item.qc.block_id,
        digest: item.digest,
      };
      return maximum === null || tupleGreater(candidate, maximum.candidate)
        ? { item, candidate }
        : maximum;
    }, null).item;
    const tc = {
      schema_version: 0,
      genesis_hash: generatedEnvironment.genesisHash,
      chain_id: generatedEnvironment.chainId,
      protocol_version: generatedEnvironment.protocolVersion,
      epoch: generatedEnvironment.epoch,
      validator_set_hash: generatedEnvironment.validatorSetHash,
      timed_out_view: qcs.reduce(
        (maximum, qc) => (qc.view > maximum ? qc.view : maximum),
        0n,
      ),
      entries: [],
      referenced_qcs: referencedQcs,
      selected_high_qc_digest: selected.digest,
    };
    const entryReferences = [referenceData[0], referenceData[1], referenceData[1]];
    tc.entries = keyRecords.slice(0, 3).map((record, position) => {
      const reference = entryReferences[position];
      const summary = qcSummary(reference.qc, reference.digest);
      const timeoutRoot = digest(
        generatedEnvironment.domains.get("timeout").ascii,
        encodeValue("TimeoutSignV0", timeoutSign(tc, summary), index),
      );
      return {
        validator_id: record.validatorId,
        high_qc: summary,
        signature: crypto.sign(null, timeoutRoot, record.privateKey),
      };
    });
    return tc;
  }
  const validControl = makeTc([makeQc(0x11, 5n), makeQc(0x22, 6n)]);
  validateTimeoutCertificate(validControl, generatedEnvironment, index);
  const conflictingTc = makeTc([makeQc(0x11, 5n), makeQc(0x22, 5n)]);
  return { tc: conflictingTc, environment: generatedEnvironment };
}

function generatedIdentityForgery(test, environment, index) {
  const validatorId = Buffer.from("identity-forgery", "ascii");
  const publicKey = canonicalHex(test.public_key_hex, `${test.id}.public_key_hex`);
  const validatorSet = {
    schema_version: 0,
    genesis_hash: environment.genesisHash,
    chain_id: environment.chainId,
    protocol_version: environment.protocolVersion,
    epoch: environment.epoch,
    consensus_parameters_hash: environment.consensusParametersHash,
    validators: [
      {
        validator_id: validatorId,
        consensus_public_key: publicKey,
        effective_weight: 1n,
      },
    ],
  };
  const validatorSetHash = digest(
    environment.domains.get("validator_set").ascii,
    encodeValue("ValidatorSetV0", validatorSet, index),
  );
  const forgedEnvironment = {
    ...environment,
    validatorSetHash,
    validators: new Map([
      [validatorId.toString("hex"), { publicKey, power: 1n }],
    ]),
    totalPower: 1n,
    quorumPower: 1n,
  };
  const qc = {
    schema_version: 0,
    genesis_hash: forgedEnvironment.genesisHash,
    chain_id: forgedEnvironment.chainId,
    protocol_version: forgedEnvironment.protocolVersion,
    epoch: forgedEnvironment.epoch,
    validator_set_hash: forgedEnvironment.validatorSetHash,
    view: 1n,
    height: 1n,
    block_id: canonicalHex(test.block_id_hex, `${test.id}.block_id_hex`),
    signatures: [
      {
        validator_id: validatorId,
        signature: canonicalHex(test.signature_hex, `${test.id}.signature_hex`),
      },
    ],
  };
  return { qc, environment: forgedEnvironment };
}

function runBoundaryCases(corpus, validObjects, index) {
  const validatorSet = validObjects.get("validator_set_exact_10").decoded;
  const qc = validObjects.get("qc_low_exact_7").decoded;
  const tc = validObjects.get("tc_exact_7").decoded;
  for (const test of corpus.boundary_cases) {
    if (test.operation === "validator_set_chain_id_length") {
      const mutated = cloneValue(validatorSet);
      mutated.chain_id = Buffer.alloc(Number(test.length), "a");
      const action = () => {
        const decoded = decodeExact(
          "ValidatorSetV0",
          encodeValue("ValidatorSetV0", mutated, index),
          index,
        );
        validateValidatorSet(decoded);
      };
      if (test.expected_error_code) {
        expectError(test.expected_error_code, action, test.id);
      } else {
        action();
      }
    } else if (test.operation === "validator_set_chain_id_hex") {
      const mutated = cloneValue(validatorSet);
      mutated.chain_id = canonicalHex(test.hex, `${test.id}.hex`);
      expectError(
        test.expected_error_code,
        () =>
          decodeExact(
            "ValidatorSetV0",
            encodeValue("ValidatorSetV0", mutated, index),
            index,
          ),
        test.id,
      );
    } else if (test.operation === "signature_share_validator_id_length") {
      const share = {
        validator_id: Buffer.alloc(Number(test.length), "v"),
        signature: Buffer.alloc(64),
      };
      const action = () =>
        decodeExact(
          "SignatureShareV0",
          encodeValue("SignatureShareV0", share, index),
          index,
        );
      if (test.expected_error_code) {
        expectError(test.expected_error_code, action, test.id);
      } else {
        action();
      }
    } else if (test.operation === "synthetic_validator_set_count") {
      const mutated = cloneValue(validatorSet);
      mutated.validators = Array.from(
        { length: Number(test.count) },
        (_, item) => makeValidator(item),
      );
      const decoded = decodeExact(
        "ValidatorSetV0",
        encodeValue("ValidatorSetV0", mutated, index),
        index,
      );
      validateValidatorSet(decoded);
      if (decoded.validators.length !== Number(test.count)) {
        throw new Error(`${test.id}: boundary validator count changed`);
      }
    } else if (test.operation === "synthetic_qc_signature_count") {
      const mutated = cloneValue(qc);
      mutated.signatures = Array.from(
        { length: Number(test.count) },
        (_, item) => makeSignatureShare(item),
      );
      const decoded = decodeExact(
        "QuorumCertificateV0",
        encodeValue("QuorumCertificateV0", mutated, index),
        index,
      );
      if (decoded.signatures.length !== Number(test.count)) {
        throw new Error(`${test.id}: boundary signature count changed`);
      }
    } else if (test.operation === "synthetic_tc_shape") {
      const mutated = cloneValue(tc);
      mutated.entries = Array.from(
        { length: Number(test.entry_count) },
        (_, item) => ({
          validator_id: Buffer.from(
            `t${item.toString().padStart(3, "0")}`,
            "ascii",
          ),
          high_qc: cloneValue(tc.entries[0].high_qc),
          signature: Buffer.alloc(64, item & 0xff),
        }),
      );
      mutated.referenced_qcs = Array.from(
        { length: Number(test.reference_count) },
        (_, reference) => {
          const nested = cloneValue(qc);
          nested.view = BigInt(reference + 1);
          nested.signatures = Array.from(
            { length: Number(test.signatures_per_reference) },
            (_, item) => makeSignatureShare(item),
          );
          return nested;
        },
      );
      const decoded = decodeExact(
        "TimeoutCertificateV0",
        encodeValue("TimeoutCertificateV0", mutated, index),
        index,
      );
      const aggregate = decoded.referenced_qcs.reduce(
        (total, item) => total + item.signatures.length,
        0,
      );
      if (aggregate !== Number(test.expected_aggregate_qc_signatures)) {
        throw new Error(`${test.id}: aggregate nested signature count changed`);
      }
    } else {
      fail("schema_manifest_invalid", 0, `unknown boundary operation ${test.operation}`);
    }
  }
}

function runGeneratedSemanticCases(corpus, validObjects, environment, index) {
  for (const test of corpus.generated_semantic_cases) {
    const source = test.source ? validObjects.get(test.source) : null;
    if (test.source && !source) {
      fail("schema_manifest_invalid", 0, `${test.id} names missing source ${test.source}`);
    }
    let type = source?.object_type;
    let mutated = source ? cloneValue(source.decoded) : null;
    let action;
    switch (test.operation) {
      case "set_root_integer_field":
        mutated[test.field] = Number(test.value);
        break;
      case "duplicate_validator_id":
        mutated.validators[1].validator_id = Buffer.from(
          mutated.validators[0].validator_id,
        );
        break;
      case "zero_validator_set_genesis_hash":
        mutated.genesis_hash = Buffer.alloc(32);
        break;
      case "clear_validator_set":
        mutated.validators = [];
        break;
      case "zero_first_validator_public_key":
        mutated.validators[0].consensus_public_key = Buffer.alloc(32);
        break;
      case "swap_first_two_validators":
        [mutated.validators[0], mutated.validators[1]] = [
          mutated.validators[1],
          mutated.validators[0],
        ];
        break;
      case "duplicate_validator_public_key":
        mutated.validators[1].consensus_public_key = Buffer.from(
          mutated.validators[0].consensus_public_key,
        );
        break;
      case "clear_qc_signatures":
        mutated.signatures = [];
        break;
      case "set_qc_view_zero":
        mutated.view = 0n;
        break;
      case "vote_sign_message_kind":
        type = "VoteSignV0";
        mutated = qcVoteSign(source.decoded);
        mutated.context.message_kind = Number(test.value);
        action = () => {
          const parsed = decodeExact(type, encodeValue(type, mutated, index), index);
          validateSigningValue(type, parsed);
        };
        break;
      case "timeout_sign_message_kind":
        type = "TimeoutSignV0";
        mutated = timeoutSign(source.decoded, source.decoded.entries[0].high_qc);
        mutated.context.message_kind = Number(test.value);
        action = () => {
          const parsed = decodeExact(type, encodeValue(type, mutated, index), index);
          validateSigningValue(type, parsed);
        };
        break;
      case "vote_sign_context_integer_field":
        type = "VoteSignV0";
        mutated = qcVoteSign(source.decoded);
        mutated.context[test.field] = Number(test.value);
        action = () => {
          const parsed = decodeExact(type, encodeValue(type, mutated, index), index);
          validateSigningValue(type, parsed);
        };
        break;
      case "timeout_sign_context_integer_field":
        type = "TimeoutSignV0";
        mutated = timeoutSign(source.decoded, source.decoded.entries[0].high_qc);
        mutated.context[test.field] = Number(test.value);
        action = () => {
          const parsed = decodeExact(type, encodeValue(type, mutated, index), index);
          validateSigningValue(type, parsed);
        };
        break;
      case "duplicate_tc_reference":
        mutated.referenced_qcs.push(cloneValue(mutated.referenced_qcs[0]));
        mutated.referenced_qcs.sort((first, second) =>
          compareBytes(
            qcDigestForSort(first, environment, index),
            qcDigestForSort(second, environment, index),
          ),
        );
        break;
      case "add_unused_valid_tc_reference": {
        const extra = validObjects.get(test.extra_qc_source);
        if (!extra || extra.object_type !== "QuorumCertificateV0") {
          fail("schema_manifest_invalid", 0, `${test.id} lacks a valid extra QC`);
        }
        mutated.referenced_qcs.push(cloneValue(extra.decoded));
        mutated.referenced_qcs.sort((first, second) =>
          compareBytes(
            qcDigestForSort(first, environment, index),
            qcDigestForSort(second, environment, index),
          ),
        );
        break;
      }
      case "generated_authenticated_same_view_conflict": {
        const generated = generatedSameViewConflict(environment, index);
        type = "TimeoutCertificateV0";
        mutated = generated.tc;
        action = () => {
          const raw = encodeValue(type, mutated, index);
          const parsed = decodeExact(type, raw, index);
          if (!encodeValue(type, parsed, index).equals(raw)) {
            throw new Error(`${test.id}: generated TC did not round-trip`);
          }
          validateTimeoutCertificate(parsed, generated.environment, index);
        };
        break;
      }
      case "clear_first_tc_reference_signatures":
        mutated.referenced_qcs[0].signatures = [];
        break;
      case "mutate_first_tc_reference_signature":
        mutated.referenced_qcs[0].signatures[0].signature[0] ^= 1;
        break;
      case "generated_identity_small_order_forgery": {
        const generated = generatedIdentityForgery(test, environment, index);
        type = "QuorumCertificateV0";
        mutated = generated.qc;
        action = () => {
          const raw = encodeValue(type, mutated, index);
          const parsed = decodeExact(type, raw, index);
          validateOrdinaryQc(parsed, generated.environment, index);
        };
        break;
      }
      default:
        fail(
          "schema_manifest_invalid",
          0,
          `unknown semantic operation ${test.operation}`,
        );
    }
    if (!action) {
      action = () => {
        const parsed = decodeExact(type, encodeValue(type, mutated, index), index);
        validateAdmitted(type, parsed, environment, index);
      };
    }
    expectError(test.expected_error_code, action, test.id);
  }
}

function runImportedB1Cases(corpus, b1, environment, index) {
  const b1Cases = new Map(
    b1.negative_cases.map((item) => [item.id, item]),
  );
  for (const test of corpus.imported_b1_semantic_cases) {
    const source = b1Cases.get(test.source_case_id);
    if (!source) {
      fail("schema_manifest_invalid", 0, `missing B1 case ${test.source_case_id}`);
    }
    const type =
      source.object_type === "qc"
        ? "QuorumCertificateV0"
        : "TimeoutCertificateV0";
    const raw = canonicalHex(
      source.object.cev0_hex,
      `${test.source_case_id}.cev0_hex`,
    );
    const decoded = decodeExact(type, raw, index);
    if (!encodeValue(type, decoded, index).equals(raw)) {
      throw new Error(`${test.source_case_id}: mutated raw bytes do not round-trip`);
    }
    expectError(
      test.expected_error_code,
      () => validateAdmitted(type, decoded, environment, index),
      test.source_case_id,
    );
  }
  if (b1Cases.size !== corpus.imported_b1_semantic_cases.length) {
    fail(
      "schema_manifest_invalid",
      0,
      "B1 negative-case coverage is incomplete or unexpectedly expanded",
    );
  }
}

function main() {
  strictEd25519SelfTest();
  const manifest = readJson(SCHEMA_PATH);
  const corpus = readJson(CORPUS_PATH);
  const index = validateManifest(manifest);
  validateRustErrorVocabulary(manifest);
  validateCorpus(corpus, manifest);
  validateProtoProjections(manifest);

  const sourcePath = path.join(path.dirname(CORPUS_PATH), corpus.raw_source_vector);
  const b1 = readJson(sourcePath);
  const { validObjects, environment } = loadValidRawObjects(
    corpus,
    b1,
    index,
    manifest,
  );
  runRawShapeCases(corpus, validObjects, index);
  runBoundaryCases(corpus, validObjects, index);
  runGeneratedSemanticCases(corpus, validObjects, environment, index);
  runImportedB1Cases(corpus, b1, environment, index);

  const prefixCount = [...validObjects.values()].reduce(
    (total, source) => total + source.raw.length,
    0,
  );
  console.log(
    `PoCO-BFT v0 B2-A logical-schema gate passed: ${manifest.objects.length} objects, ` +
      `${manifest.transport_projections.length} transport projections, ` +
      `${validObjects.size} exact raw objects, ${prefixCount} truncated prefixes, ` +
      `${corpus.boundary_cases.length} boundary cases, ` +
      `${corpus.generated_semantic_cases.length} generated semantic cases, ` +
      `${corpus.imported_b1_semantic_cases.length} imported semantic mutations`,
  );
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
