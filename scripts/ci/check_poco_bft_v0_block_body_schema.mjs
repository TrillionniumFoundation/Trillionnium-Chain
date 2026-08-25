#!/usr/bin/env node

// Independent B2-D ordinary block-validation CEV0/parser/projection/root gate.
// Standard-library only. Receipt values are derived local execution output,
// and no function in this file can authorize a checkpoint, runtime, synthetic
// QC, epoch anchor, handoff, or first-new-epoch proposal.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "../..");
const SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-block-body-v0.json",
);
const B2C_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-epoch-commitment-v0.json",
);
const BASE_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-v0.json",
);
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/block-body-kernel-v0.json",
);
const PARAMETERS_VECTOR_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/parameters-v0.json",
);
const CONSENSUS_PROTO_PATH = path.join(
  REPO_ROOT,
  "proto/trnm/poco/bft/v0/consensus.proto",
);
const EVIDENCE_PROTO_PATH = path.join(
  REPO_ROOT,
  "proto/trnm/poco/bft/v0/evidence.proto",
);
const RUST_DECODER_PATH = path.join(
  REPO_ROOT,
  "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs",
);
const RUST_BODY_PATH = path.join(
  REPO_ROOT,
  "trillionnium/crates/trnm-consensus-types/src/body_v0.rs",
);

const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const DOMAIN_BLOCK = "trnm.poco-bft.block.v0";
const DOMAIN_PROPOSAL = "trnm.poco-bft.proposal.v0";
const DOMAIN_VOTE = "trnm.poco-bft.vote.v0";
const DOMAIN_VALIDATOR_SET = "trnm.poco-bft.validator-set.v0";
const DOMAIN_QC = "trnm.poco-bft.qc.v0";
const DOMAIN_PARAMETERS = "trnm.poco-bft.parameters.v0";
const DOMAIN_EVIDENCE = "trnm.poco-bft.double-sign-evidence.v0";
const DOMAIN_ORDERED_LEAF = "trnm.poco-bft.ordered-leaf.v0";
const DOMAIN_ORDERED_NODE = "trnm.poco-bft.ordered-node.v0";
const DOMAIN_ORDERED_ROOT = "trnm.poco-bft.ordered-root.v0";
const ACTIVE_MAX_BLOCK_BYTES = 4_194_304;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_FIELD = (1n << 255n) - 19n;
const ED25519_GROUP_ORDER =
  (1n << 252n) + 27742317777372353535851937790883648493n;

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

function u(value, width) {
  let remaining = typeof value === "bigint" ? value : BigInt(value);
  const limit = 1n << BigInt(width * 8);
  if (remaining < 0n || remaining >= limit) {
    fail("source_vector_drift", 0, `${value} does not fit u${width * 8}`, "gate");
  }
  const raw = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    raw[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return raw;
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

function loadReferenceParameters() {
  const vector = readJson(PARAMETERS_VECTOR_PATH);
  const raw = Buffer.from(vector.cev0_hex, "hex");
  if (
    vector.schema !== "trnm.poco-bft.parameters-vector.v0" ||
    raw.length !== vector.cev0_length ||
    raw.readUInt16BE(0) !== 0 ||
    raw.readUInt32BE(2) !== 0
  ) {
    fail("source_vector_drift", 0, "reference parameter vector shape drift", "gate");
  }
  const recomputed = digest(DOMAIN_PARAMETERS, raw);
  if (recomputed.toString("hex") !== vector.digest_hex) {
    fail("digest_mismatch", 0, "reference parameter digest drift", "gate");
  }
  const maxBlockBytes = raw.readUInt32BE(11);
  if (maxBlockBytes !== ACTIVE_MAX_BLOCK_BYTES) {
    fail("source_vector_drift", 11, "reference max_block_bytes drift", "gate");
  }
  return {
    raw,
    digest: recomputed,
    maxBlockBytes,
    minValidators: raw.readUInt32BE(19),
    maxValidators: raw.readUInt32BE(23),
    maxTotalPower: raw.readBigUInt64BE(40),
    scalePpm: raw.readBigUInt64BE(113),
    minValidatorPower: raw.readBigUInt64BE(241),
    maxValidatorPower: raw.readBigUInt64BE(249),
    maxValidatorSharePpm: raw.readBigUInt64BE(257),
  };
}

function labelHash(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest();
}

function fixtureSeed(label) {
  return crypto
    .createHash("sha256")
    .update(`trnm.poco-bft.qc-tc.private-fixture.v0:${label}`, "utf8")
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

function sign(privateKey, signingRoot) {
  return crypto.sign(null, signingRoot, privateKey);
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
    if ((power & 1n) === 1n) result = (result * factor) % modulus;
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
  return [fieldMod(e * f), fieldMod(g * h), fieldMod(f * g), fieldMod(e * h)];
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
  return [fieldMod(e * f), fieldMod(g * h), fieldMod(f * g), fieldMod(e * h)];
}

function scalarMultiply(point, scalar) {
  let result = ED25519_IDENTITY;
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = pointAdd(result, addend);
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
  let x = modPow(xSquared, (ED25519_FIELD + 3n) / 8n, ED25519_FIELD);
  if (fieldMod(x * x - xSquared) !== 0n) x = fieldMod(x * ED25519_SQRT_MINUS_ONE);
  if (fieldMod(x * x - xSquared) !== 0n || (x === 0n && sign === 1n)) return null;
  if ((x & 1n) !== sign) x = ED25519_FIELD - x;
  return x;
}

function littleEndianInteger(raw) {
  let result = 0n;
  for (let index = raw.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(raw[index]);
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
  if (encoded.length !== 32) return null;
  const value = littleEndianInteger(encoded);
  const sign = value >> 255n;
  const y = value & ((1n << 255n) - 1n);
  if (y >= ED25519_FIELD) return null;
  const x = recoverX(y, sign);
  if (x === null) return null;
  const point = [x, y, 1n, fieldMod(x * y)];
  if (pointsEqual(scalarMultiply(point, 8n), ED25519_IDENTITY)) return null;
  return point;
}

const ED25519_BASE_Y = fieldMod(
  4n * modPow(5n, ED25519_FIELD - 2n, ED25519_FIELD),
);
const ED25519_BASE_X = recoverX(ED25519_BASE_Y, 0n);
if (ED25519_BASE_X === null) throw new Error("failed to construct Ed25519 base point");
const ED25519_BASE_POINT = [
  ED25519_BASE_X,
  ED25519_BASE_Y,
  1n,
  fieldMod(ED25519_BASE_X * ED25519_BASE_Y),
];

function verifyEd25519(publicKey, message, signature) {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const encodedR = signature.subarray(0, 32);
  const scalar = littleEndianInteger(signature.subarray(32));
  if (scalar >= ED25519_GROUP_ORDER) return false;
  const publicPoint = decodeEd25519Point(publicKey);
  const rPoint = decodeEd25519Point(encodedR);
  if (publicPoint === null || rPoint === null) return false;
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
    throw new Error("strict Ed25519 verifier accepted wrong message");
  }
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const identityForgery = Buffer.alloc(64);
  identity.copy(identityForgery, 0);
  if (verifyEd25519(identity, Buffer.from("any message"), identityForgery)) {
    throw new Error("strict Ed25519 verifier accepted identity forgery");
  }
  const nonCanonicalScalar = Buffer.from(signature);
  littleEndianBytes(ED25519_GROUP_ORDER, 32).copy(nonCanonicalScalar, 32);
  if (verifyEd25519(publicKey, Buffer.alloc(0), nonCanonicalScalar)) {
    throw new Error("strict Ed25519 verifier accepted S >= L");
  }
  const nonCanonicalPoint = littleEndianBytes(ED25519_FIELD, 32);
  if (verifyEd25519(nonCanonicalPoint, Buffer.alloc(0), signature)) {
    throw new Error("strict Ed25519 verifier accepted noncanonical public key");
  }
  const nonCanonicalR = Buffer.from(signature);
  nonCanonicalPoint.copy(nonCanonicalR, 0);
  if (verifyEd25519(publicKey, Buffer.alloc(0), nonCanonicalR)) {
    throw new Error("strict Ed25519 verifier accepted noncanonical R");
  }
}

function cmp(first, second) {
  return Buffer.compare(first, second);
}

function equal(first, second) {
  return Buffer.isBuffer(first) && Buffer.isBuffer(second) && first.equals(second);
}

function mutateByte(raw, offset = raw.length - 1) {
  const result = Buffer.from(raw);
  result[offset] ^= 0x01;
  return result;
}

class Decoder {
  constructor(raw, rootCap = ACTIVE_MAX_BLOCK_BYTES) {
    if (!Buffer.isBuffer(raw)) fail("source_vector_drift", 0, "decoder input is not bytes", "gate");
    if (raw.length > rootCap) {
      fail("length_limit_exceeded", 0, `root length ${raw.length} exceeds ${rootCap}`);
    }
    this.raw = raw;
    this.offset = 0;
    this.rootCap = rootCap;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.rootCap) {
      fail("length_limit_exceeded", this.offset, "invalid bounded length");
    }
    if (length > this.raw.length - this.offset) {
      fail("unexpected_eof", this.raw.length, `need ${length} bytes`);
    }
    const start = this.offset;
    this.offset += length;
    return this.raw.subarray(start, this.offset);
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

  signature64() {
    return this.take(64);
  }

  bytes(max = this.rootCap) {
    const offset = this.offset;
    const length = Number(this.unsigned(4));
    if (length > max || length > this.rootCap) {
      fail("length_limit_exceeded", offset, `Bytes length ${length} exceeds ${Math.min(max, this.rootCap)}`);
    }
    return this.take(length);
  }

  consensusString() {
    const offset = this.offset;
    const length = Number(this.unsigned(2));
    if (length > 128) fail("length_limit_exceeded", offset, "ConsensusString exceeds 128");
    const raw = this.take(length);
    if (
      raw.length === 0 ||
      !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(raw.toString("latin1"))
    ) {
      fail("invalid_consensus_string", offset, "invalid consensus string");
    }
    return raw;
  }

  count(minimumItemBytes, explicitMaximum = null) {
    const offset = this.offset;
    const count = Number(this.unsigned(4));
    const capMaximum = Math.floor((this.rootCap - 4) / minimumItemBytes);
    const maximum = explicitMaximum === null
      ? capMaximum
      : Math.min(capMaximum, explicitMaximum);
    if (count > maximum) {
      fail("count_limit_exceeded", offset, `count ${count} exceeds bounded maximum ${maximum}`);
    }
    if (count * minimumItemBytes > this.raw.length - this.offset) {
      fail("unexpected_eof", this.raw.length, "declared list cannot fit minimum item frames");
    }
    return count;
  }

  finish() {
    if (this.offset !== this.raw.length) {
      fail("trailing_bytes", this.offset, `${this.raw.length - this.offset} trailing bytes`);
    }
  }
}

function decodeUtf8(raw, offset) {
  try {
    UTF8.decode(raw);
  } catch {
    fail("invalid_utf8", offset, "runtime string is not exact UTF-8");
  }
  return raw;
}

function encodeContext(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis_hash,
    consensusString(value.chain_id),
    u(value.protocol_version, 4),
    u(value.epoch, 8),
    value.validator_set_hash,
    u(value.view, 8),
    u(value.message_kind, 1),
  ]);
}

function decodeContext(decoder) {
  const start = decoder.offset;
  const schema = decoder.unsigned(2);
  const genesisOffset = decoder.offset;
  const genesis_hash = decoder.hash32();
  const chainOffset = decoder.offset;
  const chain_id = decoder.consensusString();
  const protocolOffset = decoder.offset;
  const protocol_version = decoder.unsigned(4);
  const epoch = decoder.unsigned(8);
  const validatorSetOffset = decoder.offset;
  const validator_set_hash = decoder.hash32();
  const view = decoder.unsigned(8);
  const messageKindOffset = decoder.offset;
  const message_kind = Number(decoder.unsigned(1));
  const value = {
    genesis_hash,
    chain_id,
    protocol_version,
    epoch,
    validator_set_hash,
    view,
    message_kind,
  };
  value.schema_version = schema;
  value.cev0 = Buffer.concat([
    u(schema, 2),
    value.genesis_hash,
    consensusString(value.chain_id),
    u(value.protocol_version, 4),
    u(value.epoch, 8),
    value.validator_set_hash,
    u(value.view, 8),
    u(value.message_kind, 1),
  ]);
  value._offsets = {
    start,
    genesis_hash: genesisOffset,
    chain: chainOffset,
    protocol_version: protocolOffset,
    validator_set_hash: validatorSetOffset,
    message_kind: messageKindOffset,
  };
  return value;
}

function contextsEqual(first, second) {
  return equal(first.cev0, second.cev0);
}

function encodeApplicationPayload(items) {
  return list(items, bytes);
}

function decodeApplicationPayloadExact(raw, rootCap = ACTIVE_MAX_BLOCK_BYTES) {
  const decoder = new Decoder(raw, rootCap);
  const count = decoder.count(4);
  const items = [];
  for (let index = 0; index < count; index += 1) items.push(decoder.bytes());
  decoder.finish();
  if (!equal(encodeApplicationPayload(items), raw)) {
    fail("source_vector_drift", 0, "payload failed exact re-encoding", "gate");
  }
  return items;
}

function encodeEventAttribute(value) {
  return Buffer.concat([bytes(value.key), bytes(value.value)]);
}

function encodeEvent(value) {
  return Buffer.concat([
    bytes(value.kind),
    list(value.attributes, encodeEventAttribute),
  ]);
}

function decodeEvent(decoder) {
  const kindOffset = decoder.offset;
  const kind = decoder.bytes();
  const count = decoder.count(8);
  const attributes = [];
  for (let index = 0; index < count; index += 1) {
    const keyOffset = decoder.offset;
    const key = decoder.bytes();
    const valueOffset = decoder.offset;
    const value = decoder.bytes();
    attributes.push({ key, value, _offsets: { key: keyOffset, value: valueOffset } });
  }
  return { kind, attributes, _offsets: { kind: kindOffset } };
}

function admitEvent(event) {
  decodeUtf8(event.kind, event._offsets.kind);
  for (let index = 1; index < event.attributes.length; index += 1) {
    const attribute = event.attributes[index];
    if (index > 0 && cmp(event.attributes[index - 1].key, attribute.key) >= 0) {
      fail(
        "noncanonical_event_attribute_order",
        attribute._offsets.key,
        "attribute keys are not strictly increasing",
      );
    }
  }
  for (const attribute of event.attributes) {
    decodeUtf8(attribute.key, attribute._offsets.key);
    decodeUtf8(attribute.value, attribute._offsets.value);
  }
}

function decodeExecutionEventExact(raw, rootCap = ACTIVE_MAX_BLOCK_BYTES) {
  const decoder = new Decoder(raw, rootCap);
  const event = decodeEvent(decoder);
  decoder.finish();
  admitEvent(event);
  if (!equal(encodeEvent(event), raw)) {
    fail("source_vector_drift", 0, "event failed exact re-encoding", "gate");
  }
  return event;
}

function encodeReceipt(value) {
  return Buffer.concat([
    u(0, 2),
    u(value.transaction_index, 4),
    value.payload_leaf_hash,
    u(value.gas_used, 8),
    u(value.fee_charged, 16),
    list(value.events, encodeEvent),
  ]);
}

function decodeExecutionReceiptExact(raw, rootCap = ACTIVE_MAX_BLOCK_BYTES) {
  const decoder = new Decoder(raw, rootCap);
  const schemaOffset = decoder.offset;
  const schema = decoder.unsigned(2);
  const value = {
    transaction_index: decoder.unsigned(4),
    payload_leaf_hash: decoder.hash32(),
    gas_used: decoder.unsigned(8),
    fee_charged: decoder.unsigned(16),
  };
  const count = decoder.count(8);
  value.events = [];
  for (let index = 0; index < count; index += 1) value.events.push(decodeEvent(decoder));
  decoder.finish();
  if (schema !== 0n) fail("invalid_schema_version", schemaOffset, "receipt schema is not 0");
  for (const event of value.events) admitEvent(event);
  if (!equal(encodeReceipt(value), raw)) {
    fail("source_vector_drift", 0, "receipt failed exact re-encoding", "gate");
  }
  return value;
}

function encodeVoteSign(record) {
  return Buffer.concat([
    encodeContext(record.context),
    u(record.height, 8),
    record.block_id,
  ]);
}

function voteSigningRoot(record) {
  return digest(DOMAIN_VOTE, encodeVoteSign(record));
}

function encodeVoteRecord(record) {
  return Buffer.concat([
    encodeContext(record.context),
    u(record.height, 8),
    record.block_id,
    bytes(record.author),
    record.signature,
  ]);
}

function decodeVoteRecord(decoder) {
  const start = decoder.offset;
  const context = decodeContext(decoder);
  const heightOffset = decoder.offset;
  const height = decoder.unsigned(8);
  const block_id = decoder.hash32();
  const authorOffset = decoder.offset;
  const author = decoder.bytes(128);
  const signature = decoder.signature64();
  const value = { context, height, block_id, author, signature };
  value.signing_root = voteSigningRoot(value);
  value._offsets = { start, height: heightOffset, author: authorOffset };
  return value;
}

function encodeDoubleVote(value) {
  return Buffer.concat([u(0, 2), encodeVoteRecord(value.first), encodeVoteRecord(value.second)]);
}

function admitDoubleVote(value, schemaOffset = 0) {
  for (const record of [value.first, value.second]) {
    if (record.context.schema_version !== 0n) {
      fail("invalid_schema_version", record.context._offsets.start, "context schema is not 0");
    }
    if (record.context.protocol_version !== 0n) {
      fail(
        "invalid_protocol_version",
        record.context._offsets.protocol_version,
        "context protocol version is not 0",
      );
    }
    if (record.context.message_kind !== 1) {
      fail(
        "context_mismatch",
        record.context._offsets.message_kind,
        "evidence context is not vote",
      );
    }
    if (record.context.genesis_hash.every((byte) => byte === 0)) {
      fail(
        "zero_genesis_hash",
        record.context._offsets.genesis_hash,
        "evidence genesis hash is zero",
      );
    }
    if (record.context.validator_set_hash.every((byte) => byte === 0)) {
      fail(
        "context_mismatch",
        record.context._offsets.validator_set_hash,
        "evidence validator-set hash is zero",
      );
    }
    if (record.author.length === 0) {
      fail("length_limit_exceeded", record._offsets.author, "empty author validator ID");
    }
  }
  if (!contextsEqual(value.first.context, value.second.context)) {
    fail(
      "context_mismatch",
      value.second._offsets.start,
      "evidence contexts differ",
      "admission",
    );
  }
  if (!equal(value.first.author, value.second.author)) {
    fail(
      "invalid_double_vote_evidence",
      value.second._offsets.author,
      "evidence authors differ",
      "admission",
    );
  }
  if (
    value.first.height === value.second.height &&
    equal(value.first.block_id, value.second.block_id)
  ) {
    fail(
      "invalid_double_vote_evidence",
      value.second._offsets.height,
      "evidence vote tuples are equal",
      "admission",
    );
  }
  if (cmp(value.first.signing_root, value.second.signing_root) >= 0) {
    fail(
      "invalid_double_vote_evidence",
      value.second._offsets.start,
      "evidence record signing-root order is noncanonical",
      "admission",
    );
  }
}

function decodeDoubleVoteEvidenceExact(raw, trust = null) {
  const decoder = new Decoder(raw, Number.MAX_SAFE_INTEGER);
  const schemaOffset = decoder.offset;
  const schema = decoder.unsigned(2);
  const value = {
    first: decodeVoteRecord(decoder),
    second: decodeVoteRecord(decoder),
  };
  decoder.finish();
  if (schema !== 0n) fail("invalid_schema_version", schemaOffset, "evidence schema is not 0");
  admitDoubleVote(value, schemaOffset);
  if (trust !== null) {
    for (const record of [value.first, value.second]) {
      const context = record.context;
      if (
        !equal(context.genesis_hash, trust.context.genesis_hash) ||
        !equal(context.chain_id, trust.context.chain_id) ||
        context.protocol_version !== trust.context.protocol_version ||
        context.epoch !== trust.context.epoch ||
        !equal(context.validator_set_hash, trust.context.validator_set_hash)
      ) {
        fail(
          "context_mismatch",
          context._offsets.start,
          "evidence context differs from authenticated active set",
        );
      }
      if (!trust.activeSet.byHex.has(record.author.toString("hex"))) {
        fail("unknown_signer", record._offsets.author, "evidence author is not active");
      }
    }
  }
  if (!equal(encodeDoubleVote(value), raw)) {
    fail("invalid_double_vote_evidence", 0, "evidence failed exact re-encoding", "admission");
  }
  value.cev0 = raw;
  value.evidence_id = digest(DOMAIN_EVIDENCE, raw);
  return value;
}

function validateEvidenceSignatures(value, activeKeys) {
  const key = activeKeys.get(value.first.author.toString("hex"));
  if (key === undefined) {
    fail("unknown_signer", value.first._offsets.author, "evidence author is not active");
  }
  if (
    !verifyEd25519(key, value.first.signing_root, value.first.signature) ||
    !verifyEd25519(key, value.second.signing_root, value.second.signature)
  ) {
    fail("invalid_evidence_signature", 0, "active-set Ed25519 verification failed", "admission");
  }
}

function orderedLeaf(kind, index, item) {
  return digest(
    DOMAIN_ORDERED_LEAF,
    Buffer.concat([u(0, 2), u(kind, 1), u(index, 4), bytes(item)]),
  );
}

function orderedNode(kind, level, left, right) {
  return digest(
    DOMAIN_ORDERED_NODE,
    Buffer.concat([u(0, 2), u(kind, 1), u(level, 4), left, right]),
  );
}

function orderedRoot(kind, items) {
  if (items.length > 0xffffffff) {
    fail("count_limit_exceeded", 0, "ordered-root item count exceeds u32", "admission");
  }
  let level = 0;
  let current = items.map((item, index) => orderedLeaf(kind, index, item));
  while (current.length > 1) {
    const next = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(
        orderedNode(
          kind,
          level,
          current[index],
          current[index + 1] ?? current[index],
        ),
      );
    }
    current = next;
    level += 1;
  }
  const optional = current.length === 0
    ? Buffer.from([0])
    : Buffer.concat([Buffer.from([1]), current[0]]);
  return digest(
    DOMAIN_ORDERED_ROOT,
    Buffer.concat([u(0, 2), u(kind, 1), u(items.length, 4), optional]),
  );
}

function encodeHeader(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis_hash,
    consensusString(value.chain_id),
    u(value.protocol_version, 4),
    u(value.epoch, 8),
    u(value.view, 8),
    u(value.height, 8),
    u(value.block_kind, 1),
    value.parent_block_id,
    bytes(value.proposer_id),
    value.active_validator_set_hash,
    value.consensus_parameters_hash,
    value.payload_root,
    value.state_root,
    value.receipts_root,
    value.evidence_root,
    u(value.timestamp_ms, 8),
    value.next_epoch_commitment_hash === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), value.next_epoch_commitment_hash]),
  ]);
}

function decodeHeaderExact(raw, rootCap = ACTIVE_MAX_BLOCK_BYTES) {
  const decoder = new Decoder(raw, rootCap);
  const schemaOffset = decoder.offset;
  const schema = decoder.unsigned(2);
  const genesisOffset = decoder.offset;
  const genesis_hash = decoder.hash32();
  const chain_id = decoder.consensusString();
  const protocolOffset = decoder.offset;
  const protocol_version = decoder.unsigned(4);
  const epoch = decoder.unsigned(8);
  const view = decoder.unsigned(8);
  const height = decoder.unsigned(8);
  const blockKindOffset = decoder.offset;
  const block_kind = Number(decoder.unsigned(1));
  if (block_kind > 4) {
    fail("invalid_block_kind", blockKindOffset, "header block kind is unknown");
  }
  const parent_block_id = decoder.hash32();
  const proposerOffset = decoder.offset;
  const proposer_id = decoder.bytes(128);
  const value = {
    genesis_hash,
    chain_id,
    protocol_version,
    epoch,
    view,
    height,
    block_kind,
    parent_block_id,
    proposer_id,
    active_validator_set_hash: decoder.hash32(),
    consensus_parameters_hash: decoder.hash32(),
    payload_root: decoder.hash32(),
    state_root: decoder.hash32(),
    receipts_root: decoder.hash32(),
    evidence_root: decoder.hash32(),
    timestamp_ms: decoder.unsigned(8),
  };
  const optionalOffset = decoder.offset;
  const tag = Number(decoder.unsigned(1));
  if (tag === 0) value.next_epoch_commitment_hash = null;
  else if (tag === 1) value.next_epoch_commitment_hash = decoder.hash32();
  else fail("invalid_optional_tag", optionalOffset, "header optional tag is invalid");
  decoder.finish();
  if (schema !== 0n) fail("invalid_schema_version", schemaOffset, "header schema is not 0");
  if (value.genesis_hash.every((byte) => byte === 0)) {
    fail("zero_genesis_hash", genesisOffset, "header genesis hash is zero");
  }
  if (value.protocol_version !== 0n) {
    fail("invalid_block_header", protocolOffset, "header protocol version is not 0");
  }
  if (value.proposer_id.length === 0) {
    fail("length_limit_exceeded", proposerOffset, "header proposer ID is empty");
  }
  if (value.view === 0n || value.height === 0n) {
    fail("invalid_block_header", 0, "header shape is invalid", "admission");
  }
  if (value.active_validator_set_hash.every((byte) => byte === 0)) {
    fail("invalid_block_header", 0, "header active validator set hash is zero", "admission");
  }
  const requiresCommitment = [1, 2, 3].includes(value.block_kind);
  if (
    (requiresCommitment && value.next_epoch_commitment_hash === null) ||
    (!requiresCommitment && value.next_epoch_commitment_hash !== null)
  ) {
    fail("invalid_block_header", 0, "block kind/next commitment presence mismatch", "admission");
  }
  value.cev0 = raw;
  value.block_id = digest(DOMAIN_BLOCK, raw);
  return value;
}

function encodeValidatorSet(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis_hash,
    consensusString(value.chain_id),
    u(value.protocol_version, 4),
    u(value.epoch, 8),
    value.consensus_parameters_hash,
    list(value.validators, (validator) =>
      Buffer.concat([
        bytes(validator.id),
        validator.public_key_raw,
        u(validator.power, 8),
      ]),
    ),
  ]);
}

function decodeValidatorSetExact(raw) {
  const decoder = new Decoder(raw);
  const objectOffset = decoder.offset;
  const schema = decoder.unsigned(2);
  const genesisOffset = decoder.offset;
  const value = {
    genesis_hash: decoder.hash32(),
    chain_id: decoder.consensusString(),
    protocol_version: decoder.unsigned(4),
    epoch: decoder.unsigned(8),
    consensus_parameters_hash: decoder.hash32(),
    validators: [],
  };
  const countOffset = decoder.offset;
  const count = decoder.count(48, 100);
  for (let index = 0; index < count; index += 1) {
    const offset = decoder.offset;
    value.validators.push({
      id: decoder.bytes(128),
      public_key_raw: decoder.hash32(),
      power: decoder.unsigned(8),
      offset,
    });
  }
  decoder.finish();
  if (schema !== 0n) fail("invalid_schema_version", objectOffset, "set schema is not 0");
  if (value.genesis_hash.every((byte) => byte === 0)) {
    fail("zero_genesis_hash", genesisOffset, "set genesis hash is zero");
  }
  if (value.protocol_version !== 0n) fail("invalid_protocol_version", 0, "set protocol is not 0");
  if (value.validators.length === 0) fail("empty_validator_set", countOffset, "set is empty");
  const publicKeys = new Set();
  let previous = null;
  for (const validator of value.validators) {
    if (validator.id.length === 0) {
      fail("length_limit_exceeded", validator.offset, "validator ID is empty");
    }
    if (validator.public_key_raw.every((byte) => byte === 0)) {
      fail("zero_public_key", validator.offset, "validator key is zero");
    }
    if (validator.power === 0n) fail("zero_voting_power", validator.offset, "validator power is zero");
    if (previous !== null && cmp(previous, validator.id) >= 0) {
      fail(
        equal(previous, validator.id) ? "duplicate_validator_id" : "noncanonical_validator_order",
        validator.offset,
        "validator order is not strict",
      );
    }
    const publicHex = validator.public_key_raw.toString("hex");
    if (publicKeys.has(publicHex)) {
      fail("duplicate_public_key", validator.offset, "duplicate consensus key");
    }
    publicKeys.add(publicHex);
    previous = validator.id;
  }
  value.cev0 = raw;
  value.validator_set_hash = digest(DOMAIN_VALIDATOR_SET, raw);
  return value;
}

function prepareActiveSet(activeSetRaw, activeContext) {
  const activeSet = decodeValidatorSetExact(activeSetRaw);
  const parameters = loadReferenceParameters();
  if (
    !equal(activeSet.genesis_hash, activeContext.genesis_hash) ||
    !equal(activeSet.chain_id, activeContext.chain_id) ||
    activeSet.protocol_version !== activeContext.protocol_version ||
    activeSet.epoch !== activeContext.epoch ||
    !equal(activeSet.consensus_parameters_hash, activeContext.consensus_parameters_hash) ||
    !equal(activeSet.validator_set_hash, activeContext.validator_set_hash)
  ) {
    fail("validator_set_context_mismatch", 0, "active set preimage/context mismatch", "admission");
  }
  const totalPower = activeSet.validators.reduce(
    (sum, validator) => sum + validator.power,
    0n,
  );
  if (
    activeSet.validators.length < parameters.minValidators ||
    activeSet.validators.length > parameters.maxValidators ||
    totalPower > parameters.maxTotalPower ||
    activeSet.validators.some(
      (validator) =>
        validator.power < parameters.minValidatorPower ||
        validator.power > parameters.maxValidatorPower,
    ) ||
    activeSet.validators.some(
      (validator) =>
        validator.power * parameters.scalePpm >
        totalPower * parameters.maxValidatorSharePpm,
    )
  ) {
    fail(
      "validator_set_context_mismatch",
      0,
      "active set violates reference parameter bounds",
      "admission",
    );
  }
  return {
    value: activeSet,
    byHex: new Map(activeSet.validators.map((validator) => [
      validator.id.toString("hex"),
      validator,
    ])),
    keys: new Map(activeSet.validators.map((validator) => [
      validator.id.toString("hex"),
      validator.public_key_raw,
    ])),
  };
}

function validateActiveParameterContext(activeContext) {
  const parameters = loadReferenceParameters();
  if (
    !equal(parameters.digest, activeContext.consensus_parameters_hash) ||
    activeContext.active_max_block_bytes !== parameters.maxBlockBytes
  ) {
    fail(
      "parameters_context_mismatch",
      0,
      "active parameter hash/max_block_bytes split from the reference commitment",
      "admission",
    );
  }
}

function encodeQc(value) {
  return Buffer.concat([
    u(0, 2),
    value.genesis_hash,
    consensusString(value.chain_id),
    u(value.protocol_version, 4),
    u(value.epoch, 8),
    value.validator_set_hash,
    u(value.view, 8),
    u(value.height, 8),
    value.block_id,
    list(value.signatures, (share) => Buffer.concat([bytes(share.signer), share.signature])),
  ]);
}

function decodeOrdinaryQcExact(raw, activeValidators, activeContext) {
  const decoder = new Decoder(raw);
  const schemaOffset = decoder.offset;
  const schema = decoder.unsigned(2);
  const value = {
    genesis_hash: decoder.hash32(),
    chain_id: decoder.consensusString(),
    protocol_version: decoder.unsigned(4),
    epoch: decoder.unsigned(8),
    validator_set_hash: decoder.hash32(),
    view: decoder.unsigned(8),
    height: decoder.unsigned(8),
    block_id: decoder.hash32(),
  };
  const viewOffset = decoder.offset - 8 - 8 - 32;
  const countOffset = decoder.offset;
  const count = decoder.count(68, 100);
  value.signatures = [];
  for (let index = 0; index < count; index += 1) {
    const signerOffset = decoder.offset;
    const signer = decoder.bytes(128);
    const signature = decoder.signature64();
    value.signatures.push({ signer, signature, signerOffset });
  }
  decoder.finish();
  if (schema !== 0n) fail("invalid_schema_version", schemaOffset, "QC schema is not 0");
  if (value.protocol_version !== 0n) fail("invalid_protocol_version", 0, "QC protocol is not 0");
  if (
    !equal(value.genesis_hash, activeContext.genesis_hash) ||
    !equal(value.chain_id, activeContext.chain_id) ||
    value.protocol_version !== activeContext.protocol_version ||
    value.epoch !== activeContext.epoch ||
    !equal(value.validator_set_hash, activeContext.validator_set_hash)
  ) {
    fail("ordinary_proposal_certificate_mismatch", 0, "QC active context differs", "proposal");
  }
  if (value.view === 0n || value.signatures.length === 0) {
    fail(
      "unauthorized_synthetic_qc",
      value.view === 0n ? viewOffset : countOffset,
      "ordinary proposal cannot carry a view-0 or empty-signature QC",
      "proposal",
    );
  }
  let previous = null;
  let power = 0n;
  const voteContext = {
    genesis_hash: value.genesis_hash,
    chain_id: value.chain_id,
    protocol_version: value.protocol_version,
    epoch: value.epoch,
    validator_set_hash: value.validator_set_hash,
    view: value.view,
    message_kind: 1,
  };
  const signingRoot = voteSigningRoot({
    context: voteContext,
    height: value.height,
    block_id: value.block_id,
  });
  for (const share of value.signatures) {
    if (share.signer.length === 0) {
      fail("unknown_signer", share.signerOffset, "empty QC signer");
    }
    if (previous !== null && cmp(previous, share.signer) >= 0) {
      fail(
        equal(previous, share.signer) ? "duplicate_signer" : "noncanonical_signer_order",
        share.signerOffset,
        "QC signer order is not strict",
      );
    }
    const validator = activeValidators.get(share.signer.toString("hex"));
    if (validator === undefined) fail("unknown_signer", share.signerOffset, "unknown QC signer");
    if (!verifyEd25519(validator.public_key_raw, signingRoot, share.signature)) {
      fail(
        "ordinary_proposal_certificate_mismatch",
        share.signerOffset,
        "QC signature is invalid",
        "proposal",
      );
    }
    power += validator.power;
    previous = share.signer;
  }
  const totalPower = [...activeValidators.values()].reduce(
    (sum, validator) => sum + validator.power,
    0n,
  );
  if (totalPower === 0n) {
    fail("ordinary_proposal_certificate_mismatch", 0, "active set has zero power", "proposal");
  }
  const quorum = (2n * totalPower) / 3n + 1n;
  if (power < quorum) fail("insufficient_quorum", 0, "QC lacks weighted quorum");
  if (!equal(encodeQc(value), raw)) {
    fail("ordinary_proposal_certificate_mismatch", 0, "QC exact re-encoding failed", "proposal");
  }
  value.cev0 = raw;
  value.qc_digest = digest(DOMAIN_QC, raw);
  return value;
}

function encodeProposalSign(value) {
  return Buffer.concat([
    encodeContext(value.context),
    u(value.height, 8),
    value.block_id,
    value.justify_qc_digest,
    value.timeout_certificate_digest === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), value.timeout_certificate_digest]),
    value.handoff_certificate_digest === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), value.handoff_certificate_digest]),
  ]);
}

function proposalSigningRoot(value) {
  return digest(DOMAIN_PROPOSAL, encodeProposalSign(value));
}

function decodeOptionalHash(decoder) {
  const offset = decoder.offset;
  const tag = Number(decoder.unsigned(1));
  if (tag === 0) return null;
  if (tag === 1) return decoder.hash32();
  fail("invalid_optional_tag", offset, "optional hash tag is invalid");
}

function decodeProposalSignExact(raw) {
  const decoder = new Decoder(raw, Number.MAX_SAFE_INTEGER);
  const value = {
    context: decodeContext(decoder),
    height: decoder.unsigned(8),
    block_id: decoder.hash32(),
    justify_qc_digest: decoder.hash32(),
    timeout_certificate_digest: decodeOptionalHash(decoder),
    handoff_certificate_digest: decodeOptionalHash(decoder),
  };
  decoder.finish();
  if (value.context.schema_version !== 0n) {
    fail("invalid_schema_version", value.context._offsets.start, "proposal context schema");
  }
  if (value.context.protocol_version !== 0n) {
    fail("invalid_protocol_version", value.context._offsets.protocol_version, "proposal protocol");
  }
  if (value.context.message_kind !== 0) {
    fail("context_mismatch", value.context._offsets.message_kind, "proposal context kind");
  }
  return value;
}

function receiptListBytes(receipts) {
  return list(receipts.map(encodeReceipt), bytes);
}

function validateReceiptRelations(payloadItems, receipts, activeMaxBlockBytes) {
  if (receipts.length !== payloadItems.length) {
    fail("receipt_count_mismatch", 0, "receipt count differs from transaction count", "admission");
  }
  for (let index = 0; index < receipts.length; index += 1) {
    if (receipts[index].transaction_index !== BigInt(index)) {
      fail("receipt_index_mismatch", 0, "receipt index is not contiguous", "admission");
    }
    const leaf = orderedLeaf(0, index, payloadItems[index]);
    if (!equal(receipts[index].payload_leaf_hash, leaf)) {
      fail("payload_leaf_mismatch", 0, "receipt payload leaf differs", "admission");
    }
  }
  if (receiptListBytes(receipts).length > activeMaxBlockBytes) {
    fail("receipt_list_size_exceeded", 0, "derived receipt List<Bytes> exceeds active limit", "admission");
  }
}

function validateEvidenceOrder(evidence) {
  for (let index = 1; index < evidence.length; index += 1) {
    const comparison = cmp(evidence[index - 1].evidence_id, evidence[index].evidence_id);
    if (comparison === 0) fail("duplicate_evidence", 0, "duplicate evidence ID", "admission");
    if (comparison > 0) {
      fail("noncanonical_evidence_order", 0, "evidence IDs are not strictly increasing", "admission");
    }
  }
}

function logicalBlockSize(headerRaw, payloadRaw, evidenceRaw) {
  let size = BigInt(headerRaw.length);
  for (const addend of [
    4n,
    BigInt(payloadRaw.length),
    4n,
    ...evidenceRaw.map((item) => 4n + BigInt(item.length)),
  ]) {
    size += addend;
    if (size > 0xffffffffffffffffn) {
      fail("logical_block_size_exceeded", 0, "logical size overflows u64", "admission");
    }
  }
  return size;
}

function validateOrdinaryBlockBody({
  headerRaw,
  payloadRaw,
  receiptsRaw,
  evidenceRaw,
  activeContext,
  activeSetRaw,
}) {
  validateActiveParameterContext(activeContext);
  const activeMaxBlockBytes = activeContext.active_max_block_bytes;
  const header = decodeHeaderExact(headerRaw, activeMaxBlockBytes);
  const payloadItems = decodeApplicationPayloadExact(payloadRaw, activeMaxBlockBytes);
  const receipts = receiptsRaw.map((raw) =>
    decodeExecutionReceiptExact(raw, activeMaxBlockBytes),
  );
  const activeSet = prepareActiveSet(activeSetRaw, activeContext);
  const evidence = evidenceRaw.map((raw) =>
    decodeDoubleVoteEvidenceExact(raw, { activeSet, context: activeContext }),
  );
  if (header.block_kind !== 0 || header.next_epoch_commitment_hash !== null) {
    fail("non_regular_block", 0, "B2-D admits regular blocks only", "admission");
  }
  if (
    !equal(header.genesis_hash, activeContext.genesis_hash) ||
    !equal(header.chain_id, activeContext.chain_id) ||
    header.protocol_version !== activeContext.protocol_version ||
    header.epoch !== activeContext.epoch ||
    !equal(header.consensus_parameters_hash, activeContext.consensus_parameters_hash)
  ) {
    fail("parameters_context_mismatch", 0, "header parameter context differs", "admission");
  }
  if (!equal(header.active_validator_set_hash, activeContext.validator_set_hash)) {
    fail("validator_set_context_mismatch", 0, "header set context differs", "admission");
  }
  validateReceiptRelations(payloadItems, receipts, activeMaxBlockBytes);
  validateEvidenceOrder(evidence);
  const payloadRoot = orderedRoot(0, payloadItems);
  const receiptsRoot = orderedRoot(1, receiptsRaw);
  const evidenceRoot = orderedRoot(2, evidenceRaw);
  if (!equal(header.payload_root, payloadRoot)) {
    fail("payload_root_mismatch", 0, "payload root differs", "admission");
  }
  if (!equal(header.receipts_root, receiptsRoot)) {
    fail("receipts_root_mismatch", 0, "receipts root differs", "admission");
  }
  if (!equal(header.evidence_root, evidenceRoot)) {
    fail("evidence_root_mismatch", 0, "evidence root differs", "admission");
  }
  const size = logicalBlockSize(header.cev0, payloadRaw, evidenceRaw);
  if (size > BigInt(activeMaxBlockBytes)) {
    fail("logical_block_size_exceeded", 0, "logical block exceeds active max", "admission");
  }
  for (const item of evidence) validateEvidenceSignatures(item, activeSet.keys);
  return { payloadRoot, receiptsRoot, evidenceRoot, logicalSize: size };
}

function validateOrdinaryProposalBinding({
  headerRaw,
  proposal,
  justifyQcRaw,
  activeSetRaw,
  activeContext,
}) {
  validateActiveParameterContext(activeContext);
  const header = decodeHeaderExact(headerRaw, activeContext.active_max_block_bytes);
  const activeSet = prepareActiveSet(activeSetRaw, activeContext);
  if (header.block_kind !== 0 || header.next_epoch_commitment_hash !== null) {
    fail("non_regular_block", 0, "ordinary proposal carries non-regular block", "proposal");
  }
  if (
    proposal.epoch_anchor_authorization_present ||
    proposal.handoff_certificate_digest !== null
  ) {
    fail("ordinary_proposal_context_mismatch", 0, "ordinary proposal carries anchor/handoff data", "proposal");
  }
  if (
    proposal.timeout_certificate_present ||
    proposal.timeout_certificate_digest !== null
  ) {
    fail("ordinary_proposal_certificate_mismatch", 0, "next-view fixture must not carry a TC", "proposal");
  }
  if (
    !equal(header.genesis_hash, activeContext.genesis_hash) ||
    !equal(header.chain_id, activeContext.chain_id) ||
    header.protocol_version !== activeContext.protocol_version ||
    header.epoch !== activeContext.epoch ||
    !equal(header.active_validator_set_hash, activeContext.validator_set_hash) ||
    !equal(header.consensus_parameters_hash, activeContext.consensus_parameters_hash)
  ) {
    fail("ordinary_proposal_context_mismatch", 0, "header differs from authenticated active context", "proposal");
  }
  if (header.view === 0n) {
    fail("ordinary_proposal_context_mismatch", 0, "ordinary proposal view must be positive", "proposal");
  }
  const leaderIndex = Number(
    (header.view - 1n) % BigInt(activeSet.value.validators.length),
  );
  if (!equal(header.proposer_id, activeSet.value.validators[leaderIndex].id)) {
    fail(
      "ordinary_proposal_context_mismatch",
      0,
      "header proposer is not the canonical round-robin leader",
      "proposal",
    );
  }
  const qc = decodeOrdinaryQcExact(justifyQcRaw, activeSet.byHex, activeContext);
  if (
    !equal(qc.qc_digest, proposal.justify_qc_digest) ||
    !equal(qc.block_id, header.parent_block_id) ||
    qc.height + 1n !== header.height ||
    qc.view + 1n !== header.view
  ) {
    fail("ordinary_proposal_certificate_mismatch", 0, "ordinary justify QC relation failed", "proposal");
  }
  const context = proposal.context;
  if (
    context.message_kind !== 0 ||
    !equal(context.genesis_hash, header.genesis_hash) ||
    !equal(context.chain_id, header.chain_id) ||
    context.protocol_version !== header.protocol_version ||
    context.epoch !== header.epoch ||
    !equal(context.validator_set_hash, header.active_validator_set_hash) ||
    context.view !== header.view ||
    proposal.height !== header.height ||
    !equal(proposal.block_id, header.block_id) ||
    !equal(proposal.proposer_id, header.proposer_id) ||
    !equal(activeContext.validator_set_hash, header.active_validator_set_hash)
  ) {
    fail("ordinary_proposal_context_mismatch", 0, "ordinary ProposalSignV0 binding failed", "proposal");
  }
  const proposer = activeSet.byHex.get(proposal.proposer_id.toString("hex"));
  const root = proposalSigningRoot(proposal);
  if (
    proposer === undefined ||
    !verifyEd25519(proposer.public_key_raw, root, proposal.signature)
  ) {
    fail("ordinary_proposal_signature_invalid", 0, "proposal signature failed", "proposal");
  }
  return { qc, signingRoot: root };
}

function clone(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]));
  }
  return value;
}

function makeValidator(identifier, power) {
  const privateKey = privateKeyFromSeed(fixtureSeed(identifier));
  const id = Buffer.from(identifier, "ascii");
  return {
    id,
    power: BigInt(power),
    private_key: privateKey,
    public_key_raw: publicKeyRaw(privateKey),
    public_key: publicKeyObject(publicKeyRaw(privateKey)),
  };
}

function validatorForId(validators, validatorId) {
  const validator = validators.find((candidate) => equal(candidate.id, validatorId));
  if (validator === undefined) {
    fail("source_vector_drift", 0, "header proposer is absent from the fixture set", "gate");
  }
  return validator;
}

function makeEvidence(author, context, firstTuple, secondTuple) {
  const unsigned = [firstTuple, secondTuple].map(([height, blockLabel]) => {
    const record = {
      context: clone(context),
      height: BigInt(height),
      block_id: labelHash(blockLabel),
      author: Buffer.from(author.id),
      signature: Buffer.alloc(64),
    };
    record.signing_root = voteSigningRoot(record);
    return record;
  });
  unsigned.sort((first, second) => cmp(first.signing_root, second.signing_root));
  for (const record of unsigned) {
    record.signature = sign(author.private_key, record.signing_root);
  }
  const value = { first: unsigned[0], second: unsigned[1] };
  value.cev0 = encodeDoubleVote(value);
  value.evidence_id = digest(DOMAIN_EVIDENCE, value.cev0);
  return value;
}

function makeQc(context, validators, view, height, blockId) {
  const voteContext = { ...clone(context), view: BigInt(view), message_kind: 1 };
  const unsigned = {
    genesis_hash: context.genesis_hash,
    chain_id: context.chain_id,
    protocol_version: context.protocol_version,
    epoch: context.epoch,
    validator_set_hash: context.validator_set_hash,
    view: BigInt(view),
    height: BigInt(height),
    block_id: blockId,
    signatures: [],
  };
  const root = voteSigningRoot({
    context: voteContext,
    height: unsigned.height,
    block_id: unsigned.block_id,
  });
  for (const validator of validators) {
    unsigned.signatures.push({
      signer: validator.id,
      signature: sign(validator.private_key, root),
    });
  }
  unsigned.cev0 = encodeQc(unsigned);
  unsigned.qc_digest = digest(DOMAIN_QC, unsigned.cev0);
  unsigned.signing_root = root;
  return unsigned;
}

function buildFixtureValues() {
  const validators = [
    makeValidator("validator-a", 1),
    makeValidator("validator-b", 1),
    makeValidator("validator-c", 1),
    makeValidator("validator-d", 1),
  ];
  const validatorByHex = new Map(validators.map((validator) => [
    validator.id.toString("hex"),
    validator,
  ]));
  const context = {
    genesis_hash: Buffer.from(
      "ba83a6d7b9341a0f66bece8025b3eb9592d1ef49a726285df16d4e7ecfdd3794",
      "hex",
    ),
    chain_id: Buffer.from("trnm-qc-tc-v0", "ascii"),
    protocol_version: 0n,
    epoch: 7n,
    validator_set_hash: Buffer.alloc(32),
    consensus_parameters_hash: loadReferenceParameters().digest,
    active_max_block_bytes: loadReferenceParameters().maxBlockBytes,
  };
  const activeSet = {
    genesis_hash: context.genesis_hash,
    chain_id: context.chain_id,
    protocol_version: context.protocol_version,
    epoch: context.epoch,
    consensus_parameters_hash: context.consensus_parameters_hash,
    validators,
  };
  activeSet.cev0 = encodeValidatorSet(activeSet);
  activeSet.validator_set_hash = digest(DOMAIN_VALIDATOR_SET, activeSet.cev0);
  context.validator_set_hash = activeSet.validator_set_hash;
  const payloadItems = [
    Buffer.from("transfer:alice->bob:7", "utf8"),
    Buffer.from([0x00, 0x01, 0x02, 0xff]),
    Buffer.from("runtime-call-v0", "utf8"),
  ];
  const payloadRaw = encodeApplicationPayload(payloadItems);
  const receipts = [
    {
      transaction_index: 0n,
      payload_leaf_hash: orderedLeaf(0, 0, payloadItems[0]),
      gas_used: 21000n,
      fee_charged: 777n,
      events: [{
        kind: Buffer.from("transfer", "utf8"),
        attributes: [
          { key: Buffer.from("amount"), value: Buffer.from("7") },
          { key: Buffer.from("from"), value: Buffer.from("alice") },
          { key: Buffer.from("to"), value: Buffer.from("bob") },
        ],
      }],
    },
    {
      transaction_index: 1n,
      payload_leaf_hash: orderedLeaf(0, 1, payloadItems[1]),
      gas_used: 9n,
      fee_charged: 1n,
      events: [{
        kind: Buffer.from("binary", "utf8"),
        attributes: [
          { key: Buffer.from("data"), value: Buffer.from("00ff") },
        ],
      }],
    },
    {
      transaction_index: 2n,
      payload_leaf_hash: orderedLeaf(0, 2, payloadItems[2]),
      gas_used: 0n,
      fee_charged: 0n,
      events: [],
    },
  ];
  const voteContext = {
    genesis_hash: context.genesis_hash,
    chain_id: context.chain_id,
    protocol_version: context.protocol_version,
    epoch: context.epoch,
    validator_set_hash: context.validator_set_hash,
    view: 2n,
    message_kind: 1,
  };
  const evidence = [
    makeEvidence(
      validators[2],
      voteContext,
      [9, "b2d-evidence-c-first"],
      [9, "b2d-evidence-c-second"],
    ),
    makeEvidence(
      validators[3],
      voteContext,
      [10, "b2d-evidence-d-first"],
      [11, "b2d-evidence-d-second"],
    ),
  ].sort((first, second) => cmp(first.evidence_id, second.evidence_id));
  const parentBlockId = labelHash("b2d-ordinary-parent");
  const qc = makeQc(context, validators.slice(0, 3), 3, 11, parentBlockId);
  const header = {
    genesis_hash: context.genesis_hash,
    chain_id: context.chain_id,
    protocol_version: context.protocol_version,
    epoch: context.epoch,
    view: 4n,
    height: 12n,
    block_kind: 0,
    parent_block_id: parentBlockId,
    proposer_id: validators[3].id,
    active_validator_set_hash: context.validator_set_hash,
    consensus_parameters_hash: context.consensus_parameters_hash,
    payload_root: orderedRoot(0, payloadItems),
    state_root: labelHash("b2d-state-root"),
    receipts_root: orderedRoot(1, receipts.map(encodeReceipt)),
    evidence_root: orderedRoot(2, evidence.map((item) => item.cev0)),
    timestamp_ms: 1_800_000_000_000n,
    next_epoch_commitment_hash: null,
  };
  header.cev0 = encodeHeader(header);
  header.block_id = digest(DOMAIN_BLOCK, header.cev0);
  const proposer = validatorForId(validators, header.proposer_id);
  const proposal = {
    context: {
      genesis_hash: context.genesis_hash,
      chain_id: context.chain_id,
      protocol_version: context.protocol_version,
      epoch: context.epoch,
      validator_set_hash: context.validator_set_hash,
      view: header.view,
      message_kind: 0,
    },
    proposer_id: header.proposer_id,
    height: header.height,
    block_id: header.block_id,
    justify_qc_digest: qc.qc_digest,
    timeout_certificate_digest: null,
    handoff_certificate_digest: null,
    timeout_certificate_present: false,
    epoch_anchor_authorization_present: false,
  };
  proposal.signing_root = proposalSigningRoot(proposal);
  proposal.signature = sign(proposer.private_key, proposal.signing_root);
  return {
    validators,
    validatorByHex,
    activeKeys: new Map(validators.map((validator) => [
      validator.id.toString("hex"),
      validator.public_key_raw,
    ])),
    context,
    activeSet,
    payloadItems,
    payloadRaw,
    receipts,
    evidence,
    qc,
    header,
    proposal,
  };
}

function expectError(operation, expected, label) {
  try {
    operation();
  } catch (error) {
    if (error instanceof KernelError && error.code === expected) return error;
    throw new Error(`${label}: expected ${expected}, received ${error}`);
  }
  throw new Error(`${label}: expected ${expected}, operation succeeded`);
}

let parserTrust = null;

function parserFor(name, raw) {
  if (name === "application_payload") return decodeApplicationPayloadExact(raw);
  if (name === "execution_receipt") return decodeExecutionReceiptExact(raw);
  if (name === "double_vote_evidence") return decodeDoubleVoteEvidenceExact(raw, parserTrust);
  if (name === "block_header") return decodeHeaderExact(raw);
  fail("source_vector_drift", 0, `unknown parser ${name}`, "gate");
}

function rawCase(id, parser, raw, expected) {
  const error = expectError(() => parserFor(parser, raw), expected, id);
  return {
    id,
    parser,
    raw_hex: raw.toString("hex"),
    expected_code: expected,
    expected_byte_offset: error.offset,
  };
}

function semanticEvidenceCase(id, value, expected = "invalid_double_vote_evidence") {
  return rawCase(id, "double_vote_evidence", encodeDoubleVote(value), expected);
}

function admitReceiptListSize(raw, activeMaxBlockBytes) {
  if (raw.length > activeMaxBlockBytes) {
    fail("receipt_list_size_exceeded", 0, "derived receipt list exceeds active maximum", "admission");
  }
}

function buildLogicalBoundary(values, delta) {
  const evidence = [];
  const emptyEvidenceRoot = orderedRoot(2, []);
  const skeletonHeader = {
    ...clone(values.header),
    evidence_root: emptyEvidenceRoot,
  };
  skeletonHeader.cev0 = encodeHeader(skeletonHeader);
  const target = ACTIVE_MAX_BLOCK_BYTES + delta;
  const transactionLength = target - skeletonHeader.cev0.length - 16;
  if (transactionLength < 0) fail("source_vector_drift", 0, "boundary transaction length is negative", "gate");
  const transaction = Buffer.alloc(transactionLength, 0xa5);
  const payloadItems = [transaction];
  const payloadRaw = encodeApplicationPayload(payloadItems);
  const receipts = [{
    transaction_index: 0n,
    payload_leaf_hash: orderedLeaf(0, 0, transaction),
    gas_used: 0n,
    fee_charged: 0n,
    events: [],
  }];
  const header = {
    ...skeletonHeader,
    payload_root: orderedRoot(0, payloadItems),
    receipts_root: orderedRoot(1, receipts.map(encodeReceipt)),
    evidence_root: emptyEvidenceRoot,
  };
  header.cev0 = encodeHeader(header);
  header.block_id = digest(DOMAIN_BLOCK, header.cev0);
  const size = logicalBlockSize(header.cev0, payloadRaw, evidence);
  if (size !== BigInt(target)) fail("source_vector_drift", 0, "logical boundary synthesis drift", "gate");
  return { transactionLength, payloadItems, payloadRaw, receipts, evidence, header, size };
}

function resignEvidence(value, validator, mutateContext) {
  const records = [clone(value.first), clone(value.second)];
  for (const record of records) {
    mutateContext(record.context);
    record.signature = Buffer.alloc(64);
    record.signing_root = voteSigningRoot(record);
  }
  records.sort((first, second) => cmp(first.signing_root, second.signing_root));
  for (const record of records) {
    record.signature = sign(validator.private_key, record.signing_root);
  }
  const result = { first: records[0], second: records[1] };
  result.cev0 = encodeDoubleVote(result);
  result.evidence_id = digest(DOMAIN_EVIDENCE, result.cev0);
  return result;
}

function makeProposalForHeader(values, header, qc, overrides = {}) {
  const proposer = validatorForId(values.validators, header.proposer_id);
  const proposal = {
    context: {
      genesis_hash: header.genesis_hash,
      chain_id: header.chain_id,
      protocol_version: header.protocol_version,
      epoch: header.epoch,
      validator_set_hash: header.active_validator_set_hash,
      view: header.view,
      message_kind: 0,
    },
    proposer_id: header.proposer_id,
    height: header.height,
    block_id: header.block_id,
    justify_qc_digest: qc.qc_digest,
    timeout_certificate_digest: null,
    handoff_certificate_digest: null,
    timeout_certificate_present: false,
    epoch_anchor_authorization_present: false,
    ...overrides,
  };
  proposal.signing_root = proposalSigningRoot(proposal);
  proposal.signature = sign(proposer.private_key, proposal.signing_root);
  return proposal;
}

function proposalCaseJson(id, header, proposal, qcRaw, expected) {
  return {
    id,
    header_cev0_hex: header.cev0.toString("hex"),
    proposal_sign_cev0_hex: encodeProposalSign(proposal).toString("hex"),
    proposer_id_hex: proposal.proposer_id.toString("hex"),
    proposer_signature_hex: proposal.signature.toString("hex"),
    justify_qc_cev0_hex: qcRaw.toString("hex"),
    timeout_certificate_present: proposal.timeout_certificate_present,
    epoch_anchor_authorization_present: proposal.epoch_anchor_authorization_present,
    expected_code: expected,
  };
}

function receiptCaseJson(id, receipts, expected) {
  return {
    id,
    receipt_cev0_hex: receipts.map((receipt) => encodeReceipt(receipt).toString("hex")),
    expected_code: expected,
  };
}

function bodyCaseJson(id, header, evidenceRaw, expected) {
  return {
    id,
    header_cev0_hex: encodeHeader(header).toString("hex"),
    evidence_cev0_hex: evidenceRaw.map((raw) => raw.toString("hex")),
    expected_code: expected,
  };
}

function jsonContext(context) {
  return {
    genesis_hash_hex: context.genesis_hash.toString("hex"),
    chain_id_ascii: context.chain_id.toString("ascii"),
    protocol_version: context.protocol_version.toString(),
    epoch: context.epoch.toString(),
    validator_set_hash_hex: context.validator_set_hash.toString("hex"),
    consensus_parameters_hash_hex: context.consensus_parameters_hash.toString("hex"),
    active_max_block_bytes: String(context.active_max_block_bytes),
  };
}

function buildCorpus() {
  strictEd25519SelfTest();
  const values = buildFixtureValues();
  const receiptRaw = values.receipts.map(encodeReceipt);
  const eventRaw = values.receipts.flatMap((receipt) => receipt.events.map(encodeEvent));
  const evidenceRaw = values.evidence.map((item) => item.cev0);

  const activeSet = prepareActiveSet(values.activeSet.cev0, values.context);
  parserTrust = { activeSet, context: values.context };
  for (const raw of [
    encodeApplicationPayload([]),
    values.payloadRaw,
  ]) decodeApplicationPayloadExact(raw);
  for (const raw of receiptRaw) decodeExecutionReceiptExact(raw);
  for (const raw of eventRaw) decodeExecutionEventExact(raw);
  for (const raw of evidenceRaw) {
    const decoded = decodeDoubleVoteEvidenceExact(raw, parserTrust);
    validateEvidenceSignatures(decoded, activeSet.keys);
  }
  decodeHeaderExact(values.header.cev0);
  const commitments = validateOrdinaryBlockBody({
    headerRaw: values.header.cev0,
    payloadRaw: values.payloadRaw,
    receiptsRaw: receiptRaw,
    evidenceRaw,
    activeContext: values.context,
    activeSetRaw: values.activeSet.cev0,
  });
  const proposalResult = validateOrdinaryProposalBinding({
    headerRaw: values.header.cev0,
    proposal: values.proposal,
    justifyQcRaw: values.qc.cev0,
    activeSetRaw: values.activeSet.cev0,
    activeContext: values.context,
  });

  const prefixObjects = [
    ["application_payload_empty", "application_payload", encodeApplicationPayload([])],
    ["application_payload_three", "application_payload", values.payloadRaw],
    ...receiptRaw.map((raw, index) => [`execution_receipt_${index}`, "execution_receipt", raw]),
    ...evidenceRaw.map((raw, index) => [`double_vote_evidence_${index}`, "double_vote_evidence", raw]),
    ["ordinary_block_header", "block_header", values.header.cev0],
  ];

  const receiptFixedPrefix = receiptRaw[0].subarray(0, 62);
  const eventCountMax = Buffer.concat([receiptFixedPrefix, Buffer.from("ffffffff", "hex")]);
  const eventPrefix = Buffer.concat([
    receiptFixedPrefix,
    u(1, 4),
    bytes(Buffer.from("event")),
    Buffer.from("ffffffff", "hex"),
  ]);
  const emptyAuthor = clone(values.evidence[0]);
  emptyAuthor.first.author = Buffer.alloc(0);
  const longAuthor = clone(values.evidence[0]);
  longAuthor.first.author = Buffer.alloc(129, 0x61);
  const parserBoundaries = [
    rawCase(
      "payload_declared_count_u32_max",
      "application_payload",
      Buffer.from("ffffffff", "hex"),
      "count_limit_exceeded",
    ),
    rawCase(
      "payload_item_length_active_cap_plus_one",
      "application_payload",
      Buffer.concat([u(1, 4), u(ACTIVE_MAX_BLOCK_BYTES + 1, 4)]),
      "length_limit_exceeded",
    ),
    rawCase(
      "receipt_event_count_u32_max",
      "execution_receipt",
      eventCountMax,
      "count_limit_exceeded",
    ),
    rawCase(
      "event_attribute_count_u32_max",
      "execution_receipt",
      eventPrefix,
      "count_limit_exceeded",
    ),
    rawCase(
      "evidence_empty_author",
      "double_vote_evidence",
      encodeDoubleVote(emptyAuthor),
      "length_limit_exceeded",
    ),
    rawCase(
      "evidence_author_length_129",
      "double_vote_evidence",
      encodeDoubleVote(longAuthor),
      "length_limit_exceeded",
    ),
  ];

  const invalidKindReceipt = clone(values.receipts[0]);
  invalidKindReceipt.events[0].kind = Buffer.from([0xff]);
  const invalidKeyReceipt = clone(values.receipts[0]);
  invalidKeyReceipt.events[0].attributes[
    invalidKeyReceipt.events[0].attributes.length - 1
  ].key = Buffer.from([0xff]);
  const invalidValueReceipt = clone(values.receipts[0]);
  invalidValueReceipt.events[0].attributes[0].value = Buffer.from([0xff]);
  const duplicateAttributeReceipt = clone(values.receipts[0]);
  duplicateAttributeReceipt.events[0].attributes[1].key =
    Buffer.from(duplicateAttributeReceipt.events[0].attributes[0].key);
  const reverseAttributeReceipt = clone(values.receipts[0]);
  reverseAttributeReceipt.events[0].attributes.reverse();
  const duplicateInvalidUtf8Receipt = clone(values.receipts[0]);
  duplicateInvalidUtf8Receipt.events[0].attributes[0].key = Buffer.from([0xff]);
  duplicateInvalidUtf8Receipt.events[0].attributes[1].key = Buffer.from([0xff]);

  const schemaOneReceipt = Buffer.from(receiptRaw[0]);
  schemaOneReceipt.writeUInt16BE(1, 0);
  const schemaOneEvidence = Buffer.from(evidenceRaw[0]);
  schemaOneEvidence.writeUInt16BE(1, 0);
  const nonVote = clone(values.evidence[0]);
  nonVote.first.context.message_kind = 0;
  nonVote.second.context.message_kind = 0;
  const unknownKind = clone(values.evidence[0]);
  unknownKind.first.context.message_kind = 5;
  unknownKind.second.context.message_kind = 5;
  const contextMismatch = clone(values.evidence[0]);
  contextMismatch.second.context.view += 1n;
  const authorMismatch = clone(values.evidence[0]);
  authorMismatch.second.author = values.validators[1].id;
  const sameTuple = clone(values.evidence[0]);
  sameTuple.second.height = sameTuple.first.height;
  sameTuple.second.block_id = Buffer.from(sameTuple.first.block_id);
  const reversedRecords = {
    first: clone(values.evidence[0].second),
    second: clone(values.evidence[0].first),
  };
  const zeroGenesis = clone(values.evidence[0]);
  zeroGenesis.first.context.genesis_hash = Buffer.alloc(32);
  zeroGenesis.second.context.genesis_hash = Buffer.alloc(32);
  const zeroSet = clone(values.evidence[0]);
  zeroSet.first.context.validator_set_hash = Buffer.alloc(32);
  zeroSet.second.context.validator_set_hash = Buffer.alloc(32);
  const headerUnknownKind = Buffer.from(values.header.cev0);
  const headerKindOffset =
    2 + 32 + 2 + values.header.chain_id.length + 4 + 8 + 8 + 8;
  headerUnknownKind[headerKindOffset] = 5;
  const headerZeroGenesis = { ...clone(values.header), genesis_hash: Buffer.alloc(32) };
  const headerZeroSet = {
    ...clone(values.header),
    active_validator_set_hash: Buffer.alloc(32),
  };
  const headerProtocolOne = { ...clone(values.header), protocol_version: 1n };
  const headerEmptyProposer = { ...clone(values.header), proposer_id: Buffer.alloc(0) };
  const headerRegularCommitment = {
    ...clone(values.header),
    next_epoch_commitment_hash: labelHash("unexpected-regular-commitment"),
  };
  const headerCheckpointWithoutCommitment = {
    ...clone(values.header),
    block_kind: 1,
    next_epoch_commitment_hash: null,
  };
  const semanticCases = [
    rawCase("event_kind_invalid_utf8", "execution_receipt", encodeReceipt(invalidKindReceipt), "invalid_utf8"),
    rawCase("event_key_invalid_utf8", "execution_receipt", encodeReceipt(invalidKeyReceipt), "invalid_utf8"),
    rawCase("event_value_invalid_utf8", "execution_receipt", encodeReceipt(invalidValueReceipt), "invalid_utf8"),
    rawCase("event_duplicate_attribute", "execution_receipt", encodeReceipt(duplicateAttributeReceipt), "noncanonical_event_attribute_order"),
    rawCase("event_reverse_attribute_order", "execution_receipt", encodeReceipt(reverseAttributeReceipt), "noncanonical_event_attribute_order"),
    rawCase("event_order_precedes_utf8", "execution_receipt", encodeReceipt(duplicateInvalidUtf8Receipt), "noncanonical_event_attribute_order"),
    rawCase("receipt_schema_version_1", "execution_receipt", schemaOneReceipt, "invalid_schema_version"),
    rawCase("evidence_schema_version_1", "double_vote_evidence", schemaOneEvidence, "invalid_schema_version"),
    semanticEvidenceCase("evidence_known_non_vote_kind", nonVote, "context_mismatch"),
    semanticEvidenceCase("evidence_unknown_message_kind", unknownKind, "context_mismatch"),
    semanticEvidenceCase("evidence_context_mismatch", contextMismatch, "context_mismatch"),
    semanticEvidenceCase("evidence_author_mismatch", authorMismatch),
    semanticEvidenceCase("evidence_same_vote_tuple", sameTuple),
    semanticEvidenceCase("evidence_record_order_reversed", reversedRecords),
    semanticEvidenceCase("evidence_zero_genesis", zeroGenesis, "zero_genesis_hash"),
    semanticEvidenceCase("evidence_zero_set_hash", zeroSet, "context_mismatch"),
    rawCase("header_unknown_block_kind", "block_header", headerUnknownKind, "invalid_block_kind"),
    rawCase("header_zero_genesis", "block_header", encodeHeader(headerZeroGenesis), "zero_genesis_hash"),
    rawCase("header_zero_active_set", "block_header", encodeHeader(headerZeroSet), "invalid_block_header"),
    rawCase("header_protocol_version_1", "block_header", encodeHeader(headerProtocolOne), "invalid_block_header"),
    rawCase("header_empty_proposer", "block_header", encodeHeader(headerEmptyProposer), "length_limit_exceeded"),
    rawCase("header_regular_with_commitment", "block_header", encodeHeader(headerRegularCommitment), "invalid_block_header"),
    rawCase("header_checkpoint_without_commitment", "block_header", encodeHeader(headerCheckpointWithoutCommitment), "invalid_block_header"),
    rawCase(
      "receipt_semantic_plus_trailing_prefers_trailing",
      "execution_receipt",
      Buffer.concat([schemaOneReceipt, Buffer.from([0])]),
      "trailing_bytes",
    ),
    rawCase(
      "evidence_semantic_plus_trailing_prefers_trailing",
      "double_vote_evidence",
      Buffer.concat([encodeDoubleVote(nonVote), Buffer.from([0])]),
      "trailing_bytes",
    ),
    rawCase(
      "evidence_semantic_plus_truncation_prefers_eof",
      "double_vote_evidence",
      encodeDoubleVote(nonVote).subarray(0, encodeDoubleVote(nonVote).length - 1),
      "unexpected_eof",
    ),
  ];

  const mutatedSignatureEvidence = clone(values.evidence[0]);
  mutatedSignatureEvidence.first.signature = mutateByte(mutatedSignatureEvidence.first.signature);
  const wrongDomainEvidence = clone(values.evidence[0]);
  const wrongDomainAuthor = values.validatorByHex.get(
    wrongDomainEvidence.first.author.toString("hex"),
  );
  wrongDomainEvidence.first.signature = sign(
    wrongDomainAuthor.private_key,
    digest(DOMAIN_PROPOSAL, encodeVoteSign(wrongDomainEvidence.first)),
  );
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const identityForgery = Buffer.alloc(64);
  identity.copy(identityForgery, 0);
  const validRecord = values.evidence[0].first;
  const noncanonicalScalar = Buffer.from(validRecord.signature);
  littleEndianBytes(ED25519_GROUP_ORDER, 32).copy(noncanonicalScalar, 32);
  const noncanonicalPoint = littleEndianBytes(ED25519_FIELD, 32);
  const noncanonicalR = Buffer.from(validRecord.signature);
  noncanonicalPoint.copy(noncanonicalR, 0);
  const smallOrderR = Buffer.from(validRecord.signature);
  identity.copy(smallOrderR, 0);
  const strictCryptoCases = [
    {
      id: "valid_public_reproducible_double_vote_signature",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: validRecord.signature.toString("hex"),
      expected_valid: true,
    },
    {
      id: "mutated_signature",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: mutateByte(validRecord.signature).toString("hex"),
      expected_valid: false,
    },
    {
      id: "wrong_domain_signature",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: wrongDomainEvidence.first.signing_root.toString("hex"),
      signature_hex: wrongDomainEvidence.first.signature.toString("hex"),
      expected_valid: false,
    },
    {
      id: "identity_public_key_and_identity_signature",
      public_key_hex: identity.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: identityForgery.toString("hex"),
      expected_valid: false,
    },
    {
      id: "noncanonical_scalar_s_equals_l",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: noncanonicalScalar.toString("hex"),
      expected_valid: false,
    },
    {
      id: "noncanonical_public_key_y_equals_p",
      public_key_hex: noncanonicalPoint.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: validRecord.signature.toString("hex"),
      expected_valid: false,
    },
    {
      id: "noncanonical_r_y_equals_p",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: noncanonicalR.toString("hex"),
      expected_valid: false,
    },
    {
      id: "small_order_identity_r",
      public_key_hex: wrongDomainAuthor.public_key_raw.toString("hex"),
      signing_root_hex: validRecord.signing_root.toString("hex"),
      signature_hex: smallOrderR.toString("hex"),
      expected_valid: false,
    },
  ];

  const receiptCountMissing = values.receipts.slice(0, 2);
  const receiptIndexWrong = clone(values.receipts);
  receiptIndexWrong[1].transaction_index = 9n;
  const receiptLeafWrong = clone(values.receipts);
  receiptLeafWrong[0].payload_leaf_hash = mutateByte(receiptLeafWrong[0].payload_leaf_hash);
  const receiptAdmissionCases = [
    receiptCaseJson("receipt_count_mismatch", receiptCountMissing, "receipt_count_mismatch"),
    receiptCaseJson("receipt_index_mismatch", receiptIndexWrong, "receipt_index_mismatch"),
    receiptCaseJson("payload_leaf_mismatch", receiptLeafWrong, "payload_leaf_mismatch"),
  ];

  const payloadRootHeader = { ...clone(values.header), payload_root: mutateByte(values.header.payload_root) };
  const receiptsRootHeader = { ...clone(values.header), receipts_root: mutateByte(values.header.receipts_root) };
  const evidenceRootHeader = { ...clone(values.header), evidence_root: mutateByte(values.header.evidence_root) };
  const nonRegularHeader = {
    ...clone(values.header),
    block_kind: 1,
    next_epoch_commitment_hash: labelHash("b2d-checkpoint-commitment"),
  };
  const parameterHeader = {
    ...clone(values.header),
    consensus_parameters_hash: labelHash("b2d-wrong-parameters"),
  };
  const setHeader = {
    ...clone(values.header),
    active_validator_set_hash: labelHash("b2d-wrong-set"),
  };
  const invalidSignatureEvidenceRaw = [
    encodeDoubleVote(mutatedSignatureEvidence),
    evidenceRaw[1],
  ].sort((first, second) =>
    cmp(digest(DOMAIN_EVIDENCE, first), digest(DOMAIN_EVIDENCE, second)));
  const invalidSignatureHeader = {
    ...clone(values.header),
    evidence_root: orderedRoot(2, invalidSignatureEvidenceRaw),
  };
  const bodyAdmissionCases = [
    bodyCaseJson("payload_root_mismatch", payloadRootHeader, evidenceRaw, "payload_root_mismatch"),
    bodyCaseJson("receipts_root_mismatch", receiptsRootHeader, evidenceRaw, "receipts_root_mismatch"),
    bodyCaseJson("evidence_root_mismatch", evidenceRootHeader, evidenceRaw, "evidence_root_mismatch"),
    bodyCaseJson("non_regular_block", nonRegularHeader, evidenceRaw, "non_regular_block"),
    bodyCaseJson("parameters_context_mismatch", parameterHeader, evidenceRaw, "parameters_context_mismatch"),
    bodyCaseJson("validator_set_context_mismatch", setHeader, evidenceRaw, "validator_set_context_mismatch"),
    bodyCaseJson(
      "noncanonical_evidence_order",
      values.header,
      [...evidenceRaw].reverse(),
      "noncanonical_evidence_order",
    ),
    bodyCaseJson(
      "duplicate_evidence",
      values.header,
      [evidenceRaw[0], evidenceRaw[0]],
      "duplicate_evidence",
    ),
    bodyCaseJson(
      "invalid_evidence_signature",
      invalidSignatureHeader,
      invalidSignatureEvidenceRaw,
      "invalid_evidence_signature",
    ),
  ];

  const contextMutations = [
    ["signed_evidence_wrong_genesis", (context) => { context.genesis_hash = labelHash("wrong-genesis"); }],
    ["signed_evidence_wrong_chain", (context) => { context.chain_id = Buffer.from("trnm-other-chain"); }],
    ["signed_evidence_wrong_epoch", (context) => { context.epoch += 1n; }],
    ["signed_evidence_wrong_set", (context) => { context.validator_set_hash = labelHash("wrong-set"); }],
  ];
  for (const [id, mutation] of contextMutations) {
    const author = values.validatorByHex.get(values.evidence[0].first.author.toString("hex"));
    const changed = resignEvidence(values.evidence[0], author, mutation);
    bodyAdmissionCases.push(
      bodyCaseJson(id, values.header, [changed.cev0], "context_mismatch"),
    );
  }
  const unknownAuthorEvidence = clone(values.evidence[0]);
  unknownAuthorEvidence.first.author = Buffer.from("validator-z");
  unknownAuthorEvidence.second.author = Buffer.from("validator-z");
  for (const record of [unknownAuthorEvidence.first, unknownAuthorEvidence.second]) {
    record.signing_root = voteSigningRoot(record);
  }
  if (
    cmp(
      unknownAuthorEvidence.first.signing_root,
      unknownAuthorEvidence.second.signing_root,
    ) > 0
  ) {
    [unknownAuthorEvidence.first, unknownAuthorEvidence.second] = [
      unknownAuthorEvidence.second,
      unknownAuthorEvidence.first,
    ];
  }
  bodyAdmissionCases.push(
    bodyCaseJson(
      "evidence_unknown_active_author",
      values.header,
      [encodeDoubleVote(unknownAuthorEvidence)],
      "unknown_signer",
    ),
  );

  const proposalNegativeCases = [];
  const badSignatureProposal = clone(values.proposal);
  badSignatureProposal.signature = mutateByte(badSignatureProposal.signature);
  proposalNegativeCases.push(
    proposalCaseJson(
      "proposal_bad_signature",
      values.header,
      badSignatureProposal,
      values.qc.cev0,
      "ordinary_proposal_signature_invalid",
    ),
  );
  for (const [id, overrides, expected] of [
    ["proposal_epoch_anchor_present", { epoch_anchor_authorization_present: true }, "ordinary_proposal_context_mismatch"],
    ["proposal_handoff_digest_present", { handoff_certificate_digest: labelHash("handoff") }, "ordinary_proposal_context_mismatch"],
    ["proposal_timeout_present", { timeout_certificate_present: true, timeout_certificate_digest: labelHash("tc") }, "ordinary_proposal_certificate_mismatch"],
  ]) {
    proposalNegativeCases.push(
      proposalCaseJson(
        id,
        values.header,
        makeProposalForHeader(values, values.header, values.qc, overrides),
        values.qc.cev0,
        expected,
      ),
    );
  }
  for (const [id, mutation] of [
    ["proposal_context_view_mismatch", (proposal) => { proposal.context.view += 1n; }],
    ["proposal_height_mismatch", (proposal) => { proposal.height += 1n; }],
    ["proposal_context_genesis_mismatch", (proposal) => { proposal.context.genesis_hash = labelHash("proposal-wrong-genesis"); }],
    ["proposal_context_chain_mismatch", (proposal) => { proposal.context.chain_id = Buffer.from("trnm-other-chain"); }],
    ["proposal_context_set_mismatch", (proposal) => { proposal.context.validator_set_hash = labelHash("proposal-wrong-set"); }],
    ["proposal_block_id_mismatch", (proposal) => { proposal.block_id = labelHash("proposal-wrong-block"); }],
    ["proposal_justify_digest_mismatch", (proposal) => { proposal.justify_qc_digest = labelHash("proposal-wrong-qc"); }],
  ]) {
    const proposal = clone(values.proposal);
    mutation(proposal);
    proposal.signing_root = proposalSigningRoot(proposal);
    proposal.signature = sign(
      validatorForId(values.validators, proposal.proposer_id).private_key,
      proposal.signing_root,
    );
    proposalNegativeCases.push(
      proposalCaseJson(
        id,
        values.header,
        proposal,
        values.qc.cev0,
        id === "proposal_justify_digest_mismatch"
          ? "ordinary_proposal_certificate_mismatch"
          : "ordinary_proposal_context_mismatch",
      ),
    );
  }

  for (const [id, headerMutation] of [
    ["proposal_active_chain_mismatch", (header) => { header.chain_id = Buffer.from("trnm-other-chain"); }],
    ["proposal_active_epoch_mismatch", (header) => { header.epoch += 1n; }],
    ["proposal_active_parameters_mismatch", (header) => { header.consensus_parameters_hash = labelHash("wrong-params"); }],
  ]) {
    const header = clone(values.header);
    headerMutation(header);
    header.cev0 = encodeHeader(header);
    header.block_id = digest(DOMAIN_BLOCK, header.cev0);
    proposalNegativeCases.push(
      proposalCaseJson(
        id,
        header,
        makeProposalForHeader(values, header, values.qc),
        values.qc.cev0,
        "ordinary_proposal_context_mismatch",
      ),
    );
  }

  const wrongLeaderHeader = clone(values.header);
  wrongLeaderHeader.proposer_id = values.validators[0].id;
  wrongLeaderHeader.cev0 = encodeHeader(wrongLeaderHeader);
  wrongLeaderHeader.block_id = digest(DOMAIN_BLOCK, wrongLeaderHeader.cev0);
  proposalNegativeCases.push(
    proposalCaseJson(
      "proposal_wrong_scheduled_leader",
      wrongLeaderHeader,
      makeProposalForHeader(values, wrongLeaderHeader, values.qc),
      values.qc.cev0,
      "ordinary_proposal_context_mismatch",
    ),
  );

  for (const [id, contextMutation] of [
    ["proposal_qc_wrong_chain", (context) => { context.chain_id = Buffer.from("trnm-other-chain"); }],
    ["proposal_qc_wrong_epoch", (context) => { context.epoch += 1n; }],
    ["proposal_qc_wrong_set", (context) => { context.validator_set_hash = labelHash("wrong-set"); }],
  ]) {
    const changedContext = clone(values.context);
    contextMutation(changedContext);
    const qc = makeQc(
      changedContext,
      values.validators.slice(0, 2),
      values.qc.view,
      values.qc.height,
      values.qc.block_id,
    );
    proposalNegativeCases.push(
      proposalCaseJson(
        id,
        values.header,
        makeProposalForHeader(values, values.header, qc),
        qc.cev0,
        "ordinary_proposal_certificate_mismatch",
      ),
    );
  }
  for (const [id, qcView, qcHeight, qcBlockId] of [
    [
      "proposal_qc_parent_mismatch",
      values.qc.view,
      values.qc.height,
      labelHash("different-parent"),
    ],
    [
      "proposal_qc_height_relation_mismatch",
      values.qc.view,
      values.qc.height - 1n,
      values.qc.block_id,
    ],
    [
      "proposal_qc_view_relation_mismatch",
      values.qc.view - 1n,
      values.qc.height,
      values.qc.block_id,
    ],
  ]) {
    const qc = makeQc(
      values.context,
      values.validators.slice(0, 3),
      qcView,
      qcHeight,
      qcBlockId,
    );
    proposalNegativeCases.push(
      proposalCaseJson(
        id,
        values.header,
        makeProposalForHeader(values, values.header, qc),
        qc.cev0,
        "ordinary_proposal_certificate_mismatch",
      ),
    );
  }
  const oneBelowQc = makeQc(
    values.context,
    values.validators.slice(0, 2),
    values.qc.view,
    values.qc.height,
    values.qc.block_id,
  );
  proposalNegativeCases.push(
    proposalCaseJson(
      "proposal_qc_one_below_quorum",
      values.header,
      makeProposalForHeader(values, values.header, oneBelowQc),
      oneBelowQc.cev0,
      "insufficient_quorum",
    ),
  );
  const viewZeroQc = makeQc(
    values.context,
    values.validators.slice(0, 3),
    0,
    values.qc.height,
    values.qc.block_id,
  );
  proposalNegativeCases.push(
    proposalCaseJson(
      "proposal_signed_view_zero_qc",
      values.header,
      makeProposalForHeader(values, values.header, viewZeroQc),
      viewZeroQc.cev0,
      "unauthorized_synthetic_qc",
    ),
  );
  const emptyQc = { ...clone(values.qc), signatures: [] };
  emptyQc.cev0 = encodeQc(emptyQc);
  emptyQc.qc_digest = digest(DOMAIN_QC, emptyQc.cev0);
  proposalNegativeCases.push(
    proposalCaseJson(
      "proposal_empty_signature_qc",
      values.header,
      makeProposalForHeader(values, values.header, emptyQc),
      emptyQc.cev0,
      "unauthorized_synthetic_qc",
    ),
  );

  const exactBoundary = buildLogicalBoundary(values, 0);
  const overBoundary = buildLogicalBoundary(values, 1);
  const splitActiveSet = clone(values.activeSet);
  splitActiveSet.validators[3].power = 2n;
  splitActiveSet.cev0 = encodeValidatorSet(splitActiveSet);
  splitActiveSet.validator_set_hash = digest(DOMAIN_VALIDATOR_SET, splitActiveSet.cev0);

  return {
    schema: "trnm_poco_bft_block_body_kernel_vectors_v0",
    schema_version: 0,
    scope: "B2-D ordinary epoch-local block-validation and next-view logical proposal-binding kernel only",
    cryptographic_validity_claimed: true,
    private_key_policy: "Deterministic fixture seeds exist only in the independent Node checker. The committed corpus contains public keys, exact signing roots, and signatures, never private seeds.",
    active_context: jsonContext(values.context),
    active_validator_set: {
      cev0_hex: values.activeSet.cev0.toString("hex"),
      validator_set_hash_hex: values.activeSet.validator_set_hash.toString("hex"),
      validators: values.validators.map((validator) => ({
        validator_id_ascii: validator.id.toString("ascii"),
        public_key_hex: validator.public_key_raw.toString("hex"),
        effective_weight: validator.power.toString(),
      })),
      total_weight: "4",
      quorum_weight: "3",
    },
    valid_objects: {
      seal_empty_application_payload_cev0_hex: encodeApplicationPayload([]).toString("hex"),
      application_payload: {
        items_hex: values.payloadItems.map((item) => item.toString("hex")),
        cev0_hex: values.payloadRaw.toString("hex"),
        payload_root_hex: commitments.payloadRoot.toString("hex"),
      },
      execution_receipts: receiptRaw.map((raw, index) => ({
        transaction_index: String(index),
        cev0_hex: raw.toString("hex"),
        payload_leaf_hash_hex: values.receipts[index].payload_leaf_hash.toString("hex"),
      })),
      execution_receipts_list_cev0_hex: receiptListBytes(values.receipts).toString("hex"),
      receipts_root_hex: commitments.receiptsRoot.toString("hex"),
      double_vote_evidence: values.evidence.map((item) => ({
        author_validator_id_ascii: item.first.author.toString("ascii"),
        first_signing_root_hex: item.first.signing_root.toString("hex"),
        first_signature_hex: item.first.signature.toString("hex"),
        first_record_cev0_hex: encodeVoteRecord(item.first).toString("hex"),
        second_signing_root_hex: item.second.signing_root.toString("hex"),
        second_signature_hex: item.second.signature.toString("hex"),
        second_record_cev0_hex: encodeVoteRecord(item.second).toString("hex"),
        cev0_hex: item.cev0.toString("hex"),
        evidence_id_hex: item.evidence_id.toString("hex"),
      })),
      evidence_root_hex: commitments.evidenceRoot.toString("hex"),
      block_header: {
        cev0_hex: values.header.cev0.toString("hex"),
        block_id_hex: values.header.block_id.toString("hex"),
        logical_block_size: commitments.logicalSize.toString(),
      },
      ordinary_next_view_qc: {
        cev0_hex: values.qc.cev0.toString("hex"),
        digest_hex: values.qc.qc_digest.toString("hex"),
        vote_signing_root_hex: values.qc.signing_root.toString("hex"),
      },
      ordinary_next_view_proposal_sign: {
        cev0_hex: encodeProposalSign(values.proposal).toString("hex"),
        signing_root_hex: proposalResult.signingRoot.toString("hex"),
        proposer_validator_id_ascii: values.proposal.proposer_id.toString("ascii"),
        leader_schedule: "CanonicalValidatorRoundRobin: (view - 1) mod canonical validator count",
        proposer_signature_hex: values.proposal.signature.toString("hex"),
        timeout_certificate_absent: true,
        epoch_anchor_authorization_absent: true,
        handoff_certificate_digest_absent: true,
      },
    },
    frozen_empty_roots: {
      payload_root_hex: orderedRoot(0, []).toString("hex"),
      receipts_root_hex: orderedRoot(1, []).toString("hex"),
      evidence_root_hex: orderedRoot(2, []).toString("hex"),
    },
    parser_campaigns: {
      all_noncomplete_prefixes: {
        objects: prefixObjects.map(([id, parser, raw]) => ({
          id,
          parser,
          cev0_hex: raw.toString("hex"),
        })),
        expected_code: "unexpected_eof",
        case_count: prefixObjects.reduce((sum, [, , raw]) => sum + raw.length, 0),
      },
      one_byte_trailing: {
        object_ids: prefixObjects.map(([id]) => id),
        appended_hex: "00",
        expected_code: "trailing_bytes",
        case_count: prefixObjects.length,
      },
      active_root_cap_synthesis: [
        {
          id: "application_payload_root_cap_exact",
          object: "application_payload",
          synthesized_length: String(ACTIVE_MAX_BLOCK_BYTES),
          expected_result: "valid",
        },
        {
          id: "application_payload_root_cap_plus_one",
          object: "application_payload",
          synthesized_length: String(ACTIVE_MAX_BLOCK_BYTES + 1),
          expected_code: "length_limit_exceeded",
          expected_byte_offset: 0,
        },
        {
          id: "execution_receipt_root_cap_plus_one",
          object: "execution_receipt",
          synthesized_length: String(ACTIVE_MAX_BLOCK_BYTES + 1),
          expected_code: "length_limit_exceeded",
          expected_byte_offset: 0,
        },
      ],
    },
    parser_boundaries: parserBoundaries,
    semantic_negatives: semanticCases,
    strict_ed25519_cases: strictCryptoCases,
    receipt_admission_negatives: receiptAdmissionCases,
    body_admission_negatives: bodyAdmissionCases,
    proposal_binding_negatives: proposalNegativeCases,
    active_context_negatives: [
      {
        id: "active_parameter_cap_hash_split",
        consensus_parameters_hash_hex: values.context.consensus_parameters_hash.toString("hex"),
        active_max_block_bytes: String(ACTIVE_MAX_BLOCK_BYTES + 1),
        active_validator_set_cev0_hex: values.activeSet.cev0.toString("hex"),
        expected_code: "parameters_context_mismatch",
      },
      {
        id: "active_parameter_hash_mismatch",
        consensus_parameters_hash_hex: labelHash("b2d-wrong-active-parameters").toString("hex"),
        active_max_block_bytes: String(ACTIVE_MAX_BLOCK_BYTES),
        active_validator_set_cev0_hex: values.activeSet.cev0.toString("hex"),
        expected_code: "parameters_context_mismatch",
      },
      {
        id: "active_set_preimage_hash_split",
        consensus_parameters_hash_hex: values.context.consensus_parameters_hash.toString("hex"),
        validator_set_hash_hex: values.context.validator_set_hash.toString("hex"),
        active_max_block_bytes: String(ACTIVE_MAX_BLOCK_BYTES),
        active_validator_set_cev0_hex: splitActiveSet.cev0.toString("hex"),
        expected_code: "validator_set_context_mismatch",
      },
      {
        id: "active_set_validator_share_exceeded",
        consensus_parameters_hash_hex: values.context.consensus_parameters_hash.toString("hex"),
        validator_set_hash_hex: splitActiveSet.validator_set_hash.toString("hex"),
        active_max_block_bytes: String(ACTIVE_MAX_BLOCK_BYTES),
        active_validator_set_cev0_hex: splitActiveSet.cev0.toString("hex"),
        expected_code: "validator_set_context_mismatch",
      },
    ],
    qc_parser_boundaries: [
      {
        id: "qc_signer_count_101",
        raw_hex: Buffer.concat([
          values.qc.cev0.subarray(0, values.qc.cev0.length - (
            values.qc.signatures.reduce((sum, share) => sum + 4 + share.signer.length + 64, 0) + 4
          )),
          u(101, 4),
        ]).toString("hex"),
        expected_code: "count_limit_exceeded",
      },
      {
        id: "qc_signer_count_u32_max",
        raw_hex: Buffer.concat([
          values.qc.cev0.subarray(0, values.qc.cev0.length - (
            values.qc.signatures.reduce((sum, share) => sum + 4 + share.signer.length + 64, 0) + 4
          )),
          Buffer.from("ffffffff", "hex"),
        ]).toString("hex"),
        expected_code: "count_limit_exceeded",
      },
    ],
    size_boundaries: {
      reference_active_max_block_bytes: String(ACTIVE_MAX_BLOCK_BYTES),
      logical_block_exact: {
        synthesized_transaction_bytes: String(exactBoundary.transactionLength),
        logical_size: exactBoundary.size.toString(),
        expected_result: "valid",
      },
      logical_block_plus_one: {
        synthesized_transaction_bytes: String(overBoundary.transactionLength),
        logical_size: overBoundary.size.toString(),
        expected_code: "logical_block_size_exceeded",
      },
      derived_receipt_list_exact: {
        synthesized_cev0_bytes: String(ACTIVE_MAX_BLOCK_BYTES),
        expected_result: "valid",
      },
      derived_receipt_list_plus_one: {
        synthesized_cev0_bytes: String(ACTIVE_MAX_BLOCK_BYTES + 1),
        expected_code: "receipt_list_size_exceeded",
      },
    },
    honest_boundary: [
      "The committed strict Ed25519 vectors are publicly reproducible; private fixture seeds remain checker-only.",
      "Receipt values are caller-supplied typed commitments intended to come from the locally authorized deterministic runtime; this kernel proves no runtime provenance and the protobuf Block projection carries no peer receipt authority.",
      "ValidatedBlockCommitmentsV0 records acceptance by the caller-supplied SignatureVerifier, not verifier identity or intrinsic strict Ed25519; production MUST use trnm_consensus_crypto::StrictEd25519Verifier, whose concrete path is exercised by the crypto corpus.",
      "00000000 is the exact empty ApplicationPayloadV0 encoding, including the body shape used by seals elsewhere; this kernel does not authorize seals.",
      "The proposal artifact is a next-view logical/projection fixture, not a protobuf Proposal exact decoder or skipped-view/anchor authorization.",
      "Rust independently exact-decodes and verifies the valid ordinary QC, then reconstructs the valid ProposalWitnessV0 signing root and proposer signature; the 24 proposal/QC negatives remain Node-only, with no Rust all-negative or raw-protobuf Proposal closure claimed.",
      "4194304 is the committed reference profile's active max_block_bytes, not an eternal protocol or production decoder cap.",
      "Runtime execution, parent-state authentication, checkpoint/two-seal ancestry, epoch transition, transport admission, light client, and B2 overall remain open.",
    ],
  };
}

function validateManifest(manifest, b2c) {
  if (
    manifest.schema !== "trnm_poco_bft_cev0_logical_schema_block_body_v0" ||
    manifest.schema_version !== 0 ||
    manifest.cryptographic_validity_claimed !== true ||
    !manifest.status.includes("ordinary")
  ) {
    fail("schema_manifest_invalid", 0, "B2-D manifest identity/status/claim drift", "gate");
  }
  const expectedObjects = [
    "ApplicationPayloadV0",
    "ExecutionEventAttributeV0",
    "ExecutionEventV0",
    "ExecutionReceiptCommitmentV0",
    "ExecutionReceiptsV0",
    "VoteEvidenceRecordV0",
    "DoubleVoteEvidenceV0",
    "BlockBodyV0",
    "ProposalSignV0",
  ];
  if (
    JSON.stringify(manifest.objects.map((object) => object.name)) !==
    JSON.stringify(expectedObjects)
  ) {
    fail("schema_manifest_invalid", 0, "B2-D logical object order drift", "gate");
  }
  const baseImport = manifest.imports.find((item) =>
    item.schema === "trnm_poco_bft_cev0_logical_schema_v0");
  const headerImport = manifest.imports.find((item) =>
    item.schema === "trnm_poco_bft_cev0_logical_schema_anchor_handoff_v0");
  if (
    baseImport === undefined ||
    !baseImport.reuse.includes("ValidatorSetV0") ||
    !baseImport.reuse.includes("validator-set domain") ||
    baseImport.reuse.includes("TimeoutCertificateV0") ||
    headerImport === undefined ||
    !headerImport.reuse.includes("BlockHeaderV0")
  ) {
    fail("schema_manifest_invalid", 0, "B2-D import boundary drift", "gate");
  }
  if ("active_max_block_bytes" in manifest.hard_limits) {
    fail("schema_manifest_invalid", 0, "active 4 MiB was mislabeled a protocol hard cap", "gate");
  }
  if (
    manifest.reference_profile_limits.active_committed_max_block_bytes !== "4194304" ||
    manifest.reference_profile_limits.source !== "trusted active ConsensusParametersV0" ||
    !manifest.reference_profile_limits.non_normative_note.includes("not an eternal")
  ) {
    fail("schema_manifest_invalid", 0, "reference active limit contract drift", "gate");
  }
  const decoderAdditions = manifest.rust_decoder_error_additions.map((item) => item.code);
  const expectedDecoderAdditions = [
    "invalid_utf8",
    "noncanonical_event_attribute_order",
    "invalid_double_vote_evidence",
  ];
  if (JSON.stringify(decoderAdditions) !== JSON.stringify(expectedDecoderAdditions)) {
    fail("schema_manifest_invalid", 0, "B2-D decoder addition order drift", "gate");
  }
  const b2cCodes = b2c.decoder_error_codes.map((item) => item.code);
  if (
    b2cCodes.length !== manifest.decoder_error_import.required_exact_prefix_count ||
    decoderAdditions.some((code) => b2cCodes.includes(code)) ||
    new Set([...b2cCodes, ...decoderAdditions]).size !==
      b2cCodes.length + decoderAdditions.length
  ) {
    fail("schema_manifest_invalid", 0, "B2-A/B/C/D decoder taxonomy overlaps", "gate");
  }
  const expectedAdmission = [
    "non_regular_block",
    "receipt_count_mismatch",
    "receipt_index_mismatch",
    "payload_leaf_mismatch",
    "noncanonical_evidence_order",
    "duplicate_evidence",
    "payload_root_mismatch",
    "receipts_root_mismatch",
    "evidence_root_mismatch",
    "receipt_list_size_exceeded",
    "logical_block_size_exceeded",
    "parameters_context_mismatch",
    "validator_set_context_mismatch",
    "invalid_evidence_signature",
  ];
  const actualAdmission = manifest.admission_error_codes.map((item) => item.code);
  if (
    actualAdmission.length !== expectedAdmission.length ||
    !expectedAdmission.every((code) => actualAdmission.includes(code))
  ) {
    fail("schema_manifest_invalid", 0, "ordinary admission taxonomy drift", "gate");
  }
  const expectedCheckpointAdmissionAdditions = [
    "non_checkpoint_block",
    "state_root_mismatch",
    "next_epoch_commitment_mismatch",
  ];
  const actualCheckpointAdmissionAdditions =
    manifest.checkpoint_admission_error_additions.map((item) => item.code);
  if (
    JSON.stringify(actualCheckpointAdmissionAdditions) !==
    JSON.stringify(expectedCheckpointAdmissionAdditions) ||
    actualCheckpointAdmissionAdditions.some((code) => actualAdmission.includes(code))
  ) {
    fail("schema_manifest_invalid", 0, "checkpoint admission taxonomy drift", "gate");
  }
  const proposalObject = manifest.objects.find((object) => object.name === "ProposalSignV0");
  if (
    !proposalObject.coverage.includes("next_view_only") ||
    !proposalObject.relations.some((relation) => relation.includes("next-view only")) ||
    !proposalObject.relations.some((relation) =>
      relation.includes("CanonicalValidatorRoundRobin")) ||
    manifest.honest_boundary.some((line) => /ordinary QC\/TC|skipped-view.*closed/i.test(line))
  ) {
    fail("schema_manifest_invalid", 0, "proposal fixture overclaims skipped-view coverage", "gate");
  }
  for (const required of [
    "ValidatedBlockCommitmentsV0",
    "ValidatedCheckpointCommitmentsV0",
    "SignedProposalV0",
    "BlockBodyV0",
  ]) {
    if (!manifest.rust_type_surface.includes(required)) {
      fail("schema_manifest_invalid", 0, `missing Rust surface ${required}`, "gate");
    }
  }
  if (
    !manifest.forbidden_entry_points.includes("skipped-view proposal admission") ||
    !manifest.forbidden_entry_points.includes("first-new-block admission") ||
    !manifest.honest_boundary.some((line) => line.includes("B2 overall"))
  ) {
    fail("schema_manifest_invalid", 0, "honest boundary drift", "gate");
  }
}

function stripProtoComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

function protoMessage(source, name) {
  const match = new RegExp(`\\bmessage\\s+${name}\\s*\\{`, "m").exec(source);
  if (match === null) fail("proto_projection_drift", 0, `missing proto message ${name}`, "gate");
  const open = source.indexOf("{", match.index);
  let depth = 1;
  for (let index = open + 1; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(open + 1, index);
  }
  fail("proto_projection_drift", 0, `unterminated proto message ${name}`, "gate");
}

function protoFields(source, name) {
  const body = protoMessage(stripProtoComments(source), name);
  return [...body.matchAll(
    /^\s*(?:(repeated)\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([a-z_][a-z0-9_]*)\s*=\s*([0-9]+)\s*;/gm,
  )].map((match) => ({
    cardinality: match[1] === "repeated" ? "repeated" : "singular",
    proto_type: match[2],
    name: match[3],
    number: Number(match[4]),
  }));
}

function validateProjection(manifest) {
  const consensus = fs.readFileSync(CONSENSUS_PROTO_PATH, "utf8");
  const evidence = fs.readFileSync(EVIDENCE_PROTO_PATH, "utf8");
  const sources = new Map([
    ["proto/trnm/poco/bft/v0/consensus.proto", consensus],
    ["proto/trnm/poco/bft/v0/evidence.proto", evidence],
  ]);
  for (const projection of manifest.transport_projections) {
    if (projection.proto_file === null) continue;
    const actual = protoFields(sources.get(projection.proto_file), projection.proto_message);
    const expected = projection.fields.map(({ number, name, proto_type, cardinality }) => ({
      cardinality,
      proto_type,
      name,
      number,
    }));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail(
        "proto_projection_drift",
        0,
        `${projection.proto_message} projection fields drifted`,
        "gate",
      );
    }
  }
  const blockFields = protoFields(consensus, "Block");
  if (blockFields.some((field) => /receipt/i.test(field.name))) {
    fail("proto_projection_drift", 0, "peer Block projection gained a receipt field", "gate");
  }
  const proposal = manifest.transport_projections.find(
    (item) => item.projection_id === "ordinary_proposal_projection",
  );
  const roles = new Map(proposal.fields.map((field) => [field.name, field.role]));
  if (
    roles.get("epoch_anchor_authorization") !== "forbidden" ||
    roles.get("timeout_certificate") !== "forbidden_in_fixture" ||
    roles.get("block") !== "sidecar" ||
    roles.get("block_id") !== "derived"
  ) {
    fail("schema_manifest_invalid", 0, "ordinary proposal field-role contract drift", "gate");
  }
}

function extractRustAsStr(source) {
  const marker = source.indexOf("pub const fn as_str");
  if (marker < 0) return [];
  const matchStart = source.indexOf("match self", marker);
  const opening = source.indexOf("{", matchStart);
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
  return [];
}

function validateRustSurface(manifest, b2c, base) {
  if (!fs.existsSync(RUST_DECODER_PATH) || !fs.existsSync(RUST_BODY_PATH)) return;
  const decoderSource = fs.readFileSync(RUST_DECODER_PATH, "utf8");
  const bodySource = fs.readFileSync(RUST_BODY_PATH, "utf8");
  const rustDecoderCodes = extractRustAsStr(decoderSource);
  const nodeLocalCodes = (base.rust_decoder_error_exclusions ?? [])
    .filter((item) => item.scope === "node-local signer-intent endpoint only")
    .map((item) => item.code);
  const expectedNodeLocalCodes = [
    "invalid_sign_intent_tag",
    "invalid_sign_intent",
    "invalid_handoff_sign_intent_role",
    "invalid_handoff_sign_intent",
  ];
  const expectedDecoderCodes = [
    ...b2c.decoder_error_codes.map((item) => item.code),
    ...manifest.rust_decoder_error_additions.map((item) => item.code),
    "invalid_leader_schedule",
    "invalid_consensus_parameters",
    "invalid_finality_proof",
    "invalid_checkpoint_two_seal",
    ...nodeLocalCodes,
  ];
  if (
    new Set(rustDecoderCodes).size !== rustDecoderCodes.length ||
    JSON.stringify(nodeLocalCodes) !== JSON.stringify(expectedNodeLocalCodes) ||
    JSON.stringify(rustDecoderCodes) !== JSON.stringify(expectedDecoderCodes)
  ) {
    fail("schema_manifest_invalid", 0, "Rust DecodeErrorCode B2-A/B/C/D/E partition drift", "gate");
  }
  const rustAdmissionCodes = extractRustAsStr(bodySource);
  const manifestAdmissionCodes = manifest.admission_error_codes.map((item) => item.code);
  const checkpointAdmissionCodes =
    manifest.checkpoint_admission_error_additions.map((item) => item.code);
  if (
    JSON.stringify(rustAdmissionCodes) !==
    JSON.stringify([...manifestAdmissionCodes, ...checkpointAdmissionCodes])
  ) {
    fail("schema_manifest_invalid", 0, "Rust ordinary/checkpoint admission taxonomy drift", "gate");
  }
  const tokenMatch = /pub struct ValidatedBlockCommitmentsV0\s*\{([\s\S]*?)\n\}/m.exec(bodySource);
  if (
    tokenMatch === null ||
    /\bpub\s+[A-Za-z_][A-Za-z0-9_]*\s*:/.test(tokenMatch[1]) ||
    /decode_[A-Za-z0-9_]*validated_block_commitments/i.test(decoderSource)
  ) {
    fail("schema_manifest_invalid", 0, "validated commitment token is forgeable/raw-decodable", "gate");
  }
}

function contextFromCorpus(corpus) {
  return {
    genesis_hash: Buffer.from(corpus.active_context.genesis_hash_hex, "hex"),
    chain_id: Buffer.from(corpus.active_context.chain_id_ascii, "ascii"),
    protocol_version: BigInt(corpus.active_context.protocol_version),
    epoch: BigInt(corpus.active_context.epoch),
    validator_set_hash: Buffer.from(corpus.active_context.validator_set_hash_hex, "hex"),
    consensus_parameters_hash: Buffer.from(
      corpus.active_context.consensus_parameters_hash_hex,
      "hex",
    ),
    active_max_block_bytes: Number(corpus.active_context.active_max_block_bytes),
  };
}

function proposalFromCase(testCase) {
  const value = decodeProposalSignExact(Buffer.from(testCase.proposal_sign_cev0_hex, "hex"));
  value.proposer_id = Buffer.from(testCase.proposer_id_hex, "hex");
  value.signature = Buffer.from(testCase.proposer_signature_hex, "hex");
  value.timeout_certificate_present = testCase.timeout_certificate_present;
  value.epoch_anchor_authorization_present =
    testCase.epoch_anchor_authorization_present;
  return value;
}

function validateCorpus(corpus) {
  const activeContext = contextFromCorpus(corpus);
  const activeSetRaw = Buffer.from(corpus.active_validator_set.cev0_hex, "hex");
  const prepared = prepareActiveSet(activeSetRaw, activeContext);
  parserTrust = { activeSet: prepared, context: activeContext };
  const baseHeaderRaw = Buffer.from(corpus.valid_objects.block_header.cev0_hex, "hex");
  const basePayloadRaw = Buffer.from(corpus.valid_objects.application_payload.cev0_hex, "hex");
  const baseReceiptRaw = corpus.valid_objects.execution_receipts.map((item) =>
    Buffer.from(item.cev0_hex, "hex"));
  const baseEvidenceRaw = corpus.valid_objects.double_vote_evidence.map((item) =>
    Buffer.from(item.cev0_hex, "hex"));

  let prefixCount = 0;
  for (const object of corpus.parser_campaigns.all_noncomplete_prefixes.objects) {
    const raw = Buffer.from(object.cev0_hex, "hex");
    for (let length = 0; length < raw.length; length += 1) {
      expectError(
        () => parserFor(object.parser, raw.subarray(0, length)),
        "unexpected_eof",
        `${object.id} prefix ${length}`,
      );
      prefixCount += 1;
    }
    parserFor(object.parser, raw);
    expectError(
      () => parserFor(object.parser, Buffer.concat([raw, Buffer.from([0])])),
      "trailing_bytes",
      `${object.id} trailing`,
    );
  }
  if (prefixCount !== corpus.parser_campaigns.all_noncomplete_prefixes.case_count) {
    fail("source_vector_drift", 0, "prefix campaign count drift", "gate");
  }

  for (const testCase of [
    ...corpus.parser_boundaries,
    ...corpus.semantic_negatives,
  ]) {
    const error = expectError(
      () => parserFor(testCase.parser, Buffer.from(testCase.raw_hex, "hex")),
      testCase.expected_code,
      testCase.id,
    );
    if (error.offset !== testCase.expected_byte_offset) {
      fail("source_vector_drift", 0, `${testCase.id} byte offset drift`, "gate");
    }
  }

  const exactPayload = Buffer.concat([
    u(1, 4),
    u(ACTIVE_MAX_BLOCK_BYTES - 8, 4),
    Buffer.alloc(ACTIVE_MAX_BLOCK_BYTES - 8),
  ]);
  if (exactPayload.length !== ACTIVE_MAX_BLOCK_BYTES) {
    fail("source_vector_drift", 0, "root cap exact synthesis drift", "gate");
  }
  decodeApplicationPayloadExact(exactPayload, ACTIVE_MAX_BLOCK_BYTES);
  for (const parser of ["application_payload", "execution_receipt"]) {
    const operation = () => {
      const raw = Buffer.alloc(ACTIVE_MAX_BLOCK_BYTES + 1);
      if (parser === "application_payload") decodeApplicationPayloadExact(raw);
      else decodeExecutionReceiptExact(raw);
    };
    const error = expectError(operation, "length_limit_exceeded", `${parser} cap+1`);
    if (error.offset !== 0) fail("source_vector_drift", 0, "root cap offset drift", "gate");
  }

  for (const testCase of corpus.strict_ed25519_cases) {
    const actual = verifyEd25519(
      Buffer.from(testCase.public_key_hex, "hex"),
      Buffer.from(testCase.signing_root_hex, "hex"),
      Buffer.from(testCase.signature_hex, "hex"),
    );
    if (actual !== testCase.expected_valid) {
      fail("source_vector_drift", 0, `${testCase.id} strict Ed25519 result drift`, "gate");
    }
  }

  for (const testCase of corpus.receipt_admission_negatives) {
    expectError(
      () => validateOrdinaryBlockBody({
        headerRaw: baseHeaderRaw,
        payloadRaw: basePayloadRaw,
        receiptsRaw: testCase.receipt_cev0_hex.map((item) => Buffer.from(item, "hex")),
        evidenceRaw: baseEvidenceRaw,
        activeContext,
        activeSetRaw,
      }),
      testCase.expected_code,
      testCase.id,
    );
  }
  for (const testCase of corpus.body_admission_negatives) {
    expectError(
      () => validateOrdinaryBlockBody({
        headerRaw: Buffer.from(testCase.header_cev0_hex, "hex"),
        payloadRaw: basePayloadRaw,
        receiptsRaw: baseReceiptRaw,
        evidenceRaw: testCase.evidence_cev0_hex.map((item) => Buffer.from(item, "hex")),
        activeContext,
        activeSetRaw,
      }),
      testCase.expected_code,
      testCase.id,
    );
  }
  for (const testCase of corpus.proposal_binding_negatives) {
    expectError(
      () => validateOrdinaryProposalBinding({
        headerRaw: Buffer.from(testCase.header_cev0_hex, "hex"),
        proposal: proposalFromCase(testCase),
        justifyQcRaw: Buffer.from(testCase.justify_qc_cev0_hex, "hex"),
        activeSetRaw,
        activeContext,
      }),
      testCase.expected_code,
      testCase.id,
    );
  }
  for (const testCase of corpus.active_context_negatives) {
    const changedContext = {
      ...activeContext,
      consensus_parameters_hash: Buffer.from(
        testCase.consensus_parameters_hash_hex,
        "hex",
      ),
      validator_set_hash: testCase.validator_set_hash_hex === undefined
        ? activeContext.validator_set_hash
        : Buffer.from(testCase.validator_set_hash_hex, "hex"),
      active_max_block_bytes: Number(testCase.active_max_block_bytes),
    };
    expectError(
      () => validateOrdinaryBlockBody({
        headerRaw: baseHeaderRaw,
        payloadRaw: basePayloadRaw,
        receiptsRaw: baseReceiptRaw,
        evidenceRaw: baseEvidenceRaw,
        activeContext: changedContext,
        activeSetRaw: Buffer.from(testCase.active_validator_set_cev0_hex, "hex"),
      }),
      testCase.expected_code,
      testCase.id,
    );
  }
  const activeSetMap = prepared.byHex;
  for (const testCase of corpus.qc_parser_boundaries) {
    expectError(
      () => decodeOrdinaryQcExact(
        Buffer.from(testCase.raw_hex, "hex"),
        activeSetMap,
        activeContext,
      ),
      testCase.expected_code,
      testCase.id,
    );
  }

  const values = buildFixtureValues();
  const exact = buildLogicalBoundary(values, 0);
  const over = buildLogicalBoundary(values, 1);
  const exactResult = validateOrdinaryBlockBody({
    headerRaw: exact.header.cev0,
    payloadRaw: exact.payloadRaw,
    receiptsRaw: exact.receipts.map(encodeReceipt),
    evidenceRaw: exact.evidence,
    activeContext: values.context,
    activeSetRaw: values.activeSet.cev0,
  });
  if (exactResult.logicalSize !== BigInt(ACTIVE_MAX_BLOCK_BYTES)) {
    fail("source_vector_drift", 0, "logical equality boundary rejected", "gate");
  }
  expectError(
    () => validateOrdinaryBlockBody({
      headerRaw: over.header.cev0,
      payloadRaw: over.payloadRaw,
      receiptsRaw: over.receipts.map(encodeReceipt),
      evidenceRaw: over.evidence,
      activeContext: values.context,
      activeSetRaw: values.activeSet.cev0,
    }),
    "logical_block_size_exceeded",
    "logical max plus one",
  );
  admitReceiptListSize(Buffer.alloc(ACTIVE_MAX_BLOCK_BYTES), ACTIVE_MAX_BLOCK_BYTES);
  expectError(
    () => admitReceiptListSize(
      Buffer.alloc(ACTIVE_MAX_BLOCK_BYTES + 1),
      ACTIVE_MAX_BLOCK_BYTES,
    ),
    "receipt_list_size_exceeded",
    "receipt list max plus one",
  );

  if (
    corpus.valid_objects.seal_empty_application_payload_cev0_hex !== "00000000" ||
    orderedRoot(0, []).toString("hex") !== corpus.frozen_empty_roots.payload_root_hex ||
    orderedRoot(1, []).toString("hex") !== corpus.frozen_empty_roots.receipts_root_hex ||
    orderedRoot(2, []).toString("hex") !== corpus.frozen_empty_roots.evidence_root_hex
  ) {
    fail("source_vector_drift", 0, "empty payload/root freeze drift", "gate");
  }
}

function main() {
  const manifest = readJson(SCHEMA_PATH);
  const b2c = readJson(B2C_SCHEMA_PATH);
  const base = readJson(BASE_SCHEMA_PATH);
  validateManifest(manifest, b2c);
  validateProjection(manifest);
  validateRustSurface(manifest, b2c, base);
  const expected = buildCorpus();
  if (process.argv.includes("--emit-corpus")) {
    process.stdout.write(`${JSON.stringify(expected, null, 2)}\n`);
    return;
  }
  const committed = readJson(CORPUS_PATH);
  if (JSON.stringify(committed) !== JSON.stringify(expected)) {
    fail("source_vector_drift", 0, "committed B2-D corpus differs from deterministic source", "gate");
  }
  validateCorpus(committed);
  const prefixCount = committed.parser_campaigns.all_noncomplete_prefixes.case_count;
  console.log(
    `PoCO-BFT v0 B2-D block body kernel: valid (${prefixCount} prefixes, ` +
      `${committed.parser_boundaries.length} parser boundaries, ` +
      `${committed.semantic_negatives.length} semantic negatives, ` +
      `${committed.strict_ed25519_cases.length} strict Ed25519 cases, ` +
      `${committed.body_admission_negatives.length} body admission negatives)`,
  );
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
