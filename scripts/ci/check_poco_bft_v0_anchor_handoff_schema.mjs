#!/usr/bin/env node

// Independent B2-B CEV0 schema/parser gate for the synthetic-anchor and
// handoff certificate kernel. Standard-library only. It deliberately imports
// the committed B2-A manifest rather than copying its primitives, QC, or
// SignatureShare schema. The anchor-finality fixture is shape-only: this gate
// never treats its opaque signatures as cryptographic positives.

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
const SCHEMA_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-anchor-handoff-v0.json",
);
const CORPUS_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/cev0-parser-anchor-handoff-kernel-v0.json",
);
const SOURCE_PATH = path.join(
  REPO_ROOT,
  "docs/protocol/poco-bft-v0/vectors/anchor-finality-v0.json",
);
const HASH_PREFIX = Buffer.from("trnm.cev0.hash.v0", "ascii");
const META = Symbol("cev0_meta");

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
    fail("schema_manifest_invalid", 0, `${label} is not canonical decimal text`, "gate");
  }
  return BigInt(value);
}

function safeNumber(value, label) {
  const parsed = canonicalDecimal(value, label);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("schema_manifest_invalid", 0, `${label} exceeds Number safe range`, "gate");
  }
  return Number(parsed);
}

function canonicalHex(value, label, gateCode = "source_vector_drift") {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]*$/.test(value)
  ) {
    fail(gateCode, 0, `${label} is not lowercase hexadecimal`, "gate");
  }
  const decoded = Buffer.from(value, "hex");
  if (decoded.toString("hex") !== value) {
    fail(gateCode, 0, `${label} is not canonical hexadecimal`, "gate");
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

function bytesEqual(first, second) {
  return Buffer.isBuffer(first) && Buffer.isBuffer(second) && first.equals(second);
}

function compareBytes(first, second) {
  return Buffer.compare(first, second);
}

function frame(value) {
  if (!Buffer.isBuffer(value) || value.length > 0xffffffff) {
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

function resolvePointer(root, pointer) {
  if (pointer === "") {
    return root;
  }
  if (typeof pointer !== "string" || !pointer.startsWith("/")) {
    fail("schema_manifest_invalid", 0, `invalid JSON pointer ${pointer}`, "gate");
  }
  let current = root;
  for (const component of pointer.slice(1).split("/")) {
    const key = component.replaceAll("~1", "/").replaceAll("~0", "~");
    if (current === null || typeof current !== "object" || !(key in current)) {
      fail("source_vector_drift", 0, `JSON pointer ${pointer} is missing`, "gate");
    }
    current = current[key];
  }
  return current;
}

function makeIndex(base, extension) {
  const combineUnique = (first, second, label) => {
    const result = new Map();
    for (const item of [...first, ...second]) {
      if (result.has(item.name)) {
        fail("schema_manifest_invalid", 0, `duplicate imported ${label} ${item.name}`, "gate");
      }
      result.set(item.name, item);
    }
    return result;
  };
  const domains = new Map();
  for (const item of [...base.domains, ...extension.domains]) {
    if (domains.has(item.id)) {
      fail("schema_manifest_invalid", 0, `duplicate domain id ${item.id}`, "gate");
    }
    domains.set(item.id, item);
  }
  return {
    aliases: combineUnique(base.aliases, [], "alias"),
    enums: combineUnique(base.enums, extension.enums, "enum"),
    objects: combineUnique(base.objects, extension.objects, "object"),
    domains,
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
      const maximum = safeNumber(type.max_count, "list max_count");
      if (count > maximum) {
        fail(
          "count_limit_exceeded",
          countOffset,
          `list count ${count} exceeds hard maximum ${maximum}`,
        );
      }
      // Bounds are checked before allocating the output array.
      const result = new Array(count);
      for (let position = 0; position < count; position += 1) {
        result[position] = this.decode(type.item);
      }
      return result;
    }

    if (typeof type === "object" && type?.kind === "optional") {
      const tagOffset = this.offset;
      const tag = this.unsigned(1);
      if (tag === 0) {
        return null;
      }
      if (tag !== 1) {
        fail("invalid_optional_tag", tagOffset, `optional tag ${tag} is not 0 or 1`);
      }
      return this.decode(type.item);
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
      const enumOffset = this.offset;
      const value = this.unsigned(INTEGER_WIDTHS.get(enumeration.encoding));
      if (!enumeration.variants.some((variant) => variant.value === value)) {
        const code = type === "BlockKindV0" ? "invalid_block_kind" : "context_mismatch";
        fail(code, enumOffset, `${type} has unknown discriminant ${value}`);
      }
      return value;
    }
    const object = this.index.objects.get(type);
    if (object) {
      const start = this.offset;
      const result = {};
      const fields = {};
      for (const field of object.fields) {
        fields[field.name] = this.offset;
        result[field.name] = this.decode(field.type, field);
      }
      if (object.name === "HandoffCertificateV0") {
        const aggregate =
          result.old_signatures.length + result.new_signatures.length;
        if (aggregate > 200) {
          fail(
            "aggregate_limit_exceeded",
            fields.new_signatures,
            `handoff aggregate signature count ${aggregate} exceeds 200`,
          );
        }
      }
      Object.defineProperty(result, META, {
        value: { start, end: this.offset, fields },
        enumerable: false,
      });
      return result;
    }
    fail("schema_manifest_invalid", this.offset, `unknown logical type ${String(type)}`, "gate");
  }
}

function encodeUnsigned(value, width) {
  const bigint = typeof value === "bigint" ? value : BigInt(value);
  const maximum = 1n << BigInt(width * 8);
  if (bigint < 0n || bigint >= maximum) {
    fail("schema_manifest_invalid", 0, `integer does not fit ${width} bytes`, "gate");
  }
  const result = Buffer.alloc(width);
  let remaining = bigint;
  for (let position = width - 1; position >= 0; position -= 1) {
    result[position] = Number(remaining & 0xffn);
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
  if (typeof type === "object" && type?.kind === "optional") {
    return value === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), encodeValue(type.item, value, index)]);
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
      fail("schema_manifest_invalid", 0, `${type} has the wrong byte length`, "gate");
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
  fail("schema_manifest_invalid", 0, `cannot encode unknown logical type ${String(type)}`, "gate");
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

function fieldOffset(value, field) {
  const offset = value?.[META]?.fields?.[field];
  return Number.isInteger(offset) ? offset : 0;
}

function isZero(bytes) {
  return bytes.every((byte) => byte === 0);
}

function requireSchemaZero(value, label) {
  if (value.schema_version !== 0) {
    fail(
      "invalid_schema_version",
      fieldOffset(value, "schema_version"),
      `${label} schema_version is not 0`,
      "admission",
    );
  }
}

function requireNonzeroGenesis(value, label) {
  if (isZero(value.genesis_hash)) {
    fail(
      "zero_genesis_hash",
      fieldOffset(value, "genesis_hash"),
      `${label} genesis_hash is zero`,
      "admission",
    );
  }
}

function requireNonzeroHash(value, field, label, code) {
  if (isZero(value[field])) {
    fail(
      code,
      fieldOffset(value, field),
      `${label} ${field} is zero`,
      "admission",
    );
  }
}

function requireOrderedSigners(items, owner, fieldName) {
  for (let position = 1; position < items.length; position += 1) {
    const order = compareBytes(items[position - 1].validator_id, items[position].validator_id);
    if (order === 0) {
      fail(
        "duplicate_signer",
        items[position]?.[META]?.start ?? fieldOffset(owner, fieldName),
        `${fieldName} contains a duplicate validator_id`,
        "admission",
      );
    }
    if (order > 0) {
      fail(
        "noncanonical_signer_order",
        items[position]?.[META]?.start ?? fieldOffset(owner, fieldName),
        `${fieldName} is not strictly validator_id ordered`,
        "admission",
      );
    }
  }
}

function admitBlockHeader(header) {
  requireSchemaZero(header, "BlockHeaderV0");
  requireNonzeroGenesis(header, "BlockHeaderV0");
  requireNonzeroHash(
    header,
    "active_validator_set_hash",
    "BlockHeaderV0",
    "invalid_block_header",
  );
  if (header.view === 0n || header.height === 0n) {
    fail(
      "invalid_block_header",
      header.view === 0n ? fieldOffset(header, "view") : fieldOffset(header, "height"),
      "network block view and height must both be positive",
      "admission",
    );
  }
  const carriesCommitment = header.next_epoch_commitment_hash !== null;
  const mustCarry = header.block_kind >= 1 && header.block_kind <= 3;
  if (carriesCommitment !== mustCarry) {
    fail(
      "invalid_block_header",
      fieldOffset(header, "next_epoch_commitment_hash"),
      "block kind and next-epoch commitment presence disagree",
      "admission",
    );
  }
}

function admitDescriptor(descriptor) {
  requireSchemaZero(descriptor, "HandoffDescriptorV0");
  requireNonzeroGenesis(descriptor, "HandoffDescriptorV0");
  requireNonzeroHash(
    descriptor,
    "old_validator_set_hash",
    "HandoffDescriptorV0",
    "invalid_handoff_descriptor",
  );
  requireNonzeroHash(
    descriptor,
    "new_validator_set_hash",
    "HandoffDescriptorV0",
    "invalid_handoff_descriptor",
  );
  for (const field of [
    "old_consensus_parameters_hash",
    "new_consensus_parameters_hash",
    "checkpoint_block_id",
    "checkpoint_state_root",
    "next_epoch_commitment_digest",
    "terminal_old_block_id",
    "terminal_old_qc_digest",
  ]) {
    requireNonzeroHash(
      descriptor,
      field,
      "HandoffDescriptorV0",
      "invalid_handoff_descriptor",
    );
  }
  if (descriptor.new_epoch !== descriptor.old_epoch + 1n) {
    fail(
      "descriptor_epoch_mismatch",
      fieldOffset(descriptor, "new_epoch"),
      "new_epoch must equal old_epoch + 1",
      "admission",
    );
  }
  if (descriptor.checkpoint_height > descriptor.terminal_old_height) {
    fail(
      "descriptor_height_mismatch",
      fieldOffset(descriptor, "checkpoint_height"),
      "checkpoint_height exceeds terminal_old_height",
      "admission",
    );
  }
  if (descriptor.activation_height !== descriptor.terminal_old_height + 1n) {
    fail(
      "descriptor_height_mismatch",
      fieldOffset(descriptor, "activation_height"),
      "activation_height must immediately follow terminal_old_height",
      "admission",
    );
  }
  if (descriptor.initial_new_view !== 1n) {
    fail(
      "descriptor_initial_view_mismatch",
      fieldOffset(descriptor, "initial_new_view"),
      "initial_new_view must equal 1",
      "admission",
    );
  }
}

function descriptorDigest(descriptor, index) {
  return digest(
    "trnm.poco-bft.handoff-descriptor.v0",
    encodeValue("HandoffDescriptorV0", descriptor, index),
  );
}

function expectedHandoffVote(descriptor, role, index) {
  const old = role === "old";
  if (!old && role !== "new") {
    fail("schema_manifest_invalid", 0, `unknown handoff role ${role}`, "gate");
  }
  return {
    schema_version: 0,
    genesis_hash: descriptor.genesis_hash,
    chain_id: descriptor.chain_id,
    signing_protocol_version: old
      ? descriptor.old_protocol_version
      : descriptor.new_protocol_version,
    signing_epoch: old ? descriptor.old_epoch : descriptor.new_epoch,
    signing_validator_set_hash: old
      ? descriptor.old_validator_set_hash
      : descriptor.new_validator_set_hash,
    signing_view: old ? descriptor.terminal_old_view : descriptor.initial_new_view,
    message_kind: old ? 3 : 4,
    handoff_descriptor_digest: descriptorDigest(descriptor, index),
  };
}

function admitHandoffVote(vote, descriptor, role, index) {
  requireSchemaZero(vote, "HandoffVoteSignV0");
  requireNonzeroGenesis(vote, "HandoffVoteSignV0");
  requireNonzeroHash(
    vote,
    "signing_validator_set_hash",
    "HandoffVoteSignV0",
    "handoff_role_scope_mismatch",
  );
  if (vote.signing_view === 0n) {
    fail(
      "handoff_role_scope_mismatch",
      fieldOffset(vote, "signing_view"),
      "handoff signing view must be positive",
      "admission",
    );
  }
  const expected = expectedHandoffVote(descriptor, role, index);
  const scopeFields = [
    "schema_version",
    "genesis_hash",
    "chain_id",
    "signing_protocol_version",
    "signing_epoch",
    "signing_validator_set_hash",
    "signing_view",
    "message_kind",
  ];
  for (const field of scopeFields) {
    const same = Buffer.isBuffer(expected[field])
      ? bytesEqual(vote[field], expected[field])
      : vote[field] === expected[field];
    if (!same) {
      fail(
        "handoff_role_scope_mismatch",
        fieldOffset(vote, field),
        `${role} handoff vote field ${field} does not match the descriptor role`,
        "admission",
      );
    }
  }
  if (!bytesEqual(vote.handoff_descriptor_digest, expected.handoff_descriptor_digest)) {
    fail(
      "handoff_descriptor_digest_mismatch",
      fieldOffset(vote, "handoff_descriptor_digest"),
      "handoff vote does not bind the exact descriptor digest",
      "admission",
    );
  }
}

function admitCertificate(certificate) {
  requireSchemaZero(certificate, "HandoffCertificateV0");
  admitDescriptor(certificate.descriptor);
  if (certificate.old_signatures.length === 0) {
    fail(
      "empty_handoff_role",
      fieldOffset(certificate, "old_signatures"),
      "old handoff role is empty",
      "admission",
    );
  }
  if (certificate.new_signatures.length === 0) {
    fail(
      "empty_handoff_role",
      fieldOffset(certificate, "new_signatures"),
      "new handoff role is empty",
      "admission",
    );
  }
  requireOrderedSigners(certificate.old_signatures, certificate, "old_signatures");
  requireOrderedSigners(certificate.new_signatures, certificate, "new_signatures");
}

function admitTerminalQc(qc) {
  requireSchemaZero(qc, "terminal QuorumCertificateV0");
  requireNonzeroGenesis(qc, "terminal QuorumCertificateV0");
  requireNonzeroHash(
    qc,
    "validator_set_hash",
    "terminal QuorumCertificateV0",
    "context_mismatch",
  );
  if (qc.signatures.length === 0) {
    fail(
      "terminal_qc_unauthorized",
      fieldOffset(qc, "signatures"),
      "the terminal old QC must be an ordinary non-empty QC",
      "admission",
    );
  }
  requireOrderedSigners(qc.signatures, qc, "signatures");
}

function blockId(header, index) {
  return digest(
    "trnm.poco-bft.block.v0",
    encodeValue("BlockHeaderV0", header, index),
  );
}

function qcDigest(qc, index) {
  return digest(
    "trnm.poco-bft.qc.v0",
    encodeValue("QuorumCertificateV0", qc, index),
  );
}

function admitAuthorizationKernelRelations(authorization, index) {
  const header = authorization.terminal_old_header;
  const qc = authorization.terminal_old_qc;
  const certificate = authorization.handoff_certificate;
  const descriptor = certificate.descriptor;

  if (header.block_kind !== 3) {
    fail(
      "terminal_not_epoch_seal_2",
      fieldOffset(header, "block_kind"),
      "terminal old header is not epoch_seal_2",
      "admission",
    );
  }
  admitBlockHeader(header);
  admitCertificate(certificate);
  admitTerminalQc(qc);

  const certifiedHeaderFields = [
    ["genesis_hash", "genesis_hash"],
    ["chain_id", "chain_id"],
    ["protocol_version", "protocol_version"],
    ["epoch", "epoch"],
    ["validator_set_hash", "active_validator_set_hash"],
    ["view", "view"],
    ["height", "height"],
  ];
  for (const [qcField, headerField] of certifiedHeaderFields) {
    const same = Buffer.isBuffer(qc[qcField])
      ? bytesEqual(qc[qcField], header[headerField])
      : qc[qcField] === header[headerField];
    if (!same) {
      fail(
        "terminal_qc_mismatch",
        fieldOffset(qc, qcField),
        `terminal QC ${qcField} does not match its header`,
        "admission",
      );
    }
  }
  if (!bytesEqual(qc.block_id, blockId(header, index))) {
    fail(
      "terminal_qc_mismatch",
      fieldOffset(qc, "block_id"),
      "terminal QC does not certify the exact terminal header block ID",
      "admission",
    );
  }

  const terminalRelations = [
    ["genesis_hash", header.genesis_hash],
    ["chain_id", header.chain_id],
    ["old_protocol_version", header.protocol_version],
    ["old_epoch", header.epoch],
    ["old_validator_set_hash", header.active_validator_set_hash],
    ["old_consensus_parameters_hash", header.consensus_parameters_hash],
    ["terminal_old_view", header.view],
    ["terminal_old_height", header.height],
    ["terminal_old_block_id", blockId(header, index)],
    ["terminal_old_qc_digest", qcDigest(qc, index)],
    ["checkpoint_state_root", header.state_root],
    ["next_epoch_commitment_digest", header.next_epoch_commitment_hash],
  ];
  for (const [field, expected] of terminalRelations) {
    const same = Buffer.isBuffer(expected)
      ? bytesEqual(descriptor[field], expected)
      : descriptor[field] === expected;
    if (!same) {
      fail(
        "descriptor_terminal_mismatch",
        fieldOffset(descriptor, field),
        `descriptor ${field} does not match the terminal header/QC`,
        "admission",
      );
    }
  }
}

// Gate-only fixture calculation. This freezes the candidate byte binding but
// does not return an anchor from the decoder or authorize a usable anchor.
function deriveFutureEpochAnchorCandidateFixture(authorization) {
  const descriptor = authorization.handoff_certificate.descriptor;
  return {
    schema_version: 0,
    genesis_hash: descriptor.genesis_hash,
    chain_id: descriptor.chain_id,
    protocol_version: descriptor.new_protocol_version,
    epoch: descriptor.new_epoch,
    validator_set_hash: descriptor.new_validator_set_hash,
    view: 0n,
    height: descriptor.terminal_old_height,
    block_id: descriptor.terminal_old_block_id,
    signatures: [],
  };
}

function typeReferences(type) {
  if (
    typeof type === "object" &&
    (type?.kind === "list" || type?.kind === "optional")
  ) {
    return [type.item];
  }
  return [type];
}

function assertExactCodes(entries, expected, label) {
  if (!Array.isArray(entries)) {
    fail("schema_manifest_invalid", 0, `${label} is not an array`, "gate");
  }
  const actual = entries.map((item) => item.code);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      "schema_manifest_invalid",
      0,
      `${label} drifted: ${actual.join(",")}`,
      "gate",
    );
  }
  if (new Set(actual).size !== actual.length) {
    fail("schema_manifest_invalid", 0, `${label} contains duplicate codes`, "gate");
  }
}

function validateManifest(base, manifest, index) {
  if (
    base.schema !== "trnm_poco_bft_cev0_logical_schema_v0" ||
    base.schema_version !== 0 ||
    manifest.schema !== "trnm_poco_bft_cev0_logical_schema_anchor_handoff_v0" ||
    manifest.schema_version !== 0 ||
    manifest.scope !== "B2-B synthetic-anchor and handoff certificate kernel only" ||
    manifest.status !== "closed_for_listed_objects_and_relations_only"
  ) {
    fail("schema_manifest_invalid", 0, "unexpected base/B2-B manifest identity", "gate");
  }
  if (
    Object.hasOwn(manifest, "hash_construction") ||
    Object.hasOwn(manifest, "primitives") ||
    Object.hasOwn(manifest, "aliases")
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "B2-B must import rather than redeclare CEV0 primitives or aliases",
      "gate",
    );
  }
  if (
    !Array.isArray(manifest.imports) ||
    manifest.imports.length !== 1 ||
    manifest.imports[0].path !== "cev0-logical-schema-v0.json" ||
    manifest.imports[0].schema !== base.schema ||
    manifest.imports[0].schema_version !== base.schema_version
  ) {
    fail("schema_manifest_invalid", 0, "B2-A import is not exact", "gate");
  }
  const requiredReuse = new Set([
    "hash_construction",
    "primitives",
    "Hash32",
    "Signature64",
    "MessageKindV0",
    "SignatureShareV0",
    "QuorumCertificateV0",
    "qc domain",
  ]);
  const actualReuse = new Set(manifest.imports[0].reuse ?? []);
  if (
    requiredReuse.size !== actualReuse.size ||
    [...requiredReuse].some((item) => !actualReuse.has(item))
  ) {
    fail("schema_manifest_invalid", 0, "B2-A reuse set drifted", "gate");
  }
  if (
    base.hash_construction.algorithm !== "sha256" ||
    base.hash_construction.hash_prefix_ascii !== "trnm.cev0.hash.v0" ||
    base.hash_construction.frame_length !== "u32_be"
  ) {
    fail("schema_manifest_invalid", 0, "imported hash construction drifted", "gate");
  }

  const expectedLimits = {
    max_chain_id_bytes: "128",
    max_validator_id_bytes: "128",
    max_handoff_old_signature_count: "100",
    max_handoff_new_signature_count: "100",
    max_handoff_aggregate_signature_count: "200",
  };
  if (JSON.stringify(manifest.hard_limits) !== JSON.stringify(expectedLimits)) {
    fail("schema_manifest_invalid", 0, "B2-B hard limits drifted", "gate");
  }
  for (const [name, value] of Object.entries(manifest.hard_limits)) {
    canonicalDecimal(value, `hard_limits.${name}`);
  }

  const expectedEnumNames = ["BlockKindV0"];
  if (
    JSON.stringify(manifest.enums.map((item) => item.name)) !==
    JSON.stringify(expectedEnumNames)
  ) {
    fail("schema_manifest_invalid", 0, "B2-B enum set drifted", "gate");
  }
  const blockKind = manifest.enums[0];
  const expectedBlockKinds = [
    ["regular", 0],
    ["epoch_checkpoint", 1],
    ["epoch_seal_1", 2],
    ["epoch_seal_2", 3],
    ["epoch_handoff", 4],
  ];
  if (
    blockKind.encoding !== "u8" ||
    blockKind.coverage !== "closed" ||
    JSON.stringify(blockKind.variants.map((item) => [item.name, item.value])) !==
      JSON.stringify(expectedBlockKinds)
  ) {
    fail("schema_manifest_invalid", 0, "BlockKindV0 drifted", "gate");
  }

  const expectedObjects = [
    "BlockHeaderV0",
    "HandoffDescriptorV0",
    "HandoffVoteSignV0",
    "HandoffCertificateV0",
    "EpochAnchorAuthorizationV0",
  ];
  if (
    JSON.stringify(manifest.objects.map((item) => item.name)) !==
    JSON.stringify(expectedObjects)
  ) {
    fail("schema_manifest_invalid", 0, "B2-B object set drifted", "gate");
  }
  if (
    manifest.objects.some(
      (item) => item.name === "QuorumCertificateV0" || item.name === "SignatureShareV0",
    )
  ) {
    fail("schema_manifest_invalid", 0, "imported B2-A objects were redeclared", "gate");
  }

  const knownTerminals = new Set([
    ...INTEGER_WIDTHS.keys(),
    "Bytes",
    "ConsensusString",
    ...index.aliases.keys(),
    ...index.enums.keys(),
  ]);
  for (const object of manifest.objects) {
    if (!Array.isArray(object.fields) || object.fields.length === 0) {
      fail("schema_manifest_invalid", 0, `${object.name} has no fields`, "gate");
    }
    const fieldNames = object.fields.map((field) => field.name);
    if (new Set(fieldNames).size !== fieldNames.length) {
      fail("schema_manifest_invalid", 0, `${object.name} repeats a field`, "gate");
    }
    for (const field of object.fields) {
      for (const reference of typeReferences(field.type)) {
        if (!knownTerminals.has(reference) && !index.objects.has(reference)) {
          fail(
            "schema_manifest_invalid",
            0,
            `${object.name}.${field.name} references unknown type ${reference}`,
            "gate",
          );
        }
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function walk(name) {
    if (visited.has(name)) {
      return;
    }
    if (visiting.has(name)) {
      fail("schema_manifest_invalid", 0, `object graph cycle at ${name}`, "gate");
    }
    visiting.add(name);
    const object = index.objects.get(name);
    for (const field of object.fields) {
      for (const reference of typeReferences(field.type)) {
        if (index.objects.has(reference)) {
          walk(reference);
        }
      }
    }
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of expectedObjects) {
    walk(name);
  }

  const expectedDomains = [
    ["block", "trnm.poco-bft.block.v0", "BlockHeaderV0"],
    [
      "handoff_descriptor",
      "trnm.poco-bft.handoff-descriptor.v0",
      "HandoffDescriptorV0",
    ],
    ["handoff_vote", "trnm.poco-bft.handoff-vote.v0", "HandoffVoteSignV0"],
    [
      "handoff_certificate",
      "trnm.poco-bft.handoff-certificate.v0",
      "HandoffCertificateV0",
    ],
  ];
  if (
    JSON.stringify(
      manifest.domains.map((item) => [item.id, item.ascii, item.logical_object]),
    ) !== JSON.stringify(expectedDomains)
  ) {
    fail("schema_manifest_invalid", 0, "B2-B domain table drifted", "gate");
  }
  if (manifest.domains.some((item) => item.logical_object === "EpochAnchorAuthorizationV0")) {
    fail("schema_manifest_invalid", 0, "authorization must not gain a hash domain", "gate");
  }

  const outputs = new Map(
    (manifest.context_derived_outputs ?? []).map((item) => [item.name, item]),
  );
  for (const name of ["GenesisQC", "EpochAnchorQC"]) {
    const output = outputs.get(name);
    if (
      !output ||
      output.logical_object !== "QuorumCertificateV0" ||
      output.raw_peer_decoder_exposed !== false ||
      output.ordinary_qc_admission !== false ||
      output.b2b_decoder_output !== false ||
      output.usable_after_b2b_kernel_only !== false
    ) {
      fail(
        "schema_manifest_invalid",
        0,
        `${name} is not frozen as a future trusted/candidate output`,
        "gate",
      );
    }
  }
  const forbidden = new Set(manifest.forbidden_decoder_entry_points ?? []);
  if (
    !forbidden.has("decode_genesis_qc_from_peer_bytes") ||
    !forbidden.has("decode_epoch_anchor_qc_from_peer_bytes") ||
    !forbidden.has("decode_any_empty_signature_qc_as_authorized_anchor") ||
    !forbidden.has("EpochAnchorAuthorizationKernelV0::epoch_anchor_qc") ||
    !forbidden.has("EpochAnchorAuthorizationKernelV0::into_authorization") ||
    !forbidden.has(
      "decode_epoch_anchor_authorization_kernel_v0_exact -> EpochAnchorAuthorizationV0",
    )
  ) {
    fail("schema_manifest_invalid", 0, "synthetic-QC decoder prohibition drifted", "gate");
  }
  const expectedNodeEntries = [
    "decode_block_header_v0_exact",
    "decode_handoff_descriptor_v0_exact",
    "decode_handoff_vote_sign_v0_exact_with_descriptor_role",
    "decode_handoff_certificate_v0_exact",
    "decode_epoch_anchor_authorization_v0_exact",
  ];
  if (
    JSON.stringify(manifest.node_decoder_entry_points) !==
    JSON.stringify(expectedNodeEntries)
  ) {
    fail("schema_manifest_invalid", 0, "Node decoder entry-point set drifted", "gate");
  }
  if ((manifest.node_decoder_entry_points ?? []).some((name) => /genesis_qc|epoch_anchor_qc/.test(name))) {
    fail("schema_manifest_invalid", 0, "a bare synthetic-QC decoder was exposed", "gate");
  }
  const returnContracts = manifest.rust_decoder_return_contracts ?? [];
  if (
    returnContracts.length !== 1 ||
    returnContracts[0].entry_point !==
      "decode_epoch_anchor_authorization_kernel_v0_exact" ||
    returnContracts[0].return_type !== "EpochAnchorAuthorizationKernelV0" ||
    returnContracts[0].inert !== true ||
    JSON.stringify(returnContracts[0].forbidden_methods) !==
      JSON.stringify(["epoch_anchor_qc", "into_authorization"]) ||
    !returnContracts[0].permitted_methods.includes("verify_certificate_kernel")
  ) {
    fail("schema_manifest_invalid", 0, "inert Rust kernel return contract drifted", "gate");
  }

  assertExactCodes(
    manifest.decoder_error_codes,
    [
      "unexpected_eof",
      "trailing_bytes",
      "length_limit_exceeded",
      "count_limit_exceeded",
      "aggregate_limit_exceeded",
      "invalid_schema_version",
      "invalid_protocol_version",
      "invalid_consensus_string",
      "invalid_block_kind",
      "invalid_optional_tag",
      "invalid_block_header",
      "invalid_handoff_descriptor",
      "invalid_handoff_certificate",
      "invalid_epoch_anchor_relations",
      "unauthorized_synthetic_qc",
      "zero_genesis_hash",
      "zero_public_key",
      "zero_voting_power",
      "empty_validator_set",
      "duplicate_validator_id",
      "duplicate_public_key",
      "noncanonical_validator_order",
      "context_mismatch",
      "unknown_signer",
      "duplicate_signer",
      "noncanonical_signer_order",
      "noncanonical_reference_order",
      "conflicting_same_view_qc",
      "insufficient_quorum",
      "invalid_referenced_qc",
      "empty_tc",
      "duplicate_reference",
      "future_reference_view",
      "same_block_different_coordinates",
      "reference_summary_mismatch",
      "unreferenced_qc",
      "selected_not_maximum",
    ],
    "decoder_error_codes",
  );
  assertExactCodes(
    manifest.node_admission_error_codes,
    [
      "descriptor_epoch_mismatch",
      "descriptor_height_mismatch",
      "descriptor_initial_view_mismatch",
      "handoff_role_scope_mismatch",
      "handoff_descriptor_digest_mismatch",
      "empty_handoff_role",
      "terminal_not_epoch_seal_2",
      "terminal_qc_unauthorized",
      "terminal_qc_mismatch",
      "descriptor_terminal_mismatch",
    ],
    "node_admission_error_codes",
  );
  assertExactCodes(
    manifest.gate_error_codes,
    [
      "schema_manifest_invalid",
      "proto_projection_drift",
      "source_vector_drift",
      "digest_mismatch",
    ],
    "gate_error_codes",
  );
  const layeredCodes = [
    ...manifest.decoder_error_codes,
    ...manifest.node_admission_error_codes,
    ...manifest.gate_error_codes,
  ].map((item) => item.code);
  if (new Set(layeredCodes).size !== layeredCodes.length) {
    fail("schema_manifest_invalid", 0, "stable error code is duplicated across layers", "gate");
  }
  const expectedRustEntries = [
    "decode_block_header_v0_exact",
    "decode_handoff_descriptor_v0_exact",
    "decode_handoff_certificate_v0_exact",
    "decode_epoch_anchor_authorization_kernel_v0_exact",
  ];
  if (
    JSON.stringify(manifest.rust_decoder_entry_points) !==
      JSON.stringify(expectedRustEntries) ||
    manifest.rust_decoder_error_source !==
      "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs"
  ) {
    fail("schema_manifest_invalid", 0, "Rust decoder mapping drifted", "gate");
  }
  const rustDecoderSource = fs.readFileSync(
    path.join(REPO_ROOT, manifest.rust_decoder_error_source),
    "utf8",
  );
  for (const entry of expectedRustEntries) {
    if (!new RegExp(`pub fn ${entry}\\b`).test(rustDecoderSource)) {
      fail("schema_manifest_invalid", 0, `Rust entry point ${entry} is missing`, "gate");
    }
  }
  if (
    !/pub fn decode_epoch_anchor_authorization_kernel_v0_exact\s*\([\s\S]*?\)\s*->\s*DecodeResult<EpochAnchorAuthorizationKernelV0>\s*\{/.test(
      rustDecoderSource,
    )
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "Rust epoch-anchor decoder does not return the inert kernel type",
      "gate",
    );
  }
  const kernelStruct = extractBraceBody(
    rustDecoderSource,
    "pub struct EpochAnchorAuthorizationKernelV0",
    "Rust inert kernel struct",
  );
  if (/\bpub(?:\([^)]*\))?\s+[A-Za-z_][A-Za-z0-9_]*\s*:/.test(kernelStruct)) {
    fail("schema_manifest_invalid", 0, "Rust inert kernel exposes a public field", "gate");
  }
  const kernelImpl = extractBraceBody(
    rustDecoderSource,
    "impl EpochAnchorAuthorizationKernelV0",
    "Rust inert kernel impl",
  );
  const publicKernelMethods = [
    ...kernelImpl.matchAll(/\bpub\s+(?:const\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)/g),
  ].map((match) => match[1]);
  const returnContract = manifest.rust_decoder_return_contracts[0];
  if (
    JSON.stringify(publicKernelMethods) !==
      JSON.stringify(returnContract.permitted_methods) ||
    returnContract.forbidden_methods.some((method) =>
      publicKernelMethods.includes(method),
    ) ||
    /\b(?:pub\s+)?fn\s+(?:epoch_anchor_qc|into_authorization)\b/.test(kernelImpl)
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "Rust inert kernel public/forbidden method surface drifted",
      "gate",
    );
  }
  const rustLibSource = fs.readFileSync(
    path.join(
      REPO_ROOT,
      "trillionnium/crates/trnm-consensus-types/src/lib.rs",
    ),
    "utf8",
  );
  if (!/\bEpochAnchorAuthorizationKernelV0\b/.test(rustLibSource)) {
    fail("schema_manifest_invalid", 0, "Rust inert kernel type is not exported", "gate");
  }
  const rustHandoffSource = fs.readFileSync(
    path.join(
      REPO_ROOT,
      "trillionnium/crates/trnm-consensus-types/src/handoff.rs",
    ),
    "utf8",
  );
  if (
    /\bpub\s+fn\s+epoch_anchor_qc\b/.test(rustHandoffSource) ||
    /\bpub\s+fn\s+into_authorization\b/.test(rustHandoffSource)
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "Rust authorization exposes a public anchor-producing upgrade method",
      "gate",
    );
  }
  const rustErrorCodes = [...rustDecoderSource.matchAll(/Self::[A-Za-z0-9_]+\s*=>\s*"([a-z0-9_]+)"/g)]
    .map((match) => match[1]);
  const manifestCodes = manifest.decoder_error_codes.map((item) => item.code);
  const expectedB2cAdditions = [
    "invalid_boolean",
    "invalid_rollout_phase",
    "invalid_fallback_reason",
    "invalid_next_epoch_commitment",
  ];
  const expectedB2dAdditions = [
    "invalid_utf8",
    "noncanonical_event_attribute_order",
    "invalid_double_vote_evidence",
  ];
  const expectedB2eAdditions = [
    "invalid_leader_schedule",
    "invalid_consensus_parameters",
    "invalid_finality_proof",
    "invalid_checkpoint_two_seal",
  ];
  const scopedExclusions = manifest.rust_decoder_error_exclusions ?? [];
  const b2cAdditions = scopedExclusions.slice(0, 4).map(
    (item) => item.code,
  );
  const b2dAdditions = scopedExclusions.slice(4, 7).map((item) => item.code);
  const b2eAdditions = scopedExclusions.slice(7).map((item) => item.code);
  if (
    JSON.stringify(b2cAdditions) !== JSON.stringify(expectedB2cAdditions) ||
    JSON.stringify(b2dAdditions) !== JSON.stringify(expectedB2dAdditions) ||
    JSON.stringify(b2eAdditions) !== JSON.stringify(expectedB2eAdditions) ||
    scopedExclusions.slice(0, 4).some(
      (item) => item.scope !== "B2-C NextEpochCommitmentV0 endpoint only",
    ) ||
    scopedExclusions.slice(4, 7).some(
      (item) => item.scope !== "B2-D ordinary block body endpoint only",
    ) ||
    scopedExclusions.slice(7).some(
      (item) => item.scope !== "B2-E checkpoint finality endpoint only",
    ) ||
    JSON.stringify(
      rustErrorCodes.filter(
        (code) =>
          !b2cAdditions.includes(code) &&
          !b2dAdditions.includes(code) &&
          !b2eAdditions.includes(code),
      ),
    ) !== JSON.stringify(manifestCodes)
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "B2-B scoped decoder codes plus B2-C/B2-D/B2-E exclusions do not match Rust as_str order",
      "gate",
    );
  }
  const baseCodes = base.decoder_error_codes.map((item) => item.code);
  const expectedB2bAdditions = [
    "invalid_block_kind",
    "invalid_optional_tag",
    "invalid_block_header",
    "invalid_handoff_descriptor",
    "invalid_handoff_certificate",
    "invalid_epoch_anchor_relations",
  ];
  const allBaseExclusions = (base.rust_decoder_error_exclusions ?? []).map(
    (item) => item.code,
  );
  const b2bAdditions = allBaseExclusions.slice(0, 6);
  const b2cBaseExclusions = allBaseExclusions.slice(6, 10);
  const b2dBaseExclusions = allBaseExclusions.slice(10, 13);
  const b2eBaseExclusions = allBaseExclusions.slice(13);
  if (
    JSON.stringify(b2bAdditions) !== JSON.stringify(expectedB2bAdditions) ||
    JSON.stringify(b2cBaseExclusions) !== JSON.stringify(expectedB2cAdditions) ||
    JSON.stringify(b2dBaseExclusions) !== JSON.stringify(expectedB2dAdditions) ||
    JSON.stringify(b2eBaseExclusions) !== JSON.stringify(expectedB2eAdditions) ||
    new Set(baseCodes).size !== baseCodes.length ||
    new Set(b2bAdditions).size !== b2bAdditions.length ||
    new Set(b2cAdditions).size !== b2cAdditions.length ||
    new Set(b2dAdditions).size !== b2dAdditions.length ||
    new Set(b2eAdditions).size !== b2eAdditions.length ||
    JSON.stringify(
      rustErrorCodes.filter(
        (code) =>
          !b2bAdditions.includes(code) &&
          !b2cAdditions.includes(code) &&
          !b2dAdditions.includes(code) &&
          !b2eAdditions.includes(code),
      ),
    ) !== JSON.stringify(baseCodes) ||
    rustErrorCodes.some(
      (code) =>
          Number(baseCodes.includes(code)) +
          Number(b2bAdditions.includes(code)) +
          Number(b2cAdditions.includes(code)) +
          Number(b2dAdditions.includes(code)) +
          Number(b2eAdditions.includes(code)) !==
        1,
    )
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "B2-A scoped codes plus B2-B/B2-C/B2-D/B2-E additions do not partition Rust vocabulary",
      "gate",
    );
  }
  if (
    manifest.cryptographic_validity_claimed !== false ||
    !Array.isArray(manifest.honest_boundary) ||
    !manifest.honest_boundary.some((line) => line.includes("B2 overall"))
  ) {
    fail("schema_manifest_invalid", 0, "B2-B honest boundary is incomplete", "gate");
  }
}

function stripProtoComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

function extractBraceBody(source, marker, label) {
  const start = source.indexOf(marker);
  if (start < 0) {
    fail("schema_manifest_invalid", 0, `${label} is missing`, "gate");
  }
  const open = source.indexOf("{", start + marker.length);
  if (open < 0) {
    fail("schema_manifest_invalid", 0, `${label} has no body`, "gate");
  }
  let depth = 1;
  for (let position = open + 1; position < source.length; position += 1) {
    if (source[position] === "{") {
      depth += 1;
    } else if (source[position] === "}") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(open + 1, position);
      }
    }
  }
  fail("schema_manifest_invalid", 0, `${label} is unterminated`, "gate");
}

function extractProtoBody(source, kind, name) {
  const clean = stripProtoComments(source);
  const expression = new RegExp(`\\b${kind}\\s+${name}\\s*\\{`, "g");
  const match = expression.exec(clean);
  if (!match) {
    fail("proto_projection_drift", 0, `${kind} ${name} is missing`, "gate");
  }
  const open = clean.indexOf("{", match.index);
  let depth = 1;
  for (let position = open + 1; position < clean.length; position += 1) {
    if (clean[position] === "{") {
      depth += 1;
    } else if (clean[position] === "}") {
      depth -= 1;
      if (depth === 0) {
        return clean.slice(open + 1, position);
      }
    }
  }
  fail("proto_projection_drift", 0, `${kind} ${name} is unterminated`, "gate");
}

function parseProtoFields(filename, message) {
  const body = extractProtoBody(fs.readFileSync(filename, "utf8"), "message", message);
  const fields = [];
  const expression = /\b(repeated\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([0-9]+)\s*;/g;
  for (const match of body.matchAll(expression)) {
    fields.push({
      number: Number(match[4]),
      name: match[3],
      proto_type: match[2],
      cardinality: match[1] ? "repeated" : "singular",
    });
  }
  return fields.sort((first, second) => first.number - second.number);
}

function parseProtoEnum(filename, name) {
  const body = extractProtoBody(fs.readFileSync(filename, "utf8"), "enum", name);
  const variants = [];
  const expression = /\b([A-Z][A-Z0-9_]*)\s*=\s*([0-9]+)\s*;/g;
  for (const match of body.matchAll(expression)) {
    variants.push({ name: match[1], value: Number(match[2]) });
  }
  return variants;
}

function projectionIdentity(projection) {
  return projection.projection_id ?? `${projection.proto_message}:${projection.logical_object}`;
}

function validateTransportProjections(manifest, index) {
  const roles = new Set(["canonical", "redundant", "derived", "sidecar"]);
  const projections = manifest.transport_projections ?? [];
  if (projections.length !== 7) {
    fail("schema_manifest_invalid", 0, "expected exactly seven B2-B projections", "gate");
  }
  const ids = new Set();
  for (const projection of projections) {
    const id = projectionIdentity(projection);
    if (ids.has(id)) {
      fail("schema_manifest_invalid", 0, `duplicate projection ${id}`, "gate");
    }
    ids.add(id);
    const actual = parseProtoFields(
      path.join(REPO_ROOT, projection.proto_file),
      projection.proto_message,
    );
    const declared = projection.fields.map((field) => ({
      number: field.number,
      name: field.name,
      proto_type: field.proto_type,
      cardinality: field.cardinality,
    }));
    if (JSON.stringify(actual) !== JSON.stringify(declared)) {
      fail(
        "proto_projection_drift",
        0,
        `${id} fields do not match ${projection.proto_file}`,
        "gate",
      );
    }
    for (const field of projection.fields) {
      if (!roles.has(field.role)) {
        fail("schema_manifest_invalid", 0, `${id}.${field.name} has an invalid role`, "gate");
      }
      if (field.role === "canonical" && typeof field.logical_field !== "string") {
        fail(
          "schema_manifest_invalid",
          0,
          `${id}.${field.name} lacks a canonical logical_field`,
          "gate",
        );
      }
      if (field.role === "redundant" && typeof field.binding !== "string") {
        fail(
          "schema_manifest_invalid",
          0,
          `${id}.${field.name} lacks a redundancy binding`,
          "gate",
        );
      }
      if (field.role === "derived" && typeof field.derivation !== "string") {
        fail(
          "schema_manifest_invalid",
          0,
          `${id}.${field.name} lacks a derivation`,
          "gate",
        );
      }
      if (field.role === "sidecar" && typeof field.binding !== "string") {
        fail(
          "schema_manifest_invalid",
          0,
          `${id}.${field.name} lacks a sidecar binding`,
          "gate",
        );
      }
    }
  }

  const oldNested = projections.find(
    (item) => item.projection_id === "old_handoff_vote_as_certificate_signature",
  );
  const newNested = projections.find(
    (item) => item.projection_id === "new_handoff_vote_as_certificate_signature",
  );
  for (const projection of [oldNested, newNested]) {
    if (
      !projection ||
      projection.fields.slice(0, 9).some((field) => field.role !== "redundant") ||
      projection.fields.slice(9).some((field) => field.role !== "canonical") ||
      projection.fields[9].logical_field !== "validator_id" ||
      projection.fields[10].logical_field !== "signature"
    ) {
      fail(
        "schema_manifest_invalid",
        0,
        "nested handoff vote scope must be redundant and reduce to SignatureShareV0",
        "gate",
      );
    }
  }
  const authorization = projections.find(
    (item) => item.proto_message === "EpochAnchorAuthorization",
  );
  if (
    !authorization ||
    authorization.independent_digest_domain !== null ||
    authorization.fields.length !== 3 ||
    authorization.fields.some((field) => field.role !== "canonical") ||
    authorization.fields.some((field) => /digest/.test(field.name))
  ) {
    fail(
      "schema_manifest_invalid",
      0,
      "authorization must be exactly three canonical nested values without a digest",
      "gate",
    );
  }
  const certificate = projections.find(
    (item) => item.proto_message === "JointHandoffCertificate",
  );
  if (
    !certificate ||
    certificate.fields[2].item_projection_id !==
      "old_handoff_vote_as_certificate_signature" ||
    certificate.fields[3].item_projection_id !==
      "new_handoff_vote_as_certificate_signature"
  ) {
    fail("schema_manifest_invalid", 0, "joint certificate item projection drifted", "gate");
  }

  for (const enumeration of manifest.transport_enums ?? []) {
    const actual = parseProtoEnum(
      path.join(REPO_ROOT, enumeration.proto_file),
      enumeration.proto_enum,
    );
    const expected = enumeration.variants.map((item) => ({
      name: item.proto_name,
      value: item.value,
    }));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail(
        "proto_projection_drift",
        0,
        `${enumeration.proto_enum} enum drifted`,
        "gate",
      );
    }
    const logical = index.enums.get(enumeration.logical_enum);
    if (
      !logical ||
      JSON.stringify(logical.variants.map((item) => [item.name, item.value])) !==
        JSON.stringify(
          enumeration.variants.map((item) => [item.logical_name, item.value]),
        )
    ) {
      fail("schema_manifest_invalid", 0, "transport/logical BlockKind drifted", "gate");
    }
  }
}

function validateCorpus(corpus, manifest) {
  if (
    corpus.schema !==
      "trnm_poco_bft_cev0_parser_anchor_handoff_kernel_vectors_v0" ||
    corpus.schema_version !== 0 ||
    corpus.logical_schema !==
      "../schema/cev0-logical-schema-anchor-handoff-v0.json" ||
    corpus.imported_logical_schema !== "../schema/cev0-logical-schema-v0.json" ||
    corpus.raw_source_vector !== "anchor-finality-v0.json" ||
    corpus.cryptographic_validity_claimed !== false
  ) {
    fail("schema_manifest_invalid", 0, "unexpected B2-B corpus identity", "gate");
  }
  const expectedRawIds = [
    "handoff_descriptor_shape",
    "handoff_certificate_shape",
    "epoch_anchor_authorization_shape",
    "terminal_old_header_derived",
    "old_handoff_vote_sign_derived",
    "new_handoff_vote_sign_derived",
  ];
  if (
    JSON.stringify(corpus.valid_raw_objects.map((item) => item.id)) !==
    JSON.stringify(expectedRawIds)
  ) {
    fail("schema_manifest_invalid", 0, "valid B2-B raw-object set drifted", "gate");
  }
  if (
    corpus.valid_raw_objects.some(
      (item) => item.object_type === "QuorumCertificateV0",
    )
  ) {
    fail("schema_manifest_invalid", 0, "corpus exposes a bare QC decoder case", "gate");
  }
  const expectedDerivedIds = [
    "terminal_old_header_derived",
    "old_handoff_vote_sign_derived",
    "new_handoff_vote_sign_derived",
  ];
  if (
    JSON.stringify(Object.keys(corpus.derived_exact_expectations ?? {})) !==
    JSON.stringify(expectedDerivedIds)
  ) {
    fail("schema_manifest_invalid", 0, "derived exact expectations drifted", "gate");
  }
  const outputs = corpus.trusted_output_and_candidate_bindings ?? [];
  if (
    outputs.length !== 2 ||
    outputs.some(
      (item) =>
        item.decoder_exposed !== false ||
        item.ordinary_qc_admission !== false ||
        item.b2b_decoder_output !== false,
    ) ||
    outputs[0].id !== "trusted_genesis_qc_output" ||
    outputs[1].id !== "epoch_anchor_qc_candidate_byte_binding" ||
    outputs[1].usable_after_b2b_kernel_only !== false
  ) {
    fail("schema_manifest_invalid", 0, "synthetic anchor output policy drifted", "gate");
  }
  const expectedShapeIds = [
    "every_noncomplete_prefix",
    "every_root_trailing_byte",
    "terminal_header_invalid_optional_tag",
    "handoff_certificate_signature_truncated",
    "handoff_signature_count_101",
    "handoff_signature_count_u32_max",
  ];
  if (
    JSON.stringify(corpus.raw_shape_cases.map((item) => item.id)) !==
    JSON.stringify(expectedShapeIds)
  ) {
    fail("schema_manifest_invalid", 0, "raw shape-case set drifted", "gate");
  }
  const expectedBoundaryIds = [
    "descriptor_chain_id_length_0",
    "descriptor_chain_id_length_128",
    "descriptor_chain_id_length_129",
    "descriptor_chain_id_invalid_ascii",
    "header_proposer_id_length_0",
    "header_proposer_id_length_128",
    "header_proposer_id_length_129",
    "handoff_signer_id_length_0",
    "handoff_signer_id_length_128",
    "handoff_signer_id_length_129",
    "handoff_old_signature_count_100",
    "handoff_new_signature_count_100",
    "handoff_aggregate_signature_count_200",
  ];
  if (
    JSON.stringify(corpus.boundary_cases.map((item) => item.id)) !==
    JSON.stringify(expectedBoundaryIds)
  ) {
    fail("schema_manifest_invalid", 0, "boundary-case set drifted", "gate");
  }
  const semanticIds = corpus.generated_semantic_cases.map((item) => item.id);
  if (
    semanticIds.length !== 25 ||
    new Set(semanticIds).size !== semanticIds.length
  ) {
    fail("schema_manifest_invalid", 0, "semantic mutation set drifted", "gate");
  }
  if (
    !Array.isArray(corpus.honest_boundary) ||
    !corpus.honest_boundary.some((line) => line.includes("crypto positive")) ||
    !corpus.honest_boundary.some((line) => line.includes("B2 overall"))
  ) {
    fail("schema_manifest_invalid", 0, "corpus honest boundary is incomplete", "gate");
  }
  const stableCaseCodes = new Set(
    [...manifest.decoder_error_codes, ...manifest.node_admission_error_codes].map(
      (item) => item.code,
    ),
  );
  for (const item of [
    ...corpus.raw_shape_cases,
    ...corpus.boundary_cases,
    ...corpus.generated_semantic_cases,
  ]) {
    if (
      item.expected_error_code !== undefined &&
      !stableCaseCodes.has(item.expected_error_code)
    ) {
      fail(
        "schema_manifest_invalid",
        0,
        `${item.id} names unknown stable parser/admission error ${item.expected_error_code}`,
        "gate",
      );
    }
  }
}

function domainAscii(index, id) {
  const entry = index.domains.get(id);
  if (!entry) {
    fail("schema_manifest_invalid", 0, `unknown domain id ${id}`, "gate");
  }
  return entry.ascii;
}

function readSourceArtifact(source, specification, index) {
  const artifact = resolvePointer(source, specification.json_pointer);
  if (artifact === null || typeof artifact !== "object") {
    fail("source_vector_drift", 0, `${specification.id} source is not an object`, "gate");
  }
  const bytes = canonicalHex(
    artifact.cev0_hex,
    `${specification.id}.cev0_hex`,
  );
  if (artifact.length !== bytes.length) {
    fail(
      "source_vector_drift",
      0,
      `${specification.id} length field does not match raw bytes`,
      "gate",
    );
  }
  if (specification.domain !== null) {
    const domain = domainAscii(index, specification.domain);
    if (artifact.digest_domain !== domain) {
      fail(
        "source_vector_drift",
        0,
        `${specification.id} digest domain drifted`,
        "gate",
      );
    }
    const expected = canonicalHex(
      artifact[specification.digest_field],
      `${specification.id}.${specification.digest_field}`,
    );
    const actual = digest(domain, bytes);
    if (!bytesEqual(actual, expected)) {
      fail("digest_mismatch", 0, `${specification.id} digest differs`, "gate");
    }
  } else if (artifact.independent_digest_domain !== null) {
    fail(
      "source_vector_drift",
      0,
      `${specification.id} unexpectedly acquired an independent domain`,
      "gate",
    );
  }
  const value = decodeExact(specification.object_type, bytes, index);
  const reencoded = encodeValue(specification.object_type, value, index);
  if (!bytesEqual(reencoded, bytes)) {
    fail(
      "source_vector_drift",
      0,
      `${specification.id} parse/re-encode is not byte-identical`,
      "gate",
    );
  }
  return { specification, bytes, value };
}

function admitRawObject(raw, descriptor, index) {
  switch (raw.specification.object_type) {
    case "BlockHeaderV0":
      admitBlockHeader(raw.value);
      break;
    case "HandoffDescriptorV0":
      admitDescriptor(raw.value);
      break;
    case "HandoffVoteSignV0":
      admitHandoffVote(raw.value, descriptor, raw.specification.role, index);
      break;
    case "HandoffCertificateV0":
      admitCertificate(raw.value);
      break;
    case "EpochAnchorAuthorizationV0":
      admitAuthorizationKernelRelations(raw.value, index);
      break;
    default:
      fail(
        "schema_manifest_invalid",
        0,
        `unsupported raw object ${raw.specification.object_type}`,
        "gate",
      );
  }
}

function buildValidRawObjects(corpus, source, index) {
  if (
    source.schema !== "trnm_poco_bft_anchor_finality_vectors_v0" ||
    source.canonical_codec !== "CEV0" ||
    source.hash_algorithm !== "sha256" ||
    source.hash_prefix_ascii !== "trnm.cev0.hash.v0" ||
    source.signature_fixture?.cryptographic_validity_claimed_for_composite_objects !==
      false
  ) {
    fail("source_vector_drift", 0, "anchor-finality source identity drifted", "gate");
  }

  const specifications = new Map(
    corpus.valid_raw_objects.map((item) => [item.id, item]),
  );
  const valid = new Map();
  for (const id of [
    "handoff_descriptor_shape",
    "handoff_certificate_shape",
    "epoch_anchor_authorization_shape",
  ]) {
    valid.set(id, readSourceArtifact(source, specifications.get(id), index));
  }
  const descriptor = valid.get("handoff_descriptor_shape").value;
  const certificate = valid.get("handoff_certificate_shape").value;
  const authorization = valid.get("epoch_anchor_authorization_shape").value;

  if (
    !bytesEqual(
      encodeValue("HandoffDescriptorV0", descriptor, index),
      encodeValue("HandoffDescriptorV0", certificate.descriptor, index),
    ) ||
    !bytesEqual(
      encodeValue("HandoffCertificateV0", certificate, index),
      encodeValue("HandoffCertificateV0", authorization.handoff_certificate, index),
    )
  ) {
    fail(
      "source_vector_drift",
      0,
      "standalone and authorization-nested handoff objects differ",
      "gate",
    );
  }

  const headerSpecification = specifications.get("terminal_old_header_derived");
  const headerBytes = encodeValue(
    "BlockHeaderV0",
    authorization.terminal_old_header,
    index,
  );
  const header = decodeExact("BlockHeaderV0", headerBytes, index);
  valid.set(headerSpecification.id, {
    specification: headerSpecification,
    bytes: headerBytes,
    value: header,
  });
  if (!bytesEqual(blockId(header, index), descriptor.terminal_old_block_id)) {
    fail("digest_mismatch", 0, "terminal old block ID differs from descriptor", "gate");
  }

  for (const id of [
    "old_handoff_vote_sign_derived",
    "new_handoff_vote_sign_derived",
  ]) {
    const specification = specifications.get(id);
    const vote = expectedHandoffVote(descriptor, specification.role, index);
    const bytes = encodeValue("HandoffVoteSignV0", vote, index);
    valid.set(id, {
      specification,
      bytes,
      value: decodeExact("HandoffVoteSignV0", bytes, index),
    });
  }

  for (const raw of valid.values()) {
    const exact = decodeExact(raw.specification.object_type, raw.bytes, index);
    if (
      !bytesEqual(
        encodeValue(raw.specification.object_type, exact, index),
        raw.bytes,
      )
    ) {
      fail("source_vector_drift", 0, `${raw.specification.id} exact roundtrip failed`, "gate");
    }
    raw.value = exact;
    admitRawObject(raw, descriptor, index);
    if (raw.specification.domain !== null) {
      digest(domainAscii(index, raw.specification.domain), raw.bytes);
    }
  }
  for (const id of [
    "terminal_old_header_derived",
    "old_handoff_vote_sign_derived",
    "new_handoff_vote_sign_derived",
  ]) {
    const raw = valid.get(id);
    const expected = corpus.derived_exact_expectations[id];
    const expectedBytes = canonicalHex(
      expected.cev0_hex,
      `derived_exact_expectations.${id}.cev0_hex`,
    );
    const expectedDigest = canonicalHex(
      expected.digest_hex,
      `derived_exact_expectations.${id}.digest_hex`,
    );
    const domain = domainAscii(index, raw.specification.domain);
    if (
      expected.object_type !== raw.specification.object_type ||
      expected.length !== raw.bytes.length ||
      expected.digest_domain !== domain ||
      !bytesEqual(expectedBytes, raw.bytes) ||
      !bytesEqual(expectedDigest, digest(domain, raw.bytes))
    ) {
      fail("source_vector_drift", 0, `${id} derived golden bytes drifted`, "gate");
    }
  }
  return valid;
}

function checkAnchorCandidateBindings(source, authorization, index) {
  const trustedGenesis = resolvePointer(source, "/vectors/genesis_qc");
  const trustedGenesisBytes = canonicalHex(
    trustedGenesis.cev0_hex,
    "trusted GenesisQC output",
  );
  if (trustedGenesisBytes.length !== trustedGenesis.length) {
    fail("source_vector_drift", 0, "trusted GenesisQC length drifted", "gate");
  }
  const trustedGenesisDigest = canonicalHex(
    trustedGenesis.digest_hex,
    "trusted GenesisQC digest",
  );
  if (
    trustedGenesis.digest_domain !== "trnm.poco-bft.qc.v0" ||
    !bytesEqual(
      digest("trnm.poco-bft.qc.v0", trustedGenesisBytes),
      trustedGenesisDigest,
    )
  ) {
    fail("digest_mismatch", 0, "trusted GenesisQC raw digest drifted", "gate");
  }
  // Intentionally no decodeExact call for trustedGenesisBytes.

  admitAuthorizationKernelRelations(authorization, index);
  const candidate = deriveFutureEpochAnchorCandidateFixture(authorization);
  const candidateBytes = encodeValue("QuorumCertificateV0", candidate, index);
  const expectedArtifact = resolvePointer(source, "/vectors/epoch_anchor_qc");
  const expectedBytes = canonicalHex(
    expectedArtifact.cev0_hex,
    "future EpochAnchorQC candidate byte binding",
  );
  const expectedDigest = canonicalHex(
    expectedArtifact.digest_hex,
    "future EpochAnchorQC candidate digest",
  );
  if (
    expectedArtifact.digest_domain !== "trnm.poco-bft.qc.v0" ||
    expectedArtifact.length !== expectedBytes.length ||
    !bytesEqual(candidateBytes, expectedBytes) ||
    !bytesEqual(digest("trnm.poco-bft.qc.v0", candidateBytes), expectedDigest)
  ) {
    fail(
      "digest_mismatch",
      0,
      "future EpochAnchorQC candidate byte binding differs from the committed fixture",
      "gate",
    );
  }
  // expectedBytes is compared as an output fixture and is intentionally never
  // passed through a peer-controlled empty-signature QC decoder.
}

function expectStableError(expectedCode, operation, label, maximumOffset) {
  let first;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      operation();
    } catch (error) {
      if (!(error instanceof KernelError)) {
        throw error;
      }
      if (error.code !== expectedCode) {
        fail(
          "source_vector_drift",
          0,
          `${label} returned ${error.code}, expected ${expectedCode}`,
          "gate",
        );
      }
      if (
        !Number.isInteger(error.offset) ||
        error.offset < 0 ||
        (maximumOffset !== undefined && error.offset > maximumOffset)
      ) {
        fail(
          "source_vector_drift",
          0,
          `${label} returned invalid byte_offset ${error.offset}`,
          "gate",
        );
      }
      if (first && (first.code !== error.code || first.offset !== error.offset)) {
        fail(
          "source_vector_drift",
          0,
          `${label} error code/byte_offset is not stable`,
          "gate",
        );
      }
      first = error;
      continue;
    }
    fail("source_vector_drift", 0, `${label} was unexpectedly accepted`, "gate");
  }
  return first;
}

function runRawShapeCases(corpus, valid, index) {
  const descriptor = valid.get("handoff_descriptor_shape").value;
  let prefixCount = 0;
  for (const raw of valid.values()) {
    for (let length = 0; length < raw.bytes.length; length += 1) {
      const prefix = raw.bytes.subarray(0, length);
      expectStableError(
        "unexpected_eof",
        () => decodeExact(raw.specification.object_type, prefix, index),
        `${raw.specification.id} prefix ${length}`,
        prefix.length,
      );
      prefixCount += 1;
    }
    const trailing = Buffer.concat([raw.bytes, Buffer.from([0])]);
    const error = expectStableError(
      "trailing_bytes",
      () => decodeExact(raw.specification.object_type, trailing, index),
      `${raw.specification.id} trailing byte`,
      trailing.length,
    );
    if (error.offset !== raw.bytes.length) {
      fail(
        "source_vector_drift",
        0,
        `${raw.specification.id} trailing byte offset is not the exact root length`,
        "gate",
      );
    }
  }

  const headerRaw = valid.get("terminal_old_header_derived");
  const optionalOffset = fieldOffset(
    headerRaw.value,
    "next_epoch_commitment_hash",
  );
  const invalidOptional = Buffer.from(headerRaw.bytes);
  invalidOptional[optionalOffset] = 2;
  const optionalError = expectStableError(
    "invalid_optional_tag",
    () => decodeExact("BlockHeaderV0", invalidOptional, index),
    "invalid optional tag",
    invalidOptional.length,
  );
  if (optionalError.offset !== optionalOffset) {
    fail("source_vector_drift", 0, "optional-tag byte_offset drifted", "gate");
  }

  const certificateRaw = valid.get("handoff_certificate_shape");
  expectStableError(
    "unexpected_eof",
    () =>
      decodeExact(
        "HandoffCertificateV0",
        certificateRaw.bytes.subarray(0, certificateRaw.bytes.length - 1),
        index,
      ),
    "truncated handoff Signature64",
    certificateRaw.bytes.length - 1,
  );

  const oldCountOffset = fieldOffset(certificateRaw.value, "old_signatures");
  for (const count of [101, 0xffffffff]) {
    const mutated = Buffer.from(certificateRaw.bytes);
    mutated.writeUInt32BE(count, oldCountOffset);
    const error = expectStableError(
      "count_limit_exceeded",
      () => decodeExact("HandoffCertificateV0", mutated, index),
      `rooted handoff list count ${count}`,
      mutated.length,
    );
    if (error.offset !== oldCountOffset) {
      fail("source_vector_drift", 0, "list-count byte_offset drifted", "gate");
    }
  }

  if (
    corpus.raw_shape_cases[0].expected_error_code !== "unexpected_eof" ||
    corpus.raw_shape_cases[1].expected_error_code !== "trailing_bytes" ||
    corpus.raw_shape_cases[2].expected_error_code !== "invalid_optional_tag" ||
    corpus.raw_shape_cases.slice(3).some((item, position) =>
      item.expected_error_code !==
      ["unexpected_eof", "count_limit_exceeded", "count_limit_exceeded"][position]
    )
  ) {
    fail("schema_manifest_invalid", 0, "raw shape expectations drifted", "gate");
  }
  // Exercise descriptor again after thousands of prefix failures, proving no
  // decoder state leaks between calls.
  admitDescriptor(
    decodeExact(
      "HandoffDescriptorV0",
      valid.get("handoff_descriptor_shape").bytes,
      index,
    ),
  );
  return prefixCount;
}

function boundaryValue(value) {
  return Buffer.alloc(value, 0x61);
}

function makeSignatureShares(count) {
  const shares = [];
  for (let position = 0; position < count; position += 1) {
    shares.push({
      validator_id: Buffer.from([position]),
      signature: Buffer.alloc(64, position),
    });
  }
  return shares;
}

function runBoundaryCases(corpus, valid, index) {
  const descriptorTemplate = valid.get("handoff_descriptor_shape").value;
  const headerTemplate = valid.get("terminal_old_header_derived").value;
  const certificateTemplate = valid.get("handoff_certificate_shape").value;
  let checked = 0;
  for (const specification of corpus.boundary_cases) {
    if (specification.operation === "descriptor_chain_id_length") {
      const value = cloneValue(descriptorTemplate);
      value.chain_id = boundaryValue(Number(specification.length));
      const bytes = encodeValue("HandoffDescriptorV0", value, index);
      if (specification.expected_result === "valid") {
        admitDescriptor(decodeExact("HandoffDescriptorV0", bytes, index));
      } else {
        expectStableError(
          specification.expected_error_code,
          () => decodeExact("HandoffDescriptorV0", bytes, index),
          specification.id,
          bytes.length,
        );
      }
    } else if (specification.operation === "descriptor_chain_id_hex") {
      const value = cloneValue(descriptorTemplate);
      value.chain_id = canonicalHex(specification.hex, specification.id, "schema_manifest_invalid");
      const bytes = encodeValue("HandoffDescriptorV0", value, index);
      expectStableError(
        specification.expected_error_code,
        () => decodeExact("HandoffDescriptorV0", bytes, index),
        specification.id,
        bytes.length,
      );
    } else if (specification.operation === "header_proposer_id_length") {
      const value = cloneValue(headerTemplate);
      value.proposer_id = boundaryValue(Number(specification.length));
      const bytes = encodeValue("BlockHeaderV0", value, index);
      if (specification.expected_result === "valid") {
        admitBlockHeader(decodeExact("BlockHeaderV0", bytes, index));
      } else {
        expectStableError(
          specification.expected_error_code,
          () => decodeExact("BlockHeaderV0", bytes, index),
          specification.id,
          bytes.length,
        );
      }
    } else if (
      specification.operation === "handoff_signer_id_length"
    ) {
      const value = cloneValue(certificateTemplate);
      value.old_signatures[0].validator_id = boundaryValue(
        Number(specification.length),
      );
      const bytes = encodeValue("HandoffCertificateV0", value, index);
      if (specification.expected_result === "valid") {
        admitCertificate(decodeExact("HandoffCertificateV0", bytes, index));
      } else {
        expectStableError(
          specification.expected_error_code,
          () => decodeExact("HandoffCertificateV0", bytes, index),
          specification.id,
          bytes.length,
        );
      }
    } else if (
      specification.operation === "synthetic_handoff_certificate_count"
    ) {
      const value = cloneValue(certificateTemplate);
      value[`${specification.role}_signatures`] = makeSignatureShares(
        Number(specification.count),
      );
      const bytes = encodeValue("HandoffCertificateV0", value, index);
      const decoded = decodeExact("HandoffCertificateV0", bytes, index);
      admitCertificate(decoded);
      if (decoded[`${specification.role}_signatures`].length !== 100) {
        fail("source_vector_drift", 0, `${specification.id} count drifted`, "gate");
      }
    } else if (
      specification.operation === "synthetic_handoff_certificate_aggregate_count"
    ) {
      const value = cloneValue(certificateTemplate);
      value.old_signatures = makeSignatureShares(Number(specification.old_count));
      value.new_signatures = makeSignatureShares(Number(specification.new_count));
      const bytes = encodeValue("HandoffCertificateV0", value, index);
      const decoded = decodeExact("HandoffCertificateV0", bytes, index);
      admitCertificate(decoded);
      const aggregate =
        decoded.old_signatures.length + decoded.new_signatures.length;
      if (aggregate !== Number(specification.expected_aggregate_count)) {
        fail("source_vector_drift", 0, `${specification.id} aggregate drifted`, "gate");
      }
    } else {
      fail(
        "schema_manifest_invalid",
        0,
        `unknown boundary operation ${specification.operation}`,
        "gate",
      );
    }
    checked += 1;
  }
  return checked;
}

function setPath(root, dottedPath, replacement) {
  const components = dottedPath.split(".");
  let owner = root;
  for (const component of components.slice(0, -1)) {
    owner = owner[component];
  }
  const field = components.at(-1);
  const previous = owner[field];
  if (typeof previous === "bigint" && typeof replacement === "string") {
    owner[field] = BigInt(replacement);
  } else {
    owner[field] = replacement;
  }
}

function flipFirstByte(value) {
  const changed = Buffer.from(value);
  changed[0] ^= 0x80;
  return changed;
}

function rawTypeAndRole(valid, sourceId) {
  const raw = valid.get(sourceId);
  if (!raw) {
    fail("schema_manifest_invalid", 0, `unknown mutation source ${sourceId}`, "gate");
  }
  return raw;
}

function decodeAndAdmitMutation(type, bytes, role, descriptor, index) {
  const decoded = decodeExact(type, bytes, index);
  switch (type) {
    case "BlockHeaderV0":
      admitBlockHeader(decoded);
      break;
    case "HandoffDescriptorV0":
      admitDescriptor(decoded);
      break;
    case "HandoffVoteSignV0":
      admitHandoffVote(decoded, descriptor, role, index);
      break;
    case "HandoffCertificateV0":
      admitCertificate(decoded);
      break;
    case "EpochAnchorAuthorizationV0":
      admitAuthorizationKernelRelations(decoded, index);
      break;
    default:
      fail("schema_manifest_invalid", 0, `unknown mutation type ${type}`, "gate");
  }
}

function buildSemanticMutation(specification, raw, descriptor, index) {
  const value = cloneValue(raw.value);
  switch (specification.operation) {
    case "set_field":
      setPath(value, specification.field, specification.value);
      break;
    case "set_nested_field":
      setPath(value, specification.path, specification.value);
      break;
    case "set_raw_enum":
      setPath(value, specification.field, specification.value);
      break;
    case "zero_fixed_bytes":
      value[specification.field] = Buffer.alloc(value[specification.field].length);
      break;
    case "copy_new_role_scope_into_old_vote": {
      const expected = expectedHandoffVote(descriptor, "new", index);
      for (const field of [
        "signing_protocol_version",
        "signing_epoch",
        "signing_validator_set_hash",
        "signing_view",
      ]) {
        value[field] = cloneValue(expected[field]);
      }
      break;
    }
    case "flip_first_byte":
      value[specification.field] = flipFirstByte(value[specification.field]);
      break;
    case "duplicate_signer":
      value[specification.field][1].validator_id = Buffer.from(
        value[specification.field][0].validator_id,
      );
      break;
    case "swap_first_two":
      [value[specification.field][0], value[specification.field][1]] = [
        value[specification.field][1],
        value[specification.field][0],
      ];
      break;
    case "empty_list":
      value[specification.field] = [];
      break;
    case "empty_nested_list":
      setPath(value, specification.path, []);
      break;
    case "flip_nested_first_byte": {
      const components = specification.path.split(".");
      let owner = value;
      for (const component of components.slice(0, -1)) {
        owner = owner[component];
      }
      const field = components.at(-1);
      owner[field] = flipFirstByte(owner[field]);
      break;
    }
    default:
      fail(
        "schema_manifest_invalid",
        0,
        `unknown semantic operation ${specification.operation}`,
        "gate",
      );
  }
  return encodeValue(raw.specification.object_type, value, index);
}

function runSemanticCases(corpus, valid, index) {
  const descriptor = valid.get("handoff_descriptor_shape").value;
  let checked = 0;
  for (const specification of corpus.generated_semantic_cases) {
    const raw = rawTypeAndRole(valid, specification.source);
    const bytes = buildSemanticMutation(specification, raw, descriptor, index);
    expectStableError(
      specification.expected_error_code,
      () =>
        decodeAndAdmitMutation(
          raw.specification.object_type,
          bytes,
          raw.specification.role,
          descriptor,
          index,
        ),
      specification.id,
      bytes.length,
    );
    checked += 1;
  }
  return checked;
}

function main() {
  const base = readJson(BASE_SCHEMA_PATH);
  const manifest = readJson(SCHEMA_PATH);
  const corpus = readJson(CORPUS_PATH);
  const source = readJson(SOURCE_PATH);
  const index = makeIndex(base, manifest);

  validateManifest(base, manifest, index);
  validateTransportProjections(manifest, index);
  validateCorpus(corpus, manifest);
  const valid = buildValidRawObjects(corpus, source, index);
  checkAnchorCandidateBindings(
    source,
    valid.get("epoch_anchor_authorization_shape").value,
    index,
  );
  const prefixCount = runRawShapeCases(corpus, valid, index);
  const boundaryCount = runBoundaryCases(corpus, valid, index);
  const semanticCount = runSemanticCases(corpus, valid, index);

  const voteDigests = [
    "old_handoff_vote_sign_derived",
    "new_handoff_vote_sign_derived",
  ].map((id) =>
    digest(
      "trnm.poco-bft.handoff-vote.v0",
      valid.get(id).bytes,
    ).toString("hex"),
  );
  if (voteDigests[0] === voteDigests[1]) {
    fail("digest_mismatch", 0, "old/new role vote roots unexpectedly collide", "gate");
  }

  if (process.argv.includes("--print-derived")) {
    const derived = {};
    for (const id of [
      "terminal_old_header_derived",
      "old_handoff_vote_sign_derived",
      "new_handoff_vote_sign_derived",
    ]) {
      const raw = valid.get(id);
      derived[id] = {
        object_type: raw.specification.object_type,
        cev0_hex: raw.bytes.toString("hex"),
        length: raw.bytes.length,
        digest_domain: domainAscii(index, raw.specification.domain),
        digest_hex: digest(
          domainAscii(index, raw.specification.domain),
          raw.bytes,
        ).toString("hex"),
      };
    }
    process.stdout.write(`${JSON.stringify(derived, null, 2)}\n`);
    return;
  }

  process.stdout.write(
    [
      "PoCO-BFT v0 B2-B anchor/handoff schema gate passed:",
      `${manifest.objects.length} objects + ${manifest.enums.length} enum`,
      `${manifest.transport_projections.length} transport projections`,
      `${valid.size} exact raw objects`,
      `${prefixCount} truncated prefixes`,
      `${boundaryCount} boundary cases`,
      `${semanticCount} generated semantic cases`,
      "1 trusted anchor fixture + 1 inert candidate byte binding",
      "cryptographic_validity_claimed=false",
    ].join(" ") + "\n",
  );
}

try {
  main();
} catch (error) {
  if (error instanceof KernelError) {
    process.stderr.write(`${error.layer}: ${error.message}\n`);
    process.exit(1);
  }
  throw error;
}
