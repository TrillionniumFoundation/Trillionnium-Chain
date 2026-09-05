#!/usr/bin/env node

/*
 * Independent H3b2b3a evidence consumer. It composes the existing independent
 * H3b2b2 raw-history reconstruction with raw exact parent-header/finality
 * CEV0 and raw JMT ICS23 namespace proofs. It never consumes an H1/H2/B2-G
 * token, caller-selected verifier, normalized Rust result, status, or event.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  parseLosslessUnsignedJson,
  strictEd25519Verify,
  validateBoundary as validateCandidateBoundary,
  validateProductionSourceSurface as validateCandidateSourceSurface,
  validateProfile as validateCandidateProfile,
  validateScenario as validateCandidateScenario,
  validateSchema as validateCandidateSchema,
} from "./check_poco_bft_v0_authenticated_candidate_selection.mjs";
import {
  decodeCommitment,
  decodeFinality,
  decodeHeader,
  decodeParameters,
  decodeValidatorSet,
  encodeCommitment,
  proposalRoot,
  qcVoteRoot,
  validateCertified,
} from "./check_poco_bft_v0_joint_handoff_schema.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCHEMA_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/schema/poco-authenticated-next-epoch-commitment-v0.json");
const VECTOR_PATH = process.env.TRNM_POCO_AUTHENTICATED_NEXT_EPOCH_COMMITMENT_VECTOR ?? path.join(
  ROOT,
  "docs/protocol/poco-bft-v0/vectors/poco-authenticated-next-epoch-commitment-v0.json",
);
const CANDIDATE_SCHEMA_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/schema/poco-authenticated-candidate-selection-v0.json");
const CANDIDATE_VECTOR_PATH = path.join(ROOT, "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json");

const FIXTURE_SCHEMA = "trnm.poco-bft.authenticated-next-epoch-commitment-fixture.v0";
const AUTHORIZATION_DOMAIN = "trnm.poco-bft.authorized-next-epoch-commitment.v0";
const HASH_V1_PREFIX = Buffer.from("trnm.domain.hash.v1", "ascii");
const JMT_LEAF_DOMAIN = Buffer.from("JMT::LeafNode", "ascii");
const JMT_INTERNAL_DOMAIN = Buffer.from("JMT::IntrnalNode", "ascii");
const AUTHENTICATED_KEY_DOMAIN = Buffer.from("trnm/authenticated-state/v4", "ascii");
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U32 = (1n << 32n) - 1n;
const MAX_U16 = (1n << 16n) - 1n;
const MAX_U8 = (1n << 8n) - 1n;
const ED25519_FIELD_MODULUS = (1n << 255n) - 19n;
const ED25519_NONCANONICAL_R = littleEndianBytes(ED25519_FIELD_MODULUS, 32);
const ED25519_SMALL_ORDER_PUBLIC_KEY = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);

const stats = { scenarios: 0, h1Signatures: 0, h2Memberships: 0, negatives: 0 };

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function rustUnsignedJson(value, maximum, label) {
  invariant(
    typeof value === "number" || typeof value === "bigint",
    `${label}: Rust integer fields require an unquoted JSON number`,
  );
  invariant(
    typeof value === "bigint" || (Number.isSafeInteger(value) && value >= 0),
    `${label}: canonical unsigned integer required`,
  );
  const decoded = BigInt(value);
  invariant(decoded >= 0n && decoded <= maximum, `${label}: unsigned integer out of range`);
  return decoded;
}

function rustU64(value, label) {
  return rustUnsignedJson(value, MAX_U64, label);
}

function rustU32(value, label) {
  return Number(rustUnsignedJson(value, MAX_U32, label));
}

function rustU16(value, label) {
  return Number(rustUnsignedJson(value, MAX_U16, label));
}

function rustU8(value, label) {
  return Number(rustUnsignedJson(value, MAX_U8, label));
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

function runLosslessFixtureJsonSelfTests() {
  const accepted = [
    ["9007199254740991", "number"],
    ["9007199254740992", "bigint"],
    ["18446744073709551615", "bigint"],
  ];
  for (const [literal, expectedType] of accepted) {
    const parsed = parseLosslessUnsignedJson(Buffer.from(`{"value":${literal}}`, "utf8"), `lossless self-test ${literal}`);
    invariant(typeof parsed.value === expectedType, `${literal}: decoded type drift`);
    invariant(String(parsed.value) === literal, `${literal}: decoded value drift`);
  }
  const rejected = [
    `{"value":18446744073709551616}`,
    `{"value":01}`,
    `{"value":1.0}`,
    `{"value":1e0}`,
    `{"value":-1}`,
  ];
  for (const raw of rejected) {
    let rejectedAsRequired = false;
    try {
      parseLosslessUnsignedJson(Buffer.from(raw, "utf8"), "lossless rejection self-test");
    } catch {
      rejectedAsRequired = true;
    }
    invariant(rejectedAsRequired, `${raw}: malformed integer JSON accepted`);
  }
  return { accepted: accepted.length, rejected: rejected.length };
}

function exactKeys(value, expected, label) {
  invariant(value !== null && typeof value === "object" && !Array.isArray(value), `${label}: object required`);
  invariant(JSON.stringify(Object.keys(value)) === JSON.stringify(expected), `${label}: exact field order`);
}

function exactHex(value, bytes, label) {
  invariant(typeof value === "string" && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value), `${label}: canonical ${bytes}-byte hex`);
  return Buffer.from(value, "hex");
}

function boundedHex(value, minimum, maximum, label) {
  invariant(typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]+$/.test(value), `${label}: canonical hex`);
  const raw = Buffer.from(value, "hex");
  invariant(raw.length >= minimum && raw.length <= maximum, `${label}: byte length`);
  return raw;
}

function uint(value, width) {
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

function frame64(value) {
  return Buffer.concat([uint(value.length, 8), value]);
}

function hashV1(domain, parts) {
  return crypto.createHash("sha256").update(Buffer.concat([
    HASH_V1_PREFIX,
    frame64(Buffer.from(domain, "ascii")),
    ...parts.map(frame64),
  ])).digest();
}

function sha256(raw) {
  return crypto.createHash("sha256").update(raw).digest();
}

// Remaining exact H1/H2/commitment validation is intentionally defined below
// before main; keeping this file import-safe lets later gates reuse only the
// authenticated facts, never an inert authority token.

class ProtoReader {
  constructor(raw, label) {
    this.raw = raw;
    this.label = label;
    this.offset = 0;
  }

  varint() {
    const start = this.offset;
    let value = 0n;
    let shift = 0n;
    for (let count = 0; count < 10; count += 1) {
      invariant(this.offset < this.raw.length, `${this.label}: truncated protobuf varint`);
      const byte = this.raw[this.offset++];
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        let canonical = value;
        const encoded = [];
        do {
          const low = Number(canonical & 0x7fn);
          canonical >>= 7n;
          encoded.push(low | (canonical === 0n ? 0 : 0x80));
        } while (canonical !== 0n);
        invariant(Buffer.from(encoded).equals(this.raw.subarray(start, this.offset)), `${this.label}: noncanonical protobuf varint`);
        return value;
      }
      shift += 7n;
    }
    throw new Error(`${this.label}: protobuf varint overflow`);
  }

  bytes() {
    const length = this.varint();
    invariant(length <= BigInt(Number.MAX_SAFE_INTEGER), `${this.label}: protobuf length overflow`);
    const size = Number(length);
    invariant(this.offset + size <= this.raw.length, `${this.label}: truncated protobuf bytes`);
    const value = Buffer.from(this.raw.subarray(this.offset, this.offset + size));
    this.offset += size;
    return value;
  }

  tag() {
    const value = this.varint();
    const field = Number(value >> 3n);
    const wire = Number(value & 7n);
    invariant(field > 0, `${this.label}: zero protobuf field`);
    return { field, wire };
  }

  finish() {
    invariant(this.offset === this.raw.length, `${this.label}: trailing protobuf bytes`);
  }
}

function parseLeaf(raw, label) {
  const reader = new ProtoReader(raw, label);
  const leaf = { hash: 0n, prehashKey: 0n, prehashValue: 0n, length: 0n, prefix: Buffer.alloc(0) };
  let previous = 0;
  while (reader.offset < raw.length) {
    const { field, wire } = reader.tag();
    invariant(field > previous, `${label}: duplicate or reordered leaf field`);
    previous = field;
    if (field >= 1 && field <= 4) {
      invariant(wire === 0, `${label}: leaf enum wire type`);
      const value = reader.varint();
      if (field === 1) leaf.hash = value;
      else if (field === 2) leaf.prehashKey = value;
      else if (field === 3) leaf.prehashValue = value;
      else leaf.length = value;
    } else if (field === 5) {
      invariant(wire === 2, `${label}: leaf prefix wire type`);
      leaf.prefix = reader.bytes();
    } else {
      throw new Error(`${label}: unknown leaf field ${field}`);
    }
  }
  reader.finish();
  invariant(
    leaf.hash === 1n && leaf.prehashKey === 1n && leaf.prehashValue === 1n &&
      leaf.length === 0n && leaf.prefix.equals(JMT_LEAF_DOMAIN),
    `${label}: not the frozen jmt 0.12.0 ICS23 leaf spec`,
  );
  return leaf;
}

function parseInner(raw, label) {
  const reader = new ProtoReader(raw, label);
  const inner = { hash: 0n, prefix: Buffer.alloc(0), suffix: Buffer.alloc(0) };
  let previous = 0;
  while (reader.offset < raw.length) {
    const { field, wire } = reader.tag();
    invariant(field > previous, `${label}: duplicate or reordered inner field`);
    previous = field;
    if (field === 1) {
      invariant(wire === 0, `${label}: inner hash wire type`);
      inner.hash = reader.varint();
    } else if (field === 2 || field === 3) {
      invariant(wire === 2, `${label}: inner bytes wire type`);
      if (field === 2) inner.prefix = reader.bytes();
      else inner.suffix = reader.bytes();
    } else {
      throw new Error(`${label}: unknown inner field ${field}`);
    }
  }
  reader.finish();
  invariant(inner.hash === 1n, `${label}: inner hash is not SHA-256`);
  const leftSibling = inner.prefix.length === JMT_INTERNAL_DOMAIN.length + 32 &&
    inner.prefix.subarray(0, JMT_INTERNAL_DOMAIN.length).equals(JMT_INTERNAL_DOMAIN) &&
    inner.suffix.length === 0;
  const rightSibling = inner.prefix.equals(JMT_INTERNAL_DOMAIN) && inner.suffix.length === 32;
  invariant(leftSibling || rightSibling, `${label}: inner op differs from frozen binary JMT spec`);
  return inner;
}

function parseExistence(raw, label) {
  const reader = new ProtoReader(raw, label);
  let key = null;
  let value = null;
  let leaf = null;
  const path = [];
  let previous = 0;
  while (reader.offset < raw.length) {
    const { field, wire } = reader.tag();
    invariant(field >= previous && (field === 4 || field > previous), `${label}: duplicate or reordered existence field`);
    previous = field;
    invariant(wire === 2, `${label}: existence field is not length-delimited`);
    const nested = reader.bytes();
    if (field === 1) key = nested;
    else if (field === 2) value = nested;
    else if (field === 3) leaf = parseLeaf(nested, `${label}.leaf`);
    else if (field === 4) path.push(parseInner(nested, `${label}.path[${path.length}]`));
    else throw new Error(`${label}: unknown existence field ${field}`);
  }
  reader.finish();
  invariant(key !== null && key.length > 0 && value !== null && value.length > 0 && leaf !== null, `${label}: incomplete existence proof`);
  invariant(path.length <= 64, `${label}: JMT path exceeds 64 inner ops`);
  return { key, value, path };
}

function parseCommitmentProof(raw, label) {
  const reader = new ProtoReader(raw, label);
  const { field, wire } = reader.tag();
  invariant(field === 1 && wire === 2, `${label}: proof is not one ICS23 existence proof`);
  const proof = parseExistence(reader.bytes(), `${label}.exist`);
  reader.finish();
  return proof;
}

function verifyIcs23Point(raw, expected, label) {
  exactKeys(raw, ["version", "root_hash_hex", "key_hex", "value_hex", "commitment_proof_hex"], label);
  invariant(rustU64(raw.version, `${label}.version`) === expected.version, `${label}: version mismatch`);
  const root = exactHex(raw.root_hash_hex, 32, `${label}.root`);
  invariant(root.equals(expected.root), `${label}: root mismatch`);
  const key = boundedHex(raw.key_hex, 1, 65_536, `${label}.key`);
  invariant(key.equals(expected.key), `${label}: key mismatch`);
  invariant(typeof raw.value_hex === "string", `${label}: membership proof lacks value`);
  const value = boundedHex(raw.value_hex, 1, 65_536, `${label}.value`);
  invariant(value.equals(expected.value), `${label}: value mismatch`);
  const proof = parseCommitmentProof(
    boundedHex(raw.commitment_proof_hex, 1, 32_768, `${label}.commitment_proof`),
    `${label}.commitment_proof`,
  );
  invariant(proof.key.equals(key) && proof.value.equals(value), `${label}: embedded proof key/value mismatch`);
  let computed = sha256(Buffer.concat([JMT_LEAF_DOMAIN, sha256(key), sha256(value)]));
  for (const inner of proof.path) computed = sha256(Buffer.concat([inner.prefix, computed, inner.suffix]));
  invariant(computed.equals(root), `${label}: ICS23 root mismatch`);
  stats.h2Memberships += 1;
}

function namespacedKey(components) {
  return Buffer.concat([
    AUTHENTICATED_KEY_DOMAIN,
    uint(8, 2),
    uint(components.length, 2),
    ...components.flatMap((component) => [uint(component.length, 4), component]),
  ]);
}

function manifestKey() {
  return namespacedKey([Buffer.from("manifest", "ascii")]);
}

function entryKey(kind, logicalKey) {
  return namespacedKey([Buffer.from("entry", "ascii"), Buffer.from([kind]), logicalKey]);
}

function decodeManifest(raw, label) {
  invariant(raw.length === 47, `${label}: manifest length`);
  invariant(raw.readUInt16BE(0) === 0 && raw[2] === 8, `${label}: manifest schema/namespace`);
  return {
    height: raw.readBigUInt64BE(3),
    count: raw.readUInt32BE(11),
    entriesRoot: Buffer.from(raw.subarray(15, 47)),
  };
}

function sameHeaderContext(header, set, parameters) {
  return header.genesis.equals(set.genesis) && header.chain.equals(set.chain) &&
    header.protocol === set.protocol && header.epoch === set.epoch &&
    header.setHash.equals(set.hash) && header.parametersHash.equals(parameters.hash);
}

function strictValidateQc(qc, set, label) {
  const root = qcVoteRoot(qc, qc.view, qc.height, qc.blockId);
  for (const [index, share] of qc.signatures.entries()) {
    const validator = set.byId.get(share.validatorId.toString("hex"));
    invariant(validator !== undefined, `${label}: unknown QC signer ${index}`);
    invariant(
      strictEd25519Verify(root, validator.publicKey, share.signature),
      `${label}: non-strict or invalid QC signature ${index}`,
    );
    stats.h1Signatures += 1;
  }
}

function strictValidateCertified(certified, set, label) {
  strictValidateQc(certified.justifyQc, set, `${label.name}.justify`);
  const proposer = set.byId.get(certified.header.proposerId.toString("hex"));
  invariant(proposer !== undefined, `${label.name}: unknown proposer`);
  invariant(
    strictEd25519Verify(
      proposalRoot(certified.header, certified.justifyQc.id),
      proposer.publicKey,
      certified.proposerSignature,
    ),
    `${label.name}: non-strict or invalid proposer signature`,
  );
  stats.h1Signatures += 1;
  strictValidateQc(certified.certifyingQc, set, `${label.name}.certifying`);
  // The imported helper retains the current no-TC corpus's structural,
  // quorum, and direct-view checks. Run it only after every signature has
  // crossed this gate's stricter canonical-key/R/S boundary.
  validateCertified(certified, set, label.parameters);
}

function validateRawH1(raw, oldSet, oldParameters, expectedCutoff, label) {
  exactKeys(raw, [
    "cutoff_parent_header_cev0_hex", "cutoff_parent_block_id_hex",
    "cutoff_parent_timestamp_ms", "finality_proof_cev0_hex", "proof_id_hex",
    "finalized_cutoff_block_id_hex", "finalized_cutoff_height",
    "finalized_cutoff_state_root_hex", "child_block_id_hex", "grandchild_block_id_hex",
  ], label);
  const parentRaw = boundedHex(raw.cutoff_parent_header_cev0_hex, 1, 8 * 1024 * 1024, `${label}.parent_header`);
  const parent = decodeHeader(parentRaw, oldParameters, true);
  const proofRaw = boundedHex(raw.finality_proof_cev0_hex, 1, 8 * 1024 * 1024, `${label}.finality_proof`);
  const proof = decodeFinality(proofRaw, oldParameters, true);
  invariant(sameHeaderContext(parent, oldSet, oldParameters), `${label}: parent old-context mismatch`);
  invariant(parent.kind === 0 && parent.nextCommitment === null, `${label}: parent is not scheduled regular`);
  invariant(parent.id.equals(exactHex(raw.cutoff_parent_block_id_hex, 32, `${label}.parent_id`)), `${label}: parent ID evidence drift`);
  invariant(
    parent.timestamp === rustU64(raw.cutoff_parent_timestamp_ms, `${label}.cutoff_parent_timestamp_ms`),
    `${label}: parent timestamp evidence drift`,
  );
  invariant(
    proof.genesis.equals(oldSet.genesis) && proof.chain.equals(oldSet.chain) &&
      proof.protocol === oldSet.protocol && proof.epoch === oldSet.epoch &&
      proof.setHash.equals(oldSet.hash) && proof.parametersHash.equals(oldParameters.hash),
    `${label}: outer finality context mismatch`,
  );
  const blocks = [proof.finalizedBlock, proof.child, proof.grandchild];
  for (const [index, block] of blocks.entries()) {
    strictValidateCertified(block, oldSet, {
      name: `${label}.certified[${index}]`,
      parameters: oldParameters,
    });
  }
  const [finalized, child, grandchild] = blocks;
  invariant(parent.height + 1n === finalized.header.height, `${label}: parent height mismatch`);
  invariant(
    parent.id.equals(finalized.header.parentId) && parent.id.equals(finalized.justifyQc.blockId) &&
      parent.height === finalized.justifyQc.height && parent.view === finalized.justifyQc.view,
    `${label}: raw parent is not the strict finalized justify-QC subject`,
  );
  invariant(
    child.header.parentId.equals(finalized.header.id) &&
      grandchild.header.parentId.equals(child.header.id) &&
      child.justifyQc.id.equals(finalized.certifyingQc.id) &&
      grandchild.justifyQc.id.equals(child.certifyingQc.id),
    `${label}: finality three-chain linkage mismatch`,
  );
  invariant(
    finalized.certifyingQc.view < child.certifyingQc.view &&
      child.certifyingQc.view < grandchild.certifyingQc.view,
    `${label}: finality certifying views are not increasing`,
  );
  let priorTimestamp = parent.timestamp;
  for (const block of blocks) {
    const delta = block.header.timestamp - priorTimestamp;
    invariant(delta > 0n && delta <= oldParameters.fields.max_block_time_step_ms, `${label}: timestamp step`);
    priorTimestamp = block.header.timestamp;
  }
  const epochEnd = (oldSet.epoch + 1n) * oldParameters.fields.epoch_length_blocks;
  const checkpointHeight = epochEnd - 2n;
  const cutoffHeight = epochEnd - 2n - oldParameters.fields.snapshot_lead_blocks;
  invariant(
    oldParameters.fields.epoch_length_blocks === 10n &&
      oldParameters.fields.snapshot_lead_blocks === 3n &&
      oldParameters.fields.snapshot_lead_blocks >= BigInt(oldParameters.fields.finality_certified_chain_length) &&
    parent.kind === 0 && parent.height + 1n === cutoffHeight &&
      finalized.header.kind === 0 && finalized.header.height === cutoffHeight &&
      child.header.kind === 0 && child.header.height === cutoffHeight + 1n &&
      grandchild.header.kind === 0 && grandchild.header.height === cutoffHeight + 2n &&
      grandchild.header.height + 1n === checkpointHeight &&
      parent.nextCommitment === null && finalized.header.nextCommitment === null &&
      child.header.nextCommitment === null && grandchild.header.nextCommitment === null &&
      finalized.header.height === expectedCutoff.version &&
      finalized.header.stateRoot.equals(expectedCutoff.root),
    `${label}: unified parent/cutoff/child/grandchild/pre-checkpoint schedule mismatch`,
  );
  invariant(proof.id.equals(exactHex(raw.proof_id_hex, 32, `${label}.proof_id`)), `${label}: proof ID drift`);
  invariant(finalized.header.id.equals(exactHex(raw.finalized_cutoff_block_id_hex, 32, `${label}.cutoff_block_id`)), `${label}: finalized block ID drift`);
  invariant(
    finalized.header.height === rustU64(raw.finalized_cutoff_height, `${label}.finalized_cutoff_height`),
    `${label}: finalized height evidence drift`,
  );
  invariant(finalized.header.stateRoot.equals(exactHex(raw.finalized_cutoff_state_root_hex, 32, `${label}.cutoff_root`)), `${label}: finalized state-root evidence drift`);
  invariant(child.header.id.equals(exactHex(raw.child_block_id_hex, 32, `${label}.child_id`)), `${label}: child ID drift`);
  invariant(grandchild.header.id.equals(exactHex(raw.grandchild_block_id_hex, 32, `${label}.grandchild_id`)), `${label}: grandchild ID drift`);
  return { parentRaw, parent, proofRaw, proof, finalized, child, grandchild };
}

function validateRawH2(raw, candidate, label) {
  exactKeys(raw, ["manifest_cev0_hex", "manifest_proof", "members", "absences"], label);
  const manifestRaw = exactHex(raw.manifest_cev0_hex, 47, `${label}.manifest`);
  const manifest = decodeManifest(manifestRaw, `${label}.manifest`);
  const cutoffVersion = BigInt(candidate.history.cutoffVersion);
  invariant(
    manifest.height === cutoffVersion &&
      manifest.count === candidate.cutoff.entries.length &&
      manifest.entriesRoot.equals(candidate.cutoff.root),
    `${label}: manifest differs from independently reconstructed candidate cutoff`,
  );
  const expectedRoot = exactHex(candidate.source.cutoff_root_hex, 32, `${label}.candidate_cutoff_root`);
  verifyIcs23Point(raw.manifest_proof, {
    version: cutoffVersion,
    root: expectedRoot,
    key: manifestKey(),
    value: manifestRaw,
  }, `${label}.manifest_proof`);
  invariant(Array.isArray(raw.members) && raw.members.length === candidate.cutoff.entries.length, `${label}: member count`);
  for (const [index, member] of raw.members.entries()) {
    exactKeys(member, ["kind", "logical_key_hex", "value_hex", "canonical_entry_cev0_hex", "proof"], `${label}.members[${index}]`);
    const expected = candidate.cutoff.entries[index];
    const kind = rustU8(member.kind, `${label}.members[${index}].kind`);
    invariant(kind === expected.kind, `${label}.members[${index}]: kind`);
    const logicalKey = exactHex(member.logical_key_hex, 32, `${label}.members[${index}].logical_key`);
    invariant(logicalKey.equals(expected.key), `${label}.members[${index}]: logical key`);
    const value = boundedHex(member.value_hex, 1, 65_536, `${label}.members[${index}].value`);
    invariant(value.equals(expected.value), `${label}.members[${index}]: value`);
    invariant(
      boundedHex(member.canonical_entry_cev0_hex, 1, 65_536 + 128, `${label}.members[${index}].entry`).equals(expected.canonical),
      `${label}.members[${index}]: canonical entry`,
    );
    verifyIcs23Point(member.proof, {
      version: cutoffVersion,
      root: expectedRoot,
      key: entryKey(kind, logicalKey),
      value,
    }, `${label}.members[${index}].proof`);
  }
  invariant(Array.isArray(raw.absences) && raw.absences.length === 0, `${label}: fixture absences must be exact empty list`);
  return { manifestRaw, manifest, root: expectedRoot, absenceCount: 0 };
}

function selectCandidateScenario(vector, id) {
  if (vector.positive.id === id) return vector.positive;
  if (vector.authenticated_fallback.id === id) return vector.authenticated_fallback;
  throw new Error(`unknown candidate source ${id}`);
}

function validateCandidateBinding(raw, candidateScenario, candidate, label) {
  exactKeys(raw, [
    "authorization_id_hex", "checkpoint_execution_id_hex", "candidate_parameters_hash_hex",
    "cutoff_version", "cutoff_state_root_hex", "cutoff_entries_root_hex",
    "cutoff_entry_count", "fallback_used", "fallback_reason_code",
    "old_validator_set_cev0_hex", "old_parameters_cev0_hex",
    "new_validator_set_cev0_hex", "new_parameters_cev0_hex",
  ], label);
  invariant(raw.authorization_id_hex === candidate.authorization.toString("hex"), `${label}: candidate authorization`);
  invariant(raw.checkpoint_execution_id_hex === candidateScenario.checkpoint.execution_id_hex, `${label}: checkpoint execution ID`);
  invariant(
    raw.candidate_parameters_hash_hex === candidate.reconstructed.candidateParametersHash.toString("hex") &&
      raw.candidate_parameters_hash_hex === candidateScenario.checkpoint.candidate_parameters_hash_hex,
    `${label}: candidate-parameters hash`,
  );
  invariant(
    rustU64(raw.cutoff_version, `${label}.cutoff_version`) === BigInt(candidate.history.cutoffVersion),
    `${label}: cutoff version`,
  );
  invariant(raw.cutoff_state_root_hex === candidateScenario.source.cutoff_root_hex, `${label}: cutoff state root`);
  invariant(raw.cutoff_entries_root_hex === candidate.cutoff.root.toString("hex"), `${label}: cutoff entries root`);
  invariant(
    rustU32(raw.cutoff_entry_count, `${label}.cutoff_entry_count`) === candidate.cutoff.entries.length,
    `${label}: cutoff entry count`,
  );
  const fallbackReasonCode = rustU16(raw.fallback_reason_code, `${label}.fallback_reason_code`);
  invariant(
    raw.fallback_used === candidate.outcome.fallback_used &&
      fallbackReasonCode === candidate.outcome.fallback_reason_code,
    `${label}: fallback authority`,
  );
  const oldSetRaw = boundedHex(raw.old_validator_set_cev0_hex, 1, 8 * 1024 * 1024, `${label}.old_set`);
  const oldParametersRaw = boundedHex(raw.old_parameters_cev0_hex, 341, 341, `${label}.old_parameters`);
  invariant(oldSetRaw.equals(candidate.reconstructed.oldSet.cev0), `${label}: old set preimage`);
  invariant(oldParametersRaw.equals(candidate.reconstructed.oldParametersRaw), `${label}: old parameters preimage`);
  const newSetRaw = boundedHex(raw.new_validator_set_cev0_hex, 1, 8 * 1024 * 1024, `${label}.new_set`);
  invariant(newSetRaw.toString("hex") === candidateScenario.checkpoint.effective_validator_set_cev0_hex, `${label}: effective set preimage`);
  const expectedNewParametersRaw = candidate.outcome.fallback_used
    ? candidate.reconstructed.oldParametersRaw
    : candidate.reconstructed.candidateParametersRaw;
  const newParametersRaw = boundedHex(raw.new_parameters_cev0_hex, 341, 341, `${label}.new_parameters`);
  invariant(newParametersRaw.equals(expectedNewParametersRaw), `${label}: effective parameters preimage`);
  const oldParameters = decodeParameters(oldParametersRaw, true);
  const oldSet = decodeValidatorSet(oldSetRaw, oldParameters, true);
  const newParameters = decodeParameters(newParametersRaw, true);
  const newSet = decodeValidatorSet(newSetRaw, newParameters, true);
  invariant(
    oldSet.genesis.equals(newSet.genesis) && oldSet.chain.equals(newSet.chain) &&
      oldSet.protocol === 0 && newSet.protocol === 0 && newSet.epoch === oldSet.epoch + 1n &&
      oldParameters.fields.epoch_length_blocks === newParameters.fields.epoch_length_blocks,
    `${label}: same-version old/new context`,
  );
  return { oldSetRaw, oldParametersRaw, newSetRaw, newParametersRaw, oldSet, oldParameters, newSet, newParameters };
}

function validateCommitmentAuthority(raw, binding, h1, h2, label) {
  exactKeys(raw, ["cev0_hex", "id_hex"], label);
  const commitmentRaw = boundedHex(raw.cev0_hex, 1, 8 * 1024 * 1024, `${label}.cev0`);
  const commitment = decodeCommitment(commitmentRaw, true);
  invariant(commitment.id.equals(exactHex(raw.id_hex, 32, `${label}.id`)), `${label}: commitment ID`);
  const expected = {
    genesis: binding.oldSet.genesis,
    chain: binding.oldSet.chain,
    oldEpoch: binding.oldSet.epoch,
    newEpoch: binding.newSet.epoch,
    snapshotCutoffHeight: h1.finalized.header.height,
    snapshotStateRoot: h1.finalized.header.stateRoot,
    newProtocolVersion: 0,
    newValidatorSetHash: binding.newSet.hash,
    newParametersHash: binding.newParameters.hash,
    rolloutPhase: binding.newParameters.fields.rollout_phase,
    upgradePlanHash: null,
    fallbackUsed: binding.fallbackUsed,
    fallbackReason: binding.fallbackReason,
    activationHeight: (binding.oldSet.epoch + 1n) * binding.oldParameters.fields.epoch_length_blocks + 1n,
  };
  const expectedRaw = encodeCommitment(expected);
  invariant(expectedRaw.equals(commitmentRaw), `${label}: commitment fields are not uniquely derived`);
  invariant(commitment.snapshotCutoffHeight === h2.manifest.height, `${label}: H1/H2 cutoff height`);
  invariant(commitment.snapshotStateRoot.equals(h2.root), `${label}: H1/H2 cutoff root`);
  invariant(
    h1.grandchild.header.kind === 0 && h1.grandchild.header.nextCommitment === null,
    `${label}: H1 grandchild must remain a regular pre-checkpoint carrier`,
  );
  return { commitmentRaw, commitment };
}

function validateScenario(raw, candidateVector, label) {
  exactKeys(raw, [
    "id", "candidate_source_id", "candidate_binding", "h1", "h2", "commitment",
    "authorization_id_hex",
  ], label);
  invariant(typeof raw.id === "string" && raw.id.length > 0, `${label}: scenario ID`);
  const candidateScenario = selectCandidateScenario(candidateVector, raw.candidate_source_id);
  const candidate = validateCandidateScenario(
    candidateVector.compact_profile,
    candidateScenario,
    `${label}.candidate_source`,
  );
  const binding = validateCandidateBinding(raw.candidate_binding, candidateScenario, candidate, `${label}.candidate_binding`);
  binding.fallbackUsed = candidate.outcome.fallback_used;
  binding.fallbackReason = candidate.outcome.fallback_reason_code;
  const h1 = validateRawH1(raw.h1, binding.oldSet, binding.oldParameters, {
    version: BigInt(candidate.history.cutoffVersion),
    root: exactHex(candidateScenario.source.cutoff_root_hex, 32, `${label}.candidate_cutoff_root`),
  }, `${label}.h1`);
  const h2 = validateRawH2(raw.h2, { ...candidate, source: candidateScenario.source }, `${label}.h2`);
  invariant(h1.proof.id.equals(h1.finalized.header.id) === false, `${label}: proof ID collapsed to block ID`);
  const commitment = validateCommitmentAuthority(raw.commitment, binding, h1, h2, `${label}.commitment`);
  const authorization = hashV1(AUTHORIZATION_DOMAIN, [
    candidate.authorization,
    candidate.reconstructed.candidateParametersHash,
    h1.parentRaw,
    h1.proof.id,
    h1.finalized.header.id,
    h1.finalized.header.stateRoot,
    h2.manifest.entriesRoot,
    uint(h2.manifest.count, 4),
    uint(h2.absenceCount, 4),
    binding.oldSetRaw,
    binding.oldParametersRaw,
    binding.newSetRaw,
    binding.newParametersRaw,
    commitment.commitmentRaw,
  ]);
  invariant(authorization.equals(exactHex(raw.authorization_id_hex, 32, `${label}.authorization_id`)), `${label}: private authorization seal`);
  stats.scenarios += 1;
  return { raw, candidateScenario, candidate, binding, h1, h2, commitment, authorization };
}

function validateSourceSurface() {
  const source = fs.readFileSync(path.join(ROOT, "trillionnium/crates/trnm-consensus-app/src/poco_epoch_commitment.rs"), "utf8");
  const constructor = source.match(/pub\(crate\) fn authorize_poco_next_epoch_commitment_v0\s*\(([\s\S]*?)\)\s*->[^{]+\{/);
  invariant(constructor !== null, "production commitment constructor missing");
  for (const required of [
    "candidate: AuthenticatedPocoCandidateSelectionV0",
    "raw_finalized_cutoff_proof_cev0: &[u8]",
    "raw_cutoff_parent_header_cev0: &[u8]",
    "raw_snapshot_namespace_proof: &PocoSnapshotNamespaceProofV0",
  ]) invariant(constructor[1].includes(required), `production constructor missing ${required}`);
  for (const forbidden of [
    "SignatureVerifier", "AuthenticatedFinalizedCutoffHeaderV0",
    "AuthenticatedPocoSnapshotNamespaceV0", "NextEpochCommitmentV0Fields",
    "NextEpochCommitmentV0,", "CandidateSelectionKernelV0", "status", "event",
  ]) invariant(!constructor[1].includes(forbidden), `production constructor accepts forbidden ${forbidden}`);
  invariant(
    source.includes("decode_block_header_v0_exact(raw_cutoff_parent_header_cev0)") &&
      source.includes("decode_finality_proof_v0_exact(") &&
      source.includes("raw_finalized_cutoff_proof_cev0,") &&
      source.includes("&StrictEd25519Verifier") &&
      source.includes("verify_poco_snapshot_namespace_v0(") &&
      source.includes("NextEpochCommitmentV0::new(NextEpochCommitmentV0Fields") &&
      source.includes("snapshot lead is shorter than the finality proof chain; commitment cannot be derived before checkpoint proposal") &&
      source.includes("old_parameters.finality_certified_chain_length()") &&
      source.includes("raw_cutoff_parent_header_cev0,"),
    "production lead guard/raw-parent/strict-H1/H2/derived-commitment authority drift",
  );
  invariant(
    !source.includes("impl From<NextEpochCommitmentV0>") &&
      !source.includes("impl From<AuthenticatedFinalizedCutoffHeaderV0>"),
    "inert commitment/H1 token gained an authority conversion",
  );
}

function validateSchema(schema) {
  invariant(
    schema.schema === "trnm.poco-bft.authenticated-next-epoch-commitment.v0" &&
      schema.schema_version === 0,
    "authenticated commitment schema identity/version",
  );
  invariant(
    JSON.stringify(schema.authority_flow) === JSON.stringify([
      "independently reconstructed H3b2b2 candidate facts",
      "raw exact cutoff parent BlockHeader CEV0",
      "raw FinalityProofV0 with hard-coded StrictEd25519Verifier semantics",
      "raw complete H2 JMT ICS23 namespace bundle",
      "unique same-version NextEpochCommitmentV0 derivation",
      "private authenticated commitment capability",
    ]),
    "schema authority flow",
  );
  invariant(
    schema.parent_header_contract.some((item) => item.includes("parent.id == finalized_cutoff.parent_id == finalized ordinary justify-QC block_id")) &&
      schema.parent_header_contract.some((item) => item.includes("timestamp is read only from the exact decoded parent header")),
    "schema raw parent authority",
  );
  invariant(
    schema.h1_contract.some((item) => item.includes("strict canonical Ed25519 public key, R, and S checks")) &&
      schema.h1_contract.some((item) => item.includes("child and grandchild are regular finality carriers, not checkpoint-header authority")) &&
      schema.timing_contract.includes("the unified production-shaped compact witness uses epoch_length_blocks 10, active epoch 2, snapshot lead 3, cutoff 25, and checkpoint 28") &&
      schema.timing_contract.includes("a lead-2 cutoff at 26 is finalized only by the height-28 checkpoint carrier and is hard-rejected before H1/H2 as an impossible pre-header commitment source"),
    "schema H1 strict/nonauthority boundary",
  );
  invariant(
    schema.h2_contract.some((item) => item.includes("every manifest and member ICS23 existence proof")) &&
      schema.h2_contract.some((item) => item.includes("complete physical namespace is inherited only from the independently rerun H3b2b2 source gate")),
    "schema H2 proof/completeness boundary",
  );
  invariant(
    schema.authorization_seal.domain === AUTHORIZATION_DOMAIN &&
      JSON.stringify(schema.authorization_seal.preimage_order) === JSON.stringify([
        "candidate_authorization_id", "candidate_parameters_hash",
        "exact_cutoff_parent_header_cev0", "h1_proof_id", "cutoff_block_id",
        "cutoff_state_root", "h2_entries_root", "h2_entry_count", "h2_absence_count",
        "old_validator_set_cev0", "old_parameters_cev0", "new_validator_set_cev0",
        "new_parameters_cev0", "next_epoch_commitment_cev0",
      ]),
    "schema authorization seal",
  );
  for (const family of [
    "bad H1 signature", "noncanonical Ed25519 R or S and small-order key",
    "H2 root substitution", "cutoff splice",
    "commitment-field substitution", "parent ID substitution", "parent timestamp substitution",
  ]) invariant(schema.negative_families.includes(family), `schema missing negative ${family}`);
  for (const open of [
    "CometBFT block hash to native PoCO BlockId checkpoint-header authority",
    "native checkpoint body and ordered receipt roots",
    "checkpoint plus two-seal B2-E and joint B2-F handoff",
    "field 13 activation, field 14 new-set finality, and atomic Core epoch transition",
  ]) invariant(schema.does_not_establish.includes(open), `schema hides open boundary ${open}`);
}

function expectScenarioReject(draft, candidateVector, label, expectedError = null) {
  let rejection = null;
  try {
    validateScenario(draft, candidateVector, label);
  } catch (error) {
    rejection = error;
  }
  invariant(rejection !== null, `${label}: negative was accepted`);
  if (expectedError !== null) {
    invariant(
      expectedError.test(String(rejection.message)),
      `${label}: rejected for the wrong reason: ${rejection.message}`,
    );
  }
  stats.negatives += 1;
}

function uniqueOffset(haystack, needle, label) {
  const first = haystack.indexOf(needle);
  invariant(first >= 0 && haystack.indexOf(needle, first + 1) < 0, `${label}: mutation target is not unique`);
  return first;
}

function refreshFinalityProofId(draft, parameters, label) {
  const proofRaw = Buffer.from(draft.h1.finality_proof_cev0_hex, "hex");
  draft.h1.proof_id_hex = decodeFinality(proofRaw, parameters).id.toString("hex");
  invariant(draft.h1.proof_id_hex.length === 64, `${label}: recomputed proof ID width`);
}

function runNegativeSelfChecks(vector, candidateVector, positive, fallback) {
  const badSignature = structuredClone(vector.positive);
  const badProof = Buffer.from(badSignature.h1.finality_proof_cev0_hex, "hex");
  const signatureOffset = uniqueOffset(
    badProof,
    positive.h1.finalized.proposerSignature,
    "negative.bad_h1_signature",
  );
  badProof[signatureOffset] ^= 1;
  badSignature.h1.finality_proof_cev0_hex = badProof.toString("hex");
  refreshFinalityProofId(badSignature, positive.binding.oldParameters, "negative.bad_h1_signature");
  expectScenarioReject(
    badSignature,
    candidateVector,
    "negative.bad_h1_signature",
    /non-strict or invalid proposer signature/,
  );

  const noncanonicalScalar = structuredClone(vector.positive);
  const scalarProof = Buffer.from(noncanonicalScalar.h1.finality_proof_cev0_hex, "hex");
  const scalarOffset = uniqueOffset(
    scalarProof,
    positive.h1.finalized.proposerSignature,
    "negative.noncanonical_s",
  );
  scalarProof.fill(0xff, scalarOffset + 32, scalarOffset + 64);
  noncanonicalScalar.h1.finality_proof_cev0_hex = scalarProof.toString("hex");
  refreshFinalityProofId(noncanonicalScalar, positive.binding.oldParameters, "negative.noncanonical_s");
  expectScenarioReject(
    noncanonicalScalar,
    candidateVector,
    "negative.noncanonical_s",
    /non-strict or invalid proposer signature/,
  );

  const noncanonicalPoint = structuredClone(vector.positive);
  const pointProof = Buffer.from(noncanonicalPoint.h1.finality_proof_cev0_hex, "hex");
  const pointOffset = uniqueOffset(
    pointProof,
    positive.h1.finalized.proposerSignature,
    "negative.noncanonical_r",
  );
  ED25519_NONCANONICAL_R.copy(pointProof, pointOffset);
  noncanonicalPoint.h1.finality_proof_cev0_hex = pointProof.toString("hex");
  refreshFinalityProofId(noncanonicalPoint, positive.binding.oldParameters, "negative.noncanonical_r");
  expectScenarioReject(
    noncanonicalPoint,
    candidateVector,
    "negative.noncanonical_r",
    /non-strict or invalid proposer signature/,
  );

  const quotedU64 = structuredClone(vector.positive);
  quotedU64.candidate_binding.cutoff_version = String(quotedU64.candidate_binding.cutoff_version);
  expectScenarioReject(
    quotedU64,
    candidateVector,
    "negative.quoted_u64",
    /Rust integer fields require an unquoted JSON number/,
  );

  const quotedU32 = structuredClone(vector.positive);
  quotedU32.candidate_binding.cutoff_entry_count = String(quotedU32.candidate_binding.cutoff_entry_count);
  expectScenarioReject(
    quotedU32,
    candidateVector,
    "negative.quoted_u32",
    /Rust integer fields require an unquoted JSON number/,
  );

  const quotedU8 = structuredClone(vector.positive);
  quotedU8.h2.members[0].kind = String(quotedU8.h2.members[0].kind);
  expectScenarioReject(
    quotedU8,
    candidateVector,
    "negative.quoted_u8",
    /Rust integer fields require an unquoted JSON number/,
  );

  const h2Root = structuredClone(vector.positive);
  const root = Buffer.from(h2Root.h2.manifest_proof.root_hash_hex, "hex");
  root[0] ^= 1;
  h2Root.h2.manifest_proof.root_hash_hex = root.toString("hex");
  expectScenarioReject(h2Root, candidateVector, "negative.h2_root_substitution");

  const cutoffSplice = structuredClone(vector.authenticated_fallback);
  cutoffSplice.h1 = structuredClone(vector.positive.h1);
  cutoffSplice.h2 = structuredClone(vector.positive.h2);
  expectScenarioReject(cutoffSplice, candidateVector, "negative.cutoff_splice");

  const commitmentField = structuredClone(vector.positive);
  const commitmentRaw = Buffer.from(commitmentField.commitment.cev0_hex, "hex");
  const commitmentRootOffset = uniqueOffset(
    commitmentRaw,
    positive.h1.finalized.header.stateRoot,
    "negative.commitment_field_substitution",
  );
  commitmentRaw[commitmentRootOffset] ^= 1;
  commitmentField.commitment.cev0_hex = commitmentRaw.toString("hex");
  commitmentField.commitment.id_hex = decodeCommitment(commitmentRaw).id.toString("hex");
  expectScenarioReject(commitmentField, candidateVector, "negative.commitment_field_substitution");

  const parentId = structuredClone(vector.positive);
  const parentIdRaw = Buffer.from(parentId.h1.cutoff_parent_header_cev0_hex, "hex");
  const payloadOffset = uniqueOffset(parentIdRaw, positive.h1.parent.payloadRoot, "negative.parent_id_substitution");
  parentIdRaw[payloadOffset] ^= 1;
  const changedParent = decodeHeader(parentIdRaw, positive.binding.oldParameters);
  parentId.h1.cutoff_parent_header_cev0_hex = parentIdRaw.toString("hex");
  parentId.h1.cutoff_parent_block_id_hex = changedParent.id.toString("hex");
  expectScenarioReject(parentId, candidateVector, "negative.parent_id_substitution");

  const parentTimestamp = structuredClone(vector.positive);
  const parentTimestampRaw = Buffer.from(parentTimestamp.h1.cutoff_parent_header_cev0_hex, "hex");
  invariant(parentTimestampRaw.at(-1) === 0, "negative.parent_timestamp: regular optional tag");
  parentTimestampRaw[parentTimestampRaw.length - 2] ^= 1;
  const changedTimestampParent = decodeHeader(parentTimestampRaw, positive.binding.oldParameters);
  parentTimestamp.h1.cutoff_parent_header_cev0_hex = parentTimestampRaw.toString("hex");
  parentTimestamp.h1.cutoff_parent_block_id_hex = changedTimestampParent.id.toString("hex");
  parentTimestamp.h1.cutoff_parent_timestamp_ms = Number(changedTimestampParent.timestamp);
  expectScenarioReject(parentTimestamp, candidateVector, "negative.parent_timestamp_substitution");

  const authorization = structuredClone(vector.positive);
  const authorizationId = Buffer.from(authorization.authorization_id_hex, "hex");
  authorizationId[0] ^= 1;
  authorization.authorization_id_hex = authorizationId.toString("hex");
  expectScenarioReject(authorization, candidateVector, "negative.authorization_seal_substitution");

  invariant(!positive.authorization.equals(fallback.authorization), "positive/fallback authorization splice");
  const contextualProposer = positive.binding.oldSet.byId.get(
    positive.h1.finalized.header.proposerId.toString("hex"),
  );
  invariant(contextualProposer !== undefined, "small-order control lacks H1 proposer");
  const contextualProposalRoot = proposalRoot(
    positive.h1.finalized.header,
    positive.h1.finalized.justifyQc.id,
  );
  invariant(
    strictEd25519Verify(
      contextualProposalRoot,
      contextualProposer.publicKey,
      positive.h1.finalized.proposerSignature,
    ),
    "small-order control canonical H1 signature is invalid",
  );
  invariant(
    !strictEd25519Verify(
      contextualProposalRoot,
      ED25519_SMALL_ORDER_PUBLIC_KEY,
      positive.h1.finalized.proposerSignature,
    ),
    "strict verifier accepted a small-order public key in an H1 signature context",
  );
  stats.negatives += 1;
}

function main() {
  const losslessJsonSelfTests = runLosslessFixtureJsonSelfTests();
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  const vectorRaw = fs.readFileSync(VECTOR_PATH);
  const vector = parseLosslessUnsignedJson(vectorRaw, "authenticated commitment vector");
  const candidateSchema = JSON.parse(fs.readFileSync(CANDIDATE_SCHEMA_PATH, "utf8"));
  const candidateRaw = fs.readFileSync(CANDIDATE_VECTOR_PATH);
  const candidateVector = parseLosslessUnsignedJson(candidateRaw, "authenticated candidate vector");
  validateSchema(schema);
  validateCandidateSchema(candidateSchema);
  validateCandidateSourceSurface();
  validateCandidateProfile(candidateVector.compact_profile);
  validateCandidateBoundary(candidateVector);
  validateSourceSurface();
  exactKeys(vector, [
    "schema", "schema_version", "fixture_scope", "candidate_vector_path",
    "candidate_vector_sha256_hex", "positive", "authenticated_fallback",
  ], "vector");
  invariant(
    vector.schema === FIXTURE_SCHEMA && rustU16(vector.schema_version, "vector.schema_version") === 0,
    "vector identity/version",
  );
  invariant(
    vector.fixture_scope === "raw_strict_h1_h2_candidate_to_private_same_version_commitment_not_checkpoint_header_authority",
    "vector fixture scope",
  );
  invariant(
    vector.candidate_vector_path === "docs/protocol/poco-bft-v0/vectors/poco-authenticated-candidate-selection-v0.json" &&
      vector.candidate_vector_sha256_hex === sha256(candidateRaw).toString("hex"),
    "candidate source path/digest",
  );
  const positive = validateScenario(vector.positive, candidateVector, "positive");
  const fallback = validateScenario(vector.authenticated_fallback, candidateVector, "authenticated_fallback");
  invariant(!positive.binding.fallbackUsed && positive.binding.fallbackReason === 0, "positive is not reason-zero");
  invariant(fallback.binding.fallbackUsed && fallback.binding.fallbackReason === 3, "fallback taxonomy drift");
  runNegativeSelfChecks(vector, candidateVector, positive, fallback);
  process.stdout.write(
    `authenticated next-epoch commitment gate ok: scenarios=${stats.scenarios}, strict_h1_signatures=${stats.h1Signatures}, h2_memberships=${stats.h2Memberships}, negatives=${stats.negatives}, lossless_u64=${losslessJsonSelfTests.accepted}/${losslessJsonSelfTests.rejected}\n`,
  );
}

export { validateScenario };

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
