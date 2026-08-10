import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vector = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/vectors/poco-checkpoint-execution-v0.json"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/schema/poco-checkpoint-execution-v0.json"), "utf8"));
const snapshotVector = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json"), "utf8"));
const checkpointFinalityVector = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/vectors/checkpoint-two-seal-kernel-v0.json"), "utf8"));
const invariant = (condition, message) => { if (!condition) throw new Error(message); };
const u = (value, width) => {
  let remaining = BigInt(value);
  const output = Buffer.alloc(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    output[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  invariant(remaining === 0n, "unsigned integer overflow");
  return output;
};
const frame64 = (value) => Buffer.concat([u(value.length, 8), value]);
const frame16 = (value) => Buffer.concat([u(value.length, 2), value]);
const hashDomain = (domain, parts) => crypto.createHash("sha256").update(Buffer.concat([
  Buffer.from("trnm.domain.hash.v1"),
  frame64(Buffer.from(domain)),
  ...parts.map(frame64),
])).digest();
const hex = (value, width, name) => {
  invariant(typeof value === "string" && /^[0-9a-f]*$/.test(value) && value.length === width * 2, `${name} is not canonical ${width}-byte hex`);
  return Buffer.from(value, "hex");
};
const orderedRoot = (domain, values) => {
  let layer = values.map((value, index) => hashDomain(`${domain}.leaf`, [u(index, 4), value]));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(hashDomain(`${domain}.node`, [u(level, 4), layer[index], layer[index + 1] ?? layer[index]]));
    }
    layer = next;
    level += 1;
  }
  return layer.length === 0
    ? hashDomain(domain, [u(values.length, 4), Buffer.from([0])])
    : hashDomain(domain, [u(values.length, 4), Buffer.from([1]), layer[0]]);
};
const cev0Frame = (value) => Buffer.concat([u(value.length, 4), value]);
const cev0Digest = (domain, encoded) => crypto.createHash("sha256").update(Buffer.concat([
  cev0Frame(Buffer.from("trnm.cev0.hash.v0")),
  cev0Frame(Buffer.from(domain)),
  cev0Frame(encoded),
])).digest();
const snapshotEntryBytes = (kind, key, value) => Buffer.concat([
  u(0, 2),
  u(kind, 1),
  cev0Frame(key),
  cev0Frame(value),
]);
const snapshotEntriesRoot = (entries) => {
  let layer = entries.map(({ kind, key, value }) =>
    cev0Digest("trnm.poco-bft.snapshot-entry.v0", snapshotEntryBytes(kind, key, value)));
  let level = 0;
  while (layer.length > 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(cev0Digest(
        "trnm.poco-bft.snapshot-node.v0",
        Buffer.concat([u(0, 2), u(level, 4), layer[index], layer[index + 1] ?? layer[index]]),
      ));
    }
    layer = next;
    level += 1;
  }
  return cev0Digest(
    "trnm.poco-bft.snapshot-root.v0",
    Buffer.concat([
      u(0, 2),
      u(entries.length, 4),
      layer.length === 0 ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), layer[0]]),
    ]),
  );
};
const parseValidatorSetContext = (raw) => {
  let offset = 0;
  invariant(raw.readUInt16BE(offset) === 0, "validator-set schema drift");
  offset += 2;
  const genesis = raw.subarray(offset, offset + 32);
  offset += 32;
  const chainLength = raw.readUInt16BE(offset);
  offset += 2;
  const chain = raw.subarray(offset, offset + chainLength);
  offset += chainLength;
  const protocolVersion = raw.readUInt32BE(offset);
  offset += 4;
  const epoch = raw.readBigUInt64BE(offset);
  offset += 8;
  const parametersHash = raw.subarray(offset, offset + 32);
  return { genesis, chain, protocolVersion, epoch, parametersHash };
};
const checkpointCanonical = (source, chainId, payloadRoot, receiptsRoot) => Buffer.concat([
  u(source.canonical_schema_version, 2),
  Buffer.from(source.genesis_hash_hex, "hex"),
  frame16(chainId),
  Buffer.from(source.protocol_profile_hash_hex, "hex"),
  u(source.protocol_version, 4),
  u(source.epoch, 8),
  u(source.checkpoint_height, 8),
  Buffer.from(source.checkpoint_block_hash_hex, "hex"),
  u(source.checkpoint_timestamp_ms, 8),
  u(source.parent_height, 8),
  Buffer.from(source.parent_state_root_hex, "hex"),
  u(source.cutoff_height, 8),
  Buffer.from(source.cutoff_state_root_hex, "hex"),
  Buffer.from(source.cutoff_manifest_entries_root_hex, "hex"),
  u(source.cutoff_manifest_entry_count, 4),
  payloadRoot,
  receiptsRoot,
  Buffer.from(source.next_state_root_hex, "hex"),
  Buffer.from(source.validator_set_id_hex, "hex"),
  Buffer.from(source.consensus_parameters_hash_hex, "hex"),
]);
const refreshedCheckpointVectorV0 = () => {
  const refreshed = structuredClone(vector);
  const fixtures = snapshotVector.semantic_layout_corpus.positive_fixtures
    .filter((fixture) => fixture.kind === 13 || fixture.kind === 14)
    .sort((left, right) => left.kind - right.kind);
  invariant(fixtures.length === 2, "snapshot configuration source cardinality drift");
  const entries = fixtures.map((fixture) => ({
    kind: fixture.kind,
    key: Buffer.from(fixture.logical_key_hex, "hex"),
    value: Buffer.from(fixture.value_cev0_hex, "hex"),
  }));
  const validatorSetRaw = Buffer.from(fixtures[0].payload_cev0_hex, "hex");
  const parametersRaw = Buffer.from(fixtures[1].payload_cev0_hex, "hex");
  const context = parseValidatorSetContext(validatorSetRaw);
  const parametersHash = cev0Digest("trnm.poco-bft.parameters.v0", parametersRaw);
  invariant(context.parametersHash.equals(parametersHash), "validator-set parameter preimage drift");
  const validatorSetId = cev0Digest("trnm.poco-bft.validator-set.v0", validatorSetRaw);
  const geometry = checkpointFinalityVector.fixture;
  const valid = refreshed.valid_case;
  valid.genesis_hash_hex = context.genesis.toString("hex");
  valid.chain_id = context.chain.toString("utf8");
  valid.protocol_profile_hash_hex = parametersHash.toString("hex");
  valid.protocol_version = context.protocolVersion;
  valid.epoch = Number(context.epoch);
  valid.checkpoint_height = Number(geometry.checkpoint_height);
  valid.parent_height = valid.checkpoint_height - 1;
  valid.cutoff_height = Number(geometry.snapshot_cutoff_height);
  valid.cutoff_manifest_entries_root_hex = snapshotEntriesRoot(entries).toString("hex");
  valid.cutoff_manifest_entry_count = entries.length;
  valid.validator_set_id_hex = validatorSetId.toString("hex");
  valid.consensus_parameters_hash_hex = parametersHash.toString("hex");
  const txs = valid.txs_hex.map((value) => Buffer.from(value, "hex"));
  const results = valid.exec_tx_results_protobuf_hex.map((value) => Buffer.from(value, "hex"));
  const payloadRoot = orderedRoot(schema.execution_binding.payload_root_domain, txs);
  const receiptsRoot = orderedRoot(schema.execution_binding.receipts_root_domain, results);
  valid.payload_root_hex = payloadRoot.toString("hex");
  valid.receipts_root_hex = receiptsRoot.toString("hex");
  const canonical = checkpointCanonical(valid, context.chain, payloadRoot, receiptsRoot);
  valid.canonical_hex = canonical.toString("hex");
  valid.execution_id_hex = hashDomain(schema.execution_binding.execution_id_domain, [canonical]).toString("hex");
  return refreshed;
};

if (process.argv.includes("--emit-refreshed-vector")) {
  process.stdout.write(`${JSON.stringify(refreshedCheckpointVectorV0(), null, 2)}\n`);
  process.exit(0);
}
const valid = vector.valid_case;
invariant(schema.status === "B2-H3b2a-production-checkpoint-authority", "schema status drift");
invariant(valid.authority_schema === schema.authority.config_schema, "authority schema drift");
invariant(valid.canonical_schema_version === 0, "canonical schema version drift");
invariant(schema.execution_binding.canonical_fields[0] === "schema_version:u16=0", "canonical schema-version field drift");
const txs = valid.txs_hex.map((value, index) => hex(value, value.length / 2, `tx ${index}`));
const results = valid.exec_tx_results_protobuf_hex.map((value, index) => hex(value, value.length / 2, `result ${index}`));
invariant(txs.length === results.length, "transaction/result cardinality mismatch");
const payloadRoot = orderedRoot(schema.execution_binding.payload_root_domain, txs);
const receiptsRoot = orderedRoot(schema.execution_binding.receipts_root_domain, results);
invariant(payloadRoot.toString("hex") === valid.payload_root_hex, "payload root mismatch");
invariant(receiptsRoot.toString("hex") === valid.receipts_root_hex, "receipt root mismatch");

const canonicalFor = (chainId, overrides = {}) => Buffer.concat([
  u(valid.canonical_schema_version, 2),
  hex(valid.genesis_hash_hex, 32, "genesis hash"),
  frame16(chainId),
  hex(valid.protocol_profile_hash_hex, 32, "protocol profile hash"),
  u(valid.protocol_version, 4),
  u(valid.epoch, 8),
  u(valid.checkpoint_height, 8),
  hex(valid.checkpoint_block_hash_hex, 32, "checkpoint block hash"),
  u(valid.checkpoint_timestamp_ms, 8),
  u(valid.parent_height, 8),
  hex(valid.parent_state_root_hex, 32, "parent state root"),
  u(valid.cutoff_height, 8),
  hex(overrides.cutoff_state_root_hex ?? valid.cutoff_state_root_hex, 32, "cutoff state root"),
  hex(overrides.cutoff_manifest_entries_root_hex ?? valid.cutoff_manifest_entries_root_hex, 32, "cutoff manifest entries root"),
  u(overrides.cutoff_manifest_entry_count ?? valid.cutoff_manifest_entry_count, 4),
  payloadRoot,
  receiptsRoot,
  hex(valid.next_state_root_hex, 32, "next state root"),
  hex(valid.validator_set_id_hex, 32, "validator set ID"),
  hex(valid.consensus_parameters_hash_hex, 32, "parameter hash"),
]);
const canonical = canonicalFor(Buffer.from(valid.chain_id));
const expectedCanonical = Buffer.from(valid.canonical_hex, "hex");
const lengthContract = schema.execution_binding.canonical_length_bytes;
invariant(
  lengthContract.formula === "404 + chain_id.length" &&
    lengthContract.chain_id_minimum_bytes === 1 &&
    lengthContract.chain_id_maximum_bytes === 128 &&
    lengthContract.minimum === 405 &&
    lengthContract.maximum === 532,
  "checkpoint execution variable-length contract drift",
);
invariant(
  Buffer.byteLength(valid.chain_id) === lengthContract.fixed_vector_chain_id_bytes &&
    canonical.length === lengthContract.fixed_vector_total &&
    canonical.length === 404 + Buffer.byteLength(valid.chain_id),
  "fixed checkpoint execution canonical length drift",
);
const mismatchIndex = canonical.findIndex((value, index) => value !== expectedCanonical[index]);
invariant(canonical.equals(expectedCanonical), `canonical execution bytes mismatch at ${mismatchIndex}; actual=${canonical.length}, expected=${expectedCanonical.length}`);
const executionId = hashDomain(schema.execution_binding.execution_id_domain, [canonical]);
invariant(executionId.toString("hex") === valid.execution_id_hex, "execution ID mismatch");

invariant(vector.chain_id_length_cases.length === 2, "chain-id boundary vector count drift");
for (const test of vector.chain_id_length_cases) {
  const chainId = Buffer.from(test.chain_id);
  invariant(chainId.length === test.chain_id_utf8_bytes, `${test.id}: UTF-8 length drift`);
  invariant(chainId.length >= 1 && chainId.length <= 128, `${test.id}: chain-id bound drift`);
  invariant(frame16(chainId).toString("hex") === test.encoded_chain_id_hex, `${test.id}: actual chain-id encoding drift`);
  invariant(canonicalFor(chainId).length === test.canonical_length_bytes, `${test.id}: canonical length drift`);
  invariant(test.canonical_length_bytes === 404 + chainId.length, `${test.id}: length formula drift`);
}
invariant(vector.chain_id_length_cases[0].chain_id_utf8_bytes === 1, "minimum chain-id case absent");
invariant(vector.chain_id_length_cases[1].chain_id_utf8_bytes === 128, "maximum chain-id case absent");

const aggregate = schema.execution_binding.aggregate_bounds;
invariant(
  aggregate.transaction_count_maximum === 4_294_967_295 &&
    aggregate.transaction_bytes_maximum === 8_388_608 &&
    aggregate.encoded_receipt_bytes_maximum === 8_388_608 &&
    aggregate.arithmetic === "checked" &&
    aggregate.admission_order ===
      "count, transaction-byte total, and encoded-receipt-byte total reject before receipt collection, ordered-root encoding, or hashing",
  "checkpoint aggregate-bound contract drift",
);
const boundedAggregate = (test) => {
  const count = BigInt(test.count);
  if (count > BigInt(aggregate.transaction_count_maximum)) return false;
  const maximum = test.field === "transaction_bytes"
    ? BigInt(aggregate.transaction_bytes_maximum)
    : test.field === "encoded_receipt_bytes"
      ? BigInt(aggregate.encoded_receipt_bytes_maximum)
      : null;
  if (test.field === "count") return test.term_bytes.length === 0;
  invariant(maximum !== null, `${test.id}: unknown aggregate field`);
  let total = 0n;
  for (const raw of test.term_bytes) {
    const term = BigInt(raw);
    if (term > maximum - total) return false;
    total += term;
  }
  return true;
};
invariant(vector.aggregate_bound_cases.length === 6, "aggregate boundary vector count drift");
for (const test of vector.aggregate_bound_cases) {
  invariant(
    test.expected === (boundedAggregate(test) ? "accept" : "reject"),
    `${test.id}: aggregate boundary drift`,
  );
}

const reversedPayload = orderedRoot(schema.execution_binding.payload_root_domain, [...txs].reverse());
invariant(!reversedPayload.equals(payloadRoot), "transaction order is not bound");
const changedParent = Buffer.from(canonical);
changedParent[190] ^= 1;
invariant(!hashDomain(schema.execution_binding.execution_id_domain, [changedParent]).equals(executionId), "parent mutation is not bound");
const changedManifest = Buffer.from(canonical);
const manifestOffset = changedManifest.indexOf(hex(valid.cutoff_manifest_entries_root_hex, 32, "cutoff manifest entries root"));
invariant(manifestOffset >= 0, "cutoff manifest root is absent from canonical bytes");
changedManifest[manifestOffset] ^= 1;
invariant(!hashDomain(schema.execution_binding.execution_id_domain, [changedManifest]).equals(executionId), "cutoff manifest mutation is not bound");
const flipFirstByte = (value) => `${(Number.parseInt(value.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0")}${value.slice(2)}`;
const changedCutoffRoot = canonicalFor(Buffer.from(valid.chain_id), {
  cutoff_state_root_hex: flipFirstByte(valid.cutoff_state_root_hex),
});
invariant(!changedCutoffRoot.equals(canonical), "cutoff root substitution did not mutate canonical bytes");
invariant(!hashDomain(schema.execution_binding.execution_id_domain, [changedCutoffRoot]).equals(executionId), "cutoff root substitution is not bound");
const changedManifestRoot = canonicalFor(Buffer.from(valid.chain_id), {
  cutoff_manifest_entries_root_hex: flipFirstByte(valid.cutoff_manifest_entries_root_hex),
});
invariant(!changedManifestRoot.equals(canonical), "manifest root substitution did not mutate canonical bytes");
invariant(!hashDomain(schema.execution_binding.execution_id_domain, [changedManifestRoot]).equals(executionId), "manifest root substitution is not bound");
const changedManifestCount = canonicalFor(Buffer.from(valid.chain_id), {
  cutoff_manifest_entry_count: valid.cutoff_manifest_entry_count + 1,
});
invariant(!changedManifestCount.equals(canonical), "manifest count substitution did not mutate canonical bytes");
invariant(!hashDomain(schema.execution_binding.execution_id_domain, [changedManifestCount]).equals(executionId), "manifest count substitution is not bound");
invariant(new Set(vector.negative_relations).size === 11, "negative relation inventory drift");
for (const required of ["authority_config_not_genesis_authenticated", "cutoff_root_mismatch", "cutoff_manifest_root_or_count_substitution", "transaction_order_substitution"]) {
  invariant(vector.negative_relations.includes(required), `missing negative relation ${required}`);
}
invariant(
  schema.event_output.type === "trnm.poco.checkpoint-execution.v0" &&
    schema.event_output.role === "telemetry_only" &&
    schema.event_output.consensus_dependency === "none; admission and later joins consume only the private capability returned by same-call verification",
  "checkpoint event authority boundary drift",
);
invariant(
  schema.projection_cache.role === "performance_only" &&
    schema.projection_cache.maximum_entries === 4 &&
    JSON.stringify(schema.projection_cache.key) === JSON.stringify(["JMT version", "state_root"]) &&
    schema.projection_cache.semantic_invariance ===
      "cache hit, miss, eviction, or disabled cache produces the same accept/reject result and capability bytes",
  "projection cache authority boundary drift",
);
console.log("PoCO checkpoint execution schema/vector gate passed (authority, sealed cutoff projection, ordered payload/receipts with 8 MiB aggregate bounds, canonical length 404+chain_id.length with 1/128-byte boundaries, execution ID, concrete cutoff/manifest substitutions, telemetry-only event, performance-only cache, 11 fail-closed relations)");
