import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vector = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/vectors/consumption-certificate-v0.json"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/schema/consumption-certificate-v0.json"), "utf8"));
const f = vector.fixture;
const inv = (condition, message) => { if (!condition) throw new Error(message); };
const hex = value => Buffer.from(value, "hex");
const uint = (value, width) => {
  let remaining = BigInt(value); const result = Buffer.alloc(width);
  inv(remaining >= 0n && remaining < (1n << BigInt(width * 8)), `u${width * 8} overflow`);
  for (let i = width - 1; i >= 0; i -= 1) { result[i] = Number(remaining & 255n); remaining >>= 8n; }
  return result;
};
const frame = value => Buffer.concat([uint(value.length, 4), value]);
const bytes = frame;
const cstring = value => Buffer.concat([uint(value.length, 2), value]);
const digest = (domain, encoded) => crypto.createHash("sha256").update(Buffer.concat([
  frame(Buffer.from(vector.hash_prefix, "ascii")), frame(Buffer.from(domain, "ascii")), frame(encoded),
])).digest();

inv(schema.schema === vector.schema && schema.version === 0, "schema/vector identity drift");
const body = Buffer.concat([
  uint(0, 2), hex(f.genesis_hash_hex), cstring(Buffer.from(f.chain_id_ascii, "ascii")),
  bytes(hex(f.provider_id_hex)), bytes(hex(f.consumer_id_hex)), bytes(hex(f.consumer_key_id_hex)),
  bytes(hex(f.task_id_hex)), hex(f.output_commitment_hex), bytes(hex(f.meter_id_hex)),
  uint(f.meter_version, 4), uint(f.consumed_units, 16), uint(f.billing_start_height, 8),
  uint(f.billing_end_height, 8), uint(f.consumer_nonce, 8), hex(f.settlement_commitment_hex),
  Buffer.from([1]), hex(f.measurement_evidence_root_hex),
]);
inv(body.toString("hex") === f.body_cev0_hex, "body CEV0 drift");
const rootDigest = digest(vector.body_domain, body);
inv(rootDigest.toString("hex") === f.body_digest_hex, "body digest drift");
const id = digest(vector.id_domain, rootDigest);
inv(id.toString("hex") === f.certificate_id_hex, "certificate ID drift");
const signature = hex(f.consumer_signature_hex);
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), hex(f.consumer_public_key_hex)]);
const publicKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
inv(crypto.verify(null, rootDigest, publicKey, signature), "strict Ed25519 fixture rejected");
const complete = Buffer.concat([body, signature, id]);
inv(complete.toString("hex") === f.certificate_cev0_hex, "complete object drift");

function exactDecode(raw) {
  let offset = 0;
  const take = n => { if (offset + n > raw.length) throw new Error(`unexpected_end@${offset}`); const v = raw.subarray(offset, offset + n); offset += n; return v; };
  const number = n => { let value = 0n; for (const byte of take(n)) value = (value << 8n) | BigInt(byte); return value; };
  const bounded = () => { const start = offset; const len = Number(number(4)); if (len < 1) throw new Error(`empty_id@${start}`); if (len > 128) throw new Error(`id_too_long@${start}`); return take(len); };
  if (number(2) !== 0n) throw new Error("invalid_schema@0");
  if (take(32).every(byte => byte === 0)) throw new Error("zero_genesis@2");
  const chainLen = Number(number(2)); const chain = take(chainLen).toString("ascii");
  if (chainLen < 1 || chainLen > 128 || !/^[a-z0-9][a-z0-9._:-]*$/.test(chain)) throw new Error("invalid_chain");
  const provider = bounded(); const consumer = bounded(); bounded(); bounded();
  if (provider.equals(consumer)) throw new Error("same_provider_consumer");
  take(32); bounded(); number(4);
  if (number(16) === 0n) throw new Error("zero_units"); const start = number(8); const end = number(8);
  if (start > end) throw new Error("billing_window"); number(8);
  take(32);
  const tag = Number(number(1)); if (tag === 1) take(32); else if (tag !== 0) throw new Error("optional_tag");
  take(64); const suppliedId = take(32); if (!suppliedId.equals(id)) throw new Error("certificate_id");
  if (offset !== raw.length) throw new Error(`trailing@${offset}`);
}
exactDecode(complete);
for (let i = 0; i < complete.length; i += 1) { let failed = false; try { exactDecode(complete.subarray(0, i)); } catch { failed = true; } inv(failed, `prefix ${i} accepted`); }
const mustReject = (label, raw) => { let failed = false; try { exactDecode(raw); } catch { failed = true; } inv(failed, `${label} accepted`); };
mustReject("trailing byte", Buffer.concat([complete, Buffer.from([0])]));
const mutations = [];
const mutate = (label, offset, value) => { const raw = Buffer.from(complete); raw[offset] = value; mutations.push([label, raw]); };
mutate("wrong schema", 1, 1);
const zeroGenesis = Buffer.from(complete); zeroGenesis.fill(0, 2, 34); mutations.push(["zero genesis", zeroGenesis]);
mutate("invalid chain", 36, "T".charCodeAt(0));
const providerLengthOffset = 36 + Buffer.byteLength(f.chain_id_ascii);
const providerStart = providerLengthOffset + 4;
const consumerLengthOffset = providerStart + hex(f.provider_id_hex).length;
const consumerStart = consumerLengthOffset + 4;
const sameRelation = Buffer.from(complete);
hex(f.provider_id_hex).copy(sameRelation, consumerStart);
mutations.push(["provider equals consumer", sameRelation]);
const taskLengthOffset = consumerStart + hex(f.consumer_id_hex).length + 4 + hex(f.consumer_key_id_hex).length;
const emptyTask = Buffer.from(complete); emptyTask.fill(0, taskLengthOffset, taskLengthOffset + 4); mutations.push(["empty task", emptyTask]);
const unitsOffset = body.indexOf(uint(f.consumed_units, 16));
const zeroUnits = Buffer.from(complete); zeroUnits.fill(0, unitsOffset, unitsOffset + 16); mutations.push(["zero units", zeroUnits]);
const reverseWindow = Buffer.from(complete); uint(21, 8).copy(reverseWindow, unitsOffset + 16); uint(20, 8).copy(reverseWindow, unitsOffset + 24); mutations.push(["reversed billing", reverseWindow]);
mutate("invalid optional tag", body.length - 33, 2);
const wrongId = Buffer.from(complete); wrongId[wrongId.length - 1] ^= 1; mutations.push(["wrong certificate ID", wrongId]);
for (const [label, raw] of mutations) mustReject(label, raw);
inv(!crypto.verify(null, rootDigest, crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.alloc(32, 9)]), format: "der", type: "spki" }), signature), "wrong key accepted");
const wrongSignature = Buffer.from(signature); wrongSignature[0] ^= 1;
inv(!crypto.verify(null, rootDigest, publicKey, wrongSignature), "wrong signature accepted");
console.log(`[ok] consumption certificate: 1 exact object, ${complete.length} rejected prefixes, ${mutations.length + 1} parser/semantic negatives, 3 strict Ed25519 checks, schema and domains aligned`);
