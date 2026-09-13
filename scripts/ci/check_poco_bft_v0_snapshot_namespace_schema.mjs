import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vector = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/vectors/poco-snapshot-namespace-v0.json"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "docs/protocol/poco-bft-v0/schema/poco-snapshot-namespace-v0.json"), "utf8"));
const invariant = (condition, message) => { if (!condition) throw new Error(message); };
const uint = (value, width) => { let v = BigInt(value); const out = Buffer.alloc(width); for (let i=width-1;i>=0;i-=1){out[i]=Number(v&255n);v>>=8n;} invariant(v===0n,"integer overflow"); return out; };
const frame = value => Buffer.concat([uint(value.length,4),value]);
const digest = (domain, encoded) => crypto.createHash("sha256").update(Buffer.concat([frame(Buffer.from("trnm.cev0.hash.v0")),frame(Buffer.from(domain)),frame(encoded)])).digest();
const hex = value => Buffer.from(value,"hex");
const namespaced = components => Buffer.concat([Buffer.from("trnm/authenticated-state/v4"),Buffer.from([0,8]),uint(components.length,2),...components.flatMap(component=>[uint(component.length,4),component])]);
const encodeEntry = entry => { const key=Buffer.from(entry.logical_key_ascii); const value=hex(entry.value_hex); return Buffer.concat([uint(0,2),uint(entry.kind,1),frame(key),frame(value)]); };
const entryKey = entry => namespaced([Buffer.from("entry"),uint(entry.kind,1),Buffer.from(entry.logical_key_ascii)]);
invariant(schema.schema===vector.schema && schema.namespace.discriminant===8,"schema/vector drift");
let previous=null; const encoded=[];
for (const entry of vector.entries) {
  const identity=[entry.kind,Buffer.from(entry.logical_key_ascii)];
  if(previous) invariant(previous[0]<identity[0] || (previous[0]===identity[0] && Buffer.compare(previous[1],identity[1])<0),"noncanonical entries");
  previous=identity; const raw=encodeEntry(entry); encoded.push(raw);
  invariant(raw.toString("hex")===entry.cev0_hex,"entry CEV0 drift");
  invariant(entryKey(entry).toString("hex")===entry.jmt_key_hex,"entry key drift");
}
let layer=encoded.map(value=>digest("trnm.poco-bft.snapshot-entry.v0",value)); let level=0;
while(layer.length>1){const next=[];for(let i=0;i<layer.length;i+=2){const left=layer[i],right=layer[i+1]??left;next.push(digest("trnm.poco-bft.snapshot-node.v0",Buffer.concat([uint(0,2),uint(level,4),left,right])));}layer=next;level+=1;}
const entriesRoot=digest("trnm.poco-bft.snapshot-root.v0",Buffer.concat([uint(0,2),uint(encoded.length,4),Buffer.from([1]),layer[0]]));
invariant(entriesRoot.toString("hex")===vector.entries_root_hex,"entries root drift");
const manifest=Buffer.concat([uint(0,2),uint(8,1),uint(vector.cutoff_height,8),uint(encoded.length,4),entriesRoot]);
invariant(manifest.toString("hex")===vector.manifest_cev0_hex,"manifest drift");
invariant(namespaced([Buffer.from("manifest")]).toString("hex")===vector.manifest_jmt_key_hex,"manifest key drift");
invariant(entryKey(vector.absence_query).toString("hex")===vector.absence_query.jmt_key_hex,"absence key drift");
const negatives=[vector.entries.slice(0,2),[...vector.entries].reverse(),[vector.entries[0],vector.entries[0]]];
for(const candidate of negatives){let valid=true;let prior=null;for(const entry of candidate){const id=[entry.kind,entry.logical_key_ascii];if(prior && !(prior[0]<id[0] || (prior[0]===id[0] && prior[1]<id[1])))valid=false;prior=id;}if(candidate.length!==vector.entries.length)valid=false;invariant(!valid,"negative manifest accepted");}
invariant(vector.authorization_outputs===0,"unexpected authorization output");
console.log("[ok] B2-H2 snapshot namespace: 3 canonical entries, 1 absence query, manifest/count/root/key reproduction, 3 completeness/order negatives; Rust owns 4 real JMT memberships + 1 ICS23 non-membership");
