import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relative) =>
  JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
const schema = readJson(
  "docs/protocol/poco-bft-v0/schema/poco-business-semantics-v0.json",
);
const vector = readJson(
  "docs/protocol/poco-bft-v0/vectors/poco-business-semantics-v0.json",
);
const snapshotSchema = readJson(
  "docs/protocol/poco-bft-v0/schema/poco-snapshot-transition-v0.json",
);

const invariant = (condition, message) => {
  if (!condition) throw new Error(message);
};
const sameJson = (actual, expected, message) =>
  invariant(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: ${JSON.stringify(actual)}`,
  );
const unique = (values, message) =>
  invariant(new Set(values).size === values.length, message);
const U64_MAX = 18_446_744_073_709_551_615n;
const asU64 = (value, label) => {
  invariant(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), `${label}: decimal`);
  const decoded = BigInt(value);
  invariant(decoded >= 0n && decoded <= U64_MAX, `${label}: u64 range`);
  return decoded;
};

invariant(schema.schema === "trnm.poco-bft.business-semantics.v0", "schema id drift");
invariant(schema.schema_version === 0, "schema version drift");
invariant(schema.status === "B2-H3b2b0-pure-semantic-kernel", "schema status drift");
invariant(
  schema.authority_boundary.output_authority ===
    "pure validation result only; no candidate, handoff, activation, or epoch-transition capability",
  "pure-kernel output boundary drift",
);
for (const nonClaim of [
  "external funded-and-unused settlement ledger authority",
  "measurement, evidence, or challenge-decision provenance",
  "governance approval authority",
  "validator key-rotation history or an authenticated previous registration nonce",
  "runtime, checkpoint, candidate-selection, handoff, activation, or Core epoch-transition authority",
]) {
  invariant(
    schema.authority_boundary.does_not_establish.includes(nonClaim),
    `missing authority non-claim: ${nonClaim}`,
  );
}
sameJson(
  schema.wire_compatibility.kind_3_payload_u64,
  {
    canonical_name: "max_accepted_nonce",
    former_diagnostic_name: "next_nonce",
    wire_change: false,
    encoding: "u64 big-endian",
  },
  "kind-3 nonce wire compatibility drift",
);

const snapshotKind3 = snapshotSchema.kinds.find((kind) => kind.id === 3);
invariant(snapshotKind3 !== undefined, "snapshot kind 3 missing");
sameJson(
  snapshotKind3.payload.fields.map((field) => field.name),
  ["consumer_id", "consumer_key_id", "provider_id", "max_accepted_nonce"],
  "snapshot kind-3 semantic field-name drift",
);
invariant(
  !JSON.stringify(snapshotKind3).includes("next_nonce"),
  "snapshot schema retains ambiguous next_nonce name",
);

const expectedEnums = {
  settlement_state: [[1, "finalized_funded_unused"], [2, "consumed"], [3, "released"]],
  measurement_state: [[1, "not_required"], [2, "verified"], [3, "rejected"]],
  relationship_class: [[1, "independent"], [2, "related"], [3, "reciprocal"], [4, "unresolved"]],
  registration_state: [[1, "active"], [2, "revoked"]],
  bond_state: [[1, "active_slashable"], [2, "unbonding"]],
  jail_reason: [[1, "double_vote"], [2, "downtime"], [3, "governance"]],
  lifecycle_state: [[1, "accepted"], [2, "revoked"], [3, "challenge_pending"], [4, "challenge_rejected"], [5, "challenge_sustained"]],
  rollout_phase: [[0, "shadow"], [1, "eligibility_only"], [2, "capped_weight"], [3, "full"]],
  approval_state: [[0, "proposed"], [1, "approved"]],
};
sameJson(Object.keys(schema.enum_tables), Object.keys(expectedEnums), "enum table order/name drift");
for (const [name, expected] of Object.entries(expectedEnums)) {
  const table = schema.enum_tables[name];
  invariant(table.wire_type === "u8" && table.unknown === "reject", `${name}: enum policy drift`);
  sameJson(
    table.values.map(({ value, meaning }) => [value, meaning]),
    expected,
    `${name}: enum meanings drift`,
  );
}
sameJson(
  schema.enum_tables.lifecycle_state.values.map(({ value, terminal }) => [value, terminal]),
  [[1, false], [2, true], [3, false], [4, true], [5, true]],
  "lifecycle terminal flags drift",
);

unique(
  vector.enum_cases.map((entry) => `${entry.enum}:${entry.value}`),
  "duplicate enum vector case",
);
let enumValid = 0;
let enumUnknown = 0;
for (const test of vector.enum_cases) {
  const expected = expectedEnums[test.enum];
  invariant(expected !== undefined, `unknown enum campaign ${test.enum}`);
  const match = expected.find(([value]) => value === test.value);
  if (test.expected === "accept") {
    invariant(match !== undefined && test.name === match[1], `${test.enum}:${test.value} accepted incorrectly`);
    enumValid += 1;
  } else {
    invariant(test.expected === "reject", `${test.enum}:${test.value} invalid expectation`);
    invariant(match === undefined && test.name === null, `${test.enum}:${test.value} unknown accepted`);
    enumUnknown += 1;
  }
}
for (const [name, expected] of Object.entries(expectedEnums)) {
  for (const [value, meaning] of expected) {
    invariant(
      vector.enum_cases.some(
        (test) => test.enum === name && test.value === value && test.name === meaning && test.expected === "accept",
      ),
      `${name}:${value} missing positive vector`,
    );
  }
  invariant(
    vector.enum_cases.some((test) => test.enum === name && test.expected === "reject"),
    `${name}: missing unknown vector`,
  );
}

const expectedGraphs = {
  settlement_state: { kind: 6, values: [1, 2, 3], edges: [[1, 2], [1, 3]], terminal: [2, 3] },
  registration_state: { kind: 9, values: [1, 2], edges: [[1, 2]], terminal: [2] },
  lifecycle_state: { kind: 12, values: [1, 2, 3, 4, 5], edges: [[1, 2], [1, 3], [3, 4], [3, 5]], terminal: [2, 4, 5] },
  approval_state: { kind: 15, values: [0, 1], edges: [[0, 1]], terminal: [1] },
};
for (const [name, expected] of Object.entries(expectedGraphs)) {
  sameJson(schema.transition_graphs[name].allowed_edges, expected.edges, `${name}: graph drift`);
  sameJson(schema.transition_graphs[name].terminal_values, expected.terminal, `${name}: terminal drift`);
}
unique(
  vector.transition_cases.map((entry) => `${entry.field}:${entry.from}:${entry.to}`),
  "duplicate transition vector case",
);
let transitionAllowed = 0;
let transitionRejected = 0;
for (const [field, graph] of Object.entries(expectedGraphs)) {
  for (const from of graph.values) {
    for (const to of graph.values) {
      const test = vector.transition_cases.find(
        (entry) => entry.field === field && entry.from === from && entry.to === to,
      );
      invariant(test !== undefined, `${field}:${from}->${to} missing`);
      invariant(test.kind === graph.kind, `${field}:${from}->${to} kind drift`);
      const allowed = graph.edges.some(([left, right]) => left === from && right === to);
      invariant(test.expected === (allowed ? "accept" : "reject"), `${field}:${from}->${to} expectation drift`);
      if (allowed) transitionAllowed += 1;
      else transitionRejected += 1;
    }
  }
}
invariant(
  transitionAllowed + transitionRejected === vector.transition_cases.length,
  "transition vector contains an out-of-domain case",
);

const blockRules = new Map(
  schema.clock_contract.block_height.rules.map((rule) => [rule.id, rule]),
);
const epochRules = new Map(
  schema.clock_contract.target_epoch.rules.map((rule) => [rule.id, rule]),
);
sameJson(
  [...blockRules.keys()],
  [
    "certificate_billing_window",
    "certificate_acceptance",
    "consumer_key_active",
    "meter_active",
    "settlement_finalized",
    "measurement_created",
    "relationship_unexpired",
    "lifecycle_effective",
    "rollout_activation",
  ],
  "block-height rule set drift",
);
sameJson([...epochRules.keys()], ["bond_unlocked", "jail_expired"], "target-epoch rule set drift");

const clockPredicate = (test) => {
  const value = asU64(test.value, `${test.rule}.value`);
  const boundary = Object.fromEntries(
    Object.entries(test.boundary).map(([name, raw]) => [
      name,
      raw === null ? null : asU64(raw, `${test.rule}.${name}`),
    ]),
  );
  switch (test.rule) {
    case "certificate_billing_window":
      return value >= boundary.billing_start_height && value <= boundary.billing_end_height;
    case "certificate_acceptance":
      return boundary.billing_end_height < boundary.accepted_height && value >= boundary.accepted_height;
    case "consumer_key_active":
      return value >= boundary.active_from &&
        (boundary.revoked_at === null || value < boundary.revoked_at);
    case "meter_active":
      return value >= boundary.active_from &&
        (boundary.retired_at === null || value < boundary.retired_at);
    case "settlement_finalized":
      return value >= boundary.finalized_height;
    case "measurement_created":
      return value >= boundary.authenticated_creation_height;
    case "relationship_unexpired":
      return value < boundary.expires_at;
    case "lifecycle_effective":
      return value >= boundary.effective_height;
    case "rollout_activation":
      return value >= boundary.activation_height;
    case "bond_unlocked":
      return value >= boundary.locked_until;
    case "jail_expired":
      return value >= boundary.jailed_until;
    default:
      throw new Error(`unknown clock rule ${test.rule}`);
  }
};
unique(
  vector.clock_cases.map((entry) => `${entry.clock}:${entry.rule}:${entry.value}`),
  "duplicate clock vector case",
);
let blockHeightCases = 0;
let targetEpochCases = 0;
for (const test of vector.clock_cases) {
  if (test.clock === "block_height") {
    invariant(blockRules.has(test.rule), `${test.rule}: absent block rule`);
    blockHeightCases += 1;
  } else {
    invariant(test.clock === "target_epoch" && epochRules.has(test.rule), `${test.rule}: absent epoch rule`);
    targetEpochCases += 1;
  }
  invariant(clockPredicate(test) === test.expected, `${test.rule}@${test.value}: boundary drift`);
}
for (const rule of [...blockRules.keys(), ...epochRules.keys()]) {
  const cases = vector.clock_cases.filter((test) => test.rule === rule);
  invariant(cases.length >= 3, `${rule}: boundary-1/equal/+1 campaign missing`);
  invariant(cases.some((test) => test.expected), `${rule}: no positive boundary witness`);
  invariant(cases.some((test) => !test.expected), `${rule}: no negative boundary witness`);
}

invariant(schema.nonce_watermark.kind === 3, "nonce kind drift");
invariant(schema.nonce_watermark.field === "max_accepted_nonce", "nonce field drift");
invariant(schema.nonce_watermark.skip_values === "allowed", "nonce skip policy drift");
invariant(schema.nonce_watermark.delete === "reject", "nonce deletion policy drift");
unique(vector.nonce_cases.map((entry) => entry.id), "duplicate nonce case id");
let nonceAllowed = 0;
let nonceRejected = 0;
for (const test of vector.nonce_cases) {
  const candidate = asU64(test.candidate, `${test.id}.candidate`);
  const previous = test.previous === null ? null : asU64(test.previous, `${test.id}.previous`);
  const allowed = previous === null || candidate > previous;
  invariant(test.expected === (allowed ? "accept" : "reject"), `${test.id}: nonce expectation drift`);
  if (allowed) {
    invariant(test.result === test.candidate, `${test.id}: nonce result must be candidate`);
    invariant(test.exhausted === (candidate === U64_MAX), `${test.id}: exhaustion drift`);
    nonceAllowed += 1;
  } else {
    invariant(test.result === undefined && test.exhausted === undefined, `${test.id}: rejected nonce has output`);
    nonceRejected += 1;
  }
}

invariant(
  schema.mutation_contract.revision ===
    "create requires revision 1; update requires checked expected_revision + 1; expected revision u64::MAX is exhausted and cannot update",
  "revision policy drift",
);
unique(vector.revision_cases.map((entry) => entry.id), "duplicate revision case id");
let revisionAllowed = 0;
let revisionRejected = 0;
for (const test of vector.revision_cases) {
  const next = test.next_revision === null ? null : asU64(test.next_revision, `${test.id}.next`);
  let allowed;
  if (test.operation === "create") {
    invariant(test.expected_revision === null, `${test.id}: create has expected revision`);
    allowed = next === 1n;
  } else {
    invariant(test.operation === "update", `${test.id}: unknown revision operation`);
    const previous = asU64(test.expected_revision, `${test.id}.expected`);
    allowed = previous < U64_MAX && next === previous + 1n;
  }
  invariant(test.expected === (allowed ? "accept" : "reject"), `${test.id}: revision expectation drift`);
  if (allowed) revisionAllowed += 1;
  else revisionRejected += 1;
}

const initialCreatePredicate = (test) => {
  switch (test.kind) {
    case 2:
      invariant(test.field === "revoked_at", `${test.id}: key create field drift`);
      return test.value === null;
    case 5:
      invariant(test.field === "retired_at", `${test.id}: meter create field drift`);
      return test.value === null;
    case 6:
      invariant(test.field === "state", `${test.id}: settlement create field drift`);
      return test.value === 1;
    case 9:
      invariant(test.field === "state", `${test.id}: registration create field drift`);
      return test.value === 1;
    case 12:
      invariant(test.field === "state", `${test.id}: lifecycle create field drift`);
      return test.value === 1;
    case 15:
      invariant(test.field === "approved", `${test.id}: rollout create field drift`);
      return test.value === 0;
    default:
      throw new Error(`${test.id}: unexpected constrained create kind`);
  }
};
unique(vector.create_cases.map((entry) => entry.id), "duplicate create case id");
unique(
  vector.create_cases.map((entry) => `${entry.kind}:${entry.value === null ? "null" : entry.value}`),
  "duplicate create kind/value case",
);
let createAllowed = 0;
let createRejected = 0;
for (const test of vector.create_cases) {
  const allowed = initialCreatePredicate(test);
  invariant(test.expected === (allowed ? "accept" : "reject"), `${test.id}: create expectation drift`);
  if (allowed) createAllowed += 1;
  else createRejected += 1;
}
sameJson(
  [...new Set(vector.create_cases.map((entry) => entry.kind))],
  [2, 5, 6, 9, 12, 15],
  "constrained create kind coverage drift",
);
for (const [kind, expectedValues] of [
  [2, [null, "20"]],
  [5, [null, "40"]],
  [6, [1, 2, 3]],
  [9, [1, 2]],
  [12, [1, 2, 3, 4, 5]],
  [15, [0, 1]],
]) {
  sameJson(
    vector.create_cases.filter((entry) => entry.kind === kind).map((entry) => entry.value),
    expectedValues,
    `kind ${kind}: incomplete initial-create campaign`,
  );
}

const edgeAllowed = (field, from, to) =>
  expectedGraphs[field].edges.some(([left, right]) => left === from && right === to);
const immutabilityPredicate = (test) => {
  switch (test.record) {
    case "consumer_key": {
      const activeFrom = asU64(test.active_from, `${test.id}.active_from`);
      const after = test.revoked_after === null ? null : asU64(test.revoked_after, `${test.id}.revoked_after`);
      return (
        test.public_key_equal &&
        test.active_from_equal &&
        test.revoked_before === null &&
        after !== null &&
        after > activeFrom
      );
    }
    case "meter": {
      const activeFrom = asU64(test.active_from, `${test.id}.active_from`);
      const after = test.retired_after === null ? null : asU64(test.retired_after, `${test.id}.retired_after`);
      return (
        test.unit_scale_equal &&
        test.active_from_equal &&
        test.retired_before === null &&
        after !== null &&
        after > activeFrom
      );
    }
    case "settlement":
      return (
        test.commitment_equal &&
        test.finalized_height_equal &&
        edgeAllowed("settlement_state", test.state_before, test.state_after)
      );
    case "registration":
      return (
        test.key_equal &&
        test.nonce_equal &&
        test.pop_equal &&
        edgeAllowed("registration_state", test.state_before, test.state_after)
      );
    case "lifecycle":
      return (
        asU64(test.effective_after, `${test.id}.effective_after`) >
          asU64(test.effective_before, `${test.id}.effective_before`) &&
        edgeAllowed("lifecycle_state", test.state_before, test.state_after)
      );
    case "rollout":
      return (
        test.target_epoch_equal &&
        test.phase_equal &&
        test.parameters_hash_equal &&
        test.activation_height_equal &&
        edgeAllowed("approval_state", test.approval_before, test.approval_after)
      );
    default:
      throw new Error(`${test.id}: unknown immutability record`);
  }
};
unique(vector.immutability_campaign.map((entry) => entry.id), "duplicate immutability case id");
let immutabilityAllowed = 0;
let immutabilityRejected = 0;
for (const test of vector.immutability_campaign) {
  const allowed = immutabilityPredicate(test);
  invariant(test.expected === (allowed ? "accept" : "reject"), `${test.id}: immutability drift`);
  if (allowed) immutabilityAllowed += 1;
  else immutabilityRejected += 1;
}

const rules = schema.mutation_contract.record_rules;
invariant(rules.length === 15, "mutation rule count drift");
sameJson(rules.map((rule) => rule.kind), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], "mutation kind coverage drift");
invariant(rules.every((rule) => rule.create === true), "a kind is not create-admissible");
invariant(rules.every((rule) => rule.delete === "reject"), "a kind permits deletion");
sameJson(
  rules.map((rule) => rule.initial_create),
  [
    "exact_decoder_only",
    "revoked_at is None",
    "exact_decoder_only",
    "exact_decoder_only",
    "retired_at is None",
    "state equals 1 finalized_funded_unused",
    "exact_decoder_only",
    "exact_decoder_only",
    "state equals 1 active",
    "exact_decoder_only",
    "exact_decoder_only",
    "state equals 1 accepted",
    "exact_decoder_only",
    "exact_decoder_only",
    "approved equals 0 proposed",
  ],
  "initial-create rule drift",
);
invariant(
  rules.find((rule) => rule.kind === 12).update ===
    "effective_height is a declared block height and strictly increases; equality with the authenticated transition target_height is not established by H3b2b0; state follows lifecycle_state graph",
  "lifecycle effective-height authority boundary drift",
);
invariant(
  rules.find((rule) => rule.kind === 15).update ===
    "target_epoch identity, phase, parameters_hash, and activation_height immutable; approval follows approval_state graph",
  "rollout target-epoch immutability drift",
);
sameJson(
  vector.create_only_update_rejections,
  rules.filter((rule) => rule.update === "reject_create_only").map((rule) => rule.kind),
  "create-only update vector drift",
);
sameJson(
  vector.delete_policy,
  { operation: "delete", expected: "reject", all_kinds: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] },
  "delete policy vector drift",
);

const blockerIds = schema.external_authority_blockers.map((blocker) => blocker.id);
sameJson(blockerIds, vector.required_blockers, "authority blocker set drift");
for (const blocker of schema.external_authority_blockers) {
  invariant(blocker.affected_kinds.length > 0, `${blocker.id}: no affected kind`);
  invariant(blocker.missing.length > 0, `${blocker.id}: no missing authority named`);
}
const blockers = Object.fromEntries(schema.external_authority_blockers.map((blocker) => [blocker.id, blocker]));
for (const required of [
  ["meter_authority", "task/output binding"],
  ["settlement_authority", "funded-and-unused ledger proof"],
  ["challenge_authority", "decision id"],
  ["lifecycle_target_height_binding", "same-operation equality between declared effective_height and authenticated transition target_height"],
  ["governance_authority", "governance decision id"],
  ["validator_rotation_history", "authenticated previous registration nonce"],
  ["retention_bound", "safe pruning accumulator beyond the global 10000-entry bound"],
]) {
  invariant(blockers[required[0]].missing.includes(required[1]), `${required[0]} blocker drift`);
}

sameJson(
  vector.expected_counts,
  {
    enum_valid: enumValid,
    enum_unknown: enumUnknown,
    transition_pairs: transitionAllowed + transitionRejected,
    transition_allowed: transitionAllowed,
    transition_rejected: transitionRejected,
    block_height_cases: blockHeightCases,
    target_epoch_cases: targetEpochCases,
    nonce_cases: vector.nonce_cases.length,
    nonce_allowed: nonceAllowed,
    nonce_rejected: nonceRejected,
    revision_cases: vector.revision_cases.length,
    revision_allowed: revisionAllowed,
    revision_rejected: revisionRejected,
    create_cases: vector.create_cases.length,
    create_allowed: createAllowed,
    create_rejected: createRejected,
    immutability_cases: vector.immutability_campaign.length,
    immutability_allowed: immutabilityAllowed,
    immutability_rejected: immutabilityRejected,
    create_only_update_rejected: vector.create_only_update_rejections.length,
    delete_rejected: vector.delete_policy.all_kinds.length,
  },
  "campaign statistics drift",
);

console.log(
  `business semantics gate passed (${enumValid} enum values, ${enumUnknown} enum unknowns, ` +
    `${transitionAllowed + transitionRejected} exhaustive state edges, ` +
    `${blockHeightCases + targetEpochCases} clock boundaries, ${vector.nonce_cases.length} nonce cases, ` +
    `${vector.revision_cases.length} revision boundaries, ` +
    `${vector.create_cases.length} initial-create cases, ${vector.immutability_campaign.length} immutability cases, ` +
    `${vector.delete_policy.all_kinds.length} delete rejections)`,
);
