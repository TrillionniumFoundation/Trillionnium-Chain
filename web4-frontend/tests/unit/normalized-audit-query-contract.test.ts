import { describe, expect, it } from "vitest";

import {
  buildNormalizedAuditEventsQueryParams,
  NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS,
} from "../../lib/api-contract/client";
import { normalizedAuditEventsQuerySchema } from "../../lib/api-contract/schemas";
import type { NormalizedAuditEventsQuery } from "../../lib/api-contract/types";

const SERIALIZATION_FIXTURES: {
  [K in keyof typeof NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS]: NonNullable<NormalizedAuditEventsQuery[K]>;
} = {
  source: "governance-guard",
  eventType: "governance.proposal_executed",
  limit: 25,
  cursor: "cursor-1",
};

describe("normalized audit query contract", () => {
  it("freezes the schema key set to the expected day-1 query keys", () => {
    const schemaKeys = normalizedAuditEventsQuerySchema.keyof().options.slice().sort();
    const paramKeys = Object.keys(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS).sort();
    const wireKeys = Object.values(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS).sort();

    expect(schemaKeys).toEqual(paramKeys);
    expect(wireKeys).toEqual(["cursor", "eventType", "limit", "source"]);
    expect(new Set(wireKeys).size).toBe(wireKeys.length);
  });

  it("serializes every schema-approved query key through the drift-guard helper", () => {
    const keys = Object.keys(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS) as Array<
      keyof typeof NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS
    >;

    for (const key of keys) {
      const params = buildNormalizedAuditEventsQueryParams({
        [key]: SERIALIZATION_FIXTURES[key],
      } as Pick<NormalizedAuditEventsQuery, typeof key>);

      const wireKey = NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS[key];
      expect(params.get(wireKey)).toBe(String(SERIALIZATION_FIXTURES[key]));
      expect(Array.from(params.keys())).toEqual([wireKey]);
    }
  });

  it("rejects unknown query fields before request construction", () => {
    expect(() =>
      normalizedAuditEventsQuerySchema.parse({
        cursor: "cursor-1",
        limit: 10,
        unexpected: "nope",
      }),
    ).toThrow();
  });

  it("rejects invalid cursor values fail-closed", () => {
    expect(() =>
      normalizedAuditEventsQuerySchema.parse({
        cursor: "",
      }),
    ).toThrow();
  });

  it("rejects invalid limit values fail-closed", () => {
    expect(() =>
      normalizedAuditEventsQuerySchema.parse({
        limit: 0,
      }),
    ).toThrow();

    expect(() =>
      normalizedAuditEventsQuerySchema.parse({
        limit: -1,
      }),
    ).toThrow();

    expect(() =>
      normalizedAuditEventsQuerySchema.parse({
        limit: 1.5,
      }),
    ).toThrow();
  });

  it("omits absent optional fields from the serialized query string", () => {
    const params = buildNormalizedAuditEventsQueryParams({
      cursor: "cursor-1",
      limit: 25,
    });

    expect(params.get("cursor")).toBe("cursor-1");
    expect(params.get("limit")).toBe("25");
    expect(params.has("source")).toBe(false);
    expect(params.has("eventType")).toBe(false);
    expect(params.toString()).not.toContain("source=");
    expect(params.toString()).not.toContain("eventType=");
  });

  it("serializes the currently supported scalar query keys with stable names", () => {
    const params = buildNormalizedAuditEventsQueryParams({
      source: "governance-guard",
      eventType: "governance.proposal_executed",
      cursor: "cursor-2",
      limit: 50,
    });

    expect(params.get("source")).toBe("governance-guard");
    expect(params.get("eventType")).toBe("governance.proposal_executed");
    expect(params.get("cursor")).toBe("cursor-2");
    expect(params.get("limit")).toBe("50");
  });
});
