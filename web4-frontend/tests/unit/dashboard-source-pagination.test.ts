import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchDashboardSnapshot } from "@/lib/dashboard/source";
import * as apiContractClient from "@/lib/api-contract/client";

describe("dashboard source normalized audit pagination", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses env-configured pagination limits for normalized audit events", async () => {
    const previousLimit = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
    const previousPages = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = "2";
    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = "1";

    try {
      const mockClient = {
        queryTask: vi
          .fn()
          .mockResolvedValue({
            task: {
              id: "342",
              owner: "ops",
              status: "running",
              createdAt: "2026-03-01T00:00:00.000Z",
              metadata: {},
            },
          }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "342",
          events: [],
        }),
        queryCapabilityAudit: vi.fn().mockResolvedValue({
          subject: "did:trnm:test",
          audits: [
            {
              subject: "did:trnm:test",
              capability: "AUDIT_READ",
              granted: true,
              checkedAt: "2026-03-01T00:00:00.000Z",
            },
          ],
        }),
        queryNormalizedAuditEvents: vi
          .fn()
          .mockResolvedValueOnce({
            events: [
              {
                source: "settlement-vault",
                event_type: "vault.deposited",
                actor: "alice",
                object_id: "alice",
                timestamp: "2026-03-01T00:03:00.000Z",
                reason: "ok",
              },
            ],
            hasMore: true,
            nextCursor: "cursor-1",
          }),
      } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

      vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

      const snapshot = await fetchDashboardSnapshot();

      expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
      expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledWith({
        limit: 2,
      });
      expect(
        snapshot.events.find((event) => event.summary === "settlement-vault · vault.deposited"),
      ).toBeDefined();
    } finally {
      if (previousLimit === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = previousLimit;
      }

      if (previousPages === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = previousPages;
      }
    }
  });

  it("falls back to defaults when env values are invalid", async () => {
    const previousLimit = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
    const previousPages = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = "bad";
    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = "-1";

    try {
      const mockClient = {
        queryTask: vi
          .fn()
          .mockResolvedValue({
            task: {
              id: "343",
              owner: "ops",
              status: "running",
              createdAt: "2026-03-01T00:00:00.000Z",
              metadata: {},
            },
          }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "343",
          events: [],
        }),
        queryCapabilityAudit: vi.fn().mockResolvedValue({
          subject: "did:trnm:test",
          audits: [
            {
              subject: "did:trnm:test",
              capability: "AUDIT_READ",
              granted: true,
              checkedAt: "2026-03-01T00:00:00.000Z",
            },
          ],
        }),
        queryNormalizedAuditEvents: vi
          .fn()
          .mockResolvedValue({
            events: [],
            hasMore: false,
          }),
      } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

      vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

      const snapshot = await fetchDashboardSnapshot();

      expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledWith({
        limit: 60,
      });
      expect(snapshot.events).toBeDefined();
    } finally {
      if (previousLimit === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = previousLimit;
      }

      if (previousPages === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = previousPages;
      }
    }
  });

  it("loads multiple normalized audit pages and merges into dashboard events", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "341",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi
        .fn()
        .mockResolvedValueOnce({
          events: [
            {
              source: "governance-guard",
              event_type: "governance.proposal_executed",
              actor: "alice",
              object_id: "pp-1",
              timestamp: "2026-03-01T00:01:00.000Z",
              reason: "param",
              note: "drift_mismatch",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-1",
        })
        .mockResolvedValueOnce({
          events: [
            {
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator",
              object_id: "proof-2",
              timestamp: "2026-03-01T00:02:00.000Z",
              reason: "error_critical",
              note: "proof signature invalid",
            },
          ],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(2);
    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenNthCalledWith(1, {
      limit: 60,
    });
    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenNthCalledWith(2, {
      limit: 60,
      cursor: "cursor-1",
    });

    expect(
      snapshot.events.find((event) => event.summary === "governance-guard · governance.proposal_executed"),
    ).toBeDefined();
    expect(
      snapshot.events.find((event) => event.summary === "bridge-relay · bridge_relay.proof_submitted"),
    ).toBeDefined();
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("1");
  });

  it("fails closed when normalized audit pagination repeats the same cursor", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "345",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "345",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi
        .fn()
        .mockResolvedValueOnce({
          events: [
            {
              source: "capability-registry",
              event_type: "capability.granted",
              actor: "security",
              object_id: "did:trnm:alice",
              timestamp: "2026-03-01T00:01:00.000Z",
              reason: "ok",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-loop",
        })
        .mockResolvedValueOnce({
          events: [
            {
              source: "capability-registry",
              event_type: "capability.granted",
              actor: "security",
              object_id: "did:trnm:alice",
              timestamp: "2026-03-01T00:01:00.000Z",
              reason: "ok",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-loop",
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(2);
    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenNthCalledWith(1, {
      limit: 60,
    });
    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenNthCalledWith(2, {
      limit: 60,
      cursor: "cursor-loop",
    });
    expect(
      snapshot.events.filter((event) => event.summary === "capability-registry · capability.granted"),
    ).toHaveLength(1);
  });

  it("keeps normalized capability audit events distinct across subjects during pagination dedupe", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "346",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "346",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.granted",
            actor: "security",
            subject: "did:trnm:alice",
            timestamp: "2026-03-01T00:01:00.000Z",
            reason: "ok",
          },
          {
            source: "capability-registry",
            event_type: "capability.granted",
            actor: "security",
            subject: "did:trnm:bob",
            timestamp: "2026-03-01T00:01:00.000Z",
            reason: "ok",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const capabilityGrantedEvents = snapshot.events.filter(
      (event) => event.summary === "capability-registry · capability.granted",
    );

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(capabilityGrantedEvents).toHaveLength(2);
    expect(new Set(capabilityGrantedEvents.map((event) => event.id)).size).toBe(2);
    expect(capabilityGrantedEvents[0]?.details).toContain("did:trnm:");
    expect(capabilityGrantedEvents[1]?.details).toContain("did:trnm:");
  });

  it("keeps normalized audit events distinct when only related_id differs", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "348",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "348",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.bound",
            actor: "security",
            object_id: "did:trnm:alice",
            related_id: "scope:audit.read",
            timestamp: "2026-03-01T00:01:00.000Z",
            reason: "ok",
          },
          {
            source: "capability-registry",
            event_type: "capability.bound",
            actor: "security",
            object_id: "did:trnm:alice",
            related_id: "scope:audit.write",
            timestamp: "2026-03-01T00:01:00.000Z",
            reason: "ok",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const capabilityBoundEvents = snapshot.events.filter(
      (event) => event.summary === "capability-registry · capability.bound",
    );

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(capabilityBoundEvents).toHaveLength(2);
    expect(new Set(capabilityBoundEvents.map((event) => event.id)).size).toBe(2);
    expect(capabilityBoundEvents[0]?.details).toContain("scope:audit.");
    expect(capabilityBoundEvents[1]?.details).toContain("scope:audit.");
  });

  it("keeps normalized audit events distinct when only amount differs", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "350",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "350",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "settlement-vault",
            event_type: "vault.balance_adjusted",
            actor: "security",
            object_id: "vault:treasury",
            timestamp: "2026-03-01T00:01:00.000Z",
            amount: "10",
            reason: "ok",
          },
          {
            source: "settlement-vault",
            event_type: "vault.balance_adjusted",
            actor: "security",
            object_id: "vault:treasury",
            timestamp: "2026-03-01T00:01:00.000Z",
            amount: "20",
            reason: "ok",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const balanceAdjustedEvents = snapshot.events.filter(
      (event) => event.summary === "settlement-vault · vault.balance_adjusted",
    );

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(balanceAdjustedEvents).toHaveLength(2);
    expect(balanceAdjustedEvents[0]?.details).toContain('"amount":"10"');
    expect(balanceAdjustedEvents[1]?.details).toContain('"amount":"20"');
  });

  it("treats revocation-like normalized audit events as critical fail-closed incidents", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.revoked",
            actor: "security",
            object_id: "did:trnm:alice",
            timestamp: "2026-03-01T00:03:00.000Z",
            reason: "token_revoked",
            note: "readonly access denied after unauthorized reuse",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(
      snapshot.events.find((event) => event.summary === "capability-registry · capability.revoked")
        ?.severity,
    ).toBe("Critical");
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("1");
  });

  it("treats expiration-like normalized capability audit events as critical fail-closed incidents", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "347",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "347",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.expired",
            actor: "security",
            object_id: "did:trnm:alice",
            timestamp: "2026-03-01T00:04:00.000Z",
            reason: "capability_expired",
            note: "readonly access suspended pending renewal",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(
      snapshot.events.find((event) => event.summary === "capability-registry · capability.expired")
        ?.severity,
    ).toBe("Critical");
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("1");
  });

  it("treats revocation/expiration noun forms as critical fail-closed incidents", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "349",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "349",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.revocation_recorded",
            actor: "security",
            object_id: "did:trnm:alice",
            timestamp: "2026-03-01T00:05:00.000Z",
            reason: "policy_revocation",
            note: "manual revocation review logged",
          },
          {
            source: "capability-registry",
            event_type: "capability.expiration_review",
            actor: "security",
            object_id: "did:trnm:bob",
            timestamp: "2026-03-01T00:06:00.000Z",
            reason: "capability_expiration",
            note: "expiration follow-up queued",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(
      snapshot.events.find((event) => event.summary === "capability-registry · capability.revocation_recorded")
        ?.severity,
    ).toBe("Critical");
    expect(
      snapshot.events.find((event) => event.summary === "capability-registry · capability.expiration_review")
        ?.severity,
    ).toBe("Critical");
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("2");
  });

  it("treats disabled capability audit events as critical fail-closed incidents", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "351",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "351",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "2026-03-01T00:00:00.000Z",
          },
        ],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "capability-registry",
            event_type: "capability.disabled",
            actor: "security",
            object_id: "did:trnm:alice",
            timestamp: "2026-03-01T00:07:00.000Z",
            reason: "capability_disabled",
            note: "readonly access disabled pending compliance review",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(
      snapshot.events.find((event) => event.summary === "capability-registry · capability.disabled")
        ?.severity,
    ).toBe("Critical");
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("1");
  });
});
