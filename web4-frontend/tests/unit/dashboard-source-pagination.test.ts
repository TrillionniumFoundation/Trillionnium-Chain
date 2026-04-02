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

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(
      snapshot.events.filter((event) => event.summary === "capability-registry · capability.granted"),
    ).toHaveLength(2);
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
});
