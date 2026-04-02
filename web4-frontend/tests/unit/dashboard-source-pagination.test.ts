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

  it("stops normalized audit pagination at the configured max pages even when hasMore stays true", async () => {
    const previousPages = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = "2";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
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
                source: "governance-guard",
                event_type: "governance.proposal_created",
                actor: "alice",
                object_id: "pp-2",
                timestamp: "2026-03-01T00:01:00.000Z",
              },
            ],
            hasMore: true,
            nextCursor: " cursor-1 ",
          })
          .mockResolvedValueOnce({
            events: [
              {
                source: "bridge-relay",
                event_type: "bridge_relay.proof_submitted",
                actor: "validator",
                object_id: "proof-3",
                timestamp: "2026-03-01T00:02:00.000Z",
                reason: "warn",
              },
            ],
            hasMore: true,
            nextCursor: "cursor-2",
          })
          .mockResolvedValueOnce({
            events: [
              {
                source: "settlement-vault",
                event_type: "vault.withdrawal_requested",
                actor: "bob",
                object_id: "withdrawal-1",
                timestamp: "2026-03-01T00:03:00.000Z",
                reason: "error",
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
        snapshot.events.find((event) => event.summary === "settlement-vault · vault.withdrawal_requested"),
      ).toBeUndefined();
    } finally {
      if (previousPages === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = previousPages;
      }
    }
  });

  it("stops normalized audit pagination when hasMore stays true but nextCursor normalizes to empty", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator",
            object_id: "proof-4",
            timestamp: "2026-03-01T00:04:00.000Z",
            note: "cursor missing",
          },
        ],
        hasMore: true,
        nextCursor: "   ",
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledWith({
      limit: 60,
    });
    expect(
      snapshot.events.find((event) => event.summary === "bridge-relay · bridge_relay.proof_submitted"),
    ).toBeDefined();
  });

  it("stops normalized audit pagination when nextCursor only contains BOM/zero-width noise", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "346b",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "346b",
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator",
            object_id: "proof-4b",
            timestamp: "2026-03-01T00:04:30.000Z",
            note: "cursor hidden noise",
          },
        ],
        hasMore: true,
        nextCursor: "\uFEFF \u200B\u200D ",
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(
      snapshot.events.find((event) => event.summary === "bridge-relay · bridge_relay.proof_submitted"),
    ).toBeDefined();
  });

  it("fails closed on normalized audit pagination errors without dropping readonly task/event data", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: { region: "ap-east-1" },
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344",
        events: [
          {
            id: "evt-1",
            taskId: "344",
            type: "deploy.canary_started",
            level: "info",
            timestamp: "2026-03-01T00:05:00.000Z",
            payload: { rollout: "5%" },
          },
        ],
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
      queryNormalizedAuditEvents: vi.fn().mockRejectedValue(new Error("normalized audit timeout")),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(1);
    expect(snapshot.tasks).toHaveLength(1);
    expect(snapshot.tasks[0]?.id).toBe("344");
    expect(snapshot.events).toHaveLength(1);
    expect(snapshot.events[0]?.summary).toBe("deploy.canary_started");
    expect(snapshot.audits).toHaveLength(1);
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("0");
  });

  it("fails closed when a later normalized audit page errors after an earlier page succeeded", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "344b",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: { region: "ap-east-1" },
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344b",
        events: [
          {
            id: "evt-1",
            taskId: "344b",
            type: "deploy.canary_started",
            level: "info",
            timestamp: "2026-03-01T00:05:00.000Z",
            payload: { rollout: "5%" },
          },
        ],
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
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator",
              object_id: "proof-6",
              timestamp: "2026-03-01T00:04:00.000Z",
              reason: "error",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-2",
        })
        .mockRejectedValueOnce(new Error("normalized audit timeout page 2")),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledTimes(2);
    expect(snapshot.tasks).toHaveLength(1);
    expect(snapshot.tasks[0]?.id).toBe("344b");
    expect(snapshot.events).toHaveLength(1);
    expect(snapshot.events[0]?.summary).toBe("deploy.canary_started");
    expect(snapshot.events.find((event) => event.summary === "bridge-relay · bridge_relay.proof_submitted")).toBeUndefined();
    expect(snapshot.audits).toHaveLength(1);
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("0");
  });

  it("fails closed with mock fallback guidance when readonly task query fails", async () => {
    const mockClient = {
      queryTask: vi.fn().mockRejectedValue(new Error("task endpoint timeout")),
      queryEvents: vi.fn(),
      queryCapabilityAudit: vi.fn(),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    await expect(fetchDashboardSnapshot()).rejects.toThrow(
      "Readonly API unavailable (fail-closed): task endpoint timeout. Add ?mode=mock to switch to readonly snapshot fallback.",
    );
    expect(mockClient.queryTask).toHaveBeenCalledTimes(1);
  });

  it("falls back to '-' when readonly task timestamps are absent", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "347",
          owner: "ops",
          status: "running",
          metadata: { region: "ap-east-1" },
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
        events: [],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks).toHaveLength(1);
    expect(snapshot.tasks[0]?.updatedAt).toBe("-");
  });

  it("falls back to '-' when normalized audit events and task both lack timestamps", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "348",
          owner: "ops",
          status: "running",
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator",
            object_id: "proof-5",
            note: "timestamp omitted",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.events).toHaveLength(1);
    expect(snapshot.events[0]?.time).toBe("-");
    expect(snapshot.events[0]?.summary).toBe("bridge-relay · bridge_relay.proof_submitted");
  });

  it("fails closed when mock mode is requested in production", async () => {
    const createClientSpy = vi.spyOn(apiContractClient, "createFrontendApiClient");

    vi.stubEnv("NODE_ENV", "production");

    try {
      await expect(fetchDashboardSnapshot({ mode: "mock" })).rejects.toThrow(
        "Mock mode is disabled in production",
      );
      expect(createClientSpy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
