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
            hasMore: false,
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

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = "2abc";
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

  it("accepts pagination env values after trimming zero-width noise", async () => {
    const previousLimit = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
    const previousPages = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = "\u200B 2 \uFEFF";
    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = "\u200B 3 \uFEFF";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
          task: {
            id: "343-zero-width-env",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "343-zero-width-env",
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

      await fetchDashboardSnapshot();

      expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledWith({
        limit: 2,
      });
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

  it("falls back to default pagination limit when env is zero", async () => {
    const previousLimit = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;

    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = "0";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
          task: {
            id: "343b",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "343b",
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

      await fetchDashboardSnapshot();

      expect(mockClient.queryNormalizedAuditEvents).toHaveBeenCalledWith({
        limit: 60,
      });
    } finally {
      if (previousLimit === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT = previousLimit;
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

  it("keeps the readonly snapshot adaptable when task metadata or event payload are missing", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344",
        events: [
          {
            id: "EVT-344",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks[0]?.description).toBe("{}");
    expect(snapshot.events.find((event) => event.id === "EVT-344")?.details).toBe("{}");
  });

  it("preserves plain string metadata and payload values without adding JSON quotes", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344b",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: "manual note",
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344b",
        events: [
          {
            id: "EVT-344b",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: "human-readable payload",
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks[0]?.description).toBe("manual note");
    expect(snapshot.events.find((event) => event.id === "EVT-344b")?.details).toBe("human-readable payload");
  });

  it("trims whitespace and zero-width noise from plain string metadata and payload values", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344b-trimmed",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: " \u200Bmanual note\uFEFF  ",
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344b-trimmed",
        events: [
          {
            id: "EVT-344b-trimmed",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: "\n\u200Bhuman-readable payload\uFEFF\t",
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks[0]?.description).toBe("manual note");
    expect(snapshot.events.find((event) => event.id === "EVT-344b-trimmed")?.details).toBe("human-readable payload");
  });

  it("falls back when task metadata or event payload are blank strings", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344c",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: "   ",
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344c",
        events: [
          {
            id: "EVT-344c",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: "\n\t",
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks[0]?.description).toBe("{}");
    expect(snapshot.events.find((event) => event.id === "EVT-344c")?.details).toBe("{}");
  });

  it("normalizes blank readonly event types into stable dashboard fallbacks", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344e",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344e",
        events: [
          {
            id: "EVT-344e",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "   ",
            level: "warn",
            payload: {},
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const event = snapshot.events.find((item) => item.id === "EVT-344e");

    expect(event).toMatchObject({
      summary: "unknown-event",
      category: "Incident",
      severity: "Warning",
    });
  });

  it("falls back to a stable readonly event id when the query event id is blank", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344e-id",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344e-id",
        events: [
          {
            id: "   ",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
        .mockResolvedValue({
          events: [],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const event = snapshot.events.find((item) => item.summary === "deploy.completed");

    expect(event?.id).toBe("deploy.completed:2026-03-01T00:01:00.000Z:info");
  });

  it("falls back when task metadata, readonly payload, or normalized audit details are not JSON-serializable", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "344d",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: { counter: BigInt(7) },
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "344d",
        events: [
          {
            id: "EVT-344d",
            timestamp: "2026-03-01T00:01:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: { amount: BigInt(9) },
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
        .mockResolvedValue({
          events: [
            {
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator",
              object_id: "proof-9",
              timestamp: "2026-03-01T00:02:00.000Z",
              amount: BigInt(11),
            },
          ],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.tasks[0]?.description).toBe("{}");
    expect(snapshot.events.find((event) => event.id === "EVT-344d")?.details).toBe("{}");
    expect(snapshot.events.find((event) => event.id === "bridge-relay:proof-9")?.details).toBe("{}");
  });

  it("strips invisible cursor characters before loading the next normalized-audit page", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-cursor",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-cursor",
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
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator-a",
              object_id: "proof-341a",
              timestamp: "2026-03-01T00:02:00.000Z",
              reason: "warn",
            },
          ],
          hasMore: true,
          nextCursor: "\u200B cursor-zwsp \uFEFF",
        })
        .mockResolvedValueOnce({
          events: [
            {
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator-b",
              object_id: "proof-341b",
              timestamp: "2026-03-01T00:03:00.000Z",
              reason: "warn",
            },
          ],
          hasMore: false,
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(mockClient.queryNormalizedAuditEvents).toHaveBeenNthCalledWith(2, {
      limit: 60,
      cursor: "cursor-zwsp",
    });
    expect(snapshot.events.find((event) => event.id === "bridge-relay:proof-341b")).toBeDefined();
  });

  it("falls back to default ids when task/audit env values are blank", async () => {
    const previousTaskId = process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID;
    const previousAuditSubject = process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT;

    process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID = "   ";
    process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT = "\n";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
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
          subject: "did:trnm:core-rpc",
          audits: [
            {
              subject: "did:trnm:core-rpc",
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

      await fetchDashboardSnapshot();

      expect(mockClient.queryTask).toHaveBeenCalledWith("341");
      expect(mockClient.queryCapabilityAudit).toHaveBeenCalledWith("did:trnm:core-rpc");
    } finally {
      if (previousTaskId === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID = previousTaskId;
      }

      if (previousAuditSubject === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT = previousAuditSubject;
      }
    }
  });

  it("reads task/audit env overrides at fetch time instead of module load time", async () => {
    const previousTaskId = process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID;
    const previousAuditSubject = process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT;

    process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID = "777";
    process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT = "did:trnm:custom-dashboard";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
          task: {
            id: "777",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            metadata: {},
          },
        }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "777",
          events: [],
        }),
        queryCapabilityAudit: vi.fn().mockResolvedValue({
          subject: "did:trnm:custom-dashboard",
          audits: [
            {
              subject: "did:trnm:custom-dashboard",
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

      await fetchDashboardSnapshot();

      expect(mockClient.queryTask).toHaveBeenCalledWith("777");
      expect(mockClient.queryEvents).toHaveBeenCalledWith("777");
      expect(mockClient.queryCapabilityAudit).toHaveBeenCalledWith("did:trnm:custom-dashboard");
    } finally {
      if (previousTaskId === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID = previousTaskId;
      }

      if (previousAuditSubject === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT = previousAuditSubject;
      }
    }
  });

  it("falls back to createdAt when updatedAt is blank", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-ts",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "   ",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-ts",
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

    expect(snapshot.tasks[0]?.updatedAt).toBe("2026-03-01 08:00");
  });

  it("normalizes zero-width timestamp noise before choosing updatedAt", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-updated-at-noise",
          name: "noisy-updated-at",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "\u200B2026-03-01T00:05:00.000Z\uFEFF",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-updated-at-noise",
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

    expect(snapshot.tasks[0]?.updatedAt).toBe("2026-03-01 08:05");
  });

  it("normalizes zero-width timestamp noise before formatting readonly events and audits", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-display-time-noise",
          name: "display-time-noise",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "2026-03-01T00:05:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-display-time-noise",
        events: [
          {
            id: "EVT-341-display-time-noise",
            timestamp: "\u200B2026-03-01T00:04:00.000Z\uFEFF",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
            checkedAt: "\u200B2026-03-01T00:06:00.000Z\uFEFF",
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

    expect(snapshot.events.find((event) => event.id === "EVT-341-display-time-noise")?.time).toBe(
      "2026-03-01 08:04",
    );
    expect(snapshot.audits[0]?.reviewedAt).toBe("2026-03-01 08:06");
  });

  it("falls back to a stable owner label when task owner is blank", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-owner",
          owner: "   ",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "2026-03-01T00:05:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-owner",
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

    expect(snapshot.tasks[0]?.owner).toBe("Unassigned");
  });

  it("falls back to stable task title, audit control, and audit notes when API fields are blank", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-title",
          name: "   ",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "2026-03-01T00:05:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-title",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [
          {
            subject: "did:trnm:test",
            capability: "   ",
            granted: false,
            checkedAt: "2026-03-01T00:00:00.000Z",
            reason: "   ",
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

    expect(snapshot.tasks[0]?.title).toBe("task-341-title");
    expect(snapshot.audits[0]?.control).toBe("unknown-capability");
    expect(snapshot.audits[0]?.notes).toBe("No reason provided");
  });

  it("fails closed audit coverage when capability audit data is empty", async () => {
    const mockClient = {
      queryTask: vi.fn().mockResolvedValue({
        task: {
          id: "341-audit-empty",
          name: "audit-empty",
          owner: "ops",
          status: "running",
          createdAt: "2026-03-01T00:00:00.000Z",
          updatedAt: "2026-03-01T00:05:00.000Z",
          metadata: {},
        },
      }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "341-audit-empty",
        events: [],
      }),
      queryCapabilityAudit: vi.fn().mockResolvedValue({
        subject: "did:trnm:test",
        audits: [],
      }),
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const auditCoverage = snapshot.kpis.find((kpi) => kpi.label === "Audit Coverage");

    expect(auditCoverage).toMatchObject({
      value: "0%",
      health: "risk",
    });
    expect(snapshot.audits).toEqual([]);
  });

  it("fails closed when normalized audit pagination cannot be loaded", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "345",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "345",
        events: [
          {
            id: "EVT-345",
            timestamp: "2026-03-01T00:04:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
      queryNormalizedAuditEvents: vi.fn().mockRejectedValue(new Error("normalized audit endpoint unavailable")),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    await expect(fetchDashboardSnapshot()).rejects.toThrow(
      "Readonly API unavailable (fail-closed): normalized audit endpoint unavailable. Add ?mode=mock to switch to readonly snapshot fallback.",
    );
  });

  it("fails closed when normalized audit pagination repeats a cursor", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "345b",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "345b",
        events: [
          {
            id: "EVT-345b",
            timestamp: "2026-03-01T00:04:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
              object_id: "proof-345b",
              timestamp: "2026-03-01T00:02:00.000Z",
              reason: "warn",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-stall",
        })
        .mockResolvedValueOnce({
          events: [
            {
              source: "bridge-relay",
              event_type: "bridge_relay.proof_submitted",
              actor: "validator",
              object_id: "proof-345c",
              timestamp: "2026-03-01T00:03:00.000Z",
              reason: "warn",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-stall",
        }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    await expect(fetchDashboardSnapshot()).rejects.toThrow(
      "Readonly API unavailable (fail-closed): Normalized audit pagination cursor stalled at cursor-stall. Add ?mode=mock to switch to readonly snapshot fallback.",
    );
  });

  it("fails closed when normalized audit pagination declares more pages without a cursor", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "345c",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "345c",
        events: [
          {
            id: "EVT-345c",
            timestamp: "2026-03-01T00:04:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator",
            object_id: "proof-345d",
            timestamp: "2026-03-01T00:02:00.000Z",
            reason: "warn",
          },
        ],
        hasMore: true,
        nextCursor: "   ",
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    await expect(fetchDashboardSnapshot()).rejects.toThrow(
      "Readonly API unavailable (fail-closed): Normalized audit pagination declared more pages without a next cursor. Add ?mode=mock to switch to readonly snapshot fallback.",
    );
  });

  it("fails closed when normalized audit pagination exceeds the configured max pages", async () => {
    const previousPages = process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;
    process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = "1";

    try {
      const mockClient = {
        queryTask: vi.fn().mockResolvedValue({
          task: {
            id: "345d",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
        queryEvents: vi.fn().mockResolvedValue({
          taskId: "345d",
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
              object_id: "proof-345e",
              timestamp: "2026-03-01T00:02:00.000Z",
              reason: "warn",
            },
          ],
          hasMore: true,
          nextCursor: "cursor-next",
        }),
      } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

      vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

      await expect(fetchDashboardSnapshot()).rejects.toThrow(
        "Readonly API unavailable (fail-closed): Normalized audit pagination exceeded max pages (1). Add ?mode=mock to switch to readonly snapshot fallback.",
      );
    } finally {
      if (previousPages === undefined) {
        delete process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES;
      } else {
        process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES = previousPages;
      }
    }
  });

  it("keeps event ordering stable when fallback dashboard times are not ISO-formatted", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "346",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "346",
        events: [
          {
            id: "EVT-346",
            timestamp: "2026-03-01T00:04:00.000Z",
            type: "deploy.completed",
            level: "info",
            payload: {},
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
      queryNormalizedAuditEvents: vi.fn().mockResolvedValue({
        events: [
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator",
            object_id: "proof-346",
            timestamp: "not-an-iso-timestamp",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.events[0]?.id).toBe("EVT-346");
    expect(snapshot.events.find((event) => event.id === "bridge-relay:proof-346")).toBeDefined();
  });

  it("preserves source order when multiple fallback dashboard times are invalid", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "347",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-a",
            object_id: "proof-347a",
            timestamp: "bad-time-a",
            reason: "warn",
          },
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-b",
            object_id: "proof-347b",
            timestamp: "bad-time-b",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();

    expect(snapshot.events.map((event) => event.id)).toEqual([
      "bridge-relay:proof-347a",
      "bridge-relay:proof-347b",
    ]);
  });

  it("normalizes blank normalized-audit source and event type into stable dashboard fallbacks", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "348",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
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
            source: "   ",
            event_type: "\n",
            actor: "   ",
            timestamp: "2026-03-01T00:02:00.000Z",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const fallbackEvent = snapshot.events.find((event) => event.id === "unknown-source:unknown-event:system");

    expect(fallbackEvent).toMatchObject({
      summary: "unknown-source · unknown-event",
      severity: "Warning",
      category: "Incident",
    });
  });

  it("falls back to actor-based ids when normalized-audit object ids are blank", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "349",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-z",
            object_id: "   ",
            timestamp: "2026-03-01T00:02:00.000Z",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const fallbackEvent = snapshot.events.find(
      (event) => event.id === "bridge-relay:bridge_relay.proof_submitted:validator-z",
    );

    expect(fallbackEvent).toMatchObject({
      summary: "bridge-relay · bridge_relay.proof_submitted",
      severity: "Warning",
      category: "Security",
    });
  });

  it("falls back to actor-based ids when normalized-audit object ids contain only invisible characters", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "349b",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "349b",
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
            actor: "validator-z",
            object_id: "\u200B\uFEFF",
            timestamp: "2026-03-01T00:02:00.000Z",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const fallbackEvent = snapshot.events.find(
      (event) => event.id === "bridge-relay:bridge_relay.proof_submitted:validator-z",
    );

    expect(fallbackEvent).toMatchObject({
      summary: "bridge-relay · bridge_relay.proof_submitted",
      severity: "Warning",
      category: "Security",
    });
  });

  it("maps explicit critical normalized-audit markers to Critical severity", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "349c",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
            metadata: {},
          },
        }),
      queryEvents: vi.fn().mockResolvedValue({
        taskId: "349c",
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
            event_type: "vault.transfer",
            actor: "guardian",
            object_id: "vault-349c",
            timestamp: "2026-03-01T00:02:00.000Z",
            note: "critical threshold exceeded",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const event = snapshot.events.find((item) => item.id === "settlement-vault:vault-349c");

    expect(event).toMatchObject({
      summary: "settlement-vault · vault.transfer",
      severity: "Critical",
      category: "Security",
    });
  });

  it("suffixes duplicate fallback event ids to keep dashboard event keys stable", async () => {
    const mockClient = {
      queryTask: vi
        .fn()
        .mockResolvedValue({
          task: {
            id: "350",
            owner: "ops",
            status: "running",
            createdAt: "2026-03-01T00:00:00.000Z",
            updatedAt: "2026-03-01T00:05:00.000Z",
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
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-z",
            object_id: "   ",
            timestamp: "2026-03-01T00:02:00.000Z",
            reason: "warn",
          },
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-z",
            object_id: "",
            timestamp: "2026-03-01T00:03:00.000Z",
            reason: "warn",
          },
        ],
        hasMore: false,
      }),
    } as unknown as ReturnType<typeof apiContractClient.createFrontendApiClient>;

    vi.spyOn(apiContractClient, "createFrontendApiClient").mockReturnValue(mockClient);

    const snapshot = await fetchDashboardSnapshot();
    const duplicateIdEvents = snapshot.events.filter((event) =>
      event.id.startsWith("bridge-relay:bridge_relay.proof_submitted:validator-z"),
    );

    expect(duplicateIdEvents.map((event) => event.id)).toEqual([
      "bridge-relay:bridge_relay.proof_submitted:validator-z#2",
      "bridge-relay:bridge_relay.proof_submitted:validator-z",
    ]);
  });
});
