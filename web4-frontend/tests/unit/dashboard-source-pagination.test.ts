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

    expect(snapshot.events.find((event) => event.summary === "governance-guard · governance.proposal_executed")).toBeDefined();
    expect(snapshot.events.find((event) => event.summary === "bridge-relay · bridge_relay.proof_submitted")).toBeDefined();
    expect(snapshot.kpis.find((kpi) => kpi.label === "Open Incidents")?.value).toBe("1");
  });
});
