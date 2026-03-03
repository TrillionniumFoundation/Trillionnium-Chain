import { describe, expect, it } from "vitest";
import {
  adaptQueryCapabilityAudit,
  adaptQueryEvents,
  adaptQueryTask,
} from "@/lib/api-contract/adapters";
import { FrontendApiError } from "@/lib/api-contract/errors";

describe("api-contract adapters", () => {
  it("accepts canonical query-task payload", () => {
    const out = adaptQueryTask({
      task: {
        id: "1",
        name: "demo",
        status: "running",
        owner: "alice",
        createdAt: "2026-03-01T00:00:00.000Z",
        metadata: {},
      },
    });
    expect(out.task.id).toBe("1");
    expect(out.task.status).toBe("running");
  });

  it("adapts rpc query-task payload", () => {
    const out = adaptQueryTask({
      task_id: 42,
      status: "Completed",
      worker: "did:trnm:alice",
      bounty: 100,
      result_hash_hex: "abcd",
      version: 9,
    });
    expect(out.task.id).toBe("42");
    expect(out.task.status).toBe("succeeded");
    expect(out.task.owner).toBe("did:trnm:alice");
  });

  it("adapts rpc query-events array payload", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "commit",
          task_id: 7,
          from_status: "Assigned",
          to_status: "Committed",
          actor: "did:trnm:alice",
          tx_id: 11,
          block_height: 22,
          state_root: "root",
          ts_unix_ms: 1700000000000,
        },
      ],
      "7",
    );
    expect(out.taskId).toBe("7");
    expect(out.events[0]?.type).toBe("commit");
    expect(out.events[0]?.level).toBe("info");
  });

  it("maps frozen M2V2 resolution codes to fail-closed error signal", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 7,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 12,
          block_height: 23,
          state_root: "root-2",
          ts_unix_ms: 1700000001000,
          resolution_code: "ERR_M2V2_PROOF_MISSING",
        },
      ],
      "7",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_MISSING",
      m2v2ErrorCode: "ERR_M2V2_PROOF_MISSING",
    });
  });

  it("canonicalizes M2V2 resolution code casing/whitespace before fail-closed mapping", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 8,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 13,
          block_height: 24,
          state_root: "root-3",
          ts_unix_ms: 1700000002000,
          resolution_code: "  err_m2v2_proof_late  ",
        },
      ],
      "8",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_LATE",
      m2v2ErrorCode: "ERR_M2V2_PROOF_LATE",
    });
  });

  it("adapts rpc capability audit payload", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:bob",
        scope: "AUDIT_READ",
      },
      owner_history: [
        {
          action: "CAPABILITY_ISSUED",
          at_height: 123,
          note: "ok",
        },
      ],
    });
    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]?.capability).toBe("AUDIT_READ");
    expect(out.audits[0]?.granted).toBe(true);
  });

  it("fails closed on malformed payload", () => {
    expect(() => adaptQueryEvents({ bad: true }, "1")).toThrow(FrontendApiError);
  });
});
