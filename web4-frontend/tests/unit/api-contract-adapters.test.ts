import { describe, expect, it } from "vitest";
import {
  adaptQueryCapabilityAudit,
  adaptQueryEvents,
  adaptQueryNormalizedAuditEvents,
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

  it("fails closed on canonical query-task payloads with unknown fields", () => {
    expect(() =>
      adaptQueryTask({
        task: {
          id: "1",
          name: "demo",
          status: "running",
          owner: "alice",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
          shadowMode: true,
        },
      }),
    ).toThrow(FrontendApiError);
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
    expect(out.task.name).toBe("rpc-task:42");
    expect(out.task.owner).toBe("unmapped:rpc-owner-not-provided");
    expect(out.task.metadata).toMatchObject({
      trace: {
        name: "derived-from-rpc-task-id",
        owner: "not-derived-from-worker-field",
        workerObserved: "did:trnm:alice",
      },
    });
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

  it("normalizes canonical events with frozen M2V2 resolution code to fail-closed level", () => {
    const out = adaptQueryEvents({
      taskId: "7",
      events: [
        {
          id: "e1",
          taskId: "7",
          type: "settle",
          level: "info",
          timestamp: "2026-03-03T00:00:00.000Z",
          payload: {
            resolutionCode: " err_m2v2_proof_invalid ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_INVALID",
      m2v2ErrorCode: "ERR_M2V2_PROOF_INVALID",
    });
  });

  it("normalizes canonical events using snake_case resolution_code alias", () => {
    const out = adaptQueryEvents({
      taskId: "8",
      events: [
        {
          id: "e2",
          taskId: "8",
          type: "settle",
          level: "warn",
          timestamp: "2026-03-03T00:00:01.000Z",
          payload: {
            resolution_code: " err_m2v2_settlement_degraded ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_SETTLEMENT_DEGRADED",
      m2v2ErrorCode: "ERR_M2V2_SETTLEMENT_DEGRADED",
    });
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

  it("canonicalizes hyphen/space-separated M2V2 resolution code tokens before fail-closed mapping", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 81,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 131,
          block_height: 241,
          state_root: "root-3b",
          ts_unix_ms: 1700000002100,
          resolution_code: "err-m2v2 proof-late",
        },
      ],
      "81",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_LATE",
      m2v2ErrorCode: "ERR_M2V2_PROOF_LATE",
    });
  });

  it("canonicalizes unicode dash-separated M2V2 resolution code tokens before fail-closed mapping", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 82,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 132,
          block_height: 242,
          state_root: "root-3c",
          ts_unix_ms: 1700000002200,
          resolution_code: "err—m2v2 proof−late",
        },
      ],
      "82",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_LATE",
      m2v2ErrorCode: "ERR_M2V2_PROOF_LATE",
    });
  });

  it("canonicalizes boundary separators around M2V2 resolution code before fail-closed mapping", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 83,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 133,
          block_height: 243,
          state_root: "root-3d",
          ts_unix_ms: 1700000002300,
          resolution_code: " -- err_m2v2_proof_missing -- ",
        },
      ],
      "83",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_MISSING",
      m2v2ErrorCode: "ERR_M2V2_PROOF_MISSING",
    });
  });

  it("canonicalizes M2V2 resolution code with BOM/zero-width noise before fail-closed mapping", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "settle",
          task_id: 9,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:verifier",
          tx_id: 14,
          block_height: 25,
          state_root: "root-4",
          ts_unix_ms: 1700000003000,
          resolution_code: "\uFEFF err\u200d_m2v2_proof_invalid \u200b",
        },
      ],
      "9",
    );

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_INVALID",
      m2v2ErrorCode: "ERR_M2V2_PROOF_INVALID",
    });
  });

  it("treats all frozen M2V2 resolution codes as fail-closed errors", () => {
    const frozenCodes = [
      "ERR_M2V2_PROOF_MISSING",
      "ERR_M2V2_PROOF_LATE",
      "ERR_M2V2_PROOF_INVALID",
      "ERR_M2V2_SETTLEMENT_DEGRADED",
    ] as const;

    frozenCodes.forEach((code, idx) => {
      const out = adaptQueryEvents(
        [
          {
            event_type: "settle",
            task_id: 90 + idx,
            from_status: "Revealed",
            to_status: "Challenged",
            actor: "did:trnm:verifier",
            tx_id: 100 + idx,
            block_height: 200 + idx,
            state_root: `root-${idx}`,
            ts_unix_ms: 1700000010000 + idx,
            resolution_code: code,
          },
        ],
        String(90 + idx),
      );

      expect(out.events[0]?.level).toBe("error");
      expect(out.events[0]?.payload).toMatchObject({
        resolutionCode: code,
        m2v2ErrorCode: code,
      });
    });
  });

  it("adapts canonical paginated normalized audit-events payload", () => {
    const out = adaptQueryNormalizedAuditEvents({
      events: [
        {
          source: "bridge-relay",
          event_type: "bridge_relay.proof_submitted",
          actor: "validator-1",
          checkedAt: "height:777",
          note: "first page",
        },
      ],
      hasMore: true,
      nextCursor: "c2",
      total: 42,
    });

    expect(out.events[0]?.event_type).toBe("bridge_relay.proof_submitted");
    expect(out.hasMore).toBe(true);
    expect(out.nextCursor).toBe("c2");
    expect(out.total).toBe(42);
  });

  it("adapts canonical normalized audit-events payload", () => {

    const out = adaptQueryNormalizedAuditEvents({
      events: [
        {
          source: "governance-guard",
          event_type: "governance.proposal_executed",
          actor: "alice",
          object_id: "pp-1",
          related_id: "param",
          amount: "1",
          reason: "ok",
          note: "version drift",
          timestamp: "2026-03-03T00:00:00.000Z",
        },
      ],
    });

    expect(out.events[0]?.source).toBe("governance-guard");
    expect(out.events[0]?.event_type).toBe("governance.proposal_executed");
  });

  it("fails closed on malformed canonical normalized audit-events envelope", () => {
    expect(() =>
      adaptQueryNormalizedAuditEvents({
        source: "bridge-relay",
        events: [],
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on canonical normalized audit-event entries with unknown fields", () => {
    expect(() =>
      adaptQueryNormalizedAuditEvents({
        events: [
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-1",
            checkedAt: "height:777",
            unexpected_flag: true,
          },
        ],
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed when canonical normalized audit-events page sets hasMore without nextCursor", () => {
    expect(() =>
      adaptQueryNormalizedAuditEvents({
        events: [
          {
            source: "bridge-relay",
            event_type: "bridge_relay.proof_submitted",
            actor: "validator-1",
            checkedAt: "height:777",
          },
        ],
        hasMore: true,
      }),
    ).toThrow(FrontendApiError);
  });

  it("adapts normalized audit-events fallback with eventType/objectId aliases", () => {
    const out = adaptQueryNormalizedAuditEvents([
      {
        source: "settlement-vault",
        eventType: "vault.deposited",
        actor: "alice",
        objectId: "alice",
        relatedId: "req-1",
        amount: 20,
        note: "deposit",
        recordedAt: "2026-03-03T00:01:00.000Z",
      },
    ]);

    expect(out.events[0]?.event_type).toBe("vault.deposited");
    expect(out.events[0]?.object_id).toBe("alice");
    expect(out.events[0]?.related_id).toBe("req-1");
  });

  it("fails closed on fallback normalized audit-events entries with unknown fields", () => {
    expect(() =>
      adaptQueryNormalizedAuditEvents([
        {
          source: "settlement-vault",
          eventType: "vault.deposited",
          actor: "alice",
          objectId: "alice",
          relatedId: "req-1",
          amount: 20,
          note: "deposit",
          recordedAt: "2026-03-03T00:01:00.000Z",
          unexpectedFlag: true,
        },
      ]),
    ).toThrow(FrontendApiError);
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
    expect(out.audits[0]?.checkedAt).toBe("height:123");
  });

  it("accepts canonical capability audit payload with height marker checkedAt", () => {
    const out = adaptQueryCapabilityAudit({
      subject: "did:trnm:bob",
      audits: [
        {
          subject: "did:trnm:bob",
          capability: "AUDIT_READ",
          granted: true,
          checkedAt: "height:321",
          reason: "delegated",
        },
      ],
    });
    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]?.checkedAt).toBe("height:321");
    expect(out.audits[0]?.granted).toBe(true);
  });

  it("fails closed on malformed payload", () => {
    expect(() => adaptQueryEvents({ bad: true }, "1")).toThrow(FrontendApiError);
  });

  it("fails closed when rpc events contain mixed task ids", () => {
    expect(() =>
      adaptQueryEvents(
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
          {
            event_type: "reveal",
            task_id: 8,
            from_status: "Committed",
            to_status: "Revealed",
            actor: "did:trnm:bob",
            tx_id: 12,
            block_height: 23,
            state_root: "root-2",
            ts_unix_ms: 1700000001000,
          },
        ],
        "7",
      ),
    ).toThrow(FrontendApiError);
  });
});
