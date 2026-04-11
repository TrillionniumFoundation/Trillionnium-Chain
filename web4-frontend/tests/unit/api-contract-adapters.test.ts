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

  it("fails closed on canonical query-task payloads with invalid status", () => {
    expect(() =>
      adaptQueryTask({
        task: {
          id: "1",
          name: "demo",
          status: "done",
          owner: "alice",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
        },
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on canonical query-task payloads missing task id", () => {
    expect(() =>
      adaptQueryTask({
        task: {
          name: "demo",
          status: "running",
          owner: "alice",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
        },
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on rpc query-task payloads missing task_id", () => {
    expect(() =>
      adaptQueryTask({
        status: "Completed",
        worker: "did:trnm:alice",
        bounty: 100,
        result_hash_hex: "abcd",
        version: 9,
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on rpc query-task payloads with invalid status", () => {
    expect(() =>
      adaptQueryTask({
        task_id: 42,
        status: "Done",
        worker: "did:trnm:alice",
        bounty: 100,
        result_hash_hex: "abcd",
        version: 9,
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on rpc query-task payloads with unknown fields", () => {
    expect(() =>
      adaptQueryTask({
        task_id: 42,
        status: "Completed",
        worker: "did:trnm:alice",
        bounty: 100,
        result_hash_hex: "abcd",
        version: 9,
        unexpected_flag: true,
      }),
    ).toThrow(FrontendApiError);
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

  it("fails closed when rpc query-events payload mismatches requested task id context", () => {
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
        ],
        "8",
      ),
    ).toThrow(FrontendApiError);
  });

  it("normalizes requested task id noise before rpc query-events context enforcement", () => {
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
      " \uFEFF7\u200B ",
    );

    expect(out.taskId).toBe("7");
    expect(out.events[0]?.taskId).toBe("7");
  });

  it("normalizes rpc challenge event type noise before level classification", () => {
    const out = adaptQueryEvents(
      [
        {
          event_type: "  challenge\u200B ",
          task_id: 7,
          from_status: "Revealed",
          to_status: "Challenged",
          actor: "did:trnm:bob",
          tx_id: 12,
          block_height: 23,
          state_root: "root-2",
          ts_unix_ms: 1700000001000,
        },
      ],
      "7",
    );

    expect(out.events[0]?.type).toBe("challenge");
    expect(out.events[0]?.level).toBe("warn");
  });

  it("treats DID registration history as non-grant in rpc capability audit fallback", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:alice",
        scope: "AUDIT_READ",
      },
      owner_history: [
        {
          action: "DID_REGISTERED",
          at_height: 11,
        },
        {
          action: "CAPABILITY_ISSUED",
          at_height: 12,
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:alice");
    expect(out.audits).toEqual([
      {
        subject: "did:trnm:alice",
        capability: "AUDIT_READ",
        granted: false,
        reason: "DID_REGISTERED",
        checkedAt: "height:11",
      },
      {
        subject: "did:trnm:alice",
        capability: "AUDIT_READ",
        granted: true,
        reason: "CAPABILITY_ISSUED",
        checkedAt: "height:12",
      },
    ]);
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

  it("fails closed when canonical query-events payload contains mixed task ids", () => {
    expect(() =>
      adaptQueryEvents({
        taskId: "7",
        events: [
          {
            id: "e1",
            taskId: "7",
            type: "commit",
            level: "info",
            timestamp: "2026-03-03T00:00:00.000Z",
            payload: {},
          },
          {
            id: "e2",
            taskId: "8",
            type: "reveal",
            level: "warn",
            timestamp: "2026-03-03T00:00:01.000Z",
            payload: {},
          },
        ],
      }),
    ).toThrow(FrontendApiError);
  });

  it("normalizes canonical query-events task ids before enforcing invariants", () => {
    const out = adaptQueryEvents(
      {
        taskId: " \uFEFF7\u200B ",
        events: [
          {
            id: "e1x",
            taskId: " 7 ",
            type: "commit",
            level: "info",
            timestamp: "2026-03-03T00:00:00.000Z",
            payload: {},
          },
        ],
      },
      "7",
    );

    expect(out.taskId).toBe("7");
    expect(out.events[0]?.taskId).toBe("7");
  });

  it("fails closed when canonical query-events payload mismatches requested task id context", () => {
    expect(() =>
      adaptQueryEvents(
        {
          taskId: "7",
          events: [
            {
              id: "e1y",
              taskId: "7",
              type: "commit",
              level: "info",
              timestamp: "2026-03-03T00:00:00.000Z",
              payload: {},
            },
          ],
        },
        "8",
      ),
    ).toThrow(FrontendApiError);
  });

  it("fails closed when canonical query-events payload contains blank event type noise", () => {
    expect(() =>
      adaptQueryEvents({
        taskId: "7",
        events: [
          {
            id: "e1z",
            taskId: "7",
            type: " \uFEFF\u200B ",
            level: "info",
            timestamp: "2026-03-03T00:00:00.000Z",
            payload: {},
          },
        ],
      }),
    ).toThrow(FrontendApiError);
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

  it("ignores canonical resolution_code aliases that normalize to empty noise", () => {
    const out = adaptQueryEvents({
      taskId: "8b",
      events: [
        {
          id: "e2b",
          taskId: "8b",
          type: "settle",
          level: "warn",
          timestamp: "2026-03-03T00:00:01.500Z",
          payload: {
            resolution_code: "\uFEFF \u200B\u200D ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("warn");
    expect(out.events[0]?.payload).toMatchObject({
      resolution_code: "\uFEFF \u200B\u200D ",
    });
    expect(out.events[0]?.payload?.resolutionCode).toBeUndefined();
    expect(out.events[0]?.payload?.m2v2ErrorCode).toBeUndefined();
  });

  it("falls back to snake_case resolution_code when camelCase alias is blank noise", () => {
    const out = adaptQueryEvents({
      taskId: "8c",
      events: [
        {
          id: "e2c",
          taskId: "8c",
          type: "settle",
          level: "warn",
          timestamp: "2026-03-03T00:00:01.700Z",
          payload: {
            resolutionCode: "\uFEFF \u200B\u200D ",
            resolution_code: " err_m2v2_proof_missing ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_MISSING",
      resolution_code: " err_m2v2_proof_missing ",
      m2v2ErrorCode: "ERR_M2V2_PROOF_MISSING",
    });
  });

  it("prefers canonical resolutionCode alias when both aliases are present", () => {
    const out = adaptQueryEvents({
      taskId: "8d",
      events: [
        {
          id: "e2d",
          taskId: "8d",
          type: "settle",
          level: "warn",
          timestamp: "2026-03-03T00:00:01.800Z",
          payload: {
            resolutionCode: " err_m2v2_proof_late ",
            resolution_code: " err_m2v2_proof_missing ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("error");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: "ERR_M2V2_PROOF_LATE",
      resolution_code: " err_m2v2_proof_missing ",
      m2v2ErrorCode: "ERR_M2V2_PROOF_LATE",
    });
  });

  it("does not over-trigger fail-closed mapping for non-frozen canonical resolution codes", () => {
    const out = adaptQueryEvents({
      taskId: "8e",
      events: [
        {
          id: "e2e",
          taskId: "8e",
          type: "settle",
          level: "warn",
          timestamp: "2026-03-03T00:00:01.900Z",
          payload: {
            resolutionCode: " err_custom_resolution ",
          },
        },
      ],
    });

    expect(out.events[0]?.level).toBe("warn");
    expect(out.events[0]?.payload).toMatchObject({
      resolutionCode: " err_custom_resolution ",
    });
    expect(out.events[0]?.payload?.m2v2ErrorCode).toBeUndefined();
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

  it("fails closed when canonical normalized audit pagination reports hasMore without usable cursor", () => {
    const out = adaptQueryNormalizedAuditEvents({
      events: [
        {
          source: "bridge-relay",
          event_type: "bridge_relay.proof_submitted",
          actor: "validator-1",
          checkedAt: "height:778",
        },
      ],
      hasMore: true,
      nextCursor: "   ",
      total: 43,
    });

    expect(out.events[0]?.event_type).toBe("bridge_relay.proof_submitted");
    expect(out.hasMore).toBe(false);
    expect(out.nextCursor).toBeUndefined();
    expect(out.total).toBe(43);
  });

  it("fails closed when canonical normalized audit pagination loops back to the requested cursor", () => {
    const out = adaptQueryNormalizedAuditEvents(
      {
        events: [
          {
            source: "capability-registry",
            event_type: "capability.renewed",
            actor: "security",
            checkedAt: "height:779",
          },
        ],
        hasMore: true,
        nextCursor: "cursor-loop",
        total: 44,
      },
      { cursor: "cursor-loop" },
    );

    expect(out.events[0]?.event_type).toBe("capability.renewed");
    expect(out.hasMore).toBe(false);
    expect(out.nextCursor).toBe("cursor-loop");
    expect(out.total).toBe(44);
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

  it("fails closed on malformed canonical normalized audit-events items", () => {
    expect(() =>
      adaptQueryNormalizedAuditEvents({
        events: [
          {
            source: "governance-guard",
            event_type: 7,
            actor: "alice",
          },
        ],
      }),
    ).toThrow(FrontendApiError);
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

  it("fails closed on canonical normalized audit-events page nextCursor type mismatch", () => {
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
        nextCursor: 123,
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on canonical normalized audit-events page hasMore type mismatch", () => {
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
        hasMore: "yes",
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on canonical normalized audit-events page total non-integer", () => {
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
        total: 42.5,
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

  it("preserves historical grant entries while annotating token-revoked capability audit state", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:bob",
        scope: "AUDIT_READ",
        revoked_at: 456,
      },
      owner_history: [
        {
          action: "CAPABILITY_ISSUED",
          at_height: 123,
          note: "initial grant",
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]?.granted).toBe(true);
    expect(out.audits[0]?.reason).toBe("TOKEN_REVOKED@height:456: initial grant");
    expect(out.audits[0]?.checkedAt).toBe("height:123");
  });

  it("preserves explicit capability revoke history under token-revoked semantics", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:bob",
        scope: "AUDIT_READ",
        revoked_at: 456,
      },
      owner_history: [
        {
          action: "CAPABILITY_REVOKED",
          at_height: 124,
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]?.granted).toBe(false);
    expect(out.audits[0]?.reason).toBe("TOKEN_REVOKED@height:456: CAPABILITY_REVOKED");
    expect(out.audits[0]?.checkedAt).toBe("height:124");
  });

  it("keeps non-capability history entries non-grant even when token is revoked", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:bob",
        scope: "AUDIT_READ",
        revoked_at: 456,
      },
      owner_history: [
        {
          action: "DID_REVOKED",
          at_height: 125,
          note: "subject retired",
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]).toEqual({
      subject: "did:trnm:bob",
      capability: "AUDIT_READ",
      granted: false,
      reason: "subject retired",
      checkedAt: "height:125",
    });
  });

  it("falls back to action when rpc capability audit note is blank or whitespace", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:carol",
        scope: "AUDIT_READ",
      },
      owner_history: [
        {
          action: "CAPABILITY_REVOKED",
          at_height: 126,
          note: "   ",
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:carol");
    expect(out.audits[0]).toEqual({
      subject: "did:trnm:carol",
      capability: "AUDIT_READ",
      granted: false,
      reason: "CAPABILITY_REVOKED",
      checkedAt: "height:126",
    });
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

  it("accepts canonical capability audit payload with iso checkedAt", () => {
    const out = adaptQueryCapabilityAudit({
      subject: "did:trnm:bob",
      audits: [
        {
          subject: "did:trnm:bob",
          capability: "AUDIT_READ",
          granted: false,
          checkedAt: "2026-03-03T00:00:00.000Z",
          reason: "CAPABILITY_REVOKED",
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]?.checkedAt).toBe("2026-03-03T00:00:00.000Z");
    expect(out.audits[0]?.granted).toBe(false);
  });

  it("fails closed on canonical capability audit entries with unknown fields", () => {
    expect(() =>
      adaptQueryCapabilityAudit({
        subject: "did:trnm:bob",
        audits: [
          {
            subject: "did:trnm:bob",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "height:321",
            reason: "delegated",
            unexpectedFlag: true,
          },
        ],
      }),
    ).toThrow(FrontendApiError);
  });

  it("treats blank revoked_at as absent instead of forcing token-revoked audit semantics", () => {
    const out = adaptQueryCapabilityAudit({
      token: {
        subject_did: "did:trnm:bob",
        scope: "AUDIT_READ",
        revoked_at: "   ",
      },
      owner_history: [
        {
          action: "CAPABILITY_ISSUED",
          at_height: 126,
          note: "initial grant",
        },
      ],
    });

    expect(out.subject).toBe("did:trnm:bob");
    expect(out.audits[0]).toEqual({
      subject: "did:trnm:bob",
      capability: "AUDIT_READ",
      granted: true,
      reason: "initial grant",
      checkedAt: "height:126",
    });
  });

  it("fails closed when rpc capability audit contains invalid height markers", () => {
    expect(() =>
      adaptQueryCapabilityAudit({
        token: {
          subject_did: "did:trnm:bob",
          scope: "AUDIT_READ",
          revoked_at: "not-a-height",
        },
        owner_history: [
          {
            action: "CAPABILITY_ISSUED",
            at_height: "still-not-a-height",
          },
        ],
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed when rpc capability audit token subject is missing", () => {
    expect(() =>
      adaptQueryCapabilityAudit({
        token: {
          scope: "AUDIT_READ",
        },
        owner_history: [
          {
            action: "CAPABILITY_ISSUED",
            at_height: 123,
          },
        ],
      }),
    ).toThrow(FrontendApiError);
  });

  it("fails closed on malformed payload", () => {
    expect(() => adaptQueryEvents({ bad: true }, "1")).toThrow(FrontendApiError);
  });

  it("normalizes requested task id context for empty rpc query-events payloads", () => {
    const out = adaptQueryEvents([], " \uFEFF7\u200B ");

    expect(out.taskId).toBe("7");
    expect(out.events).toEqual([]);
  });

  it("fails closed when empty rpc query-events payload has blank requested task id context", () => {
    expect(() => adaptQueryEvents([], " \uFEFF\u200B ")).toThrow(FrontendApiError);
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

  it("fails closed when rpc query-events payload contains blank event type noise", () => {
    expect(() =>
      adaptQueryEvents(
        [
          {
            event_type: " \uFEFF\u200B ",
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
      ),
    ).toThrow(FrontendApiError);
  });

  it("fails closed when rpc query-events payload contains unknown fields", () => {
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
            unexpected_flag: true,
          },
        ],
        "7",
      ),
    ).toThrow(FrontendApiError);
  });
});
