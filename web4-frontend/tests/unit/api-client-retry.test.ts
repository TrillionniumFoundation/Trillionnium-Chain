import { describe, expect, it, vi } from "vitest";
import { createFrontendApiClient } from "@/lib/api-contract/client";
import { FrontendApiError } from "@/lib/api-contract/errors";
import { withRetry } from "@/lib/api-contract/retry";

describe("api-contract client and retry hardening", () => {
  it("fails fast when baseUrl is blank", () => {
    expect(() => createFrontendApiClient({ baseUrl: "   " })).toThrow(FrontendApiError);
  });

  it("normalizes trailing slash in base url", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        task: {
          id: "42",
          status: "running",
          owner: "alice",
          createdAt: "2026-03-01T00:00:00.000Z",
          metadata: {},
        },
      }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080///",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await client.queryTask("42");

    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/query-task/42",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("enforces minimum timeout boundary", async () => {
    const fetchImpl: typeof fetch = vi.fn(
      (_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        }),
    ) as unknown as typeof fetch;

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("9", { timeoutMs: -1, retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
    });
  });


  it("builds normalized audit query params", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryNormalizedAuditEvents({
      source: "governance-guard",
      eventType: "governance.proposal_executed",
      limit: 12,
      cursor: "cursor-1",
    });

    const calledUrl = (fetchImpl.mock.calls[0] ?? [])[0];
    expect(String(calledUrl)).toContain("/query-normalized-audit-events?");
    expect(String(calledUrl)).toContain("source=governance-guard");
    expect(String(calledUrl)).toContain("eventType=governance.proposal_executed");
    expect(String(calledUrl)).toContain("limit=12");
    expect(String(calledUrl)).toContain("cursor=cursor-1");
  });

  it("fails closed on malformed normalized audit query params", async () => {
    const fetchImpl = vi.fn();

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    try {
      client.queryNormalizedAuditEvents({
        source: "   ",
        limit: 0,
      });
      throw new Error("expected invalid query to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(FrontendApiError);
      expect(error).toMatchObject({
        code: "INVALID_PAYLOAD",
      });
    }

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed on unknown normalized audit query params", async () => {
    const fetchImpl = vi.fn();

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    try {
      client.queryNormalizedAuditEvents({
        source: "governance-guard",
        unknownFilter: "shadow-mode",
      } as never);
      throw new Error("expected unknown query field to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(FrontendApiError);
      expect(error).toMatchObject({
        code: "INVALID_PAYLOAD",
      });
    }

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("uses normalized audit endpoint", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await client.queryNormalizedAuditEvents();

    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/query-normalized-audit-events",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("clamps invalid retry options to safe defaults", async () => {
    let attempts = 0;
    await expect(
      withRetry(
        async () => {
          attempts += 1;
          throw new FrontendApiError({
            code: "NETWORK",
            message: "temporary",
            retryable: true,
          });
        },
        { retries: -5, baseDelayMs: -100, maxDelayMs: -50 },
      ),
    ).rejects.toBeInstanceOf(FrontendApiError);

    expect(attempts).toBe(1);
  });
});
