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

  it("trims normalized audit query params before request serialization", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryNormalizedAuditEvents({
      source: "  governance-guard  ",
      eventType: "\n governance.proposal_executed\t",
      limit: 12,
      cursor: "\u200B cursor-1 \uFEFF",
    });

    const calledUrl = String((fetchImpl.mock.calls[0] ?? [])[0]);
    expect(calledUrl).toContain("source=governance-guard");
    expect(calledUrl).toContain("eventType=governance.proposal_executed");
    expect(calledUrl).toContain("cursor=cursor-1");
    expect(calledUrl).not.toContain("%20%20governance-guard%20%20");
    expect(calledUrl).not.toContain("%0A%20governance.proposal_executed%09");
    expect(calledUrl).not.toContain("%E2%80%8B");
    expect(calledUrl).not.toContain("%EF%BB%BF");
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

  it("maps http 400 to bad request and does not retry", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      status: 400,
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("maps http 404 to not found and does not retry", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "NOT_FOUND",
      status: 404,
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("maps non-json backend payloads to invalid payload and does not retry", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => {
        throw new SyntaxError("bad json");
      },
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "INVALID_PAYLOAD",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("maps contract-invalid json payloads to invalid payload and does not retry", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        task: {
          id: "42",
          status: "running",
        },
      }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "INVALID_PAYLOAD",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("normalizes capability audit subject before path construction", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        subject: "did:trnm:alice/ops",
        audits: [],
      }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryCapabilityAudit("  did:trnm:alice/ops  ");

    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/query-capability-audit/did%3Atrnm%3Aalice%2Fops",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("fails closed on blank capability audit subject before request", async () => {
    const fetchImpl = vi.fn();

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    try {
      client.queryCapabilityAudit("   ");
      throw new Error("expected blank subject to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(FrontendApiError);
      expect(error).toMatchObject({
        code: "INVALID_PAYLOAD",
      });
    }

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("classifies non-network thrown errors as unknown and fail-closed", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new SyntaxError("bad parser state"));

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "UNKNOWN",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies abort-like DOMException-shaped errors as aborted and does not retry", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "AbortError",
      code: "ABORT_ERR",
      message: "The operation was aborted.",
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies cause-nested abort errors as aborted and does not retry", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "TypeError",
      message: "fetch failed",
      cause: {
        name: "AbortError",
        code: "ABORT_ERR",
        message: "The operation was aborted.",
      },
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies reason-nested abort errors as aborted and does not retry", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "TypeError",
      message: "fetch failed",
      reason: {
        name: "AbortError",
        code: "ABORT_ERR",
        message: "The operation was aborted.",
      },
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies legacy DOMException abort codes as aborted and does not retry", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      code: 20,
      message: "The operation was aborted.",
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("treats caller-supplied aborts as aborted even when the abort reason looks timeout-like", async () => {
    const fetchImpl: typeof fetch = vi.fn(
      (_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(init.signal?.reason);
          });
        }),
    ) as unknown as typeof fetch;

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const controller = new AbortController();
    const request = client.queryTask("42", { retries: 2, signal: controller.signal });
    controller.abort({ name: "TimeoutError", message: "Cancelled by caller" });

    await expect(request).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies object-shaped network errors as retryable network failures", async () => {
    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce({
        name: "NetworkError",
        message: "Connection lost",
      })
      .mockResolvedValueOnce({
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
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 1, baseDelayMs: 0, maxDelayMs: 0 })).resolves
      .toMatchObject({
        task: expect.objectContaining({ id: "42" }),
      });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("classifies TimeoutError-shaped failures as timeout and keeps them retryable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "TimeoutError",
      message: "The operation timed out.",
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
      retryable: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies undici timeout code failures as timeout and keeps them retryable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "TypeError",
      message: "fetch failed",
      cause: {
        code: "UND_ERR_CONNECT_TIMEOUT",
        message: "Connect timeout",
      },
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
      retryable: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies reason-nested timeout code failures as timeout and keeps them retryable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "TypeError",
      message: "fetch failed",
      reason: {
        code: "UND_ERR_CONNECT_TIMEOUT",
        message: "Connect timeout",
      },
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
      retryable: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies socket timeout codes as timeout and keeps them retryable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      name: "Error",
      code: "ETIMEDOUT",
      message: "Socket timed out",
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
      retryable: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("classifies legacy DOMException timeout codes as timeout and keeps them retryable", async () => {
    const fetchImpl = vi.fn().mockRejectedValue({
      code: 23,
      message: "The operation timed out.",
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.queryTask("42", { retries: 0 })).rejects.toMatchObject({
      code: "TIMEOUT",
      retryable: true,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does not retry unknown non-FrontendApiError failures in retry helper", async () => {
    let attempts = 0;

    await expect(
      withRetry(
        async () => {
          attempts += 1;
          throw new Error("boom");
        },
        { retries: 2, baseDelayMs: 0, maxDelayMs: 0 },
      ),
    ).rejects.toThrow("boom");

    expect(attempts).toBe(1);
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

  it("retries transient http statuses but fails closed on non-transient 5xx", async () => {
    const retryableFetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
      })
      .mockResolvedValueOnce({
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

    const retryableClient = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: retryableFetch as unknown as typeof fetch,
    });

    await expect(
      retryableClient.queryTask("42", { retries: 1, baseDelayMs: 0, maxDelayMs: 0 }),
    ).resolves.toMatchObject({
      task: expect.objectContaining({ id: "42" }),
    });
    expect(retryableFetch).toHaveBeenCalledTimes(2);

    const failClosedFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 501,
    });

    const failClosedClient = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: failClosedFetch as unknown as typeof fetch,
    });

    await expect(failClosedClient.queryTask("42", { retries: 2 })).rejects.toMatchObject({
      code: "HTTP_STATUS",
      status: 501,
      retryable: false,
    });
    expect(failClosedFetch).toHaveBeenCalledTimes(1);
  });
});
