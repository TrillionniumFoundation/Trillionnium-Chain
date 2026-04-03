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

  it("trims normalized audit query params and drops blank values", async () => {
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
      eventType: "   ",
      limit: 5,
      cursor: "  cursor-2  ",
    });

    const calledUrl = String((fetchImpl.mock.calls[0] ?? [])[0]);
    expect(calledUrl).toContain("source=governance-guard");
    expect(calledUrl).toContain("cursor=cursor-2");
    expect(calledUrl).toContain("limit=5");
    expect(calledUrl).not.toContain("eventType=");
    expect(calledUrl).not.toContain("%20%20");
  });

  it("strips BOM and zero-width noise from normalized audit query params", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryNormalizedAuditEvents({
      source: "\uFEFF governance-guard \u200B",
      eventType: "\u200D governance.proposal_executed \u2060",
      limit: 5,
      cursor: "\uFEFF \u200Bcursor-2\u200D ",
    });

    const calledUrl = String((fetchImpl.mock.calls[0] ?? [])[0]);
    expect(calledUrl).toContain("source=governance-guard");
    expect(calledUrl).toContain("eventType=governance.proposal_executed");
    expect(calledUrl).toContain("cursor=cursor-2");
    expect(calledUrl).not.toContain("%EF%BB%BF");
    expect(calledUrl).not.toContain("%E2%80%8B");
    expect(calledUrl).not.toContain("%E2%80%8D");
  });

  it("truncates fractional normalized audit limits and drops non-string filters", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryNormalizedAuditEvents({
      source: "bridge-relay",
      limit: 12.9,
      eventType: 42 as unknown as string,
      cursor: undefined,
    });

    const calledUrl = String((fetchImpl.mock.calls[0] ?? [])[0]);
    expect(calledUrl).toContain("source=bridge-relay");
    expect(calledUrl).toContain("limit=12");
    expect(calledUrl).not.toContain("limit=12.9");
    expect(calledUrl).not.toContain("eventType=");
    expect(calledUrl).not.toContain("cursor=");
  });

  it("drops non-positive and non-finite normalized audit limits from readonly query params", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ events: [] }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryNormalizedAuditEvents({
      source: "bridge-relay",
      limit: 0,
      cursor: "cursor-zero",
    });
    await client.queryNormalizedAuditEvents({
      source: "bridge-relay",
      limit: -3,
      cursor: "cursor-negative",
    });
    await client.queryNormalizedAuditEvents({
      source: "bridge-relay",
      limit: Number.NaN,
      cursor: "cursor-nan",
    });

    expect(String((fetchImpl.mock.calls[0] ?? [])[0])).toContain("cursor=cursor-zero");
    expect(String((fetchImpl.mock.calls[0] ?? [])[0])).not.toContain("limit=");
    expect(String((fetchImpl.mock.calls[1] ?? [])[0])).toContain("cursor=cursor-negative");
    expect(String((fetchImpl.mock.calls[1] ?? [])[0])).not.toContain("limit=");
    expect(String((fetchImpl.mock.calls[2] ?? [])[0])).toContain("cursor=cursor-nan");
    expect(String((fetchImpl.mock.calls[2] ?? [])[0])).not.toContain("limit=");
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

  it("url-encodes readonly task ids in query-task requests", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        task: {
          id: "task/alpha 42",
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

    await client.queryTask("task/alpha 42");

    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/query-task/task%2Falpha%2042",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("url-encodes readonly capability subjects in audit requests", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        subject: "settlement vault/admin",
        audits: [
          {
            subject: "settlement vault/admin",
            capability: "AUDIT_READ",
            granted: true,
            checkedAt: "height:123",
          },
        ],
      }),
    });

    const client = createFrontendApiClient({
      baseUrl: "http://127.0.0.1:8080",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await client.queryCapabilityAudit("settlement vault/admin");

    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/query-capability-audit/settlement%20vault%2Fadmin",
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

  it("fails closed when aborted during retry backoff", async () => {
    const controller = new AbortController();
    let attempts = 0;

    const run = withRetry(
      async () => {
        attempts += 1;
        throw new FrontendApiError({
          code: "NETWORK",
          message: "temporary",
          retryable: true,
        });
      },
      {
        retries: 2,
        baseDelayMs: 20,
        maxDelayMs: 20,
        signal: controller.signal,
      },
    );

    setTimeout(() => controller.abort("user canceled"), 0);

    await expect(run).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
    });
    expect(attempts).toBe(1);
  });

  it("fails closed before the first attempt when the retry signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort("preflight canceled");

    const fn = vi.fn(async () => "ok");

    await expect(
      withRetry(fn, {
        retries: 2,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      code: "ABORTED",
      retryable: false,
      causeData: "preflight canceled",
    });

    expect(fn).not.toHaveBeenCalled();
  });
});
