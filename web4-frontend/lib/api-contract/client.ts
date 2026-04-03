import {
  adaptQueryCapabilityAudit,
  adaptQueryEvents,
  adaptQueryNormalizedAuditEvents,
  adaptQueryTask,
} from "./adapters";
import { FrontendApiError, isRetryableStatus } from "./errors";
import { withRetry, type RetryOptions } from "./retry";
import type {
  QueryCapabilityAuditResult,
  QueryEventsResult,
  QueryNormalizedAuditEventsResult,
  QueryTaskResult,
  NormalizedAuditEventsQuery,
} from "./types";

type BaseClientConfig = {
  baseUrl: string;
  fetchImpl?: typeof fetch;
};

type QueryOptions = RetryOptions & {
  timeoutMs?: number;
};

const normalizeTimeoutMs = (timeoutMs: unknown): number => {
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs)) return 8_000;
  return Math.max(100, Math.trunc(timeoutMs));
};

const withTimeoutSignal = (timeoutMs: number, signal?: AbortSignal) => {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort("timeout");
  }, timeoutMs);

  const onAbort = () => controller.abort(signal?.reason);

  if (signal) {
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    isTimeout: () => timedOut,
    cleanup: () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    },
  };
};

const normalizeBaseUrl = (baseUrl: string): string => {
  const trimmed = baseUrl.trim();
  if (!trimmed) {
    throw new FrontendApiError({
      code: "UNKNOWN",
      message: "Frontend API base URL is empty",
      retryable: false,
    });
  }

  return trimmed.replace(/\/+$/, "");
};

const normalizeQueryParam = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  const trimmed = value
    .replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim();
  return trimmed ? trimmed : null;
};

export function createFrontendApiClient(config: BaseClientConfig) {
  const fetchImpl = config.fetchImpl ?? fetch;
  const normalizedBaseUrl = normalizeBaseUrl(config.baseUrl);

  const getJson = async (path: string, options: QueryOptions = {}) => {
    const timeoutMs = normalizeTimeoutMs(options.timeoutMs);

    return withRetry(async () => {
      const timeout = withTimeoutSignal(timeoutMs, options.signal);
      try {
        const response = await fetchImpl(`${normalizedBaseUrl}${path}`, {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: timeout.signal,
        });

        if (!response.ok) {
          throw new FrontendApiError({
            code: "HTTP_STATUS",
            message: `Query failed with HTTP ${response.status}`,
            status: response.status,
            retryable: isRetryableStatus(response.status),
          });
        }

        try {
          return await response.json();
        } catch (err) {
          throw new FrontendApiError({
            code: "INVALID_PAYLOAD",
            message: "Backend returned non-JSON payload",
            causeData: err,
            retryable: false,
          });
        }
      } catch (err) {
        if (err instanceof FrontendApiError) throw err;

        if (err instanceof Error && err.name === "AbortError") {
          if (timeout.isTimeout()) {
            throw new FrontendApiError({
              code: "TIMEOUT",
              message: "Query timeout",
              causeData: err,
              retryable: true,
            });
          }

          throw new FrontendApiError({
            code: "ABORTED",
            message: "Request aborted",
            causeData: err,
            retryable: false,
          });
        }

        throw new FrontendApiError({
          code: "NETWORK",
          message: "Network error while querying backend",
          causeData: err,
          retryable: true,
        });
      } finally {
        timeout.cleanup();
      }
    }, options);
  };

  return {
    queryTask(taskId: string, options?: QueryOptions): Promise<QueryTaskResult> {
      return getJson(`/query-task/${encodeURIComponent(taskId)}`, options).then(
        adaptQueryTask,
      );
    },

    queryEvents(taskId: string, options?: QueryOptions): Promise<QueryEventsResult> {
      return getJson(`/query-events/${encodeURIComponent(taskId)}`, options).then(
        (payload) => adaptQueryEvents(payload, taskId),
      );
    },

    queryNormalizedAuditEvents(
      query: NormalizedAuditEventsQuery = {},
      options?: QueryOptions,
    ): Promise<QueryNormalizedAuditEventsResult> {
      const params = new URLSearchParams();
      const source = normalizeQueryParam(query.source);
      const eventType = normalizeQueryParam(query.eventType);
      const cursor = normalizeQueryParam(query.cursor);
      if (source) params.set("source", source);
      if (eventType) params.set("eventType", eventType);
      if (cursor) params.set("cursor", cursor);
      if (query.limit != null && Number.isFinite(query.limit) && query.limit > 0) {
        params.set("limit", String(Math.trunc(query.limit)));
      }
      const qs = params.toString();

      return getJson(`/query-normalized-audit-events${qs ? `?${qs}` : ""}`, options).then(
        (payload) => adaptQueryNormalizedAuditEvents(payload, query),
      );
    },

    queryCapabilityAudit(
      subject: string,
      options?: QueryOptions,
    ): Promise<QueryCapabilityAuditResult> {
      return getJson(
        `/query-capability-audit/${encodeURIComponent(subject)}`,
        options,
      ).then(adaptQueryCapabilityAudit);
    },
  };
}
