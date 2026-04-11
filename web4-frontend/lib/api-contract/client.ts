import {
  adaptQueryCapabilityAudit,
  adaptQueryEvents,
  adaptQueryNormalizedAuditEvents,
  adaptQueryTask,
} from "./adapters";
import { normalizedAuditEventsQuerySchema } from "./schemas";
import { FrontendApiError, classifyHttpStatusCode, isRetryableStatus } from "./errors";
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

export const NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS = {
  source: "source",
  eventType: "eventType",
  limit: "limit",
  cursor: "cursor",
} as const satisfies Record<keyof NormalizedAuditEventsQuery, string>;

export const buildNormalizedAuditEventsQueryParams = (
  query: NormalizedAuditEventsQuery,
): URLSearchParams => {
  const params = new URLSearchParams();

  if (query.source) {
    params.set(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS.source, query.source);
  }
  if (query.eventType) {
    params.set(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS.eventType, query.eventType);
  }
  if (query.cursor) {
    params.set(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS.cursor, query.cursor);
  }
  if (query.limit != null) {
    params.set(NORMALIZED_AUDIT_EVENTS_QUERY_PARAM_KEYS.limit, String(query.limit));
  }

  return params;
};

const normalizeTimeoutMs = (timeoutMs: unknown): number => {
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs)) return 8_000;
  return Math.max(100, Math.trunc(timeoutMs));
};

const withTimeoutSignal = (timeoutMs: number, signal?: AbortSignal) => {
  const controller = new AbortController();
  let timedOut = false;
  let abortedByCaller = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort("timeout");
  }, timeoutMs);

  const onAbort = () => {
    abortedByCaller = true;
    controller.abort(signal?.reason);
  };

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
    isCallerAbort: () => abortedByCaller,
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

const normalizeRequiredPathParam = (value: unknown, label: string): string => {
  if (typeof value !== "string") {
    throw new FrontendApiError({
      code: "INVALID_PAYLOAD",
      message: `${label} must be a non-empty string`,
      causeData: value,
      retryable: false,
    });
  }

  const trimmed = value.trim();
  if (!trimmed) {
    throw new FrontendApiError({
      code: "INVALID_PAYLOAD",
      message: `${label} must be a non-empty string`,
      causeData: value,
      retryable: false,
    });
  }

  return trimmed;
};

const NETWORK_ERROR_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "UND_ERR_SOCKET",
]);

const isLikelyNetworkError = (err: unknown): boolean => {
  if (err instanceof TypeError) return true;
  if (!(err && typeof err === "object")) return false;

  return collectErrorLikeChain(err).some((candidate) => {
    const name = "name" in candidate ? candidate.name : undefined;
    const code = "code" in candidate ? candidate.code : undefined;
    return (
      name === "TypeError" ||
      name === "NetworkError" ||
      name === "FetchError" ||
      (typeof code === "string" && NETWORK_ERROR_CODES.has(code))
    );
  });
};

const LEGACY_ABORT_ERROR_CODE = 20;
const LEGACY_TIMEOUT_ERROR_CODE = 23;

type ErrorLikeRecord = Record<string, unknown>;

const collectErrorLikeChain = (value: unknown, maxDepth = 4): ErrorLikeRecord[] => {
  const seen = new Set<unknown>();
  const queue: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const chain: ErrorLikeRecord[] = [];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;

    const { value: candidate, depth } = current;
    if (!(candidate && typeof candidate === "object") || seen.has(candidate)) {
      continue;
    }

    seen.add(candidate);
    chain.push(candidate as ErrorLikeRecord);

    if (depth >= maxDepth) {
      continue;
    }

    const cause = "cause" in candidate ? candidate.cause : undefined;
    const reason = "reason" in candidate ? candidate.reason : undefined;
    const nestedErrors = "errors" in candidate ? candidate.errors : undefined;

    if (cause && typeof cause === "object") {
      queue.push({ value: cause, depth: depth + 1 });
    }
    if (reason && typeof reason === "object") {
      queue.push({ value: reason, depth: depth + 1 });
    }
    if (Array.isArray(nestedErrors)) {
      for (const nested of nestedErrors) {
        if (nested && typeof nested === "object") {
          queue.push({ value: nested, depth: depth + 1 });
        }
      }
    }
  }

  return chain;
};

const isAbortLikeErrorCode = (code: unknown): boolean => {
  return code === "ABORT_ERR" || code === "UND_ERR_ABORTED" || code === LEGACY_ABORT_ERROR_CODE;
};

const isAbortLikeError = (err: unknown): boolean => {
  return collectErrorLikeChain(err).some((candidate) => {
    const name = "name" in candidate ? candidate.name : undefined;
    const code = "code" in candidate ? candidate.code : undefined;
    return name === "AbortError" || isAbortLikeErrorCode(code);
  });
};

const TIMEOUT_ERROR_CODES = new Set([
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
  "ETIMEDOUT",
  "ESOCKETTIMEDOUT",
]);

const isTimeoutErrorCode = (code: unknown): boolean => {
  return code === LEGACY_TIMEOUT_ERROR_CODE || (typeof code === "string" && TIMEOUT_ERROR_CODES.has(code));
};

const isTimeoutLikeError = (err: unknown): boolean => {
  return collectErrorLikeChain(err).some((candidate) => {
    const name = "name" in candidate ? candidate.name : undefined;
    const code = "code" in candidate ? candidate.code : undefined;
    return name === "TimeoutError" || isTimeoutErrorCode(code);
  });
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
          const code = classifyHttpStatusCode(response.status);
          throw new FrontendApiError({
            code,
            message: `Query failed with HTTP ${response.status}`,
            status: response.status,
            retryable:
              isRetryableStatus(response.status) && (code === "HTTP_STATUS" || code === "TIMEOUT"),
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

        if (timeout.isTimeout()) {
          throw new FrontendApiError({
            code: "TIMEOUT",
            message: "Query timeout",
            causeData: err,
            retryable: true,
          });
        }

        if (timeout.isCallerAbort() || isAbortLikeError(err)) {
          throw new FrontendApiError({
            code: "ABORTED",
            message: "Request aborted",
            causeData: err,
            retryable: false,
          });
        }

        if (isTimeoutLikeError(err)) {
          throw new FrontendApiError({
            code: "TIMEOUT",
            message: "Query timeout",
            causeData: err,
            retryable: true,
          });
        }

        const networkLike = isLikelyNetworkError(err);
        throw new FrontendApiError({
          code: networkLike ? "NETWORK" : "UNKNOWN",
          message: networkLike
            ? "Network error while querying backend"
            : "Unexpected error while querying backend",
          causeData: err,
          retryable: networkLike,
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
      const normalizedQuery = normalizedAuditEventsQuerySchema.safeParse(query);
      if (!normalizedQuery.success) {
        throw new FrontendApiError({
          code: "INVALID_PAYLOAD",
          message: "Normalized audit query does not match frontend API contract",
          causeData: normalizedQuery.error.flatten(),
          retryable: false,
        });
      }

      const parsedQuery = normalizedQuery.data;
      const params = buildNormalizedAuditEventsQueryParams(parsedQuery);
      const qs = params.toString();

      return getJson(`/query-normalized-audit-events${qs ? `?${qs}` : ""}`, options).then(
        (payload) => adaptQueryNormalizedAuditEvents(payload, parsedQuery),
      );
    },

    queryCapabilityAudit(
      subject: string,
      options?: QueryOptions,
    ): Promise<QueryCapabilityAuditResult> {
      const normalizedSubject = normalizeRequiredPathParam(subject, "Capability audit subject");
      return getJson(
        `/query-capability-audit/${encodeURIComponent(normalizedSubject)}`,
        options,
      ).then(adaptQueryCapabilityAudit);
    },
  };
}
