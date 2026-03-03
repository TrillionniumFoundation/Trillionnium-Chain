import {
  adaptQueryCapabilityAudit,
  adaptQueryEvents,
  adaptQueryTask,
} from "./adapters";
import { FrontendApiError, isRetryableStatus } from "./errors";
import { withRetry, type RetryOptions } from "./retry";
import type {
  QueryCapabilityAuditResult,
  QueryEventsResult,
  QueryTaskResult,
} from "./types";

type BaseClientConfig = {
  baseUrl: string;
  fetchImpl?: typeof fetch;
};

type QueryOptions = RetryOptions & {
  timeoutMs?: number;
};

const withTimeoutSignal = (timeoutMs: number, signal?: AbortSignal) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);

  if (signal) {
    signal.addEventListener("abort", () => controller.abort(signal.reason), {
      once: true,
    });
  }

  return {
    signal: controller.signal,
    cleanup: () => clearTimeout(timer),
  };
};

export function createFrontendApiClient(config: BaseClientConfig) {
  const fetchImpl = config.fetchImpl ?? fetch;

  const getJson = async (path: string, options: QueryOptions = {}) => {
    const timeoutMs = options.timeoutMs ?? 8_000;

    return withRetry(async () => {
      const timeout = withTimeoutSignal(timeoutMs, options.signal);
      try {
        const response = await fetchImpl(`${config.baseUrl}${path}`, {
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

        return await response.json();
      } catch (err) {
        if (err instanceof FrontendApiError) throw err;

        if (err instanceof Error && err.name === "AbortError") {
          throw new FrontendApiError({
            code: "TIMEOUT",
            message: "Query timeout",
            causeData: err,
            retryable: true,
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
        adaptQueryEvents,
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
