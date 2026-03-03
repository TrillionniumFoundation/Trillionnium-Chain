import { FrontendApiError } from "./errors";

export type RetryOptions = {
  retries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  signal?: AbortSignal;
};

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const nextDelay = (attempt: number, baseDelayMs: number, maxDelayMs: number) => {
  const exp = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
  const jitter = Math.floor(Math.random() * Math.min(100, exp * 0.1));
  return exp + jitter;
};

export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: RetryOptions = {},
): Promise<T> {
  const retries = opts.retries ?? 2;
  const baseDelayMs = opts.baseDelayMs ?? 250;
  const maxDelayMs = opts.maxDelayMs ?? 2_000;

  let lastErr: unknown;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (opts.signal?.aborted) {
      throw new FrontendApiError({
        code: "UNKNOWN",
        message: "Request aborted",
        causeData: opts.signal.reason,
        retryable: false,
      });
    }

    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const retryable =
        err instanceof FrontendApiError ? err.retryable : attempt < retries;
      if (!retryable || attempt === retries) {
        throw err;
      }
      await sleep(nextDelay(attempt, baseDelayMs, maxDelayMs));
    }
  }

  throw lastErr;
}
