import { FrontendApiError } from "./errors";

export type RetryOptions = {
  retries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  signal?: AbortSignal;
};

const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);

    const onAbort = () => {
      clearTimeout(timer);
      reject(
        new FrontendApiError({
          code: "ABORTED",
          message: "Request aborted",
          causeData: signal?.reason,
          retryable: false,
        }),
      );
    };

    if (signal?.aborted) {
      onAbort();
      return;
    }

    signal?.addEventListener("abort", onAbort, { once: true });
  });

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
        code: "ABORTED",
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
      await sleep(nextDelay(attempt, baseDelayMs, maxDelayMs), opts.signal);
    }
  }

  throw lastErr;
}
