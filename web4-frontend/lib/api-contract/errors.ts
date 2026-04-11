export type ApiErrorCode =
  | "BAD_REQUEST"
  | "NOT_FOUND"
  | "NETWORK"
  | "TIMEOUT"
  | "ABORTED"
  | "HTTP_STATUS"
  | "INVALID_PAYLOAD"
  | "UNKNOWN";

export class FrontendApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status?: number;
  readonly causeData?: unknown;
  readonly retryable: boolean;

  constructor(params: {
    code: ApiErrorCode;
    message: string;
    status?: number;
    causeData?: unknown;
    retryable?: boolean;
  }) {
    super(params.message);
    this.name = "FrontendApiError";
    this.code = params.code;
    this.status = params.status;
    this.causeData = params.causeData;
    this.retryable = params.retryable ?? false;
  }
}

const RETRYABLE_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

export const isRetryableStatus = (status: number): boolean => {
  return RETRYABLE_HTTP_STATUSES.has(status);
};

export const classifyHttpStatusCode = (status: number): ApiErrorCode => {
  switch (status) {
    case 400:
      return "BAD_REQUEST";
    case 404:
      return "NOT_FOUND";
    default:
      return "HTTP_STATUS";
  }
};
