export type ApiErrorCode =
  | "NETWORK"
  | "TIMEOUT"
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

export const isRetryableStatus = (status: number): boolean => {
  return status === 408 || status === 429 || status >= 500;
};
