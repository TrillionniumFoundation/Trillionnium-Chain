import {
  queryCapabilityAuditResponseSchema,
  queryEventsResponseSchema,
  queryTaskResponseSchema,
} from "./schemas";
import type {
  QueryCapabilityAuditResult,
  QueryEventsResult,
  QueryTaskResult,
} from "./types";
import { FrontendApiError } from "./errors";

function normalizeSchemaError(error: unknown): FrontendApiError {
  return new FrontendApiError({
    code: "INVALID_PAYLOAD",
    message: "Backend response does not match frontend API contract",
    causeData: error,
    retryable: false,
  });
}

export const adaptQueryTask = (payload: unknown): QueryTaskResult => {
  const parsed = queryTaskResponseSchema.safeParse(payload);
  if (!parsed.success) throw normalizeSchemaError(parsed.error.flatten());
  return parsed.data;
};

export const adaptQueryEvents = (payload: unknown): QueryEventsResult => {
  const parsed = queryEventsResponseSchema.safeParse(payload);
  if (!parsed.success) throw normalizeSchemaError(parsed.error.flatten());
  return parsed.data;
};

export const adaptQueryCapabilityAudit = (
  payload: unknown,
): QueryCapabilityAuditResult => {
  const parsed = queryCapabilityAuditResponseSchema.safeParse(payload);
  if (!parsed.success) throw normalizeSchemaError(parsed.error.flatten());
  return parsed.data;
};
