# Frontend API Contract (Read-only Queries)

## Scope

This contract layer targets stable read-only endpoints:

- `GET /query-task/:taskId`
- `GET /query-events/:taskId`
- `GET /query-capability-audit/:subject`

The implementation lives in `web4-frontend/lib/api-contract` and is designed as a strict boundary between backend payloads and frontend domain models.

## Contract architecture

1. **Type layer (`types.ts`)**
   - canonical frontend domain types for task/events/capability audit.
2. **Validation layer (`schemas.ts`)**
   - `zod` schemas define exact runtime payload contract.
3. **Adapter layer (`adapters.ts`)**
   - maps raw payload -> validated typed model.
   - throws `FrontendApiError(code="INVALID_PAYLOAD")` on contract breaks.
4. **Client layer (`client.ts`)**
   - shared GET helper with timeout + retry.
   - endpoint-specific query methods call adapters.

## Error model

All query failures normalize to `FrontendApiError` with stable `code`:

- `NETWORK`: fetch/network failure
- `TIMEOUT`: timeout/abort
- `HTTP_STATUS`: non-2xx HTTP response (`status` attached)
- `INVALID_PAYLOAD`: schema mismatch
- `UNKNOWN`: fallback/internal abort

`retryable` is explicit and used by retry strategy.

## Retry policy

`withRetry` strategy (default):

- retries: `2`
- base delay: `250ms`
- max delay: `2000ms`
- exponential backoff + small jitter

Retry is attempted only when thrown error is marked `retryable`.

## Usage

```ts
import { createFrontendApiClient } from "@/lib/api-contract";

const api = createFrontendApiClient({ baseUrl: "https://rpc.example.com" });

const task = await api.queryTask("task-123");
const events = await api.queryEvents("task-123", { retries: 3 });
const audit = await api.queryCapabilityAudit("alice");
```

## Evolution guidance

- Keep this module read-only and deterministic.
- Additive changes to schemas/types should be backward-compatible.
- Breaking payload changes must update schemas + adapters + this document in the same patch.
