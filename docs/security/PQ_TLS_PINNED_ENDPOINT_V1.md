# Pinned endpoint TLS development profile V1

This opt-in component is preserved from e42f85ed5b1d0b4c9ebcfd8d5bd3247becb74959
and adapted to the current absolute-deadline client and shared-owner listeners
during the 2026-11-14 branch audit. It is a bounded development transport.
Production activation, consensus authority, public WAN acceptance, whole-chain
quantum-security qualification and whole-node rollback protection remain false.

## Selection and identities

The ordinary TLS loopback profile retains its canonical stored bytes, signature
domains, ALPN and default behavior. Endpoint selection requires the new profile
native-pq-network-tls13-endpoint-owner-v1, transport
pinned-endpoint-tls13-x25519mlkem768-mldsa65-v1, separate signed/stored policy and
request/response domains, and ALPN trnm-pq-endpoint/1. Endpoint records cannot be
opened as an old loopback owner; relabeling a frame does not change its signatures.

PqTlsEndpointPins contains one exact IPv4 address with a nonzero port and a sorted,
unique, bounded list of allowed client IPv4 addresses. Wildcard, multicast,
broadcast and IPv6 values refuse. Explicit private or loopback addresses are
permitted; address selection does not qualify a public network.

The CLI requires both its explicit pinned-endpoint-v1 selection and the new
configuration schema with endpoint and witness configuration. Absent, null,
malformed or legacy combinations refuse before credentials or owner I/O. No
address discovery, NAT substitution, automatic enrollment or fallback is added.

## Current owner boundaries

The endpoint profile requires PqWitnessV4 at owner construction and at the live
policy boundary. The actual listener address and kernel-observed peer IP are
checked; IP permission never supplies TLS/SPKI, native signature or work authority.
Both standalone and shared-owner TLS listeners enforce the exact target and stop
after 64 accepted plus refused connections. That per-service cap is not a durable,
restart-persistent denial-of-service guarantee. Existing profiles keep their
original service behavior.

Both relative-budget and absolute-deadline clients check the same exact target
before connecting. The current full-SPKI comparisons, retained-reply validation,
shared Node owner, original absolute deadlines, durable admission, replay and
native dispatch checks remain in force. All endpoint connections still use
mutual TLS 1.3, the original pinned hybrid group and ML-DSA certificate policy.

## Bounded transport and diagnostic changes

A 16 KiB ciphertext buffer amortizes owner charges without releasing uncharged
received bytes. Buffered reads check the original deadline before and after
access; the 65,536-byte handshake limits and existing connection/application
limits are unchanged. Read-ahead changes the timing and number of debit
transactions and can consume allowance for bytes not yet returned to OpenSSL.
Spent allowance is never refunded. TCP_NODELAY and a bounded first-frame
coalescing buffer preserve frame bytes.

At most 16 listener refusal records expose fixed stage/cause labels and bounded
numeric observations. The first BIO cause is retained. No raw error, payload,
credential or filesystem path enters the diagnostic record. The original error
is returned, with no diagnostic retry. The CLI harness drains the whole child
stderr for length/hash while retaining only a 4 KiB prefix for a closed-schema,
fixed-label projection; unknown fields and labels do not become output.

## Required controls and evidence scope

The required manifest names the original six endpoint library and three CLI
controls, plus two current-integration controls for the absolute-deadline client
and shared listener. Existing loopback, witness, full-SPKI, plaintext refusal and
recovery controls remain separately required. Buffer debit/deadline, exact frame
split and diagnostic projection tests supplement this roster.

A registry listing is only test presence. Each required name must execute exactly
once, pass, and not be ignored. Original and new failures remain in audit records;
source pins or a successful build are not runtime or cryptographic qualification.
The branch audit report records the exact tested source and observed results.
