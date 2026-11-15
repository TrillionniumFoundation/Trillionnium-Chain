//! A private proof of the same paid body's canonical Submit text.
//! It grants no packet, Work, owner, State, deadline or resource authority.
//! Only this module can construct the borrowed witness; ordinary strings keep
//! the original checked decoder and the full Packet codec remains mandatory.
use super::{body_maximum, ensure, lower_hex, Request, Result, MAX_BODY, MAX_PACKET};

/// Bytes for one client call, with a private proof of canonical Submit text.
/// Valid lowercase hexadecimal needs no JSON escaping. Build that exact serde
/// envelope once, without allocating an owned Packet string merely to discard
/// it. All other input retains the original serializer and checked decoder.
pub(super) struct EncodedClientRequest {
    bytes: Vec<u8>,
    canonical_submit: bool,
}

impl EncodedClientRequest {
    pub(super) fn new(request: &Request) -> Result<Self> {
        const PREFIX: &[u8] = br#"{"op":"submit","packet":""#;
        const SUFFIX: &[u8] = br#""}"#;
        if let Request::Submit { packet } = request {
            let text = packet.as_bytes();
            if text.len() <= 2 * MAX_PACKET
                && text.len().is_multiple_of(2)
                && PREFIX.len() + text.len() + SUFFIX.len() <= MAX_BODY
                && lower_hex(text)
            {
                let mut bytes = Vec::with_capacity(PREFIX.len() + text.len() + SUFFIX.len());
                bytes.extend_from_slice(PREFIX);
                bytes.extend_from_slice(text);
                bytes.extend_from_slice(SUFFIX);
                return Ok(Self {
                    bytes,
                    canonical_submit: true,
                });
            }
        }
        // Malformed/escaped/oversized strings still serialize before the
        // caller's original profile check. Validation remains after that
        // check, preserving the original error precedence for every input.
        Ok(Self {
            bytes: serde_json::to_vec(request)?,
            canonical_submit: false,
        })
    }

    pub(super) fn into_validated_bytes(self, op: u8) -> Result<Vec<u8>> {
        if !self.canonical_submit || op != 1 {
            super::canonical_request(&self.bytes, op)?;
        }
        // Only transport grammar is established. The signed body digest,
        // complete Packet codec, Work and current native owner still run.
        Ok(self.bytes)
    }
}

pub(super) struct CanonicalPacketText<'a> {
    text: &'a str,
}
impl<'a> CanonicalPacketText<'a> {
    pub(super) fn from_body(bytes: &'a [u8]) -> Result<Self> {
        ensure(
            !bytes.is_empty() && bytes.len() <= body_maximum(1)?,
            "PUBLIC_BODY_LIMIT",
        )?;
        let text = bytes
            .strip_prefix(br#"{"op":"submit","packet":""#)
            .and_then(|b| b.strip_suffix(br#""}"#))
            .ok_or("PUBLIC_REQUEST_CANONICAL")?;
        ensure(
            text.len() <= 2 * MAX_PACKET && text.len().is_multiple_of(2) && lower_hex(text),
            "PUBLIC_PACKET_TEXT",
        )?;
        let text = std::str::from_utf8(text).map_err(|_| "PUBLIC_PACKET_TEXT")?;
        Ok(Self { text })
    }

    fn decode(&self) -> Result<crate::Packet> {
        // The immutable borrow is the exact fully checked ASCII text above.
        // Convert it without another classification or owned hexadecimal copy.
        // This bounded binary allocation and the codec's owned proof/transaction
        // copies remain in the original charged Decode interval.
        let raw: Vec<u8> = self
            .text
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] & 15) + 9 * (pair[0] >> 6);
                let low = (pair[1] & 15) + 9 * (pair[1] >> 6);
                (high << 4) | low
            })
            .collect();
        crate::Packet::decode(&raw)
    }
}

pub(super) enum DecodedTaskBody<'a> {
    Owned(Request),
    CanonicalSubmit(CanonicalPacketText<'a>),
}
impl From<Request> for DecodedTaskBody<'_> {
    fn from(request: Request) -> Self {
        Self::Owned(request)
    }
}

pub(super) enum SubmitPacketText<'a> {
    Owned(String),
    Canonical(CanonicalPacketText<'a>),
}
impl SubmitPacketText<'_> {
    pub(super) fn decode(&self) -> Result<crate::Packet> {
        match self {
            Self::Owned(text) => super::super::hex_packet(text),
            Self::Canonical(text) => text.decode(),
        }
    }
}

#[cfg(test)]
mod tests;
