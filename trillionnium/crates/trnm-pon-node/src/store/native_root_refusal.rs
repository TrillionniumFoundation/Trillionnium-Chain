//! Private provenance of one actual completed native output mismatch.
//! The public scheduler may postpone only the same canonical body in the same
//! domain. This is not a validity verdict, a State cache, or commit authority.
use super::{Hash, Settings};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) struct NativeRootRefusal {
    context: [Hash; 3],
    body: Hash,
}
impl NativeRootRefusal {
    // Only store's original held and detached final comparison call this.
    // No Default, Clone, Deserialize, or external constructor is supplied.
    pub(super) fn after_complete_output_comparison(
        context: [Hash; 3],
        packet: &[u8],
        expected: (Hash, Hash),
        actual: (Hash, Hash),
    ) -> Option<Self> {
        if expected == actual || packet.is_empty() || packet.len() > 1_048_576 {
            return None;
        }
        let prefix = br#"{"op":"submit","packet":""#;
        let suffix = br#""}"#;
        let tag = b"public-request-body-v3";
        let body_len = u32::try_from(prefix.len() + 2 * packet.len() + suffix.len()).ok()?;
        let mut digest = Sha256::new();
        // Exact original pon_wire::hash(tag, &[canonical_body]) grammar. The
        // transport hashes the domain and one complete body length as well.
        digest.update(b"TRNM-PON1\0");
        digest.update((tag.len() as u16).to_le_bytes());
        digest.update(tag);
        digest.update(body_len.to_le_bytes());
        digest.update(prefix);
        // Stream the exact canonical lowercase hexadecimal envelope. No extra
        // retained packet/body allocation or guest row is introduced.
        let mut text = [0_u8; 512];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in packet.chunks(text.len() / 2) {
            for (index, byte) in chunk.iter().enumerate() {
                text[2 * index] = HEX[(byte >> 4) as usize];
                text[2 * index + 1] = HEX[(byte & 15) as usize];
            }
            digest.update(&text[..2 * chunk.len()]);
        }
        digest.update(suffix);
        Some(Self {
            context,
            body: digest.finalize().into(),
        })
    }

    pub(crate) fn matches(&self, settings: &Settings, body_digest: &str) -> Option<Hash> {
        if self.context
            != [
                settings.network(),
                settings.parameters(),
                settings.genesis(),
            ]
        {
            return None;
        }
        let mut claimed = [0; 32];
        hex::decode_to_slice(body_digest, &mut claimed).ok()?;
        (claimed == self.body).then_some(self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_native_comparison_matches_exact_wire_and_every_domain_component() {
        let settings = Settings::development(Some(1)).unwrap();
        let context = [
            settings.network(),
            settings.parameters(),
            settings.genesis(),
        ];
        for size in [1, 255, 256, 257, 1024, 1_048_576] {
            let packet: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let wire = serde_json::to_vec(&crate::ingress::public_v3::Request::Submit {
                packet: hex::encode(&packet),
            })
            .unwrap();
            let body = trnm_protocol::pon_wire::hash(b"public-request-body-v3", &[&wire]);
            let proof = NativeRootRefusal::after_complete_output_comparison(
                context,
                &packet,
                ([1; 32], [2; 32]),
                ([3; 32], [2; 32]),
            )
            .unwrap();
            assert_eq!(proof.matches(&settings, &hex::encode(body)), Some(body));
            assert_eq!(
                proof.matches(&settings, &hex::encode(Sha256::digest(&wire))),
                None,
                "plain SHA256 is not the authenticated public body digest",
            );
            let mut wrong_body = body;
            wrong_body[31] ^= 1;
            assert_eq!(proof.matches(&settings, &hex::encode(wrong_body)), None);
            assert_eq!(proof.matches(&settings, "ROOT"), None);
            for field in 0..3 {
                let mut changed = context;
                changed[field][31] ^= 1;
                let foreign = NativeRootRefusal::after_complete_output_comparison(
                    changed,
                    &packet,
                    ([1; 32], [2; 32]),
                    ([3; 32], [2; 32]),
                )
                .unwrap();
                assert_eq!(foreign.matches(&settings, &hex::encode(body)), None);
            }
        }
        assert!(NativeRootRefusal::after_complete_output_comparison(
            context,
            &[1],
            ([1; 32], [2; 32]),
            ([1; 32], [2; 32]),
        )
        .is_none());
        assert!(NativeRootRefusal::after_complete_output_comparison(
            context,
            &[],
            ([1; 32], [2; 32]),
            ([3; 32], [2; 32]),
        )
        .is_none());
    }
}
