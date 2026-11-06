//! Test-only CA/identities with public deterministic seeds. DER is assembled
//! only to let rust-openssl 0.10.81 sign X509 TBS bytes with the real pure ML-DSA
//! provider: its X509Builder::sign API cannot express a null digest. There is
//! no signature stub, production enrollment or external TLS subprocess.
use super::{PqNetworkPolicy, PqTlsClient, PqTlsIdentity, PqTlsPins, PqTlsServer, Settings};
use openssl::{
    pkey::{KeyType, PKey, Private},
    sign::Signer,
    x509::X509,
};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

pub(super) struct Identity {
    pub key: PKey<Private>,
    pub certificate: X509,
}
impl Identity {
    pub fn signer(&self) -> PqNativeSigningKey {
        let spki = self.key.public_key_to_der().unwrap();
        PqNativeSigningKey::from_owned_key(
            self.key.clone(),
            ml_dsa_65_key_id_from_spki(&spki).unwrap(),
        )
        .unwrap()
    }
    pub fn tls(&self, ca: &X509) -> PqTlsIdentity {
        PqTlsIdentity::new(self.certificate.clone(), self.key.clone(), ca.clone()).unwrap()
    }
}
pub(super) struct Fixture {
    pub settings: Settings,
    pub policy: Arc<PqNetworkPolicy>,
    pub ca: X509,
    pub server: Identity,
    pub peer: Identity,
    pub other: Identity,
}
impl Fixture {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let settings = Settings::development(Some(now - 100)).unwrap();
        let root = key(61);
        let ca = certificate(
            &root,
            &root,
            "TRNM TLS fixture CA",
            "TRNM TLS fixture CA",
            true,
            1,
        );
        let identity = |seed, subject| {
            let key = key(seed);
            let certificate = certificate(&key, &root, subject, "TRNM TLS fixture CA", false, seed);
            Identity { key, certificate }
        };
        let server = identity(71, "server");
        let peer = identity(72, "peer");
        let other = identity(73, "other");
        let policy = Arc::new(
            PqNetworkPolicy::new_tls13(
                &settings,
                &server.key.public_key_to_der().unwrap(),
                1,
                [
                    peer.key.public_key_to_der().unwrap(),
                    other.key.public_key_to_der().unwrap(),
                ],
                PqTlsPins::new(
                    Sha256::digest(ca.to_der().unwrap()).into(),
                    "localhost".into(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        Self {
            settings,
            policy,
            ca,
            server,
            peer,
            other,
        }
    }
    pub fn client(&self) -> PqTlsClient {
        PqTlsClient::new(
            self.policy.clone(),
            self.peer.signer(),
            self.peer.tls(&self.ca),
        )
        .unwrap()
    }
    pub fn policy_for_server_name(&self, name: &str) -> Arc<PqNetworkPolicy> {
        Arc::new(
            PqNetworkPolicy::new_tls13(
                &self.settings,
                &self.server.key.public_key_to_der().unwrap(),
                1,
                [
                    self.peer.key.public_key_to_der().unwrap(),
                    self.other.key.public_key_to_der().unwrap(),
                ],
                PqTlsPins::new(
                    self.policy.tls_pins().unwrap().ca_certificate_sha256(),
                    name.into(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
    }
    #[allow(dead_code)] // Used by the lib fixture; shared ordinary-CLI tests launch the real binary.
    pub fn server(&self) -> PqTlsServer {
        PqTlsServer::new(
            self.policy.clone(),
            self.server.signer(),
            self.server.tls(&self.ca),
        )
        .unwrap()
    }
}

pub(super) fn key(seed: u8) -> PKey<Private> {
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap()
}
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let length = (body.len() as u64).to_be_bytes();
        let significant = &length[length.iter().position(|b| *b != 0).unwrap()..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(body);
    out
}
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn name(cn: &str) -> Vec<u8> {
    sequence(&[der(
        0x31,
        &sequence(&[der(6, &[0x55, 4, 3]), der(0x0c, cn.as_bytes())]),
    )])
}
fn extension(oid: u8, critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![der(6, &[0x55, 0x1d, oid])];
    if critical {
        parts.push(der(1, &[0xff]));
    }
    parts.push(der(4, &value));
    sequence(&parts)
}
pub(super) fn certificate(
    subject: &PKey<Private>,
    issuer: &PKey<Private>,
    subject_name: &str,
    issuer_name: &str,
    ca: bool,
    serial: u8,
) -> X509 {
    certificate_with_profile(
        subject,
        issuer,
        subject_name,
        issuer_name,
        ca,
        serial,
        &CertificateProfile::default(),
    )
}

#[derive(Clone, Copy)]
pub(super) struct CertificateProfile {
    pub dns_name: Option<&'static str>,
    pub not_before: &'static [u8],
    pub not_after: &'static [u8],
    pub extended_key_usage: &'static [u8],
}
impl Default for CertificateProfile {
    fn default() -> Self {
        Self {
            dns_name: Some("localhost"),
            not_before: b"250101000000Z",
            not_after: b"21250101000000Z",
            extended_key_usage: &[1, 2],
        }
    }
}

// The library and actual binary must reject the same signed, correctly pinned
// server certificates. The wildcard would match node.localhost if permitted;
// CN-only certificates use the exact requested common name in both callers.
pub(super) fn local_server_refusal_cases() -> [(&'static str, &'static str, CertificateProfile); 6]
{
    [
        (
            "wrong SAN",
            "localhost",
            CertificateProfile {
                dns_name: Some("wrong.localhost"),
                ..CertificateProfile::default()
            },
        ),
        (
            "CN without SAN",
            "localhost",
            CertificateProfile {
                dns_name: None,
                ..CertificateProfile::default()
            },
        ),
        (
            "wildcard SAN",
            "node.localhost",
            CertificateProfile {
                dns_name: Some("*.localhost"),
                ..CertificateProfile::default()
            },
        ),
        (
            "expired",
            "localhost",
            CertificateProfile {
                not_before: b"230101000000Z",
                not_after: b"240101000000Z",
                ..CertificateProfile::default()
            },
        ),
        (
            "not yet valid",
            "localhost",
            CertificateProfile {
                not_before: b"21200101000000Z",
                ..CertificateProfile::default()
            },
        ),
        (
            "client-only purpose",
            "localhost",
            CertificateProfile {
                extended_key_usage: &[2],
                ..CertificateProfile::default()
            },
        ),
    ]
}

pub(super) fn certificate_with_profile(
    subject: &PKey<Private>,
    issuer: &PKey<Private>,
    subject_name: &str,
    issuer_name: &str,
    ca: bool,
    serial: u8,
    profile: &CertificateProfile,
) -> X509 {
    // id-ml-dsa-65: 2.16.840.1.101.3.4.3.18, no algorithm parameters.
    let algorithm = sequence(&[der(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12])]);
    let spki = subject.public_key_to_der().unwrap();
    let ski = Sha256::digest(&spki);
    let aki = Sha256::digest(issuer.public_key_to_der().unwrap());
    let mut extensions = vec![
        extension(
            0x13,
            true,
            if ca {
                sequence(&[der(1, &[0xff]), der(2, &[0])])
            } else {
                sequence(&[])
            },
        ),
        extension(0x0f, true, der(3, if ca { &[1, 6] } else { &[7, 0x80] })),
        extension(0x0e, false, der(4, &ski[..20])),
        extension(0x23, false, sequence(&[der(0x80, &aki[..20])])),
    ];
    if !ca {
        if let Some(name) = profile.dns_name {
            extensions.push(extension(
                0x11,
                false,
                sequence(&[der(0x82, name.as_bytes())]),
            ));
        }
        extensions.push(extension(
            0x25,
            false,
            sequence(
                &profile
                    .extended_key_usage
                    .iter()
                    .map(|purpose| der(6, &[0x2b, 6, 1, 5, 5, 7, 3, *purpose]))
                    .collect::<Vec<_>>(),
            ),
        ));
    }
    let time = |bytes: &[u8]| der(if bytes.len() == 13 { 0x17 } else { 0x18 }, bytes);
    let tbs = sequence(&[
        der(0xa0, &der(2, &[2])),
        der(2, &[serial]),
        algorithm.clone(),
        name(issuer_name),
        sequence(&[time(profile.not_before), time(profile.not_after)]),
        name(subject_name),
        spki,
        der(0xa3, &sequence(&extensions)),
    ]);
    let mut signer = Signer::new_without_digest(issuer).unwrap();
    let signature = signer.sign_oneshot_to_vec(&tbs).unwrap();
    let mut bits = vec![0];
    bits.extend_from_slice(&signature);
    let cert = X509::from_der(&sequence(&[tbs, algorithm, der(3, &bits)])).unwrap();
    assert!(cert.verify(issuer).unwrap());
    cert
}
