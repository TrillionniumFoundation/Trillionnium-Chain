use super::*;
use openssl::{
    pkey::{KeyType, PKey, Private},
    ssl::{
        AlpnError, Ssl, SslContext, SslMethod, SslOptions, SslRef, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
    x509::{verify::X509CheckFlags, X509VerifyResult, X509},
};
use sha2::{Digest, Sha256};

const ALPN: &[u8] = b"trnm-pq-node/1";
const ALPN_WIRE: &[u8] = b"\x0etrnm-pq-node/1";

/// Already-loaded operator credentials. This constructor creates no CA, key,
/// policy pin or trust store on disk. An explicit fixture CA has no production
/// custody or deployment status.
pub struct PqTlsIdentity {
    certificate: X509,
    key: PKey<Private>,
    ca_certificate: X509,
}
impl PqTlsIdentity {
    pub fn new(certificate: X509, key: PKey<Private>, ca_certificate: X509) -> Result<Self> {
        ensure(
            certificate.to_der().map_err(crypto)?.len() <= 16_384
                && ca_certificate.to_der().map_err(crypto)?.len() <= 16_384,
            "PQ_TLS_CERTIFICATE_BOUND",
        )?;
        ensure(key.is_a(KeyType::ML_DSA_65), "PQ_TLS_LOCAL_KEY")?;
        let public = certificate.public_key().map_err(crypto)?;
        ensure(
            public.is_a(KeyType::ML_DSA_65) && public.public_eq(&key),
            "PQ_TLS_LOCAL_CERTIFICATE",
        )?;
        let ca = ca_certificate.public_key().map_err(crypto)?;
        ensure(
            ca.is_a(KeyType::ML_DSA_65)
                && ca_certificate.verify(&ca).map_err(crypto)?
                && certificate.verify(&ca).map_err(crypto)?,
            "PQ_TLS_CA_SIGNATURE",
        )?;
        // Both keys use the same strict SPKI encoding accepted by the native
        // PQ owner; an OpenSSL provider alias alone does not establish a pin.
        ml_dsa_65_key_id_from_spki(&public.public_key_to_der().map_err(crypto)?).map_err(crypto)?;
        ml_dsa_65_key_id_from_spki(&ca.public_key_to_der().map_err(crypto)?).map_err(crypto)?;
        Ok(Self {
            certificate,
            key,
            ca_certificate,
        })
    }
}

pub(super) struct TlsContext {
    context: SslContext,
    policy: Arc<PqNetworkPolicy>,
    server: bool,
}
impl TlsContext {
    pub(super) fn new(
        policy: Arc<PqNetworkPolicy>,
        local_id: Hash,
        identity: PqTlsIdentity,
        server: bool,
    ) -> Result<Self> {
        let pins = policy.tls_pins()?;
        let ca_sha256: Hash =
            Sha256::digest(identity.ca_certificate.to_der().map_err(crypto)?).into();
        ensure(ca_sha256 == pins.ca_certificate_sha256(), "PQ_TLS_CA_PIN")?;
        let local_spki = identity.key.public_key_to_der().map_err(crypto)?;
        ensure(
            ml_dsa_65_key_id_from_spki(&local_spki).map_err(crypto)? == local_id
                && if server {
                    local_id == policy.server_id
                } else {
                    policy.peers.contains_key(&local_id)
                },
            "PQ_TLS_LOCAL_PIN",
        )?;
        let mut context = SslContext::builder(SslMethod::tls()).map_err(crypto)?;
        context
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(crypto)?;
        context
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(crypto)?;
        // Unknown/unsupported group or signature names fail construction.
        // No default group, classical-only retry, PSK or early-data path exists.
        context.set_groups_list("X25519MLKEM768").map_err(crypto)?;
        context.set_sigalgs_list("mldsa65").map_err(crypto)?;
        context
            .set_ciphersuites("TLS_AES_256_GCM_SHA384")
            .map_err(crypto)?;
        context.set_session_cache_mode(SslSessionCacheMode::OFF);
        context.set_options(SslOptions::NO_TICKET | SslOptions::NO_RENEGOTIATION);
        context.set_num_tickets(0).map_err(crypto)?;
        context.set_max_early_data(0).map_err(crypto)?;
        context.set_read_ahead(false);
        context.set_verify(if server {
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            SslVerifyMode::PEER
        });
        // Direct issuer only: no intermediate or network-discovered CA.
        // OpenSSL's depth excludes the end entity and its trust anchor.
        context.set_verify_depth(0);
        context
            .cert_store_mut()
            .add_cert(identity.ca_certificate)
            .map_err(crypto)?;
        context
            .set_certificate(&identity.certificate)
            .map_err(crypto)?;
        context.set_private_key(&identity.key).map_err(crypto)?;
        context.check_private_key().map_err(crypto)?;
        if server {
            context.set_alpn_select_callback(|_, offered| {
                openssl::ssl::select_next_proto(ALPN_WIRE, offered).ok_or(AlpnError::ALERT_FATAL)
            });
        } else {
            context.set_alpn_protos(ALPN_WIRE).map_err(crypto)?;
        }
        Ok(Self {
            context: context.build(),
            policy,
            server,
        })
    }

    pub(super) fn session(&self) -> Result<Ssl> {
        let mut ssl = Ssl::new(&self.context).map_err(crypto)?;
        if !self.server {
            let name = self.policy.tls_pins()?.server_name();
            ssl.set_hostname(name).map_err(crypto)?;
            ssl.param_mut()
                .set_hostflags(X509CheckFlags::NO_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT);
            ssl.param_mut().set_host(name).map_err(crypto)?;
        }
        Ok(ssl)
    }

    pub(super) fn admit(&self, ssl: &SslRef) -> Result<TransportAdmission> {
        ensure(
            ssl.version_str() == "TLSv1.3"
                && !ssl.session_reused()
                && ssl.selected_alpn_protocol() == Some(ALPN)
                && ssl.verify_result() == X509VerifyResult::OK,
            "PQ_TLS_HANDSHAKE_PROFILE",
        )?;
        let chain = ssl.verified_chain().ok_or("PQ_TLS_CERTIFICATE_CHAIN")?;
        ensure(chain.len() == 2, "PQ_TLS_CERTIFICATE_CHAIN")?;
        let ca_sha256: Hash = Sha256::digest(chain[1].to_der().map_err(crypto)?).into();
        ensure(
            ca_sha256 == self.policy.tls_pins()?.ca_certificate_sha256(),
            "PQ_TLS_CA_PIN",
        )?;
        let certificate = ssl
            .peer_certificate()
            .ok_or("PQ_TLS_MUTUAL_CERTIFICATE_REQUIRED")?;
        ensure(
            certificate.to_der().map_err(crypto)?.len() <= 16_384,
            "PQ_TLS_CERTIFICATE_BOUND",
        )?;
        let public = certificate.public_key().map_err(crypto)?;
        ensure(public.is_a(KeyType::ML_DSA_65), "PQ_TLS_PEER_KEY")?;
        let peer = ml_dsa_65_key_id_from_spki(&public.public_key_to_der().map_err(crypto)?)
            .map_err(crypto)?;
        ensure(
            if self.server {
                self.policy.peers.contains_key(&peer)
            } else {
                peer == self.policy.server_id
            },
            "PQ_TLS_PEER_PIN",
        )?;
        // rust-openssl 0.10.81 has no safe negotiated-group getter. The group
        // claim is a configuration inference from the private immutable context
        // containing exactly one group, not an observed cipher/group identity.
        Ok(TransportAdmission::Tls {
            policy: self.policy.id,
            peer,
        })
    }
}
