//! Experimental native composition; never imports Python or activates production.
#![forbid(unsafe_code)]
pub mod consensus;
pub mod ingress;
mod store;
use serde_json::{json, Value};
use std::{error, fmt};
pub use store::{ConfirmationBatch, Node, Observation};
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::pon_executor::{self, Config, State};
use trnm_protocol::pon_wire::{hash, Envelope, Hash, Header, HEADER_BYTES};

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl error::Error for Error {}
impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Self(e.into())
    }
}
impl From<String> for Error {
    fn from(e: String) -> Self {
        Self(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(format!("IO: {e}"))
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self(format!("STORAGE: {e}"))
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self(format!("JSON: {e}"))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn digest(text: &str) -> Result<Hash> {
    ensure(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "HASH",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| Error::from("HASH"))?;
    Ok(out)
}
pub fn sequence_root(tag: &str, items: &[Vec<u8>]) -> Hash {
    let mut leaves: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(i, b)| {
            hash(
                format!("{tag}-leaf").as_bytes(),
                &[&(i as u64).to_le_bytes(), b],
            )
        })
        .collect();
    if leaves.is_empty() {
        return hash(format!("{tag}-empty").as_bytes(), &[]);
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().expect("nonempty"));
        }
        leaves = leaves
            .chunks_exact(2)
            .map(|p| hash(format!("{tag}-node").as_bytes(), &[&p[0], &p[1]]))
            .collect();
    }
    leaves[0]
}

/// Fixed-size work packet. Decoding grants neither work nor state authority.
#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub transactions: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
}
impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure(
            self.transactions.len() <= 256 && self.proof.len() == pon_work::PROOF_BYTES,
            "PACKET_LIMIT",
        )?;
        let mut out = self.header.encode();
        out.extend((self.transactions.len() as u16).to_le_bytes());
        for tx in &self.transactions {
            ensure((159..=2048).contains(&tx.len()), "TRANSACTION_LIMIT")?;
            Envelope::decode(tx).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
            out.extend((tx.len() as u16).to_le_bytes());
            out.extend(tx);
        }
        out.extend(&self.proof);
        ensure(out.len() <= 1_048_576, "PACKET_LIMIT")?;
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure(
            (HEADER_BYTES + 2 + pon_work::PROOF_BYTES..=1_048_576).contains(&bytes.len()),
            "PACKET_LIMIT",
        )?;
        let header =
            Header::decode(&bytes[..HEADER_BYTES]).map_err(|_| Error::from("HEADER_CODEC"))?;
        let count = u16::from_le_bytes([bytes[HEADER_BYTES], bytes[HEADER_BYTES + 1]]) as usize;
        ensure(count <= 256, "TRANSACTION_LIMIT")?;
        let mut pos = HEADER_BYTES + 2;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let len = bytes.get(pos..pos + 2).ok_or("PACKET_LENGTH")?;
            let n = u16::from_le_bytes([len[0], len[1]]) as usize;
            pos += 2;
            ensure((159..=2048).contains(&n), "TRANSACTION_LIMIT")?;
            let tx = bytes.get(pos..pos + n).ok_or("PACKET_LENGTH")?;
            Envelope::decode(tx).map_err(|_| Error::from("TRANSACTION_CODEC"))?;
            transactions.push(tx.to_vec());
            pos += n;
        }
        ensure(bytes.len() - pos == pon_work::PROOF_BYTES, "PACKET_LENGTH")?;
        Ok(Self {
            header,
            transactions,
            proof: bytes[pos..].to_vec(),
        })
    }
    pub fn id(&self) -> Result<Hash> {
        ensure(self.proof.len() == pon_work::PROOF_BYTES, "WORK_LENGTH")?;
        let mut trace = [0; 32];
        trace.copy_from_slice(&self.proof[self.proof.len() - 32..]);
        Ok(self.header.block_id(trace))
    }
}

#[derive(Clone)]
pub struct Settings {
    pub(crate) app: Config,
    pub(crate) genesis: Hash,
    pub(crate) initial: State,
}
impl Settings {
    /// An explicit new timestamp selects a distinct valueless devnet, not a hot upgrade.
    pub fn development(genesis_timestamp: Option<u64>) -> Result<Self> {
        let mut app = Config::installed()?;
        if let Some(time) = genesis_timestamp {
            ensure(time > 0 && time <= i64::MAX as u64, "GENESIS_TIME")?;
            app.params["genesis_timestamp"] = json!(time);
            let label = format!("trnm-pon-native-wall-devnet-3-{time}");
            app.params["chain_label"] = json!(label);
            app.network = hash(b"network", &[label.as_bytes()]);
            let wire: Value =
                serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))?;
            let work: Value =
                serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))?;
            let model: Value =
                serde_json::from_str(include_str!("../../../../config/pon/model-family-v1.json"))?;
            app.parameters = hash(
                b"parameters",
                &[
                    &serde_json::to_vec(&app.params)?,
                    &serde_json::to_vec(&wire)?,
                    &serde_json::to_vec(&work)?,
                    &serde_json::to_vec(&model)?,
                ],
            );
        }
        let (a, b) = maintenance();
        let task = pon_work::task_id(&a, &b).map_err(|_| Error::from("WORK_TASK"))?;
        let mut initial = State::new();
        let count = app.params["genesis_accounts"].as_u64().ok_or("CONFIG")?;
        let funding = app.params["genesis_funding_units_per_account"]
            .as_u64()
            .ok_or("CONFIG")?;
        initial.insert(
            "meta:issued".into(),
            json!(count.checked_mul(funding).ok_or("CONFIG")?),
        );
        initial.insert("model:current".into(), json!(hex::encode([0; 32])));
        initial.insert(format!("work:{}", hex::encode(task)), json!(true));
        for i in 0..count {
            initial.insert(
                format!("account:{}", hex::encode(development_public(i)?)),
                json!({"balance":funding,"nonce":0}),
            );
        }
        let time = app.params["genesis_timestamp"].as_u64().ok_or("CONFIG")?;
        let genesis = hash(
            b"genesis",
            &[
                &app.network,
                &app.parameters,
                &pon_executor::root(&initial)?,
                &time.to_le_bytes(),
            ],
        );
        Ok(Self {
            app,
            genesis,
            initial,
        })
    }
    pub fn network(&self) -> Hash {
        self.app.network
    }
    pub fn parameters(&self) -> Hash {
        self.app.parameters
    }
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
    pub fn genesis_time(&self) -> u64 {
        self.app.params["genesis_timestamp"]
            .as_u64()
            .expect("validated settings")
    }
    pub(crate) fn limit(&self, name: &str) -> Result<u64> {
        self.app.params[name]
            .as_u64()
            .ok_or_else(|| "CONFIG".into())
    }
    pub(crate) fn target(&self, name: &str) -> Result<Hash> {
        digest(self.app.params[name].as_str().ok_or("CONFIG")?)
    }
}
pub fn maintenance() -> (Vec<u32>, Vec<u32>) {
    (
        (0..pon_work::CELLS).map(|i| (i % 31) as u32).collect(),
        (0..pon_work::CELLS)
            .map(|i| ((i * 7) % 37) as u32)
            .collect(),
    )
}
/// These identities are publicly known test identities, never production key custody.
pub fn development_public(i: u64) -> Result<Hash> {
    let seed = hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()]);
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
        .map_err(|_| Error::from("DEV_KEY"))?;
    digest(&trnm_crypto_primitives::public_key_hex(&key))
}
