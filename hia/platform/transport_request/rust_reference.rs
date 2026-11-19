//! Test-only access to the original private request/frame functions.
//!
//! The driver copies the original Cargo source into a fresh output directory,
//! preserves every original ingress.rs byte, then appends a cfg(test) module
//! declaration referring to this file. No production function is substituted.
use super::*;
use std::io::BufRead;
use std::net::Shutdown;

const MARKER: &str = "HIA_TRANSPORT_ORACLE:";

fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}

fn emit(value: Value) {
    println!("{MARKER}{}", serde_json::to_string(&value).unwrap());
}

fn family(error: &Error) -> u64 {
    if error.kind() == crate::ErrorKind::Serialization {
        return 3;
    }
    let text = error.to_string();
    match text.as_str() {
        "FRAME_EOF" => 1,
        "FRAME_LIMIT" => 2,
        "AUTH_NONCANONICAL" => 4,
        "AUTH_SCHEMA" => 5,
        "AUTH_PEER_NOT_ALLOWED" => 6,
        "AUTH_SESSION_CONTEXT" => 7,
        "AUTH_REPLAY_NONCE" => 8,
        _ if text.starts_with("AUTH_SIGNATURE:") => 9,
        _ if text.starts_with("AUTH_SESSION:") => 10,
        _ if text.starts_with("AUTH_FRAME:") => 11,
        _ => panic!("Unclassified original error: {text}"),
    }
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn metadata(verified: &VerifiedAuthenticatedRequest, body: &[u8]) -> Vec<u8> {
    let (operation, query_count) = match &verified.request {
        Request::Head => (1, 0),
        Request::Submit { .. } => (2, 0),
        Request::History { .. } => (3, 0),
        Request::Confirm { .. } => (4, 0),
        Request::ConfirmMany { queries } => (5, queries.len() as u64),
    };
    let token = b"\"request\":";
    let offset = body.windows(token.len()).position(|part| part == token).unwrap()
        + token.len() + 4;
    assert_eq!(body.get(offset - 4..offset - 4 + verified.payload.len()),
        Some(verified.payload.as_slice()));
    let mut result = Vec::with_capacity(384);
    for value in [body.len() as u64 + 4, offset as u64, verified.payload.len() as u64,
        verified.frame.replay_nonce(), verified.session.generation, operation]
    {
        result.extend_from_slice(&value.to_le_bytes());
    }
    let session = verified.frame.session();
    for value in [verified.request_digest, verified.frame.payload_digest().bytes(),
        session.peer_id().bytes(), session.session_id().bytes(),
        session.profile_digest().bytes(), session.chain_id().bytes(),
        session.protocol_digest().bytes(), digest(&verified.session.network).unwrap(),
        digest(&verified.session.peer).unwrap(), digest(&verified.session.server).unwrap()]
    {
        result.extend_from_slice(&value);
    }
    result.extend_from_slice(&query_count.to_le_bytes());
    result.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(result.len(), 384);
    result
}

fn describe(settings: &Settings) {
    let peer = identity(72);
    let server = identity(71);
    let client = AuthenticatedClient::new(peer, server.public_key().into(), 1).unwrap();
    let requests = [
        Request::Head,
        Request::Submit { packet: "deadbeef".into() },
        Request::History { tip: "UPPERCASE".into(), after: String::new() },
        Request::Confirm { transaction: "x".into(), block: String::new() },
        Request::ConfirmMany { queries: vec![ConfirmationQuery {
            transaction: "x".into(), block: "y".into() }] },
    ];
    let goldens: Vec<_> = requests.into_iter().map(|request| {
        let wire = authenticated_request_bytes(settings, &client, 1, request).unwrap();
        hex::encode(wire)
    }).collect();
    emit(json!({"mode":"describe", "network":hex::encode(settings.network()),
        "parameters":hex::encode(settings.parameters()), "genesis":hex::encode(settings.genesis()),
        "peer":client.public_key(), "server":server.public_key(), "generation":1,
        "original_request_goldens":goldens}));
}

fn verify_case(settings: &Settings, row: Value) {
    let name = row["name"].as_str().unwrap();
    let captured = std::fs::read(row["input_path"].as_str().unwrap()).unwrap();
    assert!(captured.len() >= 184);
    assert_eq!(&captured[..8], b"TRNMAQ01");
    assert_eq!(&captured[16..48], &settings.network());
    assert_eq!(&captured[48..80], &settings.parameters());
    assert_eq!(&captured[80..112], &settings.genesis());
    let server_identity = identity(71);
    assert_eq!(hex::encode(&captured[112..144]), server_identity.public_key());
    let count = usize::try_from(word(&captured, 144)).unwrap();
    assert!((1..=64).contains(&count));
    let start = 152 + count * 32;
    let peers = captured[152..start].chunks_exact(32).map(hex::encode).collect::<Vec<_>>();
    let server = AuthenticatedServer::new(server_identity, peers, word(&captured, 8)).unwrap();
    let wire = captured[start..].to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sender = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let result = stream.write_all(&wire);
        let _ = stream.shutdown(Shutdown::Write);
        result.map_err(|error| error.to_string())
    });
    let (mut stream, _) = listener.accept().unwrap();
    let decoded = read_frame_deadline(&mut stream, Instant::now() + Duration::from_secs(5));
    let mut remaining = Vec::new();
    let value = match decoded {
        Ok(body) => match authenticate_request(&body, settings, &server) {
            Ok(verified) => {
                assert_eq!(verified.wire, body);
                stream.read_to_end(&mut remaining).unwrap();
                json!({"name":name, "code":0, "metadata_hex":hex::encode(metadata(&verified, &body)),
                    "payload_bytes":verified.payload.len(), "remaining_frame_hex":hex::encode(&remaining),
                    "original_frame_body_bytes":body.len()})
            }
            Err(error) => json!({"name":name, "code":family(&error),
                "diagnostic":error.to_string(), "kind":format!("{:?}",error.kind())}),
        },
        Err(error) => json!({"name":name, "code":family(&error),
            "diagnostic":error.to_string(), "kind":format!("{:?}",error.kind())}),
    };
    drop(stream);
    let sender_result = sender.join().unwrap();
    if value["code"] == 0 {
        sender_result.unwrap();
    }
    emit(value);
}

#[test]
fn evaluate() {
    let settings = Settings::development(Some(1)).unwrap();
    match std::env::var("TRNM_HIA_TRANSPORT_ORACLE_MODE").unwrap().as_str() {
        "describe" => describe(&settings),
        "verify" => {
            let path = std::env::var("TRNM_HIA_TRANSPORT_ORACLE_CORPUS").unwrap();
            let file = std::fs::File::open(path).unwrap();
            for line in std::io::BufReader::new(file).lines() {
                verify_case(&settings, serde_json::from_str(&line.unwrap()).unwrap());
            }
        }
        other => panic!("Unknown oracle mode: {other}"),
    }
}
