//! Test-only calls to the retained original Node response/frame and serde paths.
//! The isolated driver preserves original production bytes and appends only a
//! cfg(test) module declaration. JVT2 constructs test Values; it is not a copied
//! response parser, authority hash, signer, canonicalizer or authentication path.
use super::*;
use std::io::BufRead;
use std::net::Shutdown;

const MARKER: &str = "HIA_RESPONSE_ORACLE:";

fn emit(value: Value) {
    println!("{MARKER}{}", serde_json::to_string(&value).unwrap());
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn small_word(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}

fn family(error: &Error) -> u64 {
    if error.kind() == crate::ErrorKind::Serialization {
        return 3;
    }
    let text = error.to_string();
    match text.as_str() {
        "FRAME_EOF" => 1,
        "FRAME_LIMIT" => 2,
        "AUTH_RESPONSE_NONCANONICAL" => 4,
        "AUTH_RESPONSE_CONTEXT" => 5,
        _ if text.starts_with("AUTH_RESPONSE_SIGNATURE:") => 6,
        _ => panic!("Unclassified original response error: {text}"),
    }
}

fn context(bytes: &[u8]) -> AuthSession {
    assert!(bytes.len() >= 280);
    AuthSession {
        network: hex::encode(&bytes[16..48]),
        parameters: hex::encode(&bytes[48..80]),
        genesis: hex::encode(&bytes[80..112]),
        profile: hex::encode(&bytes[112..144]),
        peer: hex::encode(&bytes[144..176]),
        server: hex::encode(&bytes[176..208]),
        session: hex::encode(&bytes[208..240]),
        generation: word(bytes, 8),
    }
}

fn metadata(body: &[u8], session: &AuthSession, nonce: u64) -> Vec<u8> {
    let response: AuthenticatedResponse = serde_json::from_slice(body).unwrap();
    let value = serde_json::to_vec(&response.value).unwrap();
    let token = b"\"value\":";
    let start = body.windows(token.len()).position(|part| part == token).unwrap() + token.len();
    assert_eq!(&body[start..start + value.len()], value.as_slice());
    let mut result = Vec::new();
    for word in [body.len() as u64 + 4, start as u64 + 4, value.len() as u64,
        u64::from(response.terminal), u64::from(response.ok)] {
        result.extend_from_slice(&word.to_le_bytes());
    }
    result.extend_from_slice(&response_authority_digest(&response).unwrap());
    for word in [nonce, session.generation, 0] {
        result.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(result.len(), 96);
    result
}

fn describe(settings: &Settings) {
    let peer = identity(72);
    let server = identity(71);
    let client = AuthenticatedClient::new(peer, server.public_key().into(), 1).unwrap();
    let requests = [Request::Head, Request::Submit { packet: "deadbeef".into() },
        Request::History { tip: "UPPERCASE".into(), after: String::new() },
        Request::Confirm { transaction: "x".into(), block: String::new() },
        Request::ConfirmMany { queries: vec![ConfirmationQuery {
            transaction: "x".into(), block: "y".into() }] }];
    let goldens: Vec<_> = requests.into_iter().map(|request| {
        hex::encode(authenticated_request_bytes(settings, &client, 1, request).unwrap())
    }).collect();
    emit(json!({"mode":"describe", "network":hex::encode(settings.network()),
        "parameters":hex::encode(settings.parameters()), "genesis":hex::encode(settings.genesis()),
        "peer":client.public_key(), "server":server.public_key(), "generation":1,
        "original_request_goldens":goldens}));
}

fn tape_value(bytes: &[u8], at: &mut usize, depth: usize) -> Value {
    let tag = bytes[*at];
    let length = small_word(bytes, *at + 1);
    *at += 5;
    let end = at.checked_add(length).unwrap();
    assert!(end <= bytes.len());
    let value = match tag {
        0 => { assert_eq!(length, 0); Value::Null }
        1 | 2 => { assert_eq!(length, 0); Value::Bool(tag == 2) }
        3 => { assert_eq!(length, 8); let value = word(bytes, *at); *at += 8; Value::from(value) }
        4 => { assert_eq!(length, 8); let value = word(bytes, *at) as i64; *at += 8; Value::from(value) }
        5 => { assert_eq!(length, 8); let value = f64::from_bits(word(bytes, *at)); *at += 8;
            Value::Number(serde_json::Number::from_f64(value).unwrap()) }
        6 => { let value = std::str::from_utf8(&bytes[*at..end]).unwrap().to_owned(); *at = end;
            Value::String(value) }
        7 => {
            assert!(depth < 127);
            let count = small_word(bytes, *at); *at += 4;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count { values.push(tape_value(bytes, at, depth + 1)); }
            Value::Array(values)
        }
        8 => {
            assert!(depth < 127);
            let count = small_word(bytes, *at); *at += 4;
            let mut values = serde_json::Map::new();
            let mut previous: Option<String> = None;
            for _ in 0..count {
                let size = small_word(bytes, *at); *at += 4;
                let key = std::str::from_utf8(&bytes[*at..*at + size]).unwrap().to_owned(); *at += size;
                if let Some(old) = &previous { assert!(old < &key); }
                previous = Some(key.clone());
                assert!(values.insert(key, tape_value(bytes, at, depth + 1)).is_none());
            }
            Value::Object(values)
        }
        _ => panic!("Malformed test-only JVT2 tag"),
    };
    assert_eq!(*at, end);
    value
}

fn tape(bytes: &[u8]) -> Value {
    assert_eq!(&bytes[..4], b"JVT2");
    assert!(bytes[4] <= 1);
    let mut at = 5;
    let value = tape_value(bytes, &mut at, usize::from(bytes[4]));
    assert_eq!(at, bytes.len());
    value
}

fn write_result(row: &Value, code: u64, bytes: &[u8]) {
    std::fs::write(row["output_path"].as_str().unwrap(), bytes).unwrap();
    emit(json!({"name":row["name"], "code":code, "output_bytes":bytes.len()}));
}

fn produce(settings: &Settings, row: Value, captured: &[u8]) {
    assert_eq!(&captured[..8], b"TRNMAS01");
    let session = context(captured);
    let server_identity = DevelopmentIdentity::from_secret_hex(&hex::encode(&captured[288..320])).unwrap();
    let client = AuthenticatedClient::new(identity(72), server_identity.public_key().into(), session.generation).unwrap();
    let request: Request = serde_json::from_value(row["request"].clone()).unwrap();
    let wire = authenticated_request_bytes(settings, &client, word(captured, 240), request).unwrap();
    let server = AuthenticatedServer::new(server_identity, vec![client.public_key().into()], session.generation).unwrap();
    let verified = authenticate_request(&wire, settings, &server).unwrap();
    assert_eq!(verified.session, session);
    assert_eq!(&verified.request_digest, &captured[248..280]);
    let outcome: Result<Value> = match captured[281] {
        0 => { assert_eq!(captured[324], 1); Ok(tape(&captured[320..])) }
        1 => Err(Error::from(std::str::from_utf8(&captured[320..]).unwrap().to_owned())),
        _ => panic!("Invalid test outcome"),
    };
    let body = signed_response(&server, &verified, captured[280] != 0, outcome).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let sender = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        let result = write_frame_deadline(&mut stream, &body, Instant::now() + Duration::from_secs(5))
            .map_err(|error| family(&error));
        stream.shutdown(Shutdown::Write).unwrap();
        result
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut frame = Vec::new(); stream.read_to_end(&mut frame).unwrap();
    match sender.join().unwrap() {
        Ok(()) => write_result(&row, frame.len() as u64, &frame),
        Err(code) => {
            assert_eq!(code, 2); assert!(frame.is_empty());
            write_result(&row, 4294967267, &[]);
        }
    }
}

fn verify(row: Value, captured: &[u8]) {
    assert_eq!(&captured[..8], b"TRNMAR01");
    let session = context(captured);
    let nonce = word(captured, 240);
    let request_digest: Hash = captured[248..280].try_into().unwrap();
    let wire = captured[280..].to_vec();
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
    let result = read_frame_deadline(&mut stream, Instant::now() + Duration::from_secs(5));
    let (code, output, tail, diagnostic) = match result {
        Ok(body) => match verify_authenticated_response(&body, &session, nonce, request_digest) {
            Ok((terminal, ok, value)) => {
                let parsed: AuthenticatedResponse = serde_json::from_slice(&body).unwrap();
                assert_eq!((terminal, ok, value), (parsed.terminal, parsed.ok, parsed.value));
                let mut tail = Vec::new(); stream.read_to_end(&mut tail).unwrap();
                (0, metadata(&body, &session, nonce), tail, String::new())
            }
            Err(error) => (family(&error), Vec::new(), Vec::new(), error.to_string()),
        },
        Err(error) => (family(&error), Vec::new(), Vec::new(), error.to_string()),
    };
    drop(stream);
    let sender_result = sender.join().unwrap();
    if code == 0 { sender_result.unwrap(); }
    std::fs::write(row["output_path"].as_str().unwrap(), &output).unwrap();
    emit(json!({"name":row["name"], "code":code, "output_bytes":output.len(),
        "remaining_frame_hex":hex::encode(tail), "diagnostic":diagnostic}));
}

fn numeric(row: Value, raw: &[u8]) {
    let number = match serde_json::from_slice::<Value>(raw) {
        Ok(Value::Number(number)) => number,
        _ => { write_result(&row, 102, &[]); return; }
    };
    let (value, kind) = if let Some(value) = number.as_u64() { (value, 0u64) }
        else if let Some(value) = number.as_i64() { (value as u64, 1) }
        else { (number.as_f64().unwrap().to_bits(), 2) };
    let rendered = serde_json::to_vec(&number).unwrap();
    let mut output = Vec::new();
    for word in [value, kind, u64::from(rendered == raw), rendered.len() as u64] {
        output.extend_from_slice(&word.to_le_bytes());
    }
    output.extend_from_slice(&rendered); output.resize(56, 0);
    write_result(&row, 0, &output);
}

fn value_wire(row: Value, captured: &[u8]) {
    #[derive(Deserialize)]
    struct Outer { value: Value }
    let raw = &captured[1..];
    let parsed = serde_json::from_slice::<Value>(raw);
    let value = match parsed {
        Ok(value) if captured[0] == 0 => Ok(value),
        Ok(_) => {
            let mut wrapped = b"{\"value\":".to_vec(); wrapped.extend_from_slice(raw); wrapped.push(b'}');
            serde_json::from_slice::<Outer>(&wrapped).map(|outer| outer.value)
        }
        Err(error) => Err(error),
    };
    let code = match value { Ok(value) => u64::from(serde_json::to_vec(&value).unwrap() != raw), Err(_) => 2 };
    write_result(&row, code, &[]);
}

fn run() {
    let mode = std::env::var("TRNM_HIA_RESPONSE_ORACLE_MODE").unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    if mode == "describe" { describe(&settings); return; }
    let path = std::env::var("TRNM_HIA_RESPONSE_ORACLE_CORPUS").unwrap();
    for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let raw = std::fs::read(row["input_path"].as_str().unwrap()).unwrap();
        match mode.as_str() {
            "produce" => produce(&settings, row, &raw),
            "verify" => verify(row, &raw),
            "number" => numeric(row, &raw),
            "value_wire" => value_wire(row, &raw),
            "value_encode" => { let bytes = serde_json::to_vec(&tape(&raw)).unwrap(); write_result(&row, bytes.len() as u64, &bytes); }
            "sign" => {
                assert_eq!(raw.len(), 64);
                let key = DevelopmentIdentity::from_secret_hex(&hex::encode(&raw[..32])).unwrap();
                let mut output = hex::decode(key.public_key()).unwrap();
                output.extend_from_slice(&hex::decode(key.sign(&raw[32..]).unwrap()).unwrap());
                write_result(&row, 0, &output);
            }
            other => panic!("Unknown response oracle mode: {other}"),
        }
    }
}

#[test]
fn evaluate() {
    // The test data includes the deepest original-legal serde containers.
    // This stack is only the independent test driver, never a production limit.
    thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(run).unwrap().join().unwrap();
}
