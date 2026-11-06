use super::*;
use std::net::TcpListener;

fn start_v3(directory: &Path, store: &Path, wire_bytes: u64) -> ServingChild {
    let mut args = serve_args(store, wire_bytes);
    replace(&mut args, "--transport", "persistent-rarest-v3");
    replace(&mut args, "--max-requests", "4");
    replace(&mut args, "--max-requests-per-connection", "4");
    arg(&mut args, "--announce-ready", "true");
    let stdout = directory.join("v3-serve.stdout");
    let stderr = directory.join("v3-serve.stderr");
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&stdout)
                .unwrap(),
        ))
        .stderr(Stdio::from(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&stderr)
                .unwrap(),
        ))
        .spawn()
        .unwrap();
    let mut child = ChildOwner(Some(child));
    let deadline = Instant::now() + Duration::from_secs(5);
    let address = loop {
        let bytes = read_log(&stdout);
        let mut address = None;
        for line in bytes
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.ends_with(b"\n"))
        {
            let record: Value = serde_json::from_slice(line).unwrap();
            if record["schema"] == "trnm.cell.ready.v1" {
                address = Some(
                    record["address"]
                        .as_str()
                        .unwrap()
                        .parse::<SocketAddr>()
                        .unwrap(),
                );
            }
        }
        if let Some(address) = address {
            break address;
        }
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "{}",
            String::from_utf8_lossy(&read_log(&stderr))
        );
        assert!(Instant::now() < deadline, "V3 provider Ready deadline");
        thread::sleep(Duration::from_millis(5));
    };
    ServingChild {
        address,
        child,
        stdout,
        stderr,
    }
}

fn finish_v3(mut server: ServingChild) -> Value {
    let status = server.child.completed().wait().unwrap();
    assert!(
        status.success(),
        "{}",
        String::from_utf8_lossy(&read_log(&server.stderr))
    );
    let reports: Vec<Value> = read_log(&server.stdout)
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0]["schema"], "trnm.cell.listen.v1");
    assert_eq!(reports[1]["schema"], "trnm.cell.ready.v1");
    reports[2].clone()
}

fn v3_fetch_args(cache: &Path, output: &Path, pinned: &str, peer: &str, bytes: u64) -> Vec<String> {
    let mut args = fetch_args(cache, output, pinned, peer, bytes);
    replace(&mut args, "--transport", "persistent-rarest-v3");
    replace(&mut args, "--max-requests", "4");
    replace(&mut args, "--max-requests-per-connection", "4");
    arg(&mut args, "--scheduling", "rarest-first-v1");
    args
}

#[test]
fn v3_cli_provider_ready_and_consumer_share_one_connection_for_inventory_and_weights() {
    let dir = tempfile::tempdir().unwrap();
    let origin_path = dir.path().join("origin.sqlite");
    let origin = CellStoreV1::open(
        &origin_path,
        CellCacheConfigV4 {
            max_database_bytes: 2_097_152,
            max_logical_bytes: 1_048_576,
            max_chunk_rows: 16,
            max_manifest_rows: 16,
        },
    )
    .unwrap();
    let payload = [vec![7_u8; 16_384], vec![8_u8; 16_384]].concat();
    let input = dir.path().join("weights");
    fs::write(&input, &payload).unwrap();
    let manifest = origin
        .pack_file(
            &input,
            CellContextV1 {
                family: "persistent-rarest-cli".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    drop(origin);
    let wire_bytes = manifest.encode().len() as u64 + payload.len() as u64 + 4 * 9 + 1;
    let server = start_v3(dir.path(), &origin_path, wire_bytes);
    let cache = dir.path().join("receiver.sqlite");
    let output = dir.path().join("complete.weights");
    let accepted = cli(&v3_fetch_args(
        &cache,
        &output,
        &digest_hex(manifest.id()),
        &server.address.to_string(),
        wire_bytes,
    ));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let fetched: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(fetched["schema"], "trnm.cell.fetch.persistent.rarest.v3");
    assert_eq!(fetched["request_attempts"], 4);
    assert_eq!(fetched["connection_attempts"], 1);
    assert_eq!(fetched["received_response_bytes"], wire_bytes);
    assert_eq!(fetched["downloaded_chunks"], 2);
    assert_eq!(fetched["cached_chunks"], 0);
    assert_eq!(fs::read(output).unwrap(), payload);
    let served = finish_v3(server);
    assert_eq!(served["schema"], "trnm.cell.serve.persistent.rarest.v3");
    assert_eq!(served["request_attempts"], 4);
    assert_eq!(served["connections"], 1);
    assert_eq!(served["completed"], 4);
    assert_eq!(served["sent_response_bytes"], wire_bytes);
}

#[test]
fn v3_cli_invalid_combinations_and_limits_refuse_before_cache_or_dial() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for (index, (name, value)) in [
        ("--scheduling", "ordered"),
        ("--scheduling", "unknown"),
        ("--max-requests", "0"),
        ("--max-requests-per-connection", "0"),
        ("--max-requests-per-connection", "5"),
        ("--transport", "persistent-v2"),
    ]
    .into_iter()
    .enumerate()
    {
        let cache = dir.path().join(format!("cache-{index}"));
        let output = dir.path().join(format!("output-{index}"));
        let mut args = v3_fetch_args(
            &cache,
            &output,
            &digest_hex([1; 32]),
            &listener.local_addr().unwrap().to_string(),
            1024,
        );
        replace(&mut args, name, value);
        let refused = cli(&args);
        assert!(!refused.status.success(), "{index}");
        assert!(!cache.exists(), "{index}");
        assert!(!output.exists(), "{index}");
        assert!(refused.stdout.is_empty(), "{index}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
