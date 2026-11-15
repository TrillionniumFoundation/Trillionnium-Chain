type Hash = [u8; 32];
#[path = "exact_inputs.rs"]
mod exact_inputs;
fn h(n: u8) -> Hash {
    [n; 32]
}
#[test]
fn exact_match_and_nonmatch() {
    let mut builder = exact_inputs::Builder::new(exact_inputs::MAX_BYTES).unwrap();
    builder.push(h(1), b"memory:alpha", b"v1").unwrap();
    builder.push(h(2), b"memory:beta", b"v1").unwrap();
    builder.push(h(3), b"memory:alpha", b"v2").unwrap();
    let d = builder.finish().unwrap();
    assert!(d.retained_bytes() <= exact_inputs::MAX_BYTES);
    assert!(d.matches(0, b"memory:alpha", b"v1"));
    assert!(d.matches(1, b"memory:beta", b"v1"));
    assert!(d.matches(2, b"memory:alpha", b"v2"));
    assert!(!d.matches(0, b"memory:alpha", b"v2"));
    assert!(!d.matches(0, b"memory:beta", b"v1"));
    assert!(!d.matches(3, b"memory:alpha", b"v1"));
}
#[test]
fn budget_and_limits() {
    assert!(exact_inputs::Builder::new(1).is_none());
    assert!(exact_inputs::Builder::new(exact_inputs::MAX_BYTES)
        .unwrap()
        .finish()
        .is_none());
    let mut b = exact_inputs::Builder::new(exact_inputs::MAX_BYTES).unwrap();
    assert!(b.push(h(1), &[b'x'; 256], b"ok").is_none());
    assert!(b.push(h(1), b"bounded", &[b'y'; 65536]).is_none());
}
#[test]
fn many_shared_prefix_rows() {
    let mut b = exact_inputs::Builder::new(exact_inputs::MAX_BYTES).unwrap();
    for i in 0..100u16 {
        let key = format!("prefix:{}", i);
        b.push(h(i as u8), key.as_bytes(), b"shared-val").unwrap();
    }
    let d = b.finish().unwrap();
    for i in 0..100u16 {
        let key = format!("prefix:{}", i);
        assert!(d.matches(i as usize, key.as_bytes(), b"shared-val"));
    }
}
#[test]
fn binary_payload_and_negative_controls() {
    let pairs = [
        (h(1), vec![0, 0xff, b':', 0], vec![0xff, 0]),
        (h(2), vec![0, 0xff, b':', 1], vec![0xff, 0]),
        (h(3), vec![0, 0xff, b':', 2], vec![0xff, 1]),
    ];
    let mut b = exact_inputs::Builder::new(exact_inputs::MAX_BYTES).unwrap();
    for (hash, key, value) in &pairs {
        b.push(*hash, key, value).unwrap();
    }
    let d = b.finish().unwrap();
    for (i, (_, key, value)) in pairs.iter().enumerate() {
        assert!(d.matches(i, key, value));
        let mut bad = value.clone();
        bad.push(0);
        assert!(!d.matches(i, key, &bad));
    }
}
