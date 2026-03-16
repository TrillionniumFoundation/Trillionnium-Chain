use super::*;

#[test]
fn read_log_tail_returns_recent_lines() {
    let tmp = unique_tmp_path("trnm-rpc-tail-test", "log");
    fs::write(
        &tmp,
        "line1
line2
[event] event_type=commit task_id=1 tx_id=1 block_height=1
",
    )
    .expect("write temp log");
    let tail = read_log_tail(&tmp, 80).expect("tail text");
    assert!(tail.contains("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_keeps_first_line_when_tail_starts_on_newline_boundary() {
    let tmp = unique_tmp_path("trnm-rpc-tail-boundary", "log");
    let content = "line1\n[event] event_type=commit task_id=7 tx_id=11 block_height=3\n";
    fs::write(&tmp, content).expect("write temp log");

    let start = "line1\n".len() as u64;
    let tail_bytes = content.len() as u64 - start;
    let tail = read_log_tail(&tmp, tail_bytes).expect("tail text");

    assert!(tail.starts_with("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_tolerates_non_utf8_bytes() {
    let tmp = unique_tmp_path("trnm-rpc-tail-binary", "log");
    let mut bytes = vec![0xff, 0xfe, b'\n'];
    bytes.extend_from_slice(b"[event] event_type=commit task_id=9 tx_id=1 block_height=1\n");
    fs::write(&tmp, bytes).expect("write temp binary log");

    let tail = read_log_tail(&tmp, 1024).expect("tail text");
    assert!(tail.contains("[event] event_type=commit task_id=9"));
    let _ = fs::remove_file(tmp);
}
