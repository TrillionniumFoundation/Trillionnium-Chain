use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, SourceSnippet};

fn snippet(content_hex: String, id: String, label: u8, origin: String) -> SourceSnippet {
    SourceSnippet { content_hex, id, label, origin }
}

fn fixture(out: &mut impl Write, rows: &[SourceSnippet], batch: bool) {
    let mut frame = if batch { b"CSB1\0\0\0\0" } else { b"CSS1\0\0\0\0" }.to_vec();
    frame.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        let fields = [&row.content_hex, &row.id, &row.origin];
        for s in fields { frame.extend_from_slice(&(s.len() as u64).to_le_bytes()); }
        frame.extend_from_slice(&(row.label as u64).to_le_bytes());
        for s in fields { frame.extend_from_slice(s.as_bytes()); }
    }
    let original = if batch { canonical(&rows.to_vec()) } else { canonical(&rows[0]) };
    let wire = match original {
        Ok(x) => x,
        Err(e) => { assert_eq!(e.to_string(), "CELL_JSON_ASCII"); vec![] }
    };
    out.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&frame).unwrap();
    out.write_all(&wire).unwrap();
}

fn main() {
    let a = snippet("012a3b".into(), "generated-a".into(), 0, "fixture-one".into());
    let b = snippet(
        (0..=127).map(char::from).collect(), "generated-b".into(), 255,
        "fixture-two\"\\/\t".into(),
    );
    let empty = snippet(String::new(), String::new(), 9, String::new());
    let non_ascii = snippet("0123".into(), "generated-id-λ".into(), 1, "fixture".into());
    let large = snippet("\0".repeat(8192), "\0".repeat(256), 255, "\0".repeat(256));
    let mut out = io::stdout().lock();
    fixture(&mut out, std::slice::from_ref(&a), false);
    fixture(&mut out, std::slice::from_ref(&b), false);
    fixture(&mut out, std::slice::from_ref(&empty), false);
    fixture(&mut out, &[], true);
    fixture(&mut out, &[a.clone(), b.clone()], true);
    fixture(&mut out, &[b, a.clone()], true);
    fixture(&mut out, &[a, non_ascii], true);
    fixture(&mut out, &vec![large; 8], true);
}
