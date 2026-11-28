// Private same-statement qualification caller, appended to the existing fixture.

unsafe extern "C" {
    #[link_name = "f0"]
    fn trnm_history_inline_record_native(
        raw: *const u8, raw_len: usize, out: *mut u8, out_len: usize,
        scratch: *mut u8, scratch_len: usize,
    ) -> u64;
}

fn compare_while_held(row: &rusqlite::Row<'_>, input: &[u8], code: u32, original_output: &[u8]) {
    assert!((72..=16_456).contains(&input.len()));
    assert!(original_output.len() == if code == 0 { 144 } else { 0 });
    let mut output = [0xA5u8; 155];
    let mut scratch = [0xC3u8; 13];
    // Borrow three disjoint local byte spans only. No SQLite pointer or general
    // descriptor reaches the native function. This Row remains borrowed until
    // after the call; no query, callback or cursor advancement intervenes.
    let native = unsafe {
        trnm_history_inline_record_native(
            input.as_ptr(), input.len(), output.as_mut_ptr(), 147,
            scratch.as_mut_ptr(), 9,
        )
    };
    assert_eq!(native, u64::from(code), "full packed status differs");
    assert_eq!(&output[..original_output.len()], original_output);
    assert!(output[original_output.len()..].iter().all(|&b| b == 0xA5));
    assert_eq!(scratch, [0xC3; 13]);
    assert_eq!(frame(row), input, "same row/ValueRefs changed before advancement");
}
