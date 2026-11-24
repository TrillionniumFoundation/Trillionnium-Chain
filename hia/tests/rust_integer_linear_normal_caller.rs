// Qualification-only code appended to a private copy of the original example.
// It is not built by Cargo or exposed through the shipped Rust entry point.
use trnm_verification_profiles::exact_integer_linear_v1::CheckedIntegerLinearUpdateV1;

unsafe extern "C" {
    fn f0(
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_len: usize,
        scratch: *mut u8,
        scratch_len: usize,
    ) -> u64;
}

fn iln1_normal(
    checked: &CheckedIntegerLinearUpdateV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const MIN: usize = 1680;
    const MAX: usize = 5535;
    const OUT_MARK: u8 = 0xa5;
    const WORK_MARK: u8 = 0x49;
    let mut input = [0_u8; 3124];
    input[..4].copy_from_slice(b"ILN1");
    input[8..40].copy_from_slice(&checked.context().contract_id());
    for (slot, value) in input[40..]
        .chunks_exact_mut(4)
        .zip(checked.delta().iter().flatten())
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let before = input;
    let mut output = [OUT_MARK; MAX + 11];
    let mut work = [WORK_MARK; 17];
    // Deliberately insufficient only in the separately linked negative-control
    // executable; neither the Rust oracle nor native code is changed.
    let capacity = if cfg!(trnm_iln_short_capacity) { MIN - 1 } else { MAX };
    // Three distinct fixed allocations stay alive and uniquely borrowed for
    // the complete call, and the native routine does not retain pointers.
    let result = unsafe {
        f0(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            capacity,
            work.as_mut_ptr(),
            work.len(),
        )
    };
    let count = (result as u32) as usize;
    if result >> 32 != 0
        || !(MIN..=capacity).contains(&count)
        || input != before
        || output[count..].iter().any(|&byte| byte != OUT_MARK)
        || work != [WORK_MARK; 17]
    {
        return Err("INTEGER_LINEAR:NativeNormalReport".into());
    }
    Ok(output[..count].to_vec())
}
