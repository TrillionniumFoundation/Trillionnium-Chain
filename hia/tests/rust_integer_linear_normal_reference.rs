// Appended next to the original private CheckedIntegerLinearUpdateV1 fields,
// exclusively for independent formatting tests. Never constructs a public witness.
pub fn reporting_fixture(parent: [u8; 32], slot: u8, delta: [[i32; COLUMNS]; ROWS]) -> Vec<u8> {
    let checked = CheckedIntegerLinearUpdateV1 {
        context: IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, parent, slot).unwrap(),
        delta,
        rank: 0,
        artifact: [0; 32],
        function_fingerprint: [0; 32],
    };
    checked.normal_bytes()
}
