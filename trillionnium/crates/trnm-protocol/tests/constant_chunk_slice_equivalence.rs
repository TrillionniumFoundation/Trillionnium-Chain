//! Keep fixed-array chunk migration transparent to existing slice consumers.

fn legacy_chunks<T>(values: &[T], size: usize) -> std::slice::ChunksExact<'_, T> {
    values.chunks_exact(size)
}

fn fixed_slices<T, const N: usize>(values: &[T]) -> impl Iterator<Item = &[T]> {
    values
        .as_chunks::<N>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
}

fn compare_borrowed_slices<const N: usize>() {
    for len in [0, 1, N - 1, N, N + 1, 2 * N, 3 * N - 1] {
        let values: Vec<i16> = (0..len)
            .map(|index| i16::try_from(index).unwrap() - 100)
            .collect();
        let old: Vec<&[i16]> = legacy_chunks(&values, N).collect();
        let new: Vec<&[i16]> = fixed_slices::<_, N>(&values).collect();
        assert_eq!(new, old);
        assert_eq!(new.len(), len / N);
        for (before, after) in old.iter().zip(&new) {
            assert_eq!(before.as_ptr(), after.as_ptr());
            assert_eq!(after.len(), N);
        }
        assert_eq!(
            legacy_chunks(&values, N).remainder(),
            &values[new.len() * N..]
        );
        // Keep serde's slice representation even for rows larger than 32 items.
        assert_eq!(
            serde_json::to_vec(&new).unwrap(),
            serde_json::to_vec(&old).unwrap()
        );
        let old_rows: Vec<Vec<i16>> = legacy_chunks(&values, N).map(<[i16]>::to_vec).collect();
        let new_rows: Vec<Vec<i16>> = fixed_slices::<_, N>(&values).map(<[i16]>::to_vec).collect();
        assert_eq!(new_rows, old_rows);
    }
}

#[test]
fn fixed_chunks_preserve_order_borrowing_remainders_and_slice_serialization() {
    compare_borrowed_slices::<2>();
    compare_borrowed_slices::<4>();
    compare_borrowed_slices::<64>();
    compare_borrowed_slices::<257>();
}

#[test]
fn fixed_chunks_preserve_fallible_slice_to_little_endian_conversion() {
    let bytes: Vec<u8> = (0..19).collect();
    let old: Result<Vec<u32>, std::array::TryFromSliceError> = legacy_chunks(&bytes, 4)
        .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
        .collect();
    let new: Result<Vec<u32>, std::array::TryFromSliceError> = fixed_slices::<_, 4>(&bytes)
        .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
        .collect();
    let old = old.expect("legacy exact-width chunks");
    let new = new.expect("slice-preserving fixed-width chunks");
    assert_eq!(new, old);
    assert_eq!(new, vec![0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c]);
}
