pub fn sequence_root(tag: &str, items: &[Vec<u8>]) -> Hash {
    let mut leaves: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(i, b)| {
            hash(
                format!("{tag}-leaf").as_bytes(),
                &[&(i as u64).to_le_bytes(), b],
            )
        })
        .collect();
    if leaves.is_empty() {
        return hash(format!("{tag}-empty").as_bytes(), &[]);
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().expect("nonempty"));
        }
        leaves = leaves
            .chunks_exact(2)
            .map(|p| hash(format!("{tag}-node").as_bytes(), &[&p[0], &p[1]]))
            .collect();
    }
    leaves[0]
}
