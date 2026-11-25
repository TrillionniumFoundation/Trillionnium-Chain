use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut data = raw.as_slice();
    let mut out = Vec::new();
    while !data.is_empty() {
        let Some((prefix, rest)) = data.split_at_checked(4) else {
            return Err(io::Error::other("missing leaf count"));
        };
        let count = u32::from_le_bytes(prefix.try_into().unwrap()) as usize;
        let Some((input, after)) = rest.split_at_checked(count.checked_mul(32).unwrap()) else {
            return Err(io::Error::other("missing leaf bytes"));
        };
        let leaves: Vec<_> = input.chunks_exact(32)
            .map(|d| Digest32V0(d.try_into().unwrap()))
            .collect();
        out.extend_from_slice(&merkle_root_v0(&leaves).0);
        data = after;
    }
    io::stdout().write_all(&out)?;
    Ok(())
}
