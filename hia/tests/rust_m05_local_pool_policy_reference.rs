// Qualification-only original excerpt adapter. No Node lifecycle or SQLite.
use store::{IdentityOnly, LightSettings, PoolLimits};

fn main() -> Result<()> {
    let mut wire = Vec::new();
    std::io::stdin().read_to_end(&mut wire)?;
    assert_eq!(wire.len() % 172, 0);
    let mut output = std::io::stdout().lock();
    for case in wire.chunks_exact(172) {
        assert_eq!(store::mempool_profile(), "native-local-queued-pnx1-v2");
        assert_eq!(&case[..4], b"LPV1");
        let identity = |i| case[i..i + 32].try_into().unwrap();
        let number = |i| usize::try_from(u64::from_le_bytes(case[i..i + 8].try_into().unwrap())).unwrap();
        let node = IdentityOnly {
            settings: LightSettings([identity(4), identity(36), identity(68)]),
        };
        let policy = PoolLimits {
            preview_miner: identity(100),
            max_records: number(132),
            max_bytes: number(140),
            max_group_members: number(148),
            critical_reserve: number(156),
            max_removals: number(164),
        };
        match node.bind(policy) {
            Ok((body, digest)) => {
                output.write_all(&(u16::try_from(body.len()).unwrap() + 32).to_le_bytes())?;
                output.write_all(&digest)?;
                output.write_all(&body)?;
            }
            Err(error) => {
                assert_eq!(error.to_string(), "POOL_LIMITS");
                output.write_all(&3u16.to_le_bytes())?;
            }
        }
    }
    Ok(())
}
