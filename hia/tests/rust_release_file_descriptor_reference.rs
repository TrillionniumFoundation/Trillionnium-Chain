// Pinned rustc compiles the exact repository observer + content reader above this
// test harness. Only digest utility wiring and synthetic fixture creation live here.
fn main() -> io::Result<()> {
    use std::{
        fs::{self, File, Metadata},
        io::{Seek, SeekFrom},
        os::unix::fs::MetadataExt,
    };
    fn take<const N: usize>(reader: &mut impl Read) -> [u8; N] {
        let mut bytes = [0; N];
        reader.read_exact(&mut bytes).unwrap();
        bytes
    }
    fn record(output: &mut impl Write, m: &Metadata) -> io::Result<()> {
        output.write_all(&m.dev().to_le_bytes())?;
        output.write_all(&m.ino().to_le_bytes())?;
        output.write_all(&m.mode().to_le_bytes())?;
        output.write_all(&[0; 4])?;
        output.write_all(&m.len().to_le_bytes())?;
        output.write_all(&m.mtime().to_le_bytes())?;
        output.write_all(&m.mtime_nsec().to_le_bytes())?;
        output.write_all(&m.ctime().to_le_bytes())?;
        output.write_all(&m.ctime_nsec().to_le_bytes())
    }

    let root = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    let mut request = Vec::new();
    io::stdin().read_to_end(&mut request)?;
    let mut req = Cursor::new(request);
    let scenario = take::<1>(&mut req)[0];
    let context = ContentContextV1 {
        profile_id: CryptoProfileId(take(&mut req)),
        instance: take(&mut req),
        generation: u64::from_le_bytes(take(&mut req)),
        kind: match take::<1>(&mut req)[0] {
            1 => ContentKind::StateSnapshot,
            2 => ContentKind::ReleaseArtifact,
            _ => unreachable!(),
        },
    };
    let mut budget = ContentReadBudget::new(
        u64::from_le_bytes(take(&mut req)),
        u64::from_le_bytes(take(&mut req)),
    )
    .unwrap();
    let size = u64::from_le_bytes(take(&mut req));
    let locator = take::<32>(&mut req);
    let platform = take::<32>(&mut req);
    let path_alias = take::<32>(&mut req);
    let mut bytes = Vec::new();
    req.read_to_end(&mut bytes)?;
    let artifact = ArtifactEntryV0 {
        logical_name: b"node".to_vec(),
        media_type: b"application/octet-stream".to_vec(),
        content_digest: Digest32V0(locator),
        platform_digest: Digest32V0(platform),
        source_path_digest: Digest32V0(path_alias),
        size_bytes: size,
        executable: true,
    };
    let dir = root.join("fixture-root");
    fs::create_dir(&dir)?;
    let artifact_path = dir.join("artifact");
    let mut file = if scenario == 3 {
        File::open(&dir)?
    } else {
        let mut writer = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&artifact_path)?;
        writer.write_all(&bytes)?;
        drop(writer);
        File::open(&artifact_path)?
    };
    match scenario {
        1 => {
            fs::rename(&artifact_path, dir.join("renamed"))?;
            assert!(!artifact_path.exists());
        }
        2 => {
            file.seek(SeekFrom::Start(1))?;
        }
        4 => {
            fs::rename(&dir, root.join("moved-root"))?;
            assert!(!artifact_path.exists());
        }
        0 | 3 => {}
        _ => panic!("unexpected held fixture"),
    }
    let before = file.metadata()?;
    let initial = if before.is_file() {
        file.stream_position()?
    } else {
        0
    };
    let (status, claim) = match observe_release_file_v1(&context, &mut budget, &artifact, &mut file)
    {
        Ok(result) => (0, result.claim.encode()),
        Err(ReleaseContentError::InvalidArtifact) => (1, vec![]),
        Err(ReleaseContentError::Content(ContentCommitmentError::Budget)) => (2, vec![]),
        Err(ReleaseContentError::LegacyLocatorMismatch) => (6, vec![]),
        Err(ReleaseContentError::FileIdentity) => (101, vec![]),
        Err(other) => panic!("unexpected original held-file outcome: {other:?}"),
    };
    let after = file.metadata()?;
    let consumed = if after.is_file() {
        file.stream_position()?
    } else {
        0
    };
    let mut out = io::stdout().lock();
    out.write_all(&[status, u8::from(budget.exhausted)])?;
    for value in [initial, consumed, budget.reads, budget.bytes] {
        out.write_all(&value.to_le_bytes())?;
    }
    record(&mut out, &before)?;
    record(&mut out, &after)?;
    out.write_all(&claim)
}
