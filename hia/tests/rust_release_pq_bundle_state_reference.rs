// Exact original pure branch body is spliced into this fixture by the test.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
};

struct SnapshotRoot {
    network_id: ReleaseDigestV1,
    generation: u64,
    expires_at: u64,
}
struct Guard {
    root: SnapshotRoot,
    event_count: usize,
    time_floor: u64,
    checkpoint: ReleaseDigestV1,
    version: u64,
    current: BTreeMap<PqReleaseRoleV1, CurrentPqReleaseV1>,
    history: BTreeSet<(PqReleaseRoleV1, ReleaseDigestV1)>,
}
impl Guard {
    fn current_content(&self, r: PqReleaseRoleV1) -> Option<ReleaseDigestV1> {
        self.current.get(&r).map(|row| row.content)
    }
    fn role_version(&self, r: PqReleaseRoleV1) -> u64 {
        assert_eq!(r, PqReleaseRoleV1::NodeSoftware);
        self.version
    }
    fn verify(&self, metadata: &PqReleaseMetadataV1, now: u64) -> Result<(), PqReleaseErrorV1> {
        // EXACT_ORIGINAL_GUARD
        Ok(())
    }
}
fn digest(b: &[u8], at: usize) -> ReleaseDigestV1 {
    b[at..at + 32].try_into().unwrap()
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn optional(b: &[u8], at: usize) -> Option<ReleaseDigestV1> {
    match b[at] {
        0 => None,
        1 => Some(digest(b, at + 1)),
        _ => panic!("bad external typed option"),
    }
}
fn role(n: u8) -> PqReleaseRoleV1 {
    match n {
        1 => PqReleaseRoleV1::NodeSoftware,
        2 => PqReleaseRoleV1::ProtocolConfiguration,
        3 => PqReleaseRoleV1::CellManifest,
        4 => PqReleaseRoleV1::CellActivation,
        _ => panic!("bad external role"),
    }
}
fn fixture(b: &[u8]) -> u8 {
    let metadata = PqReleaseMetadataV1 {
        role: role(b[0]),
        network_id: digest(b, 1),
        root_generation: number(b, 33),
        role_version: number(b, 41),
        expires_at: number(b, 49),
        expected_checkpoint: digest(b, 57),
        previous_content: optional(b, 89),
        content: digest(b, 122),
        approved_content_rollback: b[154] == 1,
    };
    let mut current = BTreeMap::new();
    if let Some(content) = optional(b, 267) {
        current.insert(
            PqReleaseRoleV1::NodeSoftware,
            CurrentPqReleaseV1 {
                content,
                root_generation: number(b, 219),
                expires_at: number(b, 227),
            },
        );
    }
    let snapshot = Guard {
        root: SnapshotRoot {
            network_id: digest(b, 187),
            generation: number(b, 219),
            expires_at: number(b, 227),
        },
        event_count: number(b, 324).try_into().unwrap(),
        time_floor: number(b, 308),
        checkpoint: digest(b, 235),
        version: number(b, 300),
        current,
        history: b[334..]
            .chunks_exact(33)
            .map(|row| (role(row[0]), digest(row, 1)))
            .collect(),
    };
    match snapshot.verify(&metadata, number(b, 316)) {
        Ok(()) => 0,
        Err(PqReleaseErrorV1::HistoryFull) => 201,
        Err(PqReleaseErrorV1::ClockRollback) => 202,
        Err(PqReleaseErrorV1::Expired) => 203,
        Err(PqReleaseErrorV1::WrongAuthority) => 204,
        Err(PqReleaseErrorV1::CheckpointConflict) => 205,
        Err(PqReleaseErrorV1::VersionRollback) => 206,
        Err(PqReleaseErrorV1::InvalidContent) => 207,
        Err(PqReleaseErrorV1::RollbackApproval) => 208,
        unexpected => panic!("wrong oracle result: {unexpected:?}"),
    }
}
fn main() {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut rest = raw.as_slice();
    let mut writer = io::stdout().lock();
    while !rest.is_empty() {
        let extent = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        let frame = &rest[4..4 + extent];
        writer.write_all(&[fixture(frame)]).unwrap();
        rest = &rest[4 + extent..];
    }
}
