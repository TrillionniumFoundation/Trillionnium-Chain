//! Explicit SP27-05 profile; legacy four-slot V1 remains separately admitted.

use super::*;
use std::io::{Seek, SeekFrom};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FaultProfileV2 {
    schema: String,
    chunks_per_page: u16,
    available_slots: Vec<u8>,
    corrupt_slots: Vec<u8>,
    read_policy: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_profile_requires_explicit_finite_fault_scope_and_policy() {
        let baseline = json!({
            "schema":"trnm.sp27-05-payload-fault-custody.v1", "chunks_per_page":64,
            "available_slots":[0,1,2,3,4,5], "corrupt_slots":[0],
            "read_policy":"typed-payload-observation-v2"
        });
        let profile: FaultProfileV2 = serde_json::from_value(baseline.clone()).unwrap();
        profile.validate().unwrap();
        let typed = profile.commitment().unwrap();
        let mut legacy = baseline.clone();
        legacy["read_policy"] = json!("legacy-fail-fast-v1");
        let legacy: FaultProfileV2 = serde_json::from_value(legacy).unwrap();
        assert_ne!(typed, legacy.commitment().unwrap());
        for (field, value) in [
            ("schema", json!("trnm.cell-sealed-paged-custody.v1")),
            ("chunks_per_page", json!(65)),
            ("available_slots", json!([0, 1, 2])),
            ("available_slots", json!([0, 1, 1, 3, 4, 5])),
            ("available_slots", json!([0, 1, 2, 3, 4, 6])),
            ("corrupt_slots", json!([0, 1, 2])),
            ("corrupt_slots", json!([6])),
            ("corrupt_slots", json!([0, 0])),
            ("read_policy", json!("swallow-errors")),
        ] {
            let mut bad = baseline.clone();
            bad[field] = value;
            assert!(serde_json::from_value::<FaultProfileV2>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut bad = baseline;
        bad["unknown"] = json!(true);
        assert!(serde_json::from_value::<FaultProfileV2>(bad).is_err());
    }
}

impl CustodyProfile for FaultProfileV2 {
    fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.sp27-05-payload-fault-custody.v1"
                && self.chunks_per_page == 64
                && (4..=6).contains(&self.available_slots.len())
                && self.available_slots.iter().all(|slot| *slot < 6)
                && self
                    .available_slots
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && self.corrupt_slots.len() <= 2
                && self
                    .corrupt_slots
                    .iter()
                    .all(|slot| self.available_slots.contains(slot))
                && self.corrupt_slots.windows(2).all(|pair| pair[0] < pair[1])
                && ["legacy-fail-fast-v1", "typed-payload-observation-v2"]
                    .contains(&self.read_policy.as_str()),
            "explicit SP27-05 finite provider-fault profile",
        )
    }
    fn commitment(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"TRNM/SP27-05/PayloadFaultCustody/v1\0");
        for value in [
            self.schema.as_bytes(),
            self.read_policy.as_bytes(),
            &self.available_slots,
            &self.corrupt_slots,
        ] {
            hash.update((value.len() as u32).to_be_bytes());
            hash.update(value);
        }
        hash.update(self.chunks_per_page.to_be_bytes());
        Ok(hash.finalize().into())
    }
    fn available_slots(&self) -> &[u8] {
        &self.available_slots
    }
    fn chunks_per_page(&self) -> u16 {
        self.chunks_per_page
    }
    fn schema(&self) -> &str {
        &self.schema
    }
    fn corrupt_slots(&self) -> &[u8] {
        &self.corrupt_slots
    }
    fn observed_payloads(&self) -> bool {
        self.read_policy == "typed-payload-observation-v2"
    }
}

pub(super) fn inject_owned_payload_faults(
    root: &Path,
    slots: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
    report: &mut Value,
) -> Result<()> {
    let mut observations = Vec::new();
    for slot in slots {
        controlled(deadline, cancelled)?;
        let path = root.join(format!("provider-{slot}/payload.arena"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let before = file.metadata()?;
        let entry = fs::symlink_metadata(&path)?;
        check(
            before.is_file()
                && entry.is_file()
                && before.nlink() == 1
                && before.len() > 0
                && before.dev() == entry.dev()
                && before.ino() == entry.ino(),
            "fresh owned provider arena for fault",
        )?;
        let mut old = [0];
        file.read_exact(&mut old)?;
        let next = [old[0] ^ 1];
        controlled(deadline, cancelled)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&next)?;
        file.sync_all()?;
        let now = fs::symlink_metadata(&path)?;
        check(
            now.is_file()
                && now.dev() == before.dev()
                && now.ino() == before.ino()
                && now.nlink() == 1
                && now.len() == before.len(),
            "provider fault retains original inode and extent",
        )?;
        file.seek(SeekFrom::Start(0))?;
        let mut actual = [0];
        file.read_exact(&mut actual)?;
        check(actual == next, "provider one-byte fault actual readback")?;
        controlled(deadline, cancelled)?;
        observations.push(
            json!({"slot":slot,"offset":0,"original_byte":old[0],"fault_byte":next[0],
            "actual_byte":actual[0],"arena_bytes":before.len(),"same_device_inode_length":true}),
        );
    }
    report["actual_provider_payload_faults"] = json!(observations);
    Ok(())
}
