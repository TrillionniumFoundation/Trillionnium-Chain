//! A small exact-byte dictionary for the previous complete arithmetic input.
//!
//! Only the root calculator constructs this private type from actual rows. A hit
//! compares the complete actual key and value bytes. Common key prefixes and
//! identical values share storage. Neither hash framing changes.
//!
//! MAX_BYTES bounds the final retained dictionary, including allocation charges.
//! Building it also uses row descriptors, maps and packing buffers. That bounded
//! temporary workspace is separate; MAX_BYTES is not an RSS or peak-memory cap.
use super::Hash;
use std::collections::BTreeMap;

pub(super) const MAX_BYTES: usize = 64 * 1024;
const ALLOCATION_CHARGE: usize = 32;
const FIXED_CHARGE: usize = std::mem::size_of::<ExactInputs>() + 4 * ALLOCATION_CHARGE;

pub(super) struct ExactInputs {
    offsets: Box<[u32]>,
    rows: Box<[u8]>,
    prefixes: Box<[Box<[u8]>]>,
    values: Box<[Box<[u8]>]>,
}

impl ExactInputs {
    pub(super) fn retained_bytes(&self) -> usize {
        FIXED_CHARGE
            + std::mem::size_of_val(self.offsets.as_ref())
            + self.rows.len()
            + std::mem::size_of_val(self.prefixes.as_ref())
            + std::mem::size_of_val(self.values.as_ref())
            + self
                .prefixes
                .iter()
                .map(|x| x.len() + ALLOCATION_CHARGE)
                .sum::<usize>()
            + self
                .values
                .iter()
                .map(|x| x.len() + ALLOCATION_CHARGE)
                .sum::<usize>()
    }

    pub(super) fn matches(&self, index: usize, key: &[u8], value: &[u8]) -> bool {
        let Some(&start) = self.offsets.get(index) else {
            return false;
        };
        let end = self
            .offsets
            .get(index + 1)
            .map_or(self.rows.len(), |&x| x as usize);
        let Some(row) = self.rows.get(start as usize..end) else {
            return false;
        };
        let Some((&suffix_len, tail)) = row.get(2..).and_then(|x| x.split_first()) else {
            return false;
        };
        let suffix_len = usize::from(suffix_len);
        if row.len() != 5 + suffix_len {
            return false;
        }
        let prefix_id = usize::from(u16::from_le_bytes([row[0], row[1]]));
        let value_id = usize::from(u16::from_le_bytes([tail[suffix_len], tail[suffix_len + 1]]));
        let Some(prefix) = self.prefixes.get(prefix_id) else {
            return false;
        };
        let Some(prior_value) = self.values.get(value_id) else {
            return false;
        };
        key.strip_prefix(prefix.as_ref()) == Some(&tail[..suffix_len])
            && value == prior_value.as_ref()
    }
}

pub(super) struct Builder {
    limit: usize,
    charged: usize,
    prefixes: BTreeMap<Vec<u8>, u16>,
    values: BTreeMap<Vec<u8>, u16>,
    rows: Vec<(Hash, Vec<u8>)>,
}

impl Builder {
    pub(super) fn new(limit: usize) -> Option<Self> {
        (limit >= FIXED_CHARGE).then(|| Self {
            limit,
            charged: FIXED_CHARGE,
            prefixes: BTreeMap::new(),
            values: BTreeMap::new(),
            rows: Vec::new(),
        })
    }

    fn intern(
        table: &mut BTreeMap<Vec<u8>, u16>,
        bytes: &[u8],
        charged: &mut usize,
        limit: usize,
    ) -> Option<u16> {
        if let Some(&id) = table.get(bytes) {
            return Some(id);
        }
        let id = u16::try_from(table.len()).ok()?;
        let next = charged
            .checked_add(bytes.len() + std::mem::size_of::<Box<[u8]>>() + ALLOCATION_CHARGE)?;
        if next > limit {
            return None;
        }
        table.insert(bytes.to_vec(), id);
        *charged = next;
        Some(id)
    }

    /// Failure drops this optional builder. The caller still consumes the whole
    /// input and enforces every original wire limit. A previous dictionary may
    /// still supply exact-byte leaf hits during this calculation.
    pub(super) fn push(&mut self, path: Hash, key: &[u8], value: &[u8]) -> Option<()> {
        let split = key
            .iter()
            .rposition(|&byte| byte == b':')
            .map_or(0, |x| x + 1);
        let (prefix, suffix) = key.split_at(split);
        let suffix_len = u8::try_from(suffix.len()).ok()?;
        let prefix_id = Self::intern(&mut self.prefixes, prefix, &mut self.charged, self.limit)?;
        let value_id = Self::intern(&mut self.values, value, &mut self.charged, self.limit)?;
        let next = self
            .charged
            .checked_add(5 + suffix.len() + std::mem::size_of::<u32>())?;
        if next > self.limit {
            return None;
        }
        let mut row = Vec::with_capacity(5 + suffix.len());
        row.extend_from_slice(&prefix_id.to_le_bytes());
        row.push(suffix_len);
        row.extend_from_slice(suffix);
        row.extend_from_slice(&value_id.to_le_bytes());
        self.rows.push((path, row));
        self.charged = next;
        Some(())
    }

    pub(super) fn finish(mut self) -> Option<ExactInputs> {
        if self.rows.is_empty() {
            return None;
        }
        self.rows.sort_unstable_by_key(|row| row.0);
        let size = self.rows.iter().map(|(_, row)| row.len()).sum();
        let mut offsets = Vec::with_capacity(self.rows.len());
        let mut rows = Vec::with_capacity(size);
        for (_, row) in self.rows {
            offsets.push(u32::try_from(rows.len()).ok()?);
            rows.extend_from_slice(&row);
        }
        fn ordered(table: BTreeMap<Vec<u8>, u16>) -> Box<[Box<[u8]>]> {
            let mut values: Vec<_> = table.into_iter().map(|(bytes, id)| (id, bytes)).collect();
            values.sort_unstable_by_key(|(id, _)| *id);
            values
                .into_iter()
                .map(|(_, bytes)| bytes.into_boxed_slice())
                .collect()
        }
        let inputs = ExactInputs {
            offsets: offsets.into_boxed_slice(),
            rows: rows.into_boxed_slice(),
            prefixes: ordered(self.prefixes),
            values: ordered(self.values),
        };
        (inputs.retained_bytes() == self.charged && self.charged <= self.limit).then_some(inputs)
    }
}
