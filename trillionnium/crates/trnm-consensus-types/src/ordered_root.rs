use alloc::vec::Vec;

use crate::{
    canonical::{
        canonical_hash, try_canonical_bytes, try_canonical_hash, Encoder, DOMAIN_ORDERED_LEAF,
        DOMAIN_ORDERED_NODE, DOMAIN_ORDERED_ROOT,
    },
    Result, ValidationError, SCHEMA_VERSION_V0,
};

/// Selects the consensus field to which an ordered root is bound.
///
/// The discriminants are part of the frozen CEV0 representation and prevent
/// the same ordered byte sequence from being reused across block-header root
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RootKind {
    Payload = 0,
    Receipts = 1,
    Evidence = 2,
}

/// The frozen v0 commitment to an ordered sequence of byte strings.
///
/// Leaves bind their zero-based `u32` index and CEV0-framed item bytes. Tree
/// nodes bind their zero-based merge level; the first merge of leaves is
/// level zero. An unpaired digest is duplicated on the right at every level.
/// The outer root binds both the kind and original item count, so duplicating
/// the final source item cannot collide with duplicate-right padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderedRootV0 {
    kind: RootKind,
    item_count: u32,
    inner: Option<[u8; 32]>,
}

impl OrderedRootV0 {
    /// Computes a frozen ordered root from already-canonical logical item
    /// bytes. Both the number of items and every item byte length must fit the
    /// CEV0 `u32` bounds.
    pub fn from_items<T: AsRef<[u8]>>(kind: RootKind, items: &[T]) -> Result<Self> {
        let item_count =
            u32::try_from(items.len()).map_err(|_| ValidationError::LengthOverflow {
                field: "OrderedRootV0 items",
                actual: items.len(),
                maximum: u32::MAX as usize,
            })?;
        for item in items {
            u32::try_from(item.as_ref().len()).map_err(|_| ValidationError::LengthOverflow {
                field: "OrderedRootV0 item bytes",
                actual: item.as_ref().len(),
                maximum: u32::MAX as usize,
            })?;
        }

        let mut layer = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| ValidationError::LengthOverflow {
                field: "OrderedRootV0 leaf index",
                actual: index,
                maximum: u32::MAX as usize,
            })?;
            layer.push(ordered_leaf_digest_v0(kind, index, item.as_ref())?);
        }

        let mut level = 0u32;
        while layer.len() > 1 {
            let capacity = layer
                .len()
                .checked_div(2)
                .and_then(|pairs| pairs.checked_add(layer.len() % 2))
                .ok_or(ValidationError::ArithmeticOverflow(
                    "OrderedRootV0 next layer capacity",
                ))?;
            let mut next = Vec::with_capacity(capacity);
            for pair in layer.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                next.push(node_digest(kind, level, &left, &right));
            }
            layer = next;
            if layer.len() > 1 {
                level = level
                    .checked_add(1)
                    .ok_or(ValidationError::ArithmeticOverflow(
                        "OrderedRootV0 tree level",
                    ))?;
            }
        }

        Ok(Self {
            kind,
            item_count,
            inner: layer.first().copied(),
        })
    }

    pub const fn kind(&self) -> RootKind {
        self.kind
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    /// Returns the final tree digest, or `None` for the empty sequence.
    pub const fn inner(&self) -> Option<[u8; 32]> {
        self.inner
    }

    /// Returns the kind- and count-bound outer digest committed by a block
    /// header.
    pub fn digest(&self) -> [u8; 32] {
        canonical_hash(DOMAIN_ORDERED_ROOT, |encoder| self.encode_cev0(encoder))
    }

    /// Returns the exact frozen CEV0 preimage used by [`Self::digest`].
    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.u8(self.kind as u8);
        encoder.u32(self.item_count);
        encoder.optional_fixed(self.inner.as_ref());
    }
}

/// Returns the exact leaf digest used by [`OrderedRootV0`].
///
/// Receipt construction must use this helper for its `payload_leaf_hash`
/// rather than maintaining a parallel encoding implementation.
pub fn ordered_leaf_digest_v0(kind: RootKind, index: u32, item: &[u8]) -> Result<[u8; 32]> {
    try_canonical_hash(DOMAIN_ORDERED_LEAF, |encoder| {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.u8(kind as u8);
        encoder.u32(index);
        encoder.bytes(item);
    })
}

fn node_digest(kind: RootKind, level: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    canonical_hash(DOMAIN_ORDERED_NODE, |encoder| {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.u8(kind as u8);
        encoder.u32(level);
        encoder.fixed(left);
        encoder.fixed(right);
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn root(kind: RootKind, items: &[&[u8]]) -> OrderedRootV0 {
        OrderedRootV0::from_items(kind, items).unwrap()
    }

    fn hash32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let source = value.as_bytes();
        let mut output = [0u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = (hex_nibble(source[index * 2]) << 4) | hex_nibble(source[index * 2 + 1]);
        }
        output
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid lowercase hex fixture"),
        }
    }

    #[test]
    fn empty_and_small_tree_shapes_are_frozen() {
        let empty = root(RootKind::Payload, &[]);
        assert_eq!(empty.item_count(), 0);
        assert_eq!(empty.inner(), None);
        assert_eq!(empty.try_cev0_bytes().unwrap(), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            empty.digest(),
            hash32("0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2")
        );
        assert_eq!(
            root(RootKind::Receipts, &[]).digest(),
            hash32("b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156")
        );
        assert_eq!(
            root(RootKind::Evidence, &[]).digest(),
            hash32("df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047")
        );

        let one = root(RootKind::Payload, &[b"a"]);
        assert_eq!(one.item_count(), 1);
        assert_eq!(
            one.inner(),
            Some(ordered_leaf_digest_v0(RootKind::Payload, 0, b"a").unwrap())
        );
        assert_eq!(
            one.inner().unwrap(),
            hash32("1945223c9d4d3cab94b2b14e3da3be3cfde6c213d9a79043462931dabddae6dd")
        );
        assert_eq!(
            one.digest(),
            hash32("ac53a4472f1a2e8b9f109eb2832736d79d425cdd1998ab2099f5da5dd1a0a469")
        );

        let two = root(RootKind::Payload, &[b"a", b"b"]);
        let leaf_a = ordered_leaf_digest_v0(RootKind::Payload, 0, b"a").unwrap();
        let leaf_b = ordered_leaf_digest_v0(RootKind::Payload, 1, b"b").unwrap();
        assert_eq!(
            two.inner(),
            Some(node_digest(RootKind::Payload, 0, &leaf_a, &leaf_b))
        );
        assert_eq!(
            two.digest(),
            hash32("49679ffdee098f13a70984da64c5ff6472be2a3209e27db84401d2adb9094e5c")
        );

        let three = root(RootKind::Payload, &[b"a", b"b", b"c"]);
        let leaf_c = ordered_leaf_digest_v0(RootKind::Payload, 2, b"c").unwrap();
        let left = node_digest(RootKind::Payload, 0, &leaf_a, &leaf_b);
        let right = node_digest(RootKind::Payload, 0, &leaf_c, &leaf_c);
        assert_eq!(
            three.inner(),
            Some(node_digest(RootKind::Payload, 1, &left, &right))
        );
        assert_eq!(
            three.digest(),
            hash32("f9019a085e5415e45bddfe6628a7d15d0c1f2f74b5354549fa2eac3437dbe92d")
        );

        let four = root(RootKind::Payload, &[b"a", b"b", b"c", b"d"]);
        let leaf_d = ordered_leaf_digest_v0(RootKind::Payload, 3, b"d").unwrap();
        let right = node_digest(RootKind::Payload, 0, &leaf_c, &leaf_d);
        assert_eq!(
            four.inner(),
            Some(node_digest(RootKind::Payload, 1, &left, &right))
        );
        assert_eq!(
            four.digest(),
            hash32("b3a7a7f52bc80402ac99260856880a362fab3ded4a4b302033aa111a7393ca18")
        );
    }

    #[test]
    fn kind_order_and_cev0_framing_are_bound() {
        assert_eq!(RootKind::Payload as u8, 0);
        assert_eq!(RootKind::Receipts as u8, 1);
        assert_eq!(RootKind::Evidence as u8, 2);

        let items = [b"alpha".as_slice(), b"beta".as_slice()];
        let payload = root(RootKind::Payload, &items);
        let receipts = root(RootKind::Receipts, &items);
        let evidence = root(RootKind::Evidence, &items);
        assert_ne!(payload.digest(), receipts.digest());
        assert_ne!(payload.digest(), evidence.digest());
        assert_ne!(receipts.digest(), evidence.digest());

        assert_ne!(
            root(RootKind::Payload, &[b"alpha", b"beta"]).digest(),
            root(RootKind::Payload, &[b"beta", b"alpha"]).digest(),
        );
        assert_ne!(
            root(RootKind::Payload, &[b"ab", b"c"]).digest(),
            root(RootKind::Payload, &[b"a", b"bc"]).digest(),
        );
    }

    #[test]
    fn item_count_and_leaf_indices_separate_duplicate_right_from_real_items() {
        let three = vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()];
        let four = vec![
            b"a".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"c".as_slice(),
        ];
        let three = root(RootKind::Payload, &three);
        let four = root(RootKind::Payload, &four);

        assert_ne!(three.digest(), four.digest());

        let same_inner_different_count = OrderedRootV0 {
            kind: three.kind(),
            item_count: four.item_count(),
            inner: three.inner(),
        };
        assert_ne!(three.digest(), same_inner_different_count.digest());
    }

    #[test]
    fn independent_python_fixture_roots_are_reproduced_for_every_kind() {
        let fixtures: [&[u8]; 4] = [b"", b"\x00", b"\x00\xff", b"cev0"];
        let cases = [
            (
                RootKind::Payload,
                [
                    "0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2",
                    "d6f18aa559ade3b7deed66f5011262054167d5e9d864722c46c4a55f1704ff29",
                    "fa07664cecbe0e6b79e35e591278bac0566a963745176a5049018abcff53b708",
                    "028a1df0f9d6b2b70454d646809baee7468ef1e389199925e037eaf83a65e0cb",
                    "7ff92afa4c2cc258207d4a7baf699be10e53256ef6a4bec372b74f3cc42e1381",
                ],
            ),
            (
                RootKind::Receipts,
                [
                    "b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156",
                    "3e6b075b71c916150dcfca239043d274710939321b250e230a49ad744330ce84",
                    "bc6adf034143eeb77fc0b4562b9b7a5cd1bebdbb72d10b98801b0a6feb8bd958",
                    "cb5408768e61558432ac94ebdb3688c3d7c0923e8a99fdd2b6451c282565eac8",
                    "7143d1938552f76cfebc8d137c17bd0122d3220030bccc49e057b4986d2fb314",
                ],
            ),
            (
                RootKind::Evidence,
                [
                    "df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047",
                    "30ac7f62248a6377c2a7fdb281c560b54dab6c5f8862474bfcc64b767fdaab5a",
                    "42906895c1b8ea27175b7ee88c7adb738d1235f0038f89ac7f6517f7946cce3b",
                    "e16d45e768dae8e475c2936759fcf3a609f22ac9b9e4fae935fcfb8d46eaee82",
                    "ac039a83b50afdd73ff09265232cfd37d6b48b365f0957cbdceef48dd989aa14",
                ],
            ),
        ];

        for (kind, expected) in cases {
            for (item_count, expected_digest) in expected.into_iter().enumerate() {
                assert_eq!(
                    OrderedRootV0::from_items(kind, &fixtures[..item_count])
                        .unwrap()
                        .digest(),
                    hash32(expected_digest),
                    "kind={kind:?}, item_count={item_count}",
                );
            }
        }
    }
}
