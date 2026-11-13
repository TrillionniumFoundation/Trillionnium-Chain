/// Research-only per-verified-parent ASERT projection. The installed Node never
/// calls this module, so it cannot change any consensus target or acceptance.
/// The caller MUST validate actual work, branch, header, application and time
/// before passing an untrusted header. A projection is never a PoW proof.
pub mod daa_incremental_research {
    use super::{daa_research, ensure, Result};
    use std::collections::BTreeMap;

    pub type Digest = [u8; 32];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ParentClock {
        Raw,
        Mtp11,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Context {
        pub network: Digest,
        pub parameters: Digest,
        pub genesis: Digest,
        pub genesis_timestamp: u64,
        pub activation_height: u64,
        pub spacing: u64,
        pub half_life: u64,
        pub pow_limit: Digest,
        pub clock: ParentClock,
        pub rule_identity: Digest,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct AlreadyValidatedHeaderResearchInput {
        pub block_id: Digest,
        pub parent_id: Digest,
        pub network: Digest,
        pub parameters: Digest,
        pub height: u64,
        pub timestamp: u64,
        pub target: Digest,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Anchor {
        block_id: Digest,
        parent_id: Digest,
        target: Digest,
        parent_time: u64,
    }

    /// A bounded readback projection, not a transferable authenticated certificate.
    /// The native owner must associate this with its own validated branch State.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Summary {
        block_id: Digest,
        height: u64,
        timestamp: u64,
        recent: [u64; 11],
        recent_len: u8,
        rule_identity: Digest,
        network: Digest,
        parameters: Digest,
        genesis: Digest,
        anchor: Option<Anchor>,
    }

    fn check_context(ctx: &Context) -> Result<()> {
        ensure(
            ctx.network != [0; 32]
                && ctx.parameters != [0; 32]
                && ctx.genesis != [0; 32]
                && ctx.rule_identity != [0; 32]
                && ctx.activation_height > 0
                && ctx.activation_height < u64::MAX
                && ctx.spacing > 0
                && ctx.half_life > 0
                && ctx.pow_limit != [0; 32],
            "ASERT_SUMMARY_CONTEXT",
        )
    }

    fn median(summary: &Summary) -> Result<u64> {
        ensure(
            (1..=11).contains(&summary.recent_len),
            "ASERT_SUMMARY_WINDOW",
        )?;
        let mut window = summary.recent;
        let used = usize::from(summary.recent_len);
        window[..used].sort_unstable();
        Ok(window[used / 2])
    }

    /// An owner's local research index. Entries are born only from an existing
    /// parent state; peer-provided summaries are not an accepted input format.
    /// Long-term storage/GC and crash recovery belong to the real native owner.
    pub struct OwnerIndex {
        ctx: Context,
        summaries: BTreeMap<Digest, Summary>,
    }

    impl OwnerIndex {
        pub fn new(ctx: Context) -> Result<Self> {
            let base = Summary::genesis(&ctx)?;
            let mut summaries = BTreeMap::new();
            summaries.insert(base.block_id(), base);
            Ok(Self { ctx, summaries })
        }

        pub fn at(&self, block_id: Digest) -> Result<Summary> {
            self.summaries.get(&block_id).copied()
                .ok_or_else(|| "ASERT_SUMMARY_UNAVAILABLE".into())
        }

        pub fn observe_already_validated(
            &mut self,
            header: &AlreadyValidatedHeaderResearchInput,
        ) -> Result<Summary> {
            ensure(!self.summaries.contains_key(&header.block_id), "ASERT_SUMMARY_DUPLICATE")?;
            let parent = self.at(header.parent_id)?;
            let summary = parent.extend_verified(&self.ctx, header)?;
            self.summaries.insert(header.block_id, summary);
            Ok(summary)
        }

        pub fn len(&self) -> usize { self.summaries.len() }
    }

    impl Summary {
        pub fn genesis(ctx: &Context) -> Result<Self> {
            check_context(ctx)?;
            let mut recent = [0_u64; 11];
            recent[0] = ctx.genesis_timestamp;
            Ok(Self {
                block_id: ctx.genesis,
                height: 0,
                timestamp: ctx.genesis_timestamp,
                recent,
                recent_len: 1,
                rule_identity: ctx.rule_identity,
                network: ctx.network, parameters: ctx.parameters, genesis: ctx.genesis,
                anchor: None,
            })
        }

        /// Strict O(11) projection for an already independently accepted header.
        /// No direct/indirect proof, lease, signature, peer or SQLite authority.
        pub fn extend_verified(
            &self,
            ctx: &Context,
            h: &AlreadyValidatedHeaderResearchInput,
        ) -> Result<Self> {
            check_context(ctx)?;
            ensure(self.rule_identity == ctx.rule_identity
                   && self.network == ctx.network
                   && self.parameters == ctx.parameters
                   && self.genesis == ctx.genesis, "ASERT_SUMMARY_CONTEXT")?;
            let next_height = self.height.checked_add(1).ok_or("ASERT_SUMMARY_HEIGHT")?;
            ensure(
                h.network == ctx.network
                    && h.parameters == ctx.parameters
                    && h.parent_id == self.block_id
                    && h.block_id != [0; 32]
                    && h.block_id != h.parent_id
                    && h.height == next_height
                    && h.target != [0; 32]
                    && h.target <= ctx.pow_limit,
                "ASERT_SUMMARY_PARENT_OR_CONTEXT",
            )?;
            let anchor = if h.height == ctx.activation_height {
                ensure(self.anchor.is_none(), "ASERT_SUMMARY_EARLY_ANCHOR")?;
                Some(Anchor {
                    block_id: h.block_id,
                    parent_id: h.parent_id,
                    target: h.target,
                    parent_time: match ctx.clock {
                        ParentClock::Raw => self.timestamp,
                        ParentClock::Mtp11 => median(self)?,
                    },
                })
            } else if h.height > ctx.activation_height {
                Some(self.anchor.ok_or("ASERT_SUMMARY_ANCHOR_MISSING")?)
            } else {
                ensure(self.anchor.is_none(), "ASERT_SUMMARY_PREACTIVATION")?;
                None
            };
            ensure((1..=11).contains(&self.recent_len), "ASERT_SUMMARY_WINDOW")?;
            let copied = usize::from(self.recent_len).min(10);
            let mut recent = [0_u64; 11];
            recent[0] = h.timestamp;
            recent[1..=copied].copy_from_slice(&self.recent[..copied]);
            Ok(Self {
                block_id: h.block_id,
                height: h.height,
                timestamp: h.timestamp,
                recent,
                recent_len: (copied + 1) as u8,
                rule_identity: ctx.rule_identity,
                network: ctx.network, parameters: ctx.parameters, genesis: ctx.genesis,
                anchor,
            })
        }

        /// Shadow-only target: existing Node and its legacy DAA never call it.
        pub fn shadow_target(&self, ctx: &Context) -> Result<Digest> {
            check_context(ctx)?;
            ensure(self.rule_identity == ctx.rule_identity
                   && self.network == ctx.network
                   && self.parameters == ctx.parameters
                   && self.genesis == ctx.genesis, "ASERT_SUMMARY_CONTEXT")?;
            ensure(self.height >= ctx.activation_height, "ASERT_NOT_ACTIVE")?;
            let next = self.height.checked_add(1).ok_or("ASERT_SUMMARY_HEIGHT")?;
            let anchor = self.anchor.ok_or("ASERT_SUMMARY_ANCHOR_MISSING")?;
            daa_research::asert_target(daa_research::AsertInputs {
                anchor_target: anchor.target,
                anchor_parent_time: anchor.parent_time,
                evaluation_parent_time: match ctx.clock {
                    ParentClock::Raw => self.timestamp,
                    ParentClock::Mtp11 => median(self)?,
                },
                anchor_height: ctx.activation_height,
                candidate_height: next,
                spacing: ctx.spacing,
                half_life: ctx.half_life,
                pow_limit: ctx.pow_limit,
            })
        }

        pub fn height(&self) -> u64 { self.height }
        pub fn block_id(&self) -> Digest { self.block_id }
        pub fn anchor_id(&self) -> Option<Digest> { self.anchor.map(|a| a.block_id) }
        pub fn recent_count(&self) -> u8 { self.recent_len }
    }
}

#[cfg(test)]
mod daa_incremental_research_tests {
    use super::daa_incremental_research::{
        AlreadyValidatedHeaderResearchInput as H, Context, ParentClock, Summary,
    };

    fn context(clock: ParentClock) -> Context {
        let mut base = [0_u8; 32];
        base[4] = 0x10; // 2^220
        let mut cap = [255_u8; 32];
        cap[0] = 0; cap[1] = 0;
        Context {
            network: [1; 32], parameters: [2; 32], genesis: [3; 32],
            genesis_timestamp: 10_000, activation_height: 16,
            spacing: 10, half_life: 7_200, pow_limit: cap,
            clock, rule_identity: [4; 32],
        }
    }

    fn expected_base() -> [u8; 32] {
        let mut base = [0_u8; 32];
        base[4] = 0x10;
        base
    }

    fn extend(parent: &Summary, ctx: &Context, height: u64, stamp: u64, fork: u8) -> Summary {
        let mut block_id = [0_u8; 32];
        block_id[..8].copy_from_slice(&height.to_le_bytes());
        block_id[8] = fork;
        parent.extend_verified(ctx, &H {
            block_id, parent_id: parent.block_id(),
            network: ctx.network, parameters: ctx.parameters,
            height, timestamp: stamp, target: expected_base(),
        }).unwrap()
    }

    #[test]
    fn shadow_is_constant_lookback_through_8192_headers() {
        for clock in [ParentClock::Raw, ParentClock::Mtp11] {
            let ctx = context(clock);
            let mut tip = Summary::genesis(&ctx).unwrap();
            for h in 1..=8192 {
                tip = extend(&tip, &ctx, h, 10_000 + h * 10, 0);
            }
            assert_eq!(tip.height(), 8192);
            assert_eq!(tip.recent_count(), 11);
            assert_eq!(tip.shadow_target(&ctx).unwrap(), expected_base());
        }
    }

    #[test]
    fn independent_pre_activation_forks_have_different_anchors() {
        let ctx = context(ParentClock::Raw);
        let mut parent = Summary::genesis(&ctx).unwrap();
        for h in 1..=13 { parent = extend(&parent, &ctx, h, 10_000 + 10*h, 0); }
        let (mut a, mut b) = (parent, parent);
        for h in 14..=25 {
            a = extend(&a, &ctx, h, 10_000 + 10*h, 1);
            b = extend(&b, &ctx, h, 10_000 + 12*h, 2);
        }
        assert_ne!(a.anchor_id(), b.anchor_id());
        assert_ne!(a.shadow_target(&ctx).unwrap(), b.shadow_target(&ctx).unwrap());
    }

    #[test]
    fn owned_index_requires_a_real_parent_and_never_accepts_peer_skip() {
        use super::daa_incremental_research::OwnerIndex;
        let ctx = context(ParentClock::Raw);
        let mut owner = OwnerIndex::new(ctx).unwrap();
        let first = H {
            block_id: [5; 32], parent_id: ctx.genesis,
            network: ctx.network, parameters: ctx.parameters,
            height: 1, timestamp: 10_010, target: expected_base(),
        };
        let forged = H { block_id: [6; 32], parent_id: [42; 32], ..first };
        assert_eq!(owner.observe_already_validated(&forged).unwrap_err().to_string(),
                   "ASERT_SUMMARY_UNAVAILABLE");
        assert_eq!(owner.len(), 1);
        assert_eq!(owner.observe_already_validated(&first).unwrap().height(), 1);
        assert_eq!(owner.observe_already_validated(&first).unwrap_err().to_string(),
                   "ASERT_SUMMARY_DUPLICATE");
        assert_eq!(owner.len(), 2);
    }

    #[test]
    fn read_only_projection_rejects_mixed_context_and_parent_or_height() {
        let ctx = context(ParentClock::Raw);
        let parent = Summary::genesis(&ctx).unwrap();
        let wrong = H {
            block_id: [9; 32], parent_id: [8; 32],
            network: ctx.network, parameters: ctx.parameters,
            height: 1, timestamp: 10_010, target: expected_base(),
        };
        assert_eq!(parent.extend_verified(&ctx, &wrong).unwrap_err().to_string(),
                   "ASERT_SUMMARY_PARENT_OR_CONTEXT");
        let mut wrong_context = ctx;
        wrong_context.rule_identity = [7; 32];
        assert_eq!(parent.extend_verified(&wrong_context, &wrong).unwrap_err().to_string(),
                   "ASERT_SUMMARY_CONTEXT");
        assert_eq!(parent.shadow_target(&ctx).unwrap_err().to_string(), "ASERT_NOT_ACTIVE");
    }
}
