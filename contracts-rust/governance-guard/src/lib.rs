use std::collections::{HashMap, HashSet};

pub type ProposalId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Queued,
    Executed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalKind {
    ParamChange,
    EmergencyUnpause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub id: ProposalId,
    pub kind: ProposalKind,
    pub proposer: String,
    pub executor: Option<String>,
    pub eta: u64,
    pub param_key: String,
    pub old_value: String,
    pub new_value: String,
    pub reason_hash: String,
    pub status: ProposalStatus,
    pub executed_at: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GovernanceBridgeState {
    pub gov_params: HashMap<String, String>,
    pub emergency_paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Unauthorized,
    InvalidEta,
    InvalidParamKey,
    ProposalNotFound,
    NotQueued,
    NotReady,
    AlreadyFinalized,
    WrongProposalKind,
    SelfExecutionForbidden,
    PauseNotActive,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct GovernanceGuard {
    admin: String,
    min_timelock_delay_secs: u64,
    nonce: ProposalId,
    proposals: HashMap<ProposalId, Proposal>,
    allowed_param_keys: HashSet<String>,
    proposers: HashSet<String>,
    executors: HashSet<String>,
    guardians: HashSet<String>,
    bridge: GovernanceBridgeState,
}

impl GovernanceGuard {
    pub fn new(admin: impl Into<String>, guardian: impl Into<String>, min_timelock_delay_secs: u64) -> Self {
        let admin = admin.into();
        let guardian = guardian.into();
        let mut guardians = HashSet::new();
        guardians.insert(guardian);

        Self {
            admin,
            min_timelock_delay_secs,
            nonce: 1,
            proposals: HashMap::new(),
            allowed_param_keys: HashSet::new(),
            proposers: HashSet::new(),
            executors: HashSet::new(),
            guardians,
            bridge: GovernanceBridgeState::default(),
        }
    }

    pub fn set_role(
        &mut self,
        caller: &str,
        who: impl Into<String>,
        can_propose: bool,
        can_execute: bool,
    ) -> Result<()> {
        self.require_admin(caller)?;
        let who = who.into();
        Self::set_membership(&mut self.proposers, &who, can_propose);
        Self::set_membership(&mut self.executors, &who, can_execute);
        Ok(())
    }

    pub fn set_guardian(&mut self, caller: &str, who: impl Into<String>, enabled: bool) -> Result<()> {
        self.require_admin(caller)?;
        let who = who.into();
        Self::set_membership(&mut self.guardians, &who, enabled);
        Ok(())
    }

    pub fn set_allowed_param_key(&mut self, caller: &str, key: impl Into<String>, enabled: bool) -> Result<()> {
        self.require_admin(caller)?;
        let key = key.into();
        Self::set_membership(&mut self.allowed_param_keys, &key, enabled);
        Ok(())
    }

    pub fn propose(
        &mut self,
        caller: &str,
        param_key: impl Into<String>,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
        eta: u64,
        reason_hash: impl Into<String>,
        now: u64,
    ) -> Result<ProposalId> {
        self.require_proposer(caller)?;
        if eta < now.saturating_add(self.min_timelock_delay_secs) {
            return Err(Error::InvalidEta);
        }

        let param_key = param_key.into();
        if !self.allowed_param_keys.contains(&param_key) {
            return Err(Error::InvalidParamKey);
        }

        let id = self.next_id();
        let proposal = Proposal {
            id,
            kind: ProposalKind::ParamChange,
            proposer: caller.to_owned(),
            executor: None,
            eta,
            param_key,
            old_value: old_value.into(),
            new_value: new_value.into(),
            reason_hash: reason_hash.into(),
            status: ProposalStatus::Pending,
            executed_at: None,
        };
        self.proposals.insert(id, proposal);
        Ok(id)
    }

    pub fn queue(&mut self, caller: &str, proposal_id: ProposalId) -> Result<()> {
        self.require_proposer(caller)?;
        let proposal = self.proposal_mut(proposal_id)?;
        if matches!(proposal.status, ProposalStatus::Executed | ProposalStatus::Cancelled) {
            return Err(Error::AlreadyFinalized);
        }
        proposal.status = ProposalStatus::Queued;
        Ok(())
    }

    pub fn execute(&mut self, caller: &str, proposal_id: ProposalId, now: u64) -> Result<()> {
        self.require_executor(caller)?;

        let (param_key, new_value) = {
            let proposal = self.proposal_mut(proposal_id)?;

            if proposal.kind != ProposalKind::ParamChange {
                return Err(Error::WrongProposalKind);
            }
            if proposal.status != ProposalStatus::Queued {
                return Err(Error::NotQueued);
            }
            if now < proposal.eta {
                return Err(Error::NotReady);
            }

            (proposal.param_key.clone(), proposal.new_value.clone())
        };

        self.bridge.gov_params.insert(param_key, new_value);

        let proposal = self.proposal_mut(proposal_id)?;
        proposal.status = ProposalStatus::Executed;
        proposal.executor = Some(caller.to_owned());
        proposal.executed_at = Some(now);
        Ok(())
    }

    pub fn cancel(&mut self, caller: &str, proposal_id: ProposalId) -> Result<()> {
        self.require_guardian(caller)?;
        let proposal = self.proposal_mut(proposal_id)?;
        if matches!(proposal.status, ProposalStatus::Executed | ProposalStatus::Cancelled) {
            return Err(Error::AlreadyFinalized);
        }
        proposal.status = ProposalStatus::Cancelled;
        Ok(())
    }

    pub fn emergency_pause(&mut self, caller: &str, _reason_hash: impl Into<String>) -> Result<()> {
        self.require_guardian(caller)?;
        self.bridge.emergency_paused = true;
        Ok(())
    }

    pub fn schedule_unpause(
        &mut self,
        caller: &str,
        eta: u64,
        reason_hash: impl Into<String>,
        now: u64,
    ) -> Result<ProposalId> {
        self.require_guardian(caller)?;
        if !self.bridge.emergency_paused {
            return Err(Error::PauseNotActive);
        }
        if eta < now.saturating_add(self.min_timelock_delay_secs) {
            return Err(Error::InvalidEta);
        }

        let id = self.next_id();
        let proposal = Proposal {
            id,
            kind: ProposalKind::EmergencyUnpause,
            proposer: caller.to_owned(),
            executor: None,
            eta,
            param_key: "emergency_pause".to_string(),
            old_value: "true".to_string(),
            new_value: "false".to_string(),
            reason_hash: reason_hash.into(),
            status: ProposalStatus::Queued,
            executed_at: None,
        };
        self.proposals.insert(id, proposal);
        Ok(id)
    }

    pub fn execute_unpause(&mut self, caller: &str, proposal_id: ProposalId, now: u64) -> Result<()> {
        self.require_executor(caller)?;

        {
            let proposal = self.proposal_mut(proposal_id)?;

            if proposal.kind != ProposalKind::EmergencyUnpause {
                return Err(Error::WrongProposalKind);
            }
            if proposal.status != ProposalStatus::Queued {
                return Err(Error::NotQueued);
            }
            if now < proposal.eta {
                return Err(Error::NotReady);
            }
            if proposal.proposer == caller {
                return Err(Error::SelfExecutionForbidden);
            }
        }

        if !self.bridge.emergency_paused {
            return Err(Error::PauseNotActive);
        }

        self.bridge.emergency_paused = false;

        let proposal = self.proposal_mut(proposal_id)?;
        proposal.status = ProposalStatus::Executed;
        proposal.executor = Some(caller.to_owned());
        proposal.executed_at = Some(now);
        Ok(())
    }

    pub fn proposal(&self, id: ProposalId) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    pub fn bridge_state(&self) -> &GovernanceBridgeState {
        &self.bridge
    }

    fn require_admin(&self, caller: &str) -> Result<()> {
        if caller == self.admin {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    fn require_proposer(&self, caller: &str) -> Result<()> {
        if self.proposers.contains(caller) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    fn require_executor(&self, caller: &str) -> Result<()> {
        if self.executors.contains(caller) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    fn require_guardian(&self, caller: &str) -> Result<()> {
        if self.guardians.contains(caller) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    fn proposal_mut(&mut self, id: ProposalId) -> Result<&mut Proposal> {
        self.proposals.get_mut(&id).ok_or(Error::ProposalNotFound)
    }

    fn next_id(&mut self) -> ProposalId {
        let id = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        id
    }

    fn set_membership(set: &mut HashSet<String>, value: &str, enabled: bool) {
        if enabled {
            set.insert(value.to_owned());
        } else {
            set.remove(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> GovernanceGuard {
        let mut gov = GovernanceGuard::new("admin", "guardian", 60);
        gov.set_role("admin", "alice", true, false).unwrap();
        gov.set_role("admin", "exec", false, true).unwrap();
        gov.set_allowed_param_key("admin", "challenge_window_blocks", true)
            .unwrap();
        gov
    }

    #[test]
    fn timelock_bypass_fails_closed_without_side_effects() {
        let mut gov = setup();
        let now = 1_000;
        let eta = now + 60;

        let pid = gov
            .propose(
                "alice",
                "challenge_window_blocks",
                "100",
                "120",
                eta,
                "reason-1",
                now,
            )
            .unwrap();
        gov.queue("alice", pid).unwrap();

        let before = gov.bridge_state().gov_params.get("challenge_window_blocks").cloned();
        let err = gov.execute("exec", pid, eta - 1).unwrap_err();
        assert_eq!(err, Error::NotReady);

        let p = gov.proposal(pid).unwrap();
        assert_eq!(p.status, ProposalStatus::Queued);
        assert_eq!(before, gov.bridge_state().gov_params.get("challenge_window_blocks").cloned());
    }

    #[test]
    fn duplicate_execute_is_blocked() {
        let mut gov = setup();
        let now = 2_000;
        let eta = now + 60;

        let pid = gov
            .propose(
                "alice",
                "challenge_window_blocks",
                "120",
                "160",
                eta,
                "reason-2",
                now,
            )
            .unwrap();
        gov.queue("alice", pid).unwrap();

        gov.execute("exec", pid, eta).unwrap();
        let second = gov.execute("exec", pid, eta + 1).unwrap_err();
        assert_eq!(second, Error::NotQueued);
    }

    #[test]
    fn permission_drift_revocation_fails_closed() {
        let mut gov = setup();
        let now = 3_000;
        let eta = now + 60;

        gov.set_role("admin", "alice", false, false).unwrap();
        assert_eq!(
            gov.propose(
                "alice",
                "challenge_window_blocks",
                "1",
                "2",
                eta,
                "reason-3",
                now,
            )
            .unwrap_err(),
            Error::Unauthorized
        );

        gov.set_role("admin", "alice", true, false).unwrap();
        let pid = gov
            .propose(
                "alice",
                "challenge_window_blocks",
                "1",
                "2",
                eta,
                "reason-4",
                now,
            )
            .unwrap();
        gov.queue("alice", pid).unwrap();

        gov.set_role("admin", "exec", false, false).unwrap();
        assert_eq!(gov.execute("exec", pid, eta).unwrap_err(), Error::Unauthorized);

        gov.set_guardian("admin", "guardian", false).unwrap();
        assert_eq!(gov.cancel("guardian", pid).unwrap_err(), Error::Unauthorized);
    }

    #[test]
    fn pause_immediate_unpause_timelocked() {
        let mut gov = setup();
        let now = 4_000;
        gov.emergency_pause("guardian", "incident-1").unwrap();
        assert!(gov.bridge_state().emergency_paused);

        let eta = now + 60;
        let pid = gov
            .schedule_unpause("guardian", eta, "recover-1", now)
            .unwrap();

        assert_eq!(
            gov.execute_unpause("exec", pid, eta - 1).unwrap_err(),
            Error::NotReady
        );
        assert!(gov.bridge_state().emergency_paused);

        gov.execute_unpause("exec", pid, eta).unwrap();
        assert!(!gov.bridge_state().emergency_paused);
    }

    #[test]
    fn emergency_unpause_requires_distinct_executor() {
        let mut gov = setup();
        gov.set_role("admin", "guardian", false, true).unwrap();

        let now = 5_000;
        let eta = now + 60;
        gov.emergency_pause("guardian", "incident-2").unwrap();
        let pid = gov
            .schedule_unpause("guardian", eta, "recover-2", now)
            .unwrap();

        assert_eq!(
            gov.execute_unpause("guardian", pid, eta).unwrap_err(),
            Error::SelfExecutionForbidden
        );
        assert!(gov.bridge_state().emergency_paused);

        gov.execute_unpause("exec", pid, eta).unwrap();
        assert!(!gov.bridge_state().emergency_paused);
    }

    #[test]
    fn schedule_unpause_rejects_when_pause_is_not_active() {
        let mut gov = setup();
        let now = 6_000;
        let eta = now + 60;

        assert_eq!(
            gov.schedule_unpause("guardian", eta, "noop-recover", now)
                .unwrap_err(),
            Error::PauseNotActive
        );
    }

    #[test]
    fn execute_unpause_rejects_if_pause_cleared_before_eta() {
        let mut gov = setup();
        let now = 7_000;
        let eta = now + 60;

        gov.emergency_pause("guardian", "incident-3").unwrap();
        let pid = gov
            .schedule_unpause("guardian", eta, "recover-3", now)
            .unwrap();

        gov.bridge.emergency_paused = false;

        assert_eq!(
            gov.execute_unpause("exec", pid, eta).unwrap_err(),
            Error::PauseNotActive
        );
    }
}
