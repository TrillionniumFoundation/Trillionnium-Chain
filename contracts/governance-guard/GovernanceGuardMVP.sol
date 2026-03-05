// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGovernanceBridge {
    function applyGovParam(string calldata key, string calldata value) external;
    function setEmergencyPause(bool paused) external;
}

contract GovernanceGuardMVP {
    error Unauthorized();
    error InvalidEta();
    error InvalidParamKey();
    error NotQueued();
    error NotReady();
    error AlreadyFinalized();

    enum Status { Pending, Queued, Executed, Cancelled }

    struct Proposal {
        address proposer;
        address executor;
        uint64 eta;
        string paramKey;
        string oldValue;
        string newValue;
        bytes32 reasonHash;
        Status status;
        uint64 executedAt;
    }

    event ParamChangeProposed(bytes32 indexed proposalId, address indexed proposer, uint64 eta, string paramKey, string oldValue, string newValue, bytes32 reasonHash);
    event ParamChangeQueued(bytes32 indexed proposalId, uint64 eta);
    event ParamChangeExecuted(bytes32 indexed proposalId, address indexed executor, uint64 eta, string paramKey, string oldValue, string newValue, uint64 executedAt);
    event ProposalCancelled(bytes32 indexed proposalId, address indexed canceller);
    event EmergencyPaused(address indexed triggeredBy, bytes32 reasonHash, uint64 at);
    event EmergencyUnpauseScheduled(bytes32 indexed proposalId, address indexed proposer, uint64 eta);
    event EmergencyUnpaused(bytes32 indexed proposalId, address indexed executor, uint64 at);

    mapping(bytes32 => Proposal) public proposals;
    mapping(string => bool) public allowedParamKeys;
    mapping(address => bool) public proposers;
    mapping(address => bool) public executors;

    address public admin;
    address public guardian;
    address public bridge;
    uint64 public immutable minTimelockDelay;
    uint256 private nonce;

    modifier onlyAdmin() { if (msg.sender != admin) revert Unauthorized(); _; }
    modifier onlyGuardian() { if (msg.sender != guardian) revert Unauthorized(); _; }
    modifier onlyProposer() { if (!proposers[msg.sender]) revert Unauthorized(); _; }
    modifier onlyExecutor() { if (!executors[msg.sender]) revert Unauthorized(); _; }

    constructor(address _admin, address _guardian, address _bridge, uint64 _delay) {
        admin = _admin;
        guardian = _guardian;
        bridge = _bridge;
        minTimelockDelay = _delay;
    }

    function setRole(address who, bool canPropose, bool canExecute) external onlyAdmin {
        proposers[who] = canPropose;
        executors[who] = canExecute;
    }

    function setAllowedParamKey(string calldata key, bool on) external onlyAdmin { allowedParamKeys[key] = on; }

    function proposeParamChange(string calldata key, string calldata oldValue, string calldata newValue, uint64 eta, bytes32 reasonHash)
        external onlyProposer returns (bytes32 proposalId)
    {
        if (!allowedParamKeys[key]) revert InvalidParamKey();
        if (eta < uint64(block.timestamp) + minTimelockDelay) revert InvalidEta();
        proposalId = keccak256(abi.encode(key, oldValue, newValue, eta, nonce++));
        proposals[proposalId] = Proposal(msg.sender, address(0), eta, key, oldValue, newValue, reasonHash, Status.Pending, 0);
        emit ParamChangeProposed(proposalId, msg.sender, eta, key, oldValue, newValue, reasonHash);
    }

    function queueProposal(bytes32 proposalId) external onlyProposer {
        Proposal storage p = proposals[proposalId];
        if (p.status == Status.Executed || p.status == Status.Cancelled) revert AlreadyFinalized();
        p.status = Status.Queued;
        emit ParamChangeQueued(proposalId, p.eta);
    }

    function executeProposal(bytes32 proposalId) external onlyExecutor {
        Proposal storage p = proposals[proposalId];
        if (p.status != Status.Queued) revert NotQueued();
        if (block.timestamp < p.eta) revert NotReady();
        IGovernanceBridge(bridge).applyGovParam(p.paramKey, p.newValue);
        p.status = Status.Executed;
        p.executor = msg.sender;
        p.executedAt = uint64(block.timestamp);
        emit ParamChangeExecuted(proposalId, msg.sender, p.eta, p.paramKey, p.oldValue, p.newValue, p.executedAt);
    }

    function cancelProposal(bytes32 proposalId) external onlyGuardian {
        Proposal storage p = proposals[proposalId];
        if (p.status == Status.Executed || p.status == Status.Cancelled) revert AlreadyFinalized();
        p.status = Status.Cancelled;
        emit ProposalCancelled(proposalId, msg.sender);
    }

    function emergencyPause(bytes32 reasonHash) external onlyGuardian {
        IGovernanceBridge(bridge).setEmergencyPause(true);
        emit EmergencyPaused(msg.sender, reasonHash, uint64(block.timestamp));
    }

    function scheduleEmergencyUnpause(uint64 eta, bytes32 reasonHash) external onlyGuardian returns (bytes32 proposalId) {
        if (eta < uint64(block.timestamp) + minTimelockDelay) revert InvalidEta();
        proposalId = keccak256(abi.encode("emergency_pause", "true", "false", eta, nonce++, reasonHash));
        proposals[proposalId] = Proposal(msg.sender, address(0), eta, "emergency_pause", "true", "false", reasonHash, Status.Queued, 0);
        emit EmergencyUnpauseScheduled(proposalId, msg.sender, eta);
    }

    function executeEmergencyUnpause(bytes32 proposalId) external onlyExecutor {
        Proposal storage p = proposals[proposalId];
        if (p.status != Status.Queued) revert NotQueued();
        if (block.timestamp < p.eta) revert NotReady();
        IGovernanceBridge(bridge).setEmergencyPause(false);
        p.status = Status.Executed;
        p.executor = msg.sender;
        p.executedAt = uint64(block.timestamp);
        emit EmergencyUnpaused(proposalId, msg.sender, p.executedAt);
    }
}
