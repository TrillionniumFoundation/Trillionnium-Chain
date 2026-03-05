// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * GovernanceGuardMVP
 * - Minimal external guard contract for high-risk param changes + emergency circuit breaker.
 * - This contract intentionally leaves bridge calls as interface stubs (IGovernanceBridge).
 */
contract GovernanceGuardMVP {
    error Unauthorized();
    error InvalidParamKey();
    error InvalidEta();
    error ProposalNotFound();
    error ProposalNotQueued();
    error TimelockNotReady();
    error AlreadyExecuted();
    error AlreadyCancelled();

    enum Status {
        Pending,
        Queued,
        Executed,
        Cancelled
    }

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

    interface IGovernanceBridge {
        function applyGovParam(string calldata key, string calldata value) external;
        function setEmergencyPause(bool paused) external;
    }

    event ParamChangeProposed(
        bytes32 indexed proposalId,
        address indexed proposer,
        uint64 eta,
        string paramKey,
        string oldValue,
        string newValue,
        bytes32 reasonHash
    );

    event ParamChangeQueued(bytes32 indexed proposalId, uint64 eta);

    event ParamChangeExecuted(
        bytes32 indexed proposalId,
        address indexed executor,
        uint64 eta,
        string paramKey,
        string oldValue,
        string newValue,
        uint64 executedAt
    );

    event ProposalCancelled(bytes32 indexed proposalId, address indexed canceller);

    event EmergencyPaused(address indexed triggeredBy, bytes32 reasonHash, uint64 at);
    event EmergencyUnpauseScheduled(bytes32 indexed proposalId, address indexed proposer, uint64 eta);
    event EmergencyUnpaused(bytes32 indexed proposalId, address indexed executor, uint64 at);

    uint64 public immutable minTimelockDelay;
    address public admin;
    address public guardian;
    address public bridge;

    mapping(address => bool) public proposers;
    mapping(address => bool) public executors;
    mapping(string => bool) public allowedParamKeys;
    mapping(bytes32 => Proposal) public proposals;

    uint256 private nonce;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert Unauthorized();
        _;
    }

    modifier onlyProposer() {
        if (!proposers[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlyExecutor() {
        if (!executors[msg.sender]) revert Unauthorized();
        _;
    }

    constructor(address _admin, address _guardian, address _bridge, uint64 _minTimelockDelay) {
        admin = _admin;
        guardian = _guardian;
        bridge = _bridge;
        minTimelockDelay = _minTimelockDelay;
    }

    function setProposer(address who, bool on) external onlyAdmin { proposers[who] = on; }
    function setExecutor(address who, bool on) external onlyAdmin { executors[who] = on; }
    function setAllowedParamKey(string calldata key, bool on) external onlyAdmin { allowedParamKeys[key] = on; }
    function setGuardian(address who) external onlyAdmin { guardian = who; }
    function setBridge(address who) external onlyAdmin { bridge = who; }

    function proposeParamChange(
        string calldata paramKey,
        string calldata oldValue,
        string calldata newValue,
        uint64 eta,
        bytes32 reasonHash
    ) external onlyProposer returns (bytes32 proposalId) {
        if (!allowedParamKeys[paramKey]) revert InvalidParamKey();
        if (eta < uint64(block.timestamp) + minTimelockDelay) revert InvalidEta();
        proposalId = keccak256(abi.encode(paramKey, oldValue, newValue, eta, nonce++));

        Proposal storage p = proposals[proposalId];
        p.proposer = msg.sender;
        p.eta = eta;
        p.paramKey = paramKey;
        p.oldValue = oldValue;
        p.newValue = newValue;
        p.reasonHash = reasonHash;
        p.status = Status.Pending;

        emit ParamChangeProposed(proposalId, msg.sender, eta, paramKey, oldValue, newValue, reasonHash);
    }

    function queueProposal(bytes32 proposalId) external onlyProposer {
        Proposal storage p = proposals[proposalId];
        if (p.proposer == address(0)) revert ProposalNotFound();
        if (p.status == Status.Cancelled) revert AlreadyCancelled();
        if (p.status == Status.Executed) revert AlreadyExecuted();
        p.status = Status.Queued;
        emit ParamChangeQueued(proposalId, p.eta);
    }

    function executeProposal(bytes32 proposalId) external onlyExecutor {
        Proposal storage p = proposals[proposalId];
        if (p.proposer == address(0)) revert ProposalNotFound();
        if (p.status != Status.Queued) revert ProposalNotQueued();
        if (p.status == Status.Executed) revert AlreadyExecuted();
        if (p.status == Status.Cancelled) revert AlreadyCancelled();
        if (block.timestamp < p.eta) revert TimelockNotReady();

        IGovernanceBridge(bridge).applyGovParam(p.paramKey, p.newValue);

        p.status = Status.Executed;
        p.executor = msg.sender;
        p.executedAt = uint64(block.timestamp);

        emit ParamChangeExecuted(
            proposalId,
            msg.sender,
            p.eta,
            p.paramKey,
            p.oldValue,
            p.newValue,
            p.executedAt
        );
    }

    function cancelProposal(bytes32 proposalId) external onlyGuardian {
        Proposal storage p = proposals[proposalId];
        if (p.proposer == address(0)) revert ProposalNotFound();
        if (p.status == Status.Executed) revert AlreadyExecuted();
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

        Proposal storage p = proposals[proposalId];
        p.proposer = msg.sender;
        p.eta = eta;
        p.paramKey = "emergency_pause";
        p.oldValue = "true";
        p.newValue = "false";
        p.reasonHash = reasonHash;
        p.status = Status.Queued;

        emit EmergencyUnpauseScheduled(proposalId, msg.sender, eta);
    }

    function executeEmergencyUnpause(bytes32 proposalId) external onlyExecutor {
        Proposal storage p = proposals[proposalId];
        if (p.proposer == address(0)) revert ProposalNotFound();
        if (p.status != Status.Queued) revert ProposalNotQueued();
        if (p.status == Status.Executed) revert AlreadyExecuted();
        if (p.status == Status.Cancelled) revert AlreadyCancelled();
        if (block.timestamp < p.eta) revert TimelockNotReady();

        IGovernanceBridge(bridge).setEmergencyPause(false);

        p.status = Status.Executed;
        p.executor = msg.sender;
        p.executedAt = uint64(block.timestamp);
        emit EmergencyUnpaused(proposalId, msg.sender, p.executedAt);
    }
}
