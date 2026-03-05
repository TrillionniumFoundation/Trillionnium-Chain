// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// NOTE(M0-MVP Lane-1): Skeleton only; not wired into production execution path.
// Audit-first shape: explicit state machine + replay guard + pause gate.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SettlementVault {
    enum Status {
        None,
        Locked,
        Released,
        Slashed,
        Cancelled
    }

    struct LockOrder {
        address owner;
        uint256 amount;
        uint64 createdAt;
        uint64 unlockAt;
        Status status;
    }

    // --- roles (minimal skeleton; replace with AccessControl in production) ---
    address public admin;
    mapping(address => bool) public pausers;
    mapping(address => bool) public lockers;
    mapping(address => bool) public settlers;

    IERC20 public immutable asset;
    bool public paused;

    uint256 public totalDeposited;
    uint256 public totalLocked;
    uint256 public totalReleased;
    uint256 public totalSlashed;
    uint256 public minLockDelay;

    mapping(address => uint256) public availableBalance;
    mapping(bytes32 => LockOrder) public lockOrders;
    mapping(bytes32 => bool) public consumedRequestIds;

    event Deposited(address indexed sender, address indexed beneficiary, uint256 amount);
    event Locked(bytes32 indexed requestId, address indexed owner, uint256 amount, uint64 unlockAt);
    event Released(bytes32 indexed requestId, address indexed owner, address indexed to, uint256 amount);
    event Slashed(bytes32 indexed requestId, address indexed owner, address indexed treasury, uint256 amount);
    event EmergencyPaused(address indexed by);
    event Unpaused(address indexed by);

    error Unauthorized();
    error Paused();
    error InvalidParam();
    error InsufficientAvailableBalance();
    error RequestAlreadyConsumed();
    error InvalidState();
    error LockNotMatured();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyPauser() {
        if (!pausers[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlyLocker() {
        if (!lockers[msg.sender]) revert Unauthorized();
        _;
    }

    modifier onlySettler() {
        if (!settlers[msg.sender]) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    constructor(address asset_, uint256 minLockDelay_) {
        if (asset_ == address(0)) revert InvalidParam();
        admin = msg.sender;
        pausers[msg.sender] = true;
        lockers[msg.sender] = true;
        settlers[msg.sender] = true;
        asset = IERC20(asset_);
        minLockDelay = minLockDelay_;
    }

    // --- admin role wiring (skeleton) ---
    function setPauser(address who, bool enabled) external onlyAdmin {
        pausers[who] = enabled;
    }

    function setLocker(address who, bool enabled) external onlyAdmin {
        lockers[who] = enabled;
    }

    function setSettler(address who, bool enabled) external onlyAdmin {
        settlers[who] = enabled;
    }

    function setMinLockDelay(uint256 value) external onlyAdmin {
        minLockDelay = value;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert InvalidParam();
        admin = newAdmin;
    }

    // --- MVP interfaces ---
    function deposit(address beneficiary, uint256 amount) external whenNotPaused {
        if (beneficiary == address(0) || amount == 0) revert InvalidParam();
        bool ok = asset.transferFrom(msg.sender, address(this), amount);
        if (!ok) revert InvalidParam();

        availableBalance[beneficiary] += amount;
        totalDeposited += amount;

        emit Deposited(msg.sender, beneficiary, amount);
    }

    function lock(bytes32 requestId, address owner, uint256 amount, uint64 unlockAt) external onlyLocker whenNotPaused {
        if (owner == address(0) || amount == 0) revert InvalidParam();
        if (consumedRequestIds[requestId]) revert RequestAlreadyConsumed();
        if (unlockAt < block.timestamp + minLockDelay) revert InvalidParam();
        if (availableBalance[owner] < amount) revert InsufficientAvailableBalance();

        consumedRequestIds[requestId] = true;
        availableBalance[owner] -= amount;
        totalLocked += amount;

        lockOrders[requestId] = LockOrder({
            owner: owner,
            amount: amount,
            createdAt: uint64(block.timestamp),
            unlockAt: unlockAt,
            status: Status.Locked
        });

        emit Locked(requestId, owner, amount, unlockAt);
    }

    function release(bytes32 requestId, address to) external onlySettler whenNotPaused {
        if (to == address(0)) revert InvalidParam();
        LockOrder storage order = lockOrders[requestId];
        if (order.status != Status.Locked) revert InvalidState();
        if (block.timestamp < order.unlockAt) revert LockNotMatured();

        order.status = Status.Released;
        totalLocked -= order.amount;
        totalReleased += order.amount;

        bool ok = asset.transfer(to, order.amount);
        if (!ok) revert InvalidParam();

        emit Released(requestId, order.owner, to, order.amount);
    }

    function slash(bytes32 requestId, address treasury) external onlySettler whenNotPaused {
        if (treasury == address(0)) revert InvalidParam();
        LockOrder storage order = lockOrders[requestId];
        if (order.status != Status.Locked) revert InvalidState();

        order.status = Status.Slashed;
        totalLocked -= order.amount;
        totalSlashed += order.amount;

        bool ok = asset.transfer(treasury, order.amount);
        if (!ok) revert InvalidParam();

        emit Slashed(requestId, order.owner, treasury, order.amount);
    }

    function emergencyPause() external onlyPauser {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }
}
