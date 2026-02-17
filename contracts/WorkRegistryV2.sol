// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title OpenClaw Optimistic Work Registry V2
 * @dev Introduces Staking, Challenge Period, and Slashing.
 */
contract WorkRegistryV2 {

    // Configuration
    uint256 public constant CHALLENGE_PERIOD = 1 days; // Time window for challenges
    uint256 public constant MIN_STAKE = 0.1 ether;    // Minimum stake to be a Worker/Verifier

    struct Task {
        address creator;
        uint256 bounty;
        string ipfsHash;
        bytes32 imageHash;
        uint256 deadline;
        
        address assignedWorker;
        uint256 workerStake;      // Worker puts skin in the game
        
        bytes32 submittedHash;    // The hash of the result
        uint256 submissionTime;   // When the result was submitted
        bool finalized;           // Is the task closed?
        bool challenged;          // Is there an active dispute?
        address challenger;       // Who challenged it?
    }

    mapping(uint256 => Task) public tasks;
    uint256 public taskCounter;

    // Events
    event TaskCreated(uint256 indexed taskId, string ipfsHash, uint256 bounty);
    event TaskClaimed(uint256 indexed taskId, address indexed worker);
    event SolutionSubmitted(uint256 indexed taskId, bytes32 resultHash);
    event ChallengeRaised(uint256 indexed taskId, address indexed challenger);
    event TaskFinalized(uint256 indexed taskId, bool success);

    // Errors
    error IncorrectStake();
    error NotAssignedWorker();
    error AlreadyCompleted();
    error NotInChallengeWindow();
    error ChallengePeriodActive();
    error OnlyArbiter();

    // 1. Create Task (User puts bounty)
    function createTask(string calldata _ipfsHash, bytes32 _imageHash) external payable {
        require(msg.value > 0, "Bounty required");
        
        uint256 taskId = taskCounter++;
        tasks[taskId] = Task({
            creator: msg.sender,
            bounty: msg.value,
            ipfsHash: _ipfsHash,
            imageHash: _imageHash,
            deadline: block.timestamp + 2 days,
            assignedWorker: address(0),
            workerStake: 0,
            submittedHash: bytes32(0),
            submissionTime: 0,
            finalized: false,
            challenged: false,
            challenger: address(0)
        });
        
        emit TaskCreated(taskId, _ipfsHash, msg.value);
    }

    // 2. Claim Task (Worker puts stake)
    function claimTask(uint256 _taskId) external payable {
        Task storage task = tasks[_taskId];
        require(task.assignedWorker == address(0), "Already assigned");
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(block.timestamp < task.deadline, "Task expired");

        task.assignedWorker = msg.sender;
        task.workerStake = msg.value;
        
        emit TaskClaimed(_taskId, msg.sender);
    }

    // 3. Submit Solution (Start Challenge Timer)
    function submitSolution(uint256 _taskId, bytes32 _resultHash) external {
        Task storage task = tasks[_taskId];
        require(msg.sender == task.assignedWorker, "Not your task");
        require(!task.finalized, "Already finalized");

        task.submittedHash = _resultHash;
        task.submissionTime = block.timestamp;
        
        emit SolutionSubmitted(_taskId, _resultHash);
    }

    // 4. Raise Challenge (Verifier puts stake)
    function challengeSolution(uint256 _taskId, bytes32 _claimedCorrectHash) external payable {
        Task storage task = tasks[_taskId];
        require(task.submissionTime > 0, "Not submitted yet");
        require(block.timestamp < task.submissionTime + CHALLENGE_PERIOD, "Challenge window closed");
        require(msg.value >= MIN_STAKE, "Insufficient challenge stake");
        require(!task.challenged, "Already challenged");

        task.challenged = true;
        task.challenger = msg.sender;
        
        // In a real system, we would now assign random arbiters or invoke a ZK-verifier contract.
        // For MVP, we emit an event for manual/DAO arbitration.
        emit ChallengeRaised(_taskId, msg.sender);
    }

    // 5. Finalize (After timeout or arbitration)
    // Simplified: Anyone can call this if no challenge & timeout passed.
    function finalizeUnchallenged(uint256 _taskId) external {
        Task storage task = tasks[_taskId];
        require(task.submissionTime > 0, "No submission");
        require(!task.finalized, "Already finalized");
        require(!task.challenged, "Under dispute");
        
        // The optimistic check: If time passed and no one complained, it's valid.
        if (block.timestamp > task.submissionTime + CHALLENGE_PERIOD) {
            task.finalized = true;
            
            // Pay Worker: Bounty + Return Stake
            payable(task.assignedWorker).transfer(task.bounty + task.workerStake);
            
            emit TaskFinalized(_taskId, true);
        } else {
            revert("Still in challenge window");
        }
    }
    
    // 6. Resolve Dispute (Admin/DAO/Arbiter Only)
    // This is the "Supreme Court" function.
    function resolveDispute(uint256 _taskId, bool workerIsCorrect) external {
        // Access Control: Only DAO or Arbiter Contract
        // require(msg.sender == ARBITER_ADDRESS);
        
        Task storage task = tasks[_taskId];
        require(task.challenged, "No dispute");
        require(!task.finalized, "Already finalized");

        task.finalized = true;

        if (workerIsCorrect) {
            // Worker wins: Get Bounty + Stake + Challenger's Stake
            uint256 reward = task.bounty + task.workerStake + MIN_STAKE; // Assuming challenger staked MIN_STAKE
            payable(task.assignedWorker).transfer(reward);
        } else {
            // Challenger wins: Get Reward + Stake + Worker's Stake
            // The bounty is returned to Creator (or burned/shared)
            uint256 reward = MIN_STAKE + task.workerStake; // Reward from slashing worker
            payable(task.challenger).transfer(reward);
            payable(task.creator).transfer(task.bounty); // Refund creator
        }
        
        emit TaskFinalized(_taskId, workerIsCorrect);
    }
}
