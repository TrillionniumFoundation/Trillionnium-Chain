// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title OpenClaw Work Registry
 * @dev A decentralized marketplace for verifiable computational tasks.
 */
contract WorkRegistry {
    
    struct Task {
        address creator;
        uint256 bounty;
        string ipfsHash;      // Contains: description.json, Dockerfile, test_cases/
        bytes32 imageHash;    // Expected base image SHA256 (e.g., python:3.9-slim)
        uint256 deadline;
        bool completed;
        address assignedWorker;
    }

    struct Submission {
        string resultIpfsHash; // The output artifacts (logs, generated code)
        bytes32 outputHash;    // Hash of stdout for quick verification
        bool verified;
        bool challenged;
    }

    // State
    mapping(uint256 => Task) public tasks;
    mapping(uint256 => Submission) public submissions;
    uint256 public taskCounter;

    // Events
    event TaskCreated(uint256 indexed taskId, string ipfsHash, uint256 bounty);
    event TaskAssigned(uint256 indexed taskId, address indexed worker);
    event SolutionSubmitted(uint256 indexed taskId, string resultIpfsHash);
    event SolutionVerified(uint256 indexed taskId, bool success);

    // Errors
    error InsufficientBounty();
    error TaskExpired();
    error NotAssignedWorker();
    error AlreadyCompleted();

    /**
     * @dev Create a new computational task.
     * @param _ipfsHash The IPFS CID of the task specification folder.
     * @param _imageHash The SHA256 hash of the required Docker base image.
     */
    function createTask(string calldata _ipfsHash, bytes32 _imageHash) external payable {
        if (msg.value == 0) revert InsufficientBounty();

        uint256 taskId = taskCounter++;
        
        tasks[taskId] = Task({
            creator: msg.sender,
            bounty: msg.value,
            ipfsHash: _ipfsHash,
            imageHash: _imageHash,
            deadline: block.timestamp + 1 days, // Default 24h
            completed: false,
            assignedWorker: address(0)
        });

        emit TaskCreated(taskId, _ipfsHash, msg.value);
    }

    /**
     * @dev Worker claims a task (Simple FCFS for MVP).
     * In production, this would require staking.
     */
    function claimTask(uint256 _taskId) external {
        Task storage task = tasks[_taskId];
        if (task.assignedWorker != address(0)) revert("Already assigned");
        if (block.timestamp > task.deadline) revert TaskExpired();

        task.assignedWorker = msg.sender;
        emit TaskAssigned(_taskId, msg.sender);
    }

    /**
     * @dev Worker submits the result.
     * @param _resultIpfsHash IPFS CID of the output artifacts.
     * @param _outputHash Hash of the stdout/result for verification.
     */
    function submitSolution(uint256 _taskId, string calldata _resultIpfsHash, bytes32 _outputHash) external {
        Task storage task = tasks[_taskId];
        if (msg.sender != task.assignedWorker) revert NotAssignedWorker();
        if (task.completed) revert AlreadyCompleted();

        submissions[_taskId] = Submission({
            resultIpfsHash: _resultIpfsHash,
            outputHash: _outputHash,
            verified: false,
            challenged: false
        });

        // In Optimistic mode, we start a challenge timer here.
        // For MVP, we mark as pending verification.
        
        emit SolutionSubmitted(_taskId, _resultIpfsHash);
    }

    /**
     * @dev Verifier (or Creator) confirms the result is valid.
     * Triggers payment release.
     */
    function finalizeTask(uint256 _taskId, bool _valid) external {
        Task storage task = tasks[_taskId];
        // Only creator or designated verifier can finalize (simplified)
        require(msg.sender == task.creator, "Only creator can verify");

        if (_valid) {
            task.completed = true;
            submissions[_taskId].verified = true;
            // Pay the worker
            payable(task.assignedWorker).transfer(task.bounty);
            emit SolutionVerified(_taskId, true);
        } else {
            // Slash or reset task (simplified: just reset assignment)
            task.assignedWorker = address(0); 
            emit SolutionVerified(_taskId, false);
        }
    }
}
