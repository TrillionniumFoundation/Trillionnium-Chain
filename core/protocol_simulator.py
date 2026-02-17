import hashlib
import time
import json
import random

# --- MOCK BLOCKCHAIN ENVIRONMENT ---

class MockBlockchain:
    def __init__(self):
        self.block_number = 0
        self.timestamp = time.time()
        self.balances = {"User": 1000, "Worker": 100, "Verifier": 100, "Contract": 0}
        self.logs = []

    def mine_block(self):
        self.block_number += 1
        self.timestamp += 12  # 12 seconds per block
        
    def log(self, event, data):
        entry = f"[Block {self.block_number}] {event}: {data}"
        self.logs.append(entry)
        print(entry)

    def transfer(self, sender, receiver, amount):
        if self.balances.get(sender, 0) < amount:
            raise ValueError(f"{sender} has insufficient funds: {self.balances.get(sender)}")
        self.balances[sender] -= amount
        self.balances[receiver] = self.balances.get(receiver, 0) + amount
        # self.log("Transfer", f"{sender} -> {receiver}: {amount} ETH")

chain = MockBlockchain()

# --- SMART CONTRACT LOGIC (Python Port of WorkRegistryV2) ---

class WorkRegistryContract:
    def __init__(self):
        self.tasks = {}
        self.task_counter = 0
        self.MIN_STAKE = 10
        self.CHALLENGE_PERIOD = 3600 # 1 hour simulated

    def create_task(self, sender, ipfs_hash, bounty):
        chain.transfer(sender, "Contract", bounty)
        
        task_id = self.task_counter
        self.tasks[task_id] = {
            "creator": sender,
            "bounty": bounty,
            "ipfs_hash": ipfs_hash,
            "status": "OPEN",
            "worker": None,
            "result_hash": None,
            "submission_time": 0,
            "stake": 0
        }
        self.task_counter += 1
        chain.log("TaskCreated", f"ID={task_id}, Bounty={bounty}, IPFS={ipfs_hash}")
        return task_id

    def claim_task(self, sender, task_id, stake):
        task = self.tasks.get(task_id)
        if not task or task["status"] != "OPEN":
            raise ValueError("Task not available")
        if stake < self.MIN_STAKE:
            raise ValueError("Insufficient stake")
            
        chain.transfer(sender, "Contract", stake)
        task["worker"] = sender
        task["stake"] = stake
        task["status"] = "ASSIGNED"
        chain.log("TaskClaimed", f"ID={task_id} by {sender} (Stake={stake})")

    def submit_solution(self, sender, task_id, result_hash):
        task = self.tasks.get(task_id)
        if task["worker"] != sender:
            raise ValueError("Not assigned worker")
            
        task["result_hash"] = result_hash
        task["submission_time"] = chain.timestamp
        task["status"] = "SUBMITTED"
        chain.log("SolutionSubmitted", f"ID={task_id}, Hash={result_hash}")

    def finalize_task(self, sender, task_id):
        task = self.tasks.get(task_id)
        if task["status"] != "SUBMITTED":
            raise ValueError("Not in submitted state")
            
        # Optimistic check
        if chain.timestamp < task["submission_time"] + self.CHALLENGE_PERIOD:
            raise ValueError("Challenge period active")
            
        # Payout
        total_payout = task["bounty"] + task["stake"]
        chain.transfer("Contract", task["worker"], total_payout)
        task["status"] = "FINALIZED"
        chain.log("TaskFinalized", f"ID={task_id}, Worker {task['worker']} paid {total_payout}")

    def challenge_task(self, sender, task_id, proof):
        # Simplified: If challenged, we assume Verifier is right for this demo
        # In reality, this would trigger arbitration
        task = self.tasks.get(task_id)
        if task["status"] != "SUBMITTED":
             raise ValueError("Cannot challenge")

        chain.transfer(sender, "Contract", self.MIN_STAKE) # Challenger stakes
        
        # Simulate arbitration logic (Worker failed)
        chain.log("ChallengeRaised", f"ID={task_id} by {sender}")
        
        # Slash Worker
        slashed_amount = task["stake"]
        reward = slashed_amount + self.MIN_STAKE # Verifier gets stake back + worker's stake
        chain.transfer("Contract", sender, reward)
        
        # Refund bounty to creator
        chain.transfer("Contract", task["creator"], task["bounty"])
        
        task["status"] = "SLASHED"
        chain.log("TaskSlashed", f"Worker lost {task['stake']}, Verifier won {reward}")

# --- AGENT ROLES ---

def run_simulation():
    contract = WorkRegistryContract()
    
    print(f"--- INITIAL BALANCES: {chain.balances} ---\n")

    # 1. User creates a task (Python Code Gen)
    print(">>> USER: Publishing task...")
    task_spec = {"desc": "Calculate Fibonacci(100)", "docker": "python:3.9"}
    ipfs_hash = hashlib.sha256(json.dumps(task_spec).encode()).hexdigest()[:8]
    task_id = contract.create_task("User", ipfs_hash, bounty=50)
    chain.mine_block()

    # 2. Worker claims task
    print("\n>>> WORKER: Claiming task...")
    contract.claim_task("Worker", task_id, stake=20) # Staking 20
    chain.mine_block()

    # 3. Worker "executes" Docker and submits
    print("\n>>> WORKER: Executing Docker...")
    # Simulate execution
    result = "354224848179261915075"
    result_hash = hashlib.sha256(result.encode()).hexdigest()[:8]
    contract.submit_solution("Worker", task_id, result_hash)
    chain.mine_block()

    # 4. Verifier checks (Scenario A: Good work)
    print("\n>>> VERIFIER: Checking result...")
    # Verifier runs same docker, gets same hash -> Do nothing (Optimistic)
    
    # 5. Time passes...
    print("\n>>> CHAIN: Time passes (Challenge Period ends)...")
    chain.timestamp += 4000 # > 3600
    chain.mine_block()

    # 6. Finalize
    print("\n>>> WORKER: Claiming payout...")
    contract.finalize_task("Worker", task_id)
    
    print(f"\n--- FINAL BALANCES: {chain.balances} ---")
    
    # --- SCENARIO B: MALICIOUS WORKER ---
    print("\n\n--- SCENARIO B: MALICIOUS WORKER ---")
    
    # User creates another task
    task_id_2 = contract.create_task("User", "bad_task_hash", bounty=100)
    
    # Bad Worker claims
    contract.claim_task("Worker", task_id_2, stake=20)
    
    # Bad Worker submits wrong result (Random hash)
    contract.submit_solution("Worker", task_id_2, "bad_result_hash")
    
    # Verifier catches it!
    print("\n>>> VERIFIER: Detects mismatch! Challenging...")
    contract.challenge_task("Verifier", task_id_2, proof="mismatch_proof")
    
    print(f"\n--- END BALANCES: {chain.balances} ---")

if __name__ == "__main__":
    run_simulation()
