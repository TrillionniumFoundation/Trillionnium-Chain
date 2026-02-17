import random
import matplotlib.pyplot as plt
import numpy as np

# --- CONFIGURATION ---
TOTAL_supply = 10_000_000_000.0  # 10 Billion TRNM
INITIAL_WORKERS = 1000
STAKE_PER_WORKER = 100_000.0   # Increased 100x (Better security & locked value)
SLASH_RATE = 0.50             # 50% slash
INFLATION_MIN = 0.04          # 4% (Lower floor)
INFLATION_MAX = 0.10          # 10% (Lower cap)
BURN_RATE = 1.00              # 100% of task fees burned (Deflationary pressure)
TASK_FEE = 10.0               # Cost to user per task
TASKS_PER_DAY = 50000         # Network activity level
MALICIOUS_RATIO = 0.05        # 5% bad actors initially

DAYS = 365
random.seed(42)

class NetworkState:
    def __init__(self):
        self.supply = TOTAL_supply
        self.staked = INITIAL_WORKERS * STAKE_PER_WORKER
        self.workers = INITIAL_WORKERS
        self.malicious_workers = int(INITIAL_WORKERS * MALICIOUS_RATIO)
        self.honest_workers = self.workers - self.malicious_workers
        self.treasury = 0.0
        self.burned_total = 0.0
        
        # Logs for plotting
        self.history = {
            "supply": [],
            "staked_ratio": [],
            "malicious_ratio": [],
            "burned": []
        }

    def daily_tick(self, day):
        # 1. Inflation (Minting)
        # Dynamic inflation based on staked ratio (Cosmos style)
        staked_ratio = self.staked / self.supply
        # If staked ratio < 67%, inflation increases towards 20%
        # If staked ratio > 67%, inflation decreases towards 7%
        target_bonded = 0.67
        inflation_rate = INFLATION_MIN + (1 - staked_ratio/target_bonded) * (INFLATION_MAX - INFLATION_MIN)
        inflation_rate = max(INFLATION_MIN, min(INFLATION_MAX, inflation_rate))
        
        daily_inflation = (self.supply * inflation_rate) / 365
        self.supply += daily_inflation
        
        # Rewards distribution (Simplified: all to stakers)
        # Malicious workers also get rewards until caught!
        reward_per_worker = daily_inflation / self.workers
        
        # 2. Task Execution & Burning
        daily_fees = TASKS_PER_DAY * TASK_FEE
        burned = daily_fees * BURN_RATE
        self.supply -= burned
        self.burned_total += burned
        
        # 3. Slashing Event (Security Check)
        # Assume probabilistic detection: 10% chance per day a bad actor is caught
        caught_malicious = 0
        for _ in range(self.malicious_workers):
            if random.random() < 0.10: # 10% chance to be caught daily
                caught_malicious += 1
        
        slashed_amount = caught_malicious * STAKE_PER_WORKER * SLASH_RATE
        self.staked -= slashed_amount
        self.supply -= slashed_amount # Slash is burned usually, or to community pool
        
        # Remove caught workers (churn)
        self.malicious_workers -= caught_malicious
        self.workers -= caught_malicious
        
        # 4. New Workers Join (Growth)
        # If network is profitable, new workers join
        if reward_per_worker > 50: # Arbitrary profitability threshold
            new_joiners = int(self.workers * 0.01) # 1% growth
            self.workers += new_joiners
            self.honest_workers += new_joiners
            self.staked += new_joiners * STAKE_PER_WORKER

        # Log state
        self.history["supply"].append(self.supply)
        self.history["staked_ratio"].append(self.staked / self.supply)
        self.history["malicious_ratio"].append(self.malicious_workers / max(1, self.workers))
        self.history["burned"].append(self.burned_total)

        if day % 30 == 0:
            print(f"Day {day:3}: Supply={self.supply/1e9:.2f}B | Staked={self.staked_ratio*100:.1f}% | Malicious={self.malicious_ratio*100:.1f}% | Inf={inflation_rate*100:.1f}%")

    @property
    def staked_ratio(self):
        return self.staked / self.supply

    @property
    def malicious_ratio(self):
        return self.malicious_workers / max(1, self.workers)

def run_test():
    print(f"--- TRILLIONNIUM ECONOMICS STRESS TEST ---")
    print(f"Initial Supply: {TOTAL_supply/1e9}B CLAW")
    print(f"Slash Rate: {SLASH_RATE*100}%")
    print(f"Burn Rate: {BURN_RATE*100}%")
    print("-" * 40)
    
    net = NetworkState()
    
    for i in range(DAYS):
        net.daily_tick(i)
        
    print("-" * 40)
    print(f"Final Supply: {net.supply/1e9:.3f}B CLAW")
    print(f"Total Burned: {net.burned_total/1e6:.2f}M CLAW")
    print(f"Malicious Workers Remaining: {net.malicious_workers}")
    
    # Simple ASCII Plot for Supply
    print("\n[Supply Trend]")
    max_s = max(net.history['supply'])
    min_s = min(net.history['supply'])
    for s in net.history['supply'][::30]: # Monthly
        normalized = int((s - min_s) / (max_s - min_s) * 20)
        print("|" + "#" * normalized)

if __name__ == "__main__":
    run_test()
