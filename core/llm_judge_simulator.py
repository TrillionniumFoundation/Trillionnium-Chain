import random
import numpy as np

class LLMJudgeSimulator:
    def __init__(self, model_name, strictness=0.5):
        self.model_name = model_name
        self.strictness = strictness # 0=Lenient, 1=Harsh

    def evaluate(self, content, rubric):
        # Simulate LLM evaluation logic
        # Ideally this calls an API, here we simulate a score distribution
        base_score = 80
        noise = random.normalvariate(0, 5)
        bias = -10 * self.strictness
        
        score = base_score + noise + bias
        return max(0, min(100, score))

def run_phase2_simulation():
    print("--- PHASE 2: LLM-as-a-Judge Consensus Simulation ---\n")
    
    # Task: "Write a blog post about Rust ownership."
    content = "Rust ownership is a unique feature that guarantees memory safety without garbage collection..."
    rubric = ["Accuracy", "Clarity", "Code Examples"]

    # The Judges (Verifiers)
    judges = [
        LLMJudgeSimulator("GPT-4o", strictness=0.2),      # Lenient
        LLMJudgeSimulator("Claude-3.5", strictness=0.5),  # Balanced
        LLMJudgeSimulator("Llama-3-70B", strictness=0.8)  # Harsh
    ]
    
    scores = []
    print(f"Task Content: {content[:50]}...")
    
    for judge in judges:
        score = judge.evaluate(content, rubric)
        scores.append(score)
        print(f"Judge [{judge.model_name}] Score: {score:.2f}")

    # Aggregation Logic
    mean_score = np.mean(scores)
    std_dev = np.std(scores)
    
    print(f"\n--- CONSENSUS RESULT ---")
    print(f"Mean Score: {mean_score:.2f}")
    print(f"Std Dev:    {std_dev:.2f}")
    
    # Decision
    PASS_THRESHOLD = 75
    VARIANCE_THRESHOLD = 15
    
    if std_dev > VARIANCE_THRESHOLD:
        print(">>> RESULT: DISPUTE (Variance too high). Escalating to Human Arbitration.")
    elif mean_score >= PASS_THRESHOLD:
        print(">>> RESULT: APPROVED. Payout released.")
    else:
        print(">>> RESULT: REJECTED. Work quality insufficient.")

if __name__ == "__main__":
    run_phase2_simulation()
