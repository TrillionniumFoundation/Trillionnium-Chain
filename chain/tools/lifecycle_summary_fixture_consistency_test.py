import json
import sys
import os

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    v2_path = os.path.join(base_dir, "examples/lifecycle_summary_v2_ok.json")
    v3_path = os.path.join(base_dir, "examples/lifecycle_summary_v3_ok.json")

    print(f"Loading v2 from {v2_path}")
    v2 = load_json(v2_path)
    print(f"Loading v3 from {v3_path}")
    v3 = load_json(v3_path)

    errors = []

    # 1. Compare Core Top-Level Fields
    common_fields = [
        "status", "worker", "start_height", "end_height", 
        "last_step", "last_tx"
    ]

    for field in common_fields:
        val2 = v2.get(field)
        val3 = v3.get(field)
        if val2 != val3:
            errors.append(f"Mismatch in root field '{field}': v2={val2} vs v3={val3}")

    # 2. Compare v2 flat fields vs v3 nested fields (Migration check)
    # v2 -> v3 mapping
    mapping = {
        "start_height": ["timing", "start_height"],
        "end_height": ["timing", "end_height"],
        "height_delta": ["timing", "height_delta"],
        "duration_s": ["timing", "duration_s"],
        "release_height": ["timing", "release_height"],
        "cooldown_waited_blocks": ["timing", "cooldown_waited_blocks"],
        "node_height": ["node", "height"],
        "catching_up": ["node", "catching_up"],
        "tx_register": ["phase_txs", "register"],
        "tx_request_unbonding": ["phase_txs", "request_unbonding"],
        "tx_finalize_unbonding": ["phase_txs", "finalize_unbonding"],
    }

    for v2_key, v3_path_list in mapping.items():
        if v2_key not in v2:
            continue # Skip if not in v2
            
        val2 = v2[v2_key]
        
        # Traverse v3
        val3 = v3
        try:
            for key in v3_path_list:
                val3 = val3[key]
        except KeyError:
            errors.append(f"Field path {v3_path_list} missing in v3")
            continue

        if val2 != val3:
            errors.append(f"Mismatch v2['{v2_key}'] vs v3{v3_path_list}: {val2} vs {val3}")

    if errors:
        print("❌ Consistency Check Failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("✅ Consistency Check Passed: v2 and v3 fixtures are semantically identical.")

if __name__ == "__main__":
    main()
