import json
import sys
import os

def load_json(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        sys.exit(1)

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    v2_path = os.path.join(base_dir, "chain/tools/examples/lifecycle_summary_v2_ok.json")
    v3_path = os.path.join(base_dir, "chain/tools/examples/lifecycle_summary_v3_ok.json")

    print(f"Checking consistency between:\n  {v2_path}\n  {v3_path}")

    v2 = load_json(v2_path)
    v3 = load_json(v3_path)

    # Core fields to compare. These must match exactly.
    # v2 is flat. v3 is structured but has flat copies or equivalents.
    # We compare flat v2 fields against v3 root fields (if they exist) or nested equivalents.
    
    # Based on file inspection:
    # v3 has flat copies of: start_height, status, worker, last_step, end_height, etc.
    # So we can compare directly.
    
    fields_to_check = [
        "status", 
        "worker", 
        "last_step", 
        "start_height", 
        "end_height", 
        "height_delta", 
        "duration_s", 
        "release_height", 
        "cooldown_waited_blocks", 
        "cooldown_stagnant_rounds",
        "node_height", 
        "catching_up"
    ]

    mismatches = []

    for field in fields_to_check:
        val2 = v2.get(field)
        val3 = v3.get(field)

        if val2 is None:
            print(f"WARNING: Field '{field}' missing in v2")
            continue
        
        # Special handling if needed (e.g. types), but JSON load handles basic types.
        # node_height might be int or string. In the files read, they were strings "110".
        
        if val2 != val3:
            # Check if one is int and other is string representation
            if str(val2) == str(val3):
                 continue
            
            mismatches.append(f"Field '{field}': v2={val2} ({type(val2)}), v3={val3} ({type(val3)})")

    # Also check internal consistency of v3 (root vs nested) if desirable, 
    # but primarily we want v2 vs v3 cross-version.
    
    if mismatches:
        print("\n❌ Semantic Mismatches Found:")
        for m in mismatches:
            print(f"  - {m}")
        sys.exit(1)
    else:
        print("\n✅ Schema/Fixture Semantic Consistency Verified: v2 and v3 match on core fields.")
        sys.exit(0)

if __name__ == "__main__":
    main()
