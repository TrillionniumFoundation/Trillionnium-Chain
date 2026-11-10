set -euo pipefail
python3 scripts/w1_qrom_semantics_audit.py --out "$W1_CLOSURE_OUT/semantics.json"
python3 scripts/w1_lifetime_current_observation.py --input evidence/pon-w1-lifetime-20261107/project-input.json > "$W1_CLOSURE_OUT/lifetime-current.json"
python3 scripts/w1_qrom_composition_budget.py > "$W1_CLOSURE_OUT/composition-unknown.json"
python3 scripts/w1_qrom_composition_budget.py --example > "$W1_CLOSURE_OUT/composition-example.json"
python3 scripts/w1_qrom_joint_oracle_diagnostic.py > "$W1_CLOSURE_OUT/joint-oracle-unknown.json"
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example alias > "$W1_CLOSURE_OUT/joint-oracle-alias.json"
python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example separated > "$W1_CLOSURE_OUT/joint-oracle-separated.json"
python3 scripts/ci/w1_qrom_closure_current_controls.py check-semantics --output "$W1_CLOSURE_OUT/semantics.json" > "$W1_CLOSURE_OUT/semantics-correspondence.json"
for name in composition-unknown composition-example joint-oracle-unknown joint-oracle-alias joint-oracle-separated; do
  cmp "evidence/pon-w1-qrom-formal-bridge-20261107/$name.json" "$W1_CLOSURE_OUT/$name.json"
done
