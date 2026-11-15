"""Hash all eleven unchanged standard summaries and every complete row."""
from pathlib import Path
import gzip
import hashlib
import json
import sys

source = Path(sys.argv[1]).resolve()
prefix = Path(sys.argv[2])
sys.path.insert(0, str(source))
from quantum_daa_model import run_scenario, standard_scenarios

rows = []
aggregate = hashlib.sha256()
with gzip.GzipFile(filename=str(prefix) + ".jsonl.gz", mode="wb", mtime=0) as archive:
    for case in standard_scenarios():
        summary, trace = run_scenario(case)
        body = json.dumps({"summary": summary, "rows": trace}, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode() + b"\n"
        aggregate.update(body)
        archive.write(body)
        rows.append({"name": case.name, "rows": len(trace), "bytes": len(body),
                     "sha256": hashlib.sha256(body).hexdigest(),
                     "security_theorem": summary["security_theorem"],
                     "production_consensus_activation": summary["production_consensus_activation"]})
print(json.dumps({"source": str(source), "cases": rows, "case_count": len(rows),
                  "total_rows": sum(row["rows"] for row in rows),
                  "full_output_sha256": aggregate.hexdigest()}, sort_keys=True))
