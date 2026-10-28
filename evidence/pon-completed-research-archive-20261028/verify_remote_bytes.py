"""Read back immutable evidence bytes; never execute archive contents."""

import hashlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMIT = "8f94ea3c5d267579844186e6e41d88e973f1e24f"
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
EXPECTED_GROUPS = {
    "evidence/pon-w1-complete-febf-20261028/receipt.bin": (
        15862780,
        "f816a6265004ae1f35c75add10268687e9afd996d8e1eaee9ddc4efa815d32d5",
    ),
    "evidence/pon-legal-ticket-v4-originals-20261028/x86_64.zip": (
        14927016,
        "f39393110c13db81500f37bb94f082163402fa35d3535be6f22801e337f93bf7",
    ),
    "evidence/pon-legal-ticket-v4-originals-20261028/aarch64.zip": (
        14613067,
        "6e409438eb496fb74439fcdf7fdd787e55cfce3a67b71053e2fb43ed2cbdfe45",
    ),
    "evidence/pon-original-campaign-paired-20261028/w1-303afe.zip": (
        67524496,
        "321812d12ac39cac068d97340ed8a1a7f588ed006f4b6dc88ea47fbf36cafa67",
    ),
    "evidence/pon-original-campaign-paired-20261028/pq-29e1f.zip": (
        70453292,
        "0aea2c18f70de9f658ce4dfec7c061ba034f9f7d1e00c4c8afb8b7dcc0b1c6ae",
    ),
}


def main():
    manifest_path = HERE / "publication-manifest-final.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    report = {
        "schema": "completed-evidence-remote-byte-readback-v1",
        "repository": REPOSITORY,
        "commit": COMMIT,
        "tree": manifest["expected_tree"],
        "parent": manifest["remote_parent"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "new_native_execution": False,
        "archive_contents_executed": False,
        "files": [],
        "complete_groups": [],
        "outcome": "incomplete",
    }
    start = time.monotonic()
    states = {key: [hashlib.sha256(), 0, 0] for key in EXPECTED_GROUPS}
    try:
        for row in manifest["files"]:
            path = row["path"]
            assert path.startswith("evidence/") and ".." not in path.split("/")
            match = re.fullmatch(r"(.+)\.part(\d{3})", path)
            group = None
            if match:
                group = states[match[1]]
                assert int(match[2]) == group[2], (path, "part order")
            sha256 = hashlib.sha256()
            git = hashlib.sha1(f"blob {row['bytes']}\0".encode())
            count = 0
            url = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/{path}"
            request = urllib.request.Request(url, headers={"User-Agent": "evidence-byte-readback"})
            with urllib.request.urlopen(request, timeout=30) as response:
                assert response.status == 200, (path, response.status)
                while chunk := response.read(65536):
                    count += len(chunk)
                    assert count <= row["bytes"], (path, "oversized response")
                    sha256.update(chunk)
                    git.update(chunk)
                    if group is not None:
                        group[0].update(chunk)
                        group[1] += len(chunk)
            observed = {
                "path": path,
                "bytes": count,
                "sha256": sha256.hexdigest(),
                "git_blob_sha1": git.hexdigest(),
            }
            assert all(observed[key] == row[key] for key in ["bytes", "sha256", "git_blob_sha1"]), path
            report["files"].append(observed)
            if group is not None:
                group[2] += 1
            if len(report["files"]) % 10 == 0:
                print(json.dumps({"verified_files": len(report["files"]), "total": len(manifest["files"])}), flush=True)
        for path, (expected_size, expected_sha256) in EXPECTED_GROUPS.items():
            sha256, size, parts = states[path]
            assert size == expected_size and sha256.hexdigest() == expected_sha256, path
            report["complete_groups"].append({"path": path, "bytes": size, "sha256": sha256.hexdigest(), "parts": parts})
        report["outcome"] = "pass"
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error"] = str(error)
    finally:
        report["elapsed_seconds"] = time.monotonic() - start
        report["file_count"] = len(report["files"])
        report["bytes"] = sum(row["bytes"] for row in report["files"])
        (HERE / "remote-byte-readback.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ["outcome", "commit", "file_count", "bytes", "elapsed_seconds"]}), flush=True)
    return 0 if report["outcome"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
