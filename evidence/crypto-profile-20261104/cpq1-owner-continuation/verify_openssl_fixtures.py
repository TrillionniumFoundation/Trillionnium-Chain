#!/usr/bin/env python3
"""One-way external math check of the frozen CPQ1 benchmark's real wire fixtures.

No repository code is imported or changed. This independently parses the exact
v1 fixture layout and invokes OpenSSL's default provider for every Rust signature.
It does not validate benchmark timings, owner policy, current authority, source
execution provenance, reverse interoperability, or production qualification.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import time


SCHEMA = "trnm.cpq1-parameter-observation.v1"
DOMAIN = b"TRNM/CryptoProfile/Envelope/v1\0"
COMMITMENT_DOMAIN = b"TRNM/CryptoProfile/Commitment/v1\0"
WORK_DIGEST = bytes.fromhex(
    "6da47a17baafdcf3748010f4fc5a9291a31ed0a8fd3ac26e41df98cd5f7685bc8f8d"
    "80325c21105bb21b1b1c24da723e4345306c1f8e579cb8f5d5c6dc0c0632"
)
PARAMETERS = {
    "ML-DSA-65": (1952, 3309, "2.16.840.1.101.3.4.3.18", bytes.fromhex(
        "8f572de360c4ffa4681d027b3c2ef0499e159ad3de2e5eccaedcffb8149e88fd"
        "fec814ae4523e25fbbe402d05b5eed54b3287c40aca16b006d504b4832dcd3ba")),
    "ML-DSA-87": (2592, 4627, "2.16.840.1.101.3.4.3.19", bytes.fromhex(
        "3d95c89d2e8ffe72d936476106fba9583d7f93a0c984fd6881d9475c3f5fa7a8"
        "47e723340e0c33688310e75697221f2ac3fd58f8d08f75097a04ae5a8bfa83a5")),
}
COUNTS = (1, 2, 4, 8)
LABELS = ("empty", "176", "4096", "maximum")
CONTEXT = "cpq1-openssl-independent-context-v1"
MAX_FILE = 64 * 1024 * 1024
MAX_LINE = 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, f"duplicate JSON key: {key}")
        out[key] = value
    return out


def no_constant(value):
    raise ValueError(f"nonfinite JSON value: {value}")


def hex_bytes(value, maximum):
    require(type(value) is str and len(value) <= 2 * maximum
            and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", value),
            "invalid, noncanonical, or excessive hex input")
    return bytes.fromhex(value)


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        require(0 <= count <= len(self.data) - self.pos, "truncated CPQ1 input")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def uint(self, size):
        return int.from_bytes(self.take(size), "big")

    def end(self):
        require(self.pos == len(self.data), "trailing CPQ1 bytes")


def parse_case(row):
    require(row.get("schema") == SCHEMA, "case schema mismatch")
    algorithm = row["algorithm"]
    require(algorithm in PARAMETERS, "unsupported algorithm")
    pk_len, sig_len, _, profile_id = PARAMETERS[algorithm]
    count, label = row["signer_count"], row["payload_label"]
    require(type(count) is int and count in COUNTS and label in LABELS,
            "unplanned fixture case")
    require(row["case_id"] == f"{algorithm}/{count}/{label}", "case ID mismatch")
    message = hex_bytes(row["signed_message_hex"], 65536)
    wire = hex_bytes(row["cpq1_wire_hex"], 131072)
    require(len(message) == row["signed_message_bytes"]
            and len(wire) == row["cpq1_wire_bytes"], "fixture byte count mismatch")
    require(hashlib.sha512(message).hexdigest() == row["signed_message_sha512"]
            and hashlib.sha512(wire).hexdigest() == row["cpq1_wire_sha512"],
            "fixture SHA-512 mismatch")
    require(row["public_key_bytes_each"] == pk_len
            and row["signature_bytes_each"] == sig_len, "parameter length mismatch")
    cur = Cursor(message)
    require(cur.take(len(DOMAIN)) == DOMAIN, "signed domain mismatch")
    require(cur.take(64) == profile_id and row["crypto_profile_id"] == profile_id.hex(),
            "frozen profile ID mismatch")
    require(cur.take(64) == WORK_DIGEST, "work configuration digest mismatch")
    require(cur.uint(2) == 9, "purpose mismatch")
    require([cur.uint(8) for _ in range(5)] == [7, 3, 11, 10, 99],
            "frozen envelope context mismatch")
    require(cur.uint(2) == count, "signed signer count mismatch")
    ids = [cur.take(64) for _ in range(count)]
    require(ids == sorted(set(ids)) and bytes(64) not in ids, "noncanonical signer set")
    require(row["signer_ids"] == [v.hex() for v in ids], "signer ID metadata mismatch")
    payload = cur.take(cur.uint(4))
    cur.end()
    expected_length = {"empty": 0, "176": 176, "4096": 4096,
                       "maximum": 65536 - 207 - 64 * count}[label]
    require(len(payload) == expected_length == row["payload_bytes"], "payload length mismatch")
    require(payload == bytes((i * 29 + 17) % 256 for i in range(len(payload))),
            "payload fixture mismatch")
    cur = Cursor(wire)
    require(cur.take(4) == b"CPQ1" and cur.uint(4) == len(message), "wire header mismatch")
    require(cur.take(len(message)) == message, "wire signed-message mismatch")
    signatures = []
    for index in range(count):
        require(cur.uint(4) == pk_len, "wire public-key length mismatch")
        public_key = cur.take(pk_len)
        require(cur.uint(4) == sig_len, "wire signature length mismatch")
        signature_offset = cur.pos
        signature = cur.take(sig_len)
        key_id = hashlib.sha512(COMMITMENT_DOMAIN + profile_id + b"\x01"
                                + struct.pack(">Q", pk_len) + public_key).digest()
        require(key_id == ids[index], "wire key is not bound by signed signer ID")
        signatures.append((public_key, signature, signature_offset))
    cur.end()
    require(row["late_invalid_byte_offset"] == signatures[-1][2]
            and row["late_invalid_xor"] == 1, "fixture mutation metadata mismatch")
    return algorithm, message, signatures


def read_cases(path):
    require(path.stat().st_size <= MAX_FILE, "input exceeds size bound")
    data = path.read_bytes()
    require(len(data) <= MAX_FILE, "input exceeds size bound")
    lines = data.splitlines()
    require(lines and all(0 < len(v) <= MAX_LINE for v in lines), "invalid JSONL line size")
    rows = [json.loads(line, object_pairs_hook=strict_object, parse_constant=no_constant)
            for line in lines]
    require(all(type(v) is dict for v in rows), "JSONL row must be an object")
    require(rows[0].get("kind") == "run" and rows[-1].get("kind") == "complete",
            "missing complete run framing")
    kinds = Counter(v.get("kind") for v in rows)
    require(kinds == {"run": 1, "case": 32, "measurement": 352, "complete": 1},
            "unexpected input row counts")
    run = rows[0]
    require(run["schema"] == SCHEMA and run["wire_format"] == "CPQ1"
            and run["signature_mode"] == "FIPS204-Pure"
            and run["fips_context_hex"] == "", "not the frozen Pure/empty-context fixture")
    require(run["algorithms"] == list(PARAMETERS) and run["signer_counts"] == list(COUNTS)
            and run["payload_labels"] == list(LABELS), "fixture grid mismatch")
    require(rows[-1]["cases"] == 32, "completion case count mismatch")
    cases = [v for v in rows if v.get("kind") == "case"]
    expected = {f"{a}/{n}/{label}" for a in PARAMETERS for n in COUNTS for label in LABELS}
    require(len({v["case_id"] for v in cases}) == 32
            and {v["case_id"] for v in cases} == expected, "missing or repeated case")
    parsed = [(v, *parse_case(v)) for v in cases]
    require(sum(len(v[3]) for v in parsed) == 120, "unexpected signature count")
    return data, parsed


def der_tlv(data, offset, wanted_tag):
    require(offset + 2 <= len(data) and data[offset] == wanted_tag, "unexpected DER tag")
    first, at = data[offset + 1], offset + 2
    if first < 128:
        length = first
    else:
        width = first & 127
        require(0 < width <= 4 and at + width <= len(data), "invalid DER length")
        encoded = data[at:at + width]
        require(encoded[0] != 0, "nonminimal DER length")
        length, at = int.from_bytes(encoded, "big"), at + width
        require(length >= 128, "nonminimal long DER length")
    require(at + length <= len(data), "truncated DER")
    return at, at + length


def oid_string(encoded):
    require(encoded, "empty OID")
    numbers, value = [], 0
    for byte in encoded:
        value = (value << 7) | (byte & 127)
        if not byte & 128:
            numbers.append(value)
            value = 0
    require(not encoded[-1] & 128 and numbers, "truncated OID")
    first = min(numbers[0] // 40, 2)
    return ".".join(map(str, [first, numbers[0] - 40 * first, *numbers[1:]]))


def spki_prefix(der, public_key_length, expected_oid):
    at, end = der_tlv(der, 0, 0x30)
    require(end == len(der), "SPKI trailing data")
    alg_at, alg_end = der_tlv(der, at, 0x30)
    oid_at, oid_end = der_tlv(der, alg_at, 0x06)
    observed_oid = oid_string(der[oid_at:oid_end])
    require(oid_end == alg_end and observed_oid == expected_oid,
            "SPKI algorithm/absent-parameters mismatch")
    bits_at, bits_end = der_tlv(der, alg_end, 0x03)
    require(bits_end == end and der[bits_at] == 0
            and bits_end - bits_at - 1 == public_key_length, "SPKI raw-key boundary mismatch")
    return der[:bits_at + 1], observed_oid


class Runner:
    def __init__(self, binary, path):
        self.binary = str(binary)
        self.env = os.environ.copy()
        self.env.update(OPENSSL_CONF=os.devnull, LC_ALL="C")
        self.log = path.open("x", encoding="utf-8")
        self.commands = 0

    def run(self, arguments, stage, expected_rc=0):
        command = [self.binary, *map(str, arguments)]
        started = time.monotonic_ns()
        result = subprocess.run(command, env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
        row = {"command": command, "stage": stage, "returncode": result.returncode,
               "elapsed_ns_including_process_startup": time.monotonic_ns() - started,
               "stdout": result.stdout.decode("utf-8", "replace"),
               "stderr": result.stderr.decode("utf-8", "replace")}
        self.log.write(json.dumps(row, sort_keys=True) + "\n")
        self.log.flush()
        self.commands += 1
        require(result.returncode == expected_rc,
                f"{stage}: exit {result.returncode}, expected {expected_rc}; see command log")
        return row

    def verify(self, key, message, signature, stage, accept, context=None):
        args = ["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                "-inkey", key, "-in", message, "-sigfile", signature,
                "-provider", "default", "-propquery", "provider=default",
                "-pkeyopt", "message-encoding:1", "-pkeyopt", "mu:0"]
        if context is not None:
            args += ["-pkeyopt", "context-string:" + context]
        row = self.run(args, stage, 0 if accept else 1)
        expected = "Signature Verified Successfully" if accept else "Signature Verification Failure"
        require(row["stdout"].strip() == expected,
                f"{stage}: unexpected verification output, not an arithmetic result")
        if accept:
            require(not row["stderr"], f"{stage}: successful verification emitted an error")
        else:
            # This exact OpenSSL release reports an ordinary arithmetic rejection
            # through both stdout and an EVP provider-signature-failure diagnostic.
            # The source's EVP_DigestVerify adds this reason when digest_verify
            # rejects without a more specific provider error. CLI options, key
            # decoding, initialization, or other diagnostics are never counted.
            expected_error = (
                r"[0-9A-Fa-f]+:error:030000EA:digital envelope routines:"
                r"EVP_DigestVerify:provider signature failure:crypto/evp/m_sigver\.c:"
                r"[0-9]+:ML-DSA-(?:65|87) digest_verify:\n"
            )
            require(not row["stderr"] or re.fullmatch(expected_error, row["stderr"]),
                    f"{stage}: CLI/parse/unrecognized stderr, not an arithmetic result")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--expected-openssl-sha256", required=True)
    parser.add_argument("--source-sha", required=True,
                        help="Caller-supplied source association; this tool does not attest it")
    args = parser.parse_args()
    args.input, args.openssl = args.input.resolve(), args.openssl.resolve()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    summary = {
        "schema": "trnm.cpq1-openssl-oneway-observation.v1", "passed": False,
        "scope": "Rust-generated CPQ1 signatures to OpenSSL default-provider mathematical verification only",
        "owner_authority_qualified": False, "reverse_interoperability_tested": False,
        "production_qualified": False, "activation_performed": False,
        "source_sha_as_supplied_by_caller": args.source_sha,
        "source_execution_provenance_attested": False,
        "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        "shell_display_only": shlex.join([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]),
        "script_sha256": digest(Path(__file__).read_bytes()),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "openssl": str(args.openssl), "input": str(args.input),
        "environment_overrides": {"OPENSSL_CONF": os.devnull, "LC_ALL": "C"},
        "provider": "default", "property_query": "provider=default",
        "signature_mode": "FIPS204-Pure", "message_encoding": 1, "mu_input": 0,
        "positive_context_hex": "", "negative_context_hex": CONTEXT.encode().hex(),
        "negative_result_required": {
            "exit_code": 1, "stdout": "Signature Verification Failure",
            "stderr": "empty or the sole exact EVP_DigestVerify 030000EA provider signature failure diagnostic",
            "cli_parameter_parse_and_other_errors_count_as_rejection": False,
        },
        "input_sha256": None, "openssl_sha256": None,
        "checks": {}, "per_algorithm_checks": {}, "case_results": [], "errors": [],
    }
    runner = None
    counts, by_algorithm = Counter(), defaultdict(Counter)
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha), "invalid source SHA")
        input_data, cases = read_cases(args.input)
        summary["input_sha256"] = digest(input_data)
        summary["openssl_sha256"] = digest(args.openssl.read_bytes())
        require(summary["input_sha256"] == args.expected_input_sha256, "input hash changed")
        require(summary["openssl_sha256"] == args.expected_openssl_sha256, "OpenSSL hash mismatch")
        runner = Runner(args.openssl, args.output_dir / "commands.jsonl")
        summary["openssl_version"] = runner.run(["version", "-a"], "openssl-version")["stdout"]
        algorithms = runner.run(["list", "-signature-algorithms", "-verbose"],
                                "openssl-signature-algorithms")["stdout"]
        summary["public_key_wrappers"] = {}
        # Fresh OpenSSL keys establish the DER wrapper and positive nonempty-ctx controls.
        # Secret keys and all derived fixtures exist only in this temporary directory.
        with tempfile.TemporaryDirectory(prefix="cpq1-openssl-") as scratch_name:
            scratch = Path(scratch_name)
            prefixes = {}
            for algorithm, (pk_len, _, oid, _) in PARAMETERS.items():
                require(algorithm in algorithms and oid in algorithms, "algorithm/OID unavailable")
                key, pub = scratch / (algorithm + ".key.pem"), scratch / (algorithm + ".pub.der")
                runner.run(["genpkey", "-algorithm", algorithm, "-out", key,
                            "-provider", "default", "-propquery", "provider=default"],
                           algorithm + "/wrapper-keygen")
                key.chmod(0o600)
                runner.run(["pkey", "-in", key, "-pubout", "-outform", "DER", "-out", pub,
                            "-provider", "default"], algorithm + "/wrapper-pubout")
                asn1 = runner.run(["asn1parse", "-inform", "DER", "-in", pub],
                                  algorithm + "/wrapper-asn1parse")["stdout"]
                prefix, observed_oid = spki_prefix(pub.read_bytes(), pk_len, oid)
                prefixes[algorithm] = prefix
                summary["public_key_wrappers"][algorithm] = {
                    "der_prefix_hex": prefix.hex(), "observed_oid": observed_oid,
                    "source": "fresh key generated and exported by this exact OpenSSL binary",
                    "asn1parse": asn1,
                }
                msg, sig = scratch / "control-message", scratch / "control-signature"
                msg.write_bytes(b"CPQ1 OpenSSL context-option positive control\n")
                runner.run(["pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg,
                            "-out", sig, "-provider", "default", "-propquery", "provider=default",
                            "-pkeyopt", "message-encoding:1", "-pkeyopt", "mu:0",
                            "-pkeyopt", "context-string:" + CONTEXT],
                           algorithm + "/nonempty-context-control-sign")
                runner.verify(pub, msg, sig, algorithm + "/nonempty-context-control-positive",
                              True, CONTEXT)
                runner.verify(pub, msg, sig, algorithm + "/nonempty-context-control-empty-reject",
                              False)
                counts["nonempty_context_positive_controls"] += 1
                counts["nonempty_context_empty_rejection_controls"] += 1
                key.unlink()
            for row, algorithm, message, signatures in cases:
                case_id = row["case_id"]
                msg, wrong_msg = scratch / "message", scratch / "wrong-message"
                msg.write_bytes(message)
                changed_message = bytearray(message)
                changed_message[-1] ^= 1
                wrong_msg.write_bytes(changed_message)
                result = {"case_id": case_id, "signed_message_sha256": digest(message),
                          "cpq1_wire_sha512": row["cpq1_wire_sha512"],
                          "wrong_message_xor": 1, "wrong_message_byte_offset": len(message) - 1,
                          "signature_challenge_xor": 1, "signature_challenge_byte_offset": 0,
                          "signatures": []}
                for index, (public_key, signature, offset) in enumerate(signatures):
                    key, sig, mutated = scratch / "public.der", scratch / "signature", scratch / "signature-mutated"
                    key.write_bytes(prefixes[algorithm] + public_key)
                    sig.write_bytes(signature)
                    changed_signature = bytearray(signature)
                    changed_signature[0] ^= 1  # c-tilde byte 0, not a W1 challenge.
                    mutated.write_bytes(changed_signature)
                    stages = [
                        ("accepted_original", msg, sig, True, None),
                        ("rejected_wrong_message", wrong_msg, sig, False, None),
                        ("rejected_signature_challenge_bitflip", msg, mutated, False, None),
                        ("rejected_nonempty_context", msg, sig, False, CONTEXT),
                    ]
                    completed = []
                    for label, message_file, signature_file, accept, context in stages:
                        runner.verify(key, message_file, signature_file,
                                      f"{case_id}/signer-{index}/{label}", accept, context)
                        counts[label] += 1
                        by_algorithm[algorithm][label] += 1
                        completed.append(label)
                    result["signatures"].append({
                        "wire_signer_index": index, "wire_signature_byte_offset": offset,
                        "public_key_sha256": digest(public_key), "signature_sha256": digest(signature),
                        "checks": completed,
                    })
                summary["case_results"].append(result)
        for label in ("accepted_original", "rejected_wrong_message",
                      "rejected_signature_challenge_bitflip", "rejected_nonempty_context"):
            require(counts[label] == 120 and all(by_algorithm[a][label] == 60 for a in PARAMETERS),
                    "incomplete mathematical checks")
        require(len(summary["case_results"]) == 32, "incomplete cases")
        require(digest(args.input.read_bytes()) == summary["input_sha256"], "input changed during run")
        require(digest(args.openssl.read_bytes()) == summary["openssl_sha256"], "OpenSSL changed during run")
        summary["passed"] = True
    except Exception as exc:
        summary["errors"].append({"type": type(exc).__name__, "message": str(exc)})
    finally:
        summary["checks"] = dict(counts)
        summary["per_algorithm_checks"] = {k: dict(v) for k, v in by_algorithm.items()}
        summary["openssl_command_count"] = runner.commands if runner else 0
        summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
        if runner:
            runner.log.close()
        (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: summary[k] for k in ("passed", "checks", "per_algorithm_checks",
                                            "openssl_command_count", "errors")}, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
