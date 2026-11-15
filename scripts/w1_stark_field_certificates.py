#!/usr/bin/env python3
"""Exact algebra certificates for two fixed W1 proof-field instances.

Checks prime moduli (complete-factorization Lucas criterion), extension
irreducibility (Rabin criterion), and the actual source root tables. Inputs
are the retained RISC Zero snapshot and locked P3 archive plus profile sources.
No upstream code is executed. Source-parameter correspondence and algebra are
separate from compiled-code semantics, FRI/RBR/PCS soundness, extraction,
random-oracle idealization, recursion, security bits, or admission rights.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "TRNM-W1-STARK-FIELD-CERTIFICATES1"
SOURCE_BASE = "e2a02f9271b49f146e70806c8a66e161b5973971"
RISC_UPSTREAM = "8c215e2f4ccdd935f0517bf05d90f1ae032840a9"
P3_UPSTREAM = "a21e3ed42905040ad49c519e402f018381c12d0c"
P3_ROOT = "formal/pon-nakamoto-v1/w1_public_stark_research/"
RISC_SNAPSHOT = "evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz"
P3_ARCHIVE = P3_ROOT + "security_model_audit/vendor_primary/p3-goldilocks-0.8.0.crate"
SOURCE_PINS = {
    RISC_SNAPSHOT: {"bytes": 69332, "sha256": "f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253"},
    P3_ARCHIVE: {"bytes": 163750, "sha256": "325a854e1232dd1ce270245d9c978b71897c286f072d2fa31740956a800e70c5"},
    P3_ROOT + "Cargo.lock": {"bytes": 18270, "sha256": "24f146fc5d5ba89f6070725a4453fbfe160fae0a81fb2449932f420fd2b7f281"},
    P3_ROOT + "src/proof_config.rs": {"bytes": 13329, "sha256": "98876ea9e223f90079f69bd6f1f75f6a17b9988ed9412fdda8a16bc40367aebf"},
    P3_ROOT + "src/tagged_sha3.rs": {"bytes": 11732, "sha256": "b6bf9e1d77e0e1711f3a8c667223afc5a7262b7658011d3fbbf6006ccd5b0847"},
}
RISC_MEMBER_PINS = {
    "risc0/core/src/field/baby_bear.rs": "df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3",
    "risc0/zkp/src/lib.rs": "107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d",
    "risc0/zkp/src/verify/mod.rs": "003a67af89a7cfaeac9ff23808225cdc4d81c41d64956f20243574531b166c4f",
    "risc0/zkp/src/verify/fri.rs": "a601cfad5d01b294f934d697d6d832c57662e4778eac20ac549b1da53d11e377",
}
P3_MEMBER_PINS = {
    "p3-goldilocks-0.8.0/src/goldilocks.rs": "bd59bea02d51616979a1bf10eb7ff70526dd68f5ba1288bf929fcdd0b86b165b",
    "p3-goldilocks-0.8.0/src/extension.rs": "64bc5d9797b8eb71e22a6bfd97f3612b35d124ae7a334e66c07770111334ce95",
    "p3-goldilocks-0.8.0/.cargo_vcs_info.json": "56784aea050040522cbfbc4a034911e0af3e921019ab1599f9647dde55068ca2",
}
BABYBEAR = 2013265921
GOLDILOCKS = 18446744069414584321


class CertificateError(ValueError):
    """A fixed input or finite algebraic certificate did not check."""


def require(ok, reason):
    if not ok:
        raise CertificateError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_integer(value, name, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum,
            name + ": exact bounded integer required")
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def nonfinite(value):
        raise CertificateError("nonfinite JSON number: " + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_pinned(root, name, record):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and str(relative) == name
            and all(part not in (".", "..") for part in relative.parts),
            "noncanonical source path")
    current = Path(root)
    for part in relative.parts[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), "nonregular source ancestor: " + name)
    path = Path(root) / name
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size == record["bytes"],
                "source size/type differs: " + name)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(record["bytes"] + 1)
        after, visible = os.fstat(descriptor), path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        require(identity(before) == identity(after) == identity(visible),
                "source changed during read: " + name)
        require(len(raw) == record["bytes"] and sha(raw) == record["sha256"],
                "source SHA-256 differs: " + name)
        return raw
    finally:
        os.close(descriptor)


def one(pattern, source, label):
    matches = list(re.finditer(pattern, source, re.S | re.M))
    require(len(matches) == 1, "missing or ambiguous source declaration: " + label)
    return matches[0]


def uint_constant(source, name):
    return int(one(r"\bconst " + re.escape(name)
                   + r": (?:usize|u64|u32) = ([0-9_]+);", source, name).group(1).replace("_", ""))


def literal_array(payload, label):
    require(re.fullmatch(r"[\s0-9a-fA-FxX_,]*", payload) is not None,
            "unsupported source array syntax: " + label)
    values = [item.strip().replace("_", "") for item in payload.split(",") if item.strip()]
    return tuple(int(value, 16 if value.lower().startswith("0x") else 10) for value in values)


def load_sources(root):
    inputs = {name: read_pinned(root, name, record) for name, record in SOURCE_PINS.items()}
    with gzip.GzipFile(fileobj=io.BytesIO(inputs[RISC_SNAPSHOT])) as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, "RISC source snapshot exceeds bound")
    snapshot = strict_json(raw)
    require(snapshot["schema"] == "TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1"
            and snapshot["repository"] == "risc0/risc0"
            and snapshot["commit"] == RISC_UPSTREAM, "RISC snapshot identity")
    rows = {row["path"]: row for row in snapshot["files"]}
    require(len(rows) == len(snapshot["files"]) == 24, "RISC snapshot roster")
    risc, member_records = {}, []
    for name, digest in RISC_MEMBER_PINS.items():
        row = rows[name]
        data = row["content"].encode("utf-8")
        require(sha(data) == digest == row["sha256"] and len(data) == row["bytes"],
                "RISC selected source identity: " + name)
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(git_blob == row["git_blob_sha1"], "RISC Git blob identity: " + name)
        require(row["source_url"] == f"https://github.com/risc0/risc0/blob/{RISC_UPSTREAM}/{name}",
                "RISC upstream source URL")
        risc[name] = data.decode("utf-8")
        member_records.append({"container": RISC_SNAPSHOT, "path": name,
                               "bytes": len(data), "sha256": digest, "git_blob_sha1": git_blob})
    p3 = {}
    with tarfile.open(fileobj=io.BytesIO(inputs[P3_ARCHIVE]), mode="r:gz") as archive:
        roster = archive.getmembers()
        members = {member.name: member for member in roster}
        require(len(members) == len(roster), "duplicate P3 archive member")
        for name, digest in P3_MEMBER_PINS.items():
            member = members[name]
            require(member.isfile() and 0 < member.size <= 128 * 1024,
                    "P3 source member type/size")
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and sha(data) == digest, "P3 member identity: " + name)
            p3[name] = data.decode("utf-8")
            member_records.append({"container": P3_ARCHIVE, "path": name,
                                   "bytes": len(data), "sha256": digest})
    vcs = strict_json(p3["p3-goldilocks-0.8.0/.cargo_vcs_info.json"])
    require(vcs["git"]["sha1"] == P3_UPSTREAM, "P3 archive VCS declaration")
    lock = tomllib.loads(inputs[P3_ROOT + "Cargo.lock"].decode("utf-8"))
    packages = [item for item in lock["package"] if item["name"] == "p3-goldilocks"]
    require(len(packages) == 1 and packages[0]["version"] == "0.8.0"
            and packages[0]["source"] == "registry+https://github.com/rust-lang/crates.io-index"
            and packages[0]["checksum"] == sha(inputs[P3_ARCHIVE]), "P3 archive/Cargo.lock mismatch")
    return inputs, risc, p3, member_records


def small_prime(value):
    """Deterministic division, used only on Lucas factors <= 65537."""
    exact_integer(value, "small factor", 2, 65537)
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))


def prime_certificate(modulus, witness, factors):
    """Lucas criterion with complete factorization of modulus - 1."""
    exact_integer(modulus, "modulus", 3)
    exact_integer(witness, "Lucas witness", 2, modulus - 1)
    require(type(factors) in (list, tuple) and 0 < len(factors) <= 16, "Lucas factor roster")
    product, seen, records = 1, set(), []
    for factor, exponent in factors:
        exact_integer(exponent, "factor exponent", 1, 64)
        require(factor not in seen and small_prime(factor), "duplicate or nonprime Lucas factor")
        seen.add(factor)
        product *= factor ** exponent
        residue = pow(witness, (modulus - 1) // factor, modulus)
        divisor = math.gcd(residue - 1, modulus)
        require(divisor == 1, "Lucas witness lacks required prime-power order")
        records.append({"prime": factor, "exponent": exponent, "residue": residue,
                        "gcd_residue_minus_one_with_modulus": divisor,
                        "factor_primality": "exact trial division through floor(sqrt(prime))"})
    require(product == modulus - 1, "incomplete factorization of modulus minus one")
    full_residue = pow(witness, modulus - 1, modulus)
    require(full_residue == 1, "Lucas Fermat identity differs")
    return {"criterion": "complete-factorization Lucas primality criterion",
            "modulus": modulus, "witness": witness, "factorization": records,
            "factor_product": product, "full_exponent_residue": full_residue,
            "prime_modulus_certified": True}


def poly_trim(values, p):
    result = [value % p for value in values]
    while result and result[-1] == 0:
        result.pop()
    return tuple(result)


def poly_add(left, right, p, sign=1):
    return poly_trim([(left[i] if i < len(left) else 0)
                      + sign * (right[i] if i < len(right) else 0)
                      for i in range(max(len(left), len(right)))], p)


def poly_mul(left, right, p):
    if not left or not right:
        return ()
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] = (out[i + j] + a * b) % p
    return poly_trim(out, p)


def poly_divmod(dividend, divisor, p):
    remainder, divisor = poly_trim(dividend, p), poly_trim(divisor, p)
    require(bool(divisor), "polynomial division by zero")
    quotient = [0] * max(0, len(remainder) - len(divisor) + 1)
    inverse = pow(divisor[-1], -1, p)
    while remainder and len(remainder) >= len(divisor):
        offset, coefficient = len(remainder) - len(divisor), remainder[-1] * inverse % p
        quotient[offset] = coefficient
        subtract = (0,) * offset + tuple(coefficient * value % p for value in divisor)
        remainder = poly_add(remainder, subtract, p, -1)
    return poly_trim(quotient, p), remainder


def poly_powmod(base, exponent, polynomial, p):
    require(type(exponent) is int and exponent >= 0, "polynomial exponent")
    value, base = (1,), poly_divmod(base, polynomial, p)[1]
    while exponent:
        if exponent & 1:
            value = poly_divmod(poly_mul(value, base, p), polynomial, p)[1]
        base = poly_divmod(poly_mul(base, base, p), polynomial, p)[1]
        exponent >>= 1
    return value


def poly_xgcd(left, right, p):
    old_r, r, old_s, s, old_t, t = left, right, (1,), (), (), (1,)
    while r:
        quotient, remainder = poly_divmod(old_r, r, p)
        old_r, r = r, remainder
        old_s, s = s, poly_add(old_s, poly_mul(quotient, s, p), p, -1)
        old_t, t = t, poly_add(old_t, poly_mul(quotient, t, p), p, -1)
    require(bool(old_r), "zero polynomial gcd")
    scale = pow(old_r[-1], -1, p)
    return tuple(poly_trim([scale * value for value in values], p)
                 for values in (old_r, old_s, old_t))


def irreducibility_certificate(p, polynomial):
    """Rabin over a prime field; caller first checks prime_certificate."""
    require(type(polynomial) in (list, tuple) and len(polynomial) in (3, 5),
            "only the quadratic and quartic certificate shapes are supported")
    require(all(type(value) is int and 0 <= value < p for value in polynomial)
            and polynomial[-1] == 1, "canonical monic extension polynomial required")
    polynomial, degree = tuple(polynomial), len(polynomial) - 1
    # Both supported degrees have the single prime divisor 2. This is the
    # complete Rabin roster, not just a search for roots in the base field.
    frobenius, current = {0: (0, 1)}, (0, 1)
    for power in range(1, degree + 1):
        current = poly_powmod(current, p, polynomial, p)
        frobenius[power] = current
    require(current == (0, 1), "Rabin final Frobenius identity differs")
    probe = poly_add(frobenius[degree // 2], (0, 1), p, -1)
    gcd, left, right = poly_xgcd(polynomial, probe, p)
    require(gcd == (1,), "extension polynomial is reducible")
    require(poly_add(poly_mul(left, polynomial, p), poly_mul(right, probe, p), p) == (1,),
            "Rabin Bezout identity differs")
    return {"criterion": "Rabin irreducibility criterion for degrees two and four",
            "degree": degree, "polynomial_low_to_high": polynomial,
            "frobenius_residues": [{"power_of_characteristic": power,
                                     "residue_low_to_high": residue}
                                    for power, residue in sorted(frobenius.items())],
            "degree_prime_divisors": [2], "gcd_probe_power": degree // 2,
            "gcd_probe_low_to_high": probe, "gcd_low_to_high": gcd,
            "bezout_coefficient_for_polynomial": left,
            "bezout_coefficient_for_probe": right,
            "bezout_identity": "A(X)*f(X) + B(X)*(X^(p^(n/2))-X mod f(X)) = 1 in F_p[X]",
            "extension_irreducible_certified": True}


def root_table_certificate(p, roots, max_log_order, inverse_roots=None):
    exact_integer(max_log_order, "base two-adicity", 1, 63)
    require(len(roots) == max_log_order + 1 and roots[0] == 1, "root table length/base")
    require((p - 1) % (1 << max_log_order) == 0
            and (p - 1) % (1 << (max_log_order + 1)) != 0, "wrong maximal base two-adicity")
    require(inverse_roots is None or len(inverse_roots) == len(roots), "inverse root table length")
    rows = []
    for power, root in enumerate(roots):
        exact_integer(root, "root", 1, p - 1)
        order = 1 << power
        full, half = pow(root, order, p), None if power == 0 else pow(root, order // 2, p)
        require(full == 1 and (power == 0 or half == p - 1), "root exact order differs")
        require(power == 0 or root * root % p == roots[power - 1], "inconsistent root table chain")
        if inverse_roots is not None:
            exact_integer(inverse_roots[power], "inverse root", 1, p - 1)
            require(root * inverse_roots[power] % p == 1, "inverse root table mismatch")
        rows.append({"log_order": power, "order": order, "root": root,
                     "full_power_residue": full, "half_power_residue": half})
    return {"domain_family": "multiplicative two-adic subgroups; nonzero shifts give same-size cosets",
            "max_log_order": max_log_order, "all_source_entries_have_exact_order": True,
            "inverse_source_entries_verified": inverse_roots is not None, "entries": rows}


def parse_risc_parameters(sources):
    field = sources["risc0/core/src/field/baby_bear.rs"]
    zkp = sources["risc0/zkp/src/lib.rs"]
    a, power, b = map(int, one(r"pub const P: u32 = (\d+) \* \(1 << (\d+)\) \+ (\d+);",
                               field, "BabyBear modulus").groups())
    p = a * (1 << power) + b
    beta = int(one(r"const BETA: Elem = Elem::new\((\d+)\);", field, "BabyBear beta").group(1))
    one(r"const NBETA: Elem = Elem::new\(P - " + str(beta) + r"\);", field, "BabyBear negative beta")
    extension = uint_constant(field, "EXT_SIZE")
    max_root = uint_constant(field, "MAX_ROU_PO2")
    roots = {}
    for name in ("ROU_FWD", "ROU_REV"):
        payload = one(r"const " + name + r": &'static \[Elem\] = &rou_array!\[(.*?)\];",
                      field, name).group(1)
        roots[name] = literal_array(payload, name)
    max_trace, inverse_rate = uint_constant(zkp, "MAX_CYCLES_PO2"), uint_constant(zkp, "INV_RATE")
    require((p, beta, extension, max_root, max_trace, inverse_rate) == (BABYBEAR, 11, 4, 27, 24, 4),
            "unsupported RISC field/domain parameters")
    verify = sources["risc0/zkp/src/verify/mod.rs"]
    fri = sources["risc0/zkp/src/verify/fri.rs"]
    require("let domain = INV_RATE * self.tot_cycles;" in verify
            and "ROU_FWD[log2_ceil(domain)]" in verify
            and "let orig_domain = INV_RATE * degree;" in fri
            and "ROU_FWD[log2_ceil(domain)]" in fri, "RISC multiplicative-domain source mapping")
    max_domain = max_trace + (inverse_rate.bit_length() - 1)
    require(max_domain <= max_root, "RISC declared domain exceeds base root table")
    return {"p": p, "polynomial": (beta, 0, 0, 0, 1), "roots": roots["ROU_FWD"],
            "inverse_roots": roots["ROU_REV"], "two_adicity": max_root,
            "domain_scope": {"generic_parser_max_trace_log": max_trace,
                "inverse_rate": inverse_rate, "generic_parser_max_domain_log": max_domain,
                "generic_parser_max_domain_has_exact_order": True,
                "all_parser_trace_sizes_reachable_proved": False}}


def parse_p3_parameters(sources, inputs):
    field = sources["p3-goldilocks-0.8.0/src/goldilocks.rs"]
    extension = sources["p3-goldilocks-0.8.0/src/extension.rs"]
    p = int(one(r"pub\(crate\) const P: u64 = (0x[0-9A-Fa-f_]+);", field,
                "Goldilocks modulus").group(1).replace("_", ""), 16)
    max_root = uint_constant(field, "TWO_ADICITY")
    witness = int(one(r"const GENERATOR: Self = Self::new\((\d+)\);", field,
                      "Goldilocks multiplicative generator").group(1))
    payload = one(r"pub const TWO_ADIC_GENERATORS: \[Self; 33\] = Self::new_array\(\[(.*?)\]\);",
                  field, "Goldilocks root table").group(1)
    roots = literal_array(payload, "Goldilocks root table")
    quadratic = one(r"impl BinomiallyExtendable<2> for Goldilocks \{(.*?)\n\}", extension,
                    "Goldilocks quadratic extension").group(1)
    nonresidue = int(one(r"const W: Self = Self::new\((\d+)\);", quadratic,
                         "Goldilocks quadratic W").group(1))
    require((p, max_root, witness, nonresidue) == (GOLDILOCKS, 32, 7, 7),
            "unsupported P3 field/domain parameters")
    profiles = []
    for suffix in ("src/proof_config.rs", "src/tagged_sha3.rs"):
        source = inputs[P3_ROOT + suffix].decode("utf-8")
        require("pub type Val = Goldilocks;" in source
                and "pub type Challenge = BinomialExtensionField<Val, 2>;" in source
                and "pub type Dft = Radix2DitParallel<Val>;" in source
                and "TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>" in source,
                "P3 field/type/PCS source mapping: " + suffix)
        require(uint_constant(source, "GOLDILOCKS_ORDER") == p
                and uint_constant(source, "LOG_BLOWUP") == 2, "P3 profile modulus/blowup")
        profiles.append({"path": P3_ROOT + suffix, "extension_degree": 2, "log_blowup": 2})
    tagged = inputs[P3_ROOT + "src/tagged_sha3.rs"].decode("utf-8")
    domains = [{"component": name, "trace_log": uint_constant(tagged, constant),
                "evaluation_log": uint_constant(tagged, constant) + 2}
               for name, constant in (("sha", "SHA_DEGREE_BITS"), ("packed_carry", "PACKED_CARRY_DEGREE_BITS"))]
    require([row["evaluation_log"] for row in domains] == [15, 16]
            and all(row["evaluation_log"] <= max_root for row in domains), "tagged fixed domain bounds")
    return {"p": p, "polynomial": (p - nonresidue, 0, 1), "roots": roots,
            "inverse_roots": None, "two_adicity": max_root, "profiles": profiles,
            "domain_scope": {"tagged_fixed_components": domains,
                "ordinary_poseidon2_all_accepted_trace_bounds_proved": False,
                "base_domain_capacity_is_not_a_trace_reachability_proof": True}}


def qualification():
    return {"prime_moduli_certified": True, "extension_irreducibility_certified": True,
            "source_root_table_orders_certified": True,
            "compiled_field_arithmetic_equivalence_proved": False,
            "complete_build_source_closure_verified": False,
            "native_binary_executed": False, "fri_soundness_qualified": False,
            "rbr_knowledge_soundness_qualified": False, "quantum_extractor_qualified": False,
            "post_quantum_soundness_qualified": False, "recursive_composition_qualified": False,
            "production_qualified": False, "consensus_admission": False,
            "security_bits_quantum": None, "whole_lifetime_failure_bound": None}


def json_safe(value):
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        return {key: json_safe(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [json_safe(item) for item in value]
    return value


def build_report(root=ROOT):
    inputs, risc_sources, p3_sources, member_records = load_sources(Path(root))
    risc, p3 = parse_risc_parameters(risc_sources), parse_p3_parameters(p3_sources, inputs)
    fields = {}
    for name, parameters, witness, factors in (
        ("risc0_babybear_fp4", risc, 31, ((2, 27), (3, 1), (5, 1))),
        ("plonky3_goldilocks_fp2", p3, 7, ((2, 32), (3, 1), (5, 1), (17, 1), (257, 1), (65537, 1))),
    ):
        p = parameters["p"]
        primality = prime_certificate(p, witness, factors)
        irreducibility = irreducibility_certificate(p, parameters["polynomial"])
        domains = root_table_certificate(p, parameters["roots"], parameters["two_adicity"],
                                        parameters["inverse_roots"])
        fields[name] = {"characteristic": p, "extension_degree": len(parameters["polynomial"]) - 1,
                        "extension_polynomial_low_to_high": parameters["polynomial"],
                        "base_two_adicity": parameters["two_adicity"], "primality": primality,
                        "irreducibility": irreducibility, "multiplicative_domains": domains,
                        "profile_domain_scope": parameters["domain_scope"],
                        "characteristic_two_additive_domain_hypothesis_matches": False,
                        "this_mismatch_proves_fri_soundness": False}
    # This is a small selected-input observation, not a whole-repository or
    # past-build read trace. The output does not claim either property.
    require(inputs == {name: read_pinned(root, name, row) for name, row in SOURCE_PINS.items()},
            "selected field inputs changed during certification")
    return json_safe({"schema": SCHEMA, "status": "FIXED_FIELD_ALGEBRA_CERTIFIED_SECURITY_HOLD",
        "source_base_commit": SOURCE_BASE, "fields": fields,
        "source_binding": {"selected_input_bytes_verified_before_and_after": True,
            "sources": [{"path": name, **row} for name, row in SOURCE_PINS.items()],
            "selected_members": member_records, "risc_upstream_commit": RISC_UPSTREAM,
            "p3_archive_declared_upstream_commit": P3_UPSTREAM,
            "p3_archive_matches_current_lockfile": True, "p3_profiles": p3["profiles"],
            "scope": "fixed source parameter declarations and finite algebra only; no upstream code execution"},
        "qualification": qualification(),
        "limits": [
            "A theorem requiring characteristic two cannot be applied directly to these odd-characteristic instances.",
            "That mismatch is no positive FRI theorem; odd-characteristic and small-base-field/extension results require separate mapping.",
            "A field certificate transfers no Poseidon2/SHA3 assumptions, query entropy, compiler semantics, extractor or recursion bound between profiles.",
            "Root availability verifies algebraic domain order, not all reachable AIR/VM traces or the entire allowed statement set.",
        ]})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root)
        output = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (ValueError, OSError, KeyError, TypeError, EOFError, tarfile.TarError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "INPUT_REJECTED", "reason": str(error),
                          "algebraic_facts_certified": False, "security_bits_quantum": None,
                          "production_qualified": False}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
