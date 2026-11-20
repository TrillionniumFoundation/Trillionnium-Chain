"""Fresh native differential for the Task owner's private signature caches.

Only decoded public points and fixed-base comb tables are cached. Every complete
signature still checks R, canonical S, weak points, SHA512(R || A || message),
and the group equation. Fixtures are fixed public test vectors; neither Python
arithmetic nor a host crypto library supplies the native verifier result.

Scratch is a new zeroed private 262144-byte owner arena, with guarded ends.
Private continuation crypto stays below the cache ranges. The generic kp_joint2
table uses [143360, 151552), so it must use a separate arena; the production Store
closure never calls it. The uncached comparison uses that separate arena here.
This observer cannot authorize caching in caller-controlled generic scratch.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.build import Build, INPUTS as PINNED_INPUTS
from hia.platform.task_kernel.build_boundary import SourceBuild
from hia.platform.task_kernel.build_store_audit import DEPENDENCIES
from hia.tools.toolchain import pinned_toolchain

WORK_BYTES = 262144
POINT_START, POINT_END, POINT_CURSOR = 147456, 149664, 149664
COMB_START, COMB_END, COMB_CURSOR = 149696, 149816, 149816
POINT_MARKER = 3551735579062913868
SEQUENCE = [0, 1, 0, 2, 1, 3, 0, 4, 5, 4, 2, 6, 7, 0, 7]
EXPECTED_CASES = 115

HARNESS = '''hia-asm.v1 hepta.hia.program.v8 trnm_task_private_cache_comparison
fn f0(input:readbuf,output:mutbuf,work:mutbuf) -> (u32) effects(read,write,trap) entry(start)
block start(input:readbuf,output:mutbuf,work:mutbuf)
  zero:u64 = const() {"value":0}
  mode:u64 = call(input,zero) {"function":"cp_read"}
  eight:u64 = const() {"value":8}
  key:u64 = const() {"value":140160}
  width:u64 = const() {"value":32}
  copied:u64 = call(input,eight,work,key,width) {"function":"cp_copy"}
  initialized:u32 = call(work) {"function":"ed_init"}
  two:u64 = const() {"value":2}
  cached_key_only:bool = compare.eq(mode,two)
  five:u64 = const() {"value":5}
  cached_full:bool = compare.eq(mode,five)
  cached:bool = select(cached_key_only,cached_key_only,cached_full)
  branch cached cached_key(input,output,work,mode) original_key(input,output,work,mode)
block cached_key(input_c:readbuf,output_c:mutbuf,work_c:mutbuf,mode_c:u64)
  cached_value:u64 = call(work_c) {"function":"sp_public_key"}
  jump prepared(input_c,output_c,work_c,mode_c,cached_value)
block original_key(input_o:readbuf,output_o:mutbuf,work_o:mutbuf,mode_o:u64)
  original_value:u64 = call(work_o) {"function":"kp_public_key"}
  jump prepared(input_o,output_o,work_o,mode_o,original_value)
block prepared(input_p:readbuf,output_p:mutbuf,work_p:mutbuf,mode_p:u64,key_valid:u64)
  two_p:u64 = const() {"value":2}
  four_p:u64 = const() {"value":4}
  full:bool = compare.ge(mode_p,four_p)
  branch full finish(input_p,output_p,work_p,mode_p,key_valid) partial(input_p,output_p,work_p,mode_p,key_valid)
block partial(q0_input_p:readbuf,q0_output_p:mutbuf,q0_work_p:mutbuf,q0_mode_p:u64,q0_key_valid:u64)
  q0_two_p:u64 = const() {"value":2}
  q0_key_only:bool = compare.ge(q0_mode_p,q0_two_p)
  branch q0_key_only result(q0_output_p,q0_work_p,q0_key_valid) signature(q0_input_p,q0_output_p,q0_work_p,q0_mode_p,q0_key_valid)
block finish(q1_input_f:readbuf,q1_output_f:mutbuf,q1_work_f:mutbuf,q1_mode_f:u64,q1_key_f:u64)
  q1_sig_offset:u64 = const() {"value":40}
  q1_sig_pointer:u64 = const() {"value":43136}
  q1_stored:u64 = call(q1_work_f,q1_sig_pointer,q1_sig_offset) {"function":"cp_put"}
  q1_message_at:u64 = const() {"value":108}
  q1_message_dest:u64 = const() {"value":81920}
  q1_message_width:u64 = const() {"value":32}
  q1_message_copy:u64 = call(q1_input_f,q1_message_at,q1_work_f,q1_message_dest,q1_message_width) {"function":"cp_copy"}
  q1_prepared:u64 = call(q1_input_f,q1_work_f,q1_key_f) {"function":"kp_signature_prepare_finish"}
  q1_ready:u64 = const() {"value":2}
  q1_is_ready:bool = compare.eq(q1_prepared,q1_ready)
  branch q1_is_ready full_equation(q1_output_f,q1_work_f,q1_mode_f) full_error(q1_output_f,q1_work_f)
block full_error(q2_output_e:mutbuf,q2_work_e:mutbuf)
  q2_rejected:u64 = const() {"value":0}
  jump result(q2_output_e,q2_work_e,q2_rejected)
block full_equation(q3_output_g:mutbuf,q3_work_g:mutbuf,q3_mode_g:u64)
  q3_original_mode:u64 = const() {"value":4}
  q3_full_original:bool = compare.eq(q3_mode_g,q3_original_mode)
  branch q3_full_original original_equation(q3_output_g,q3_work_g) cached_equation(q3_output_g,q3_work_g)
block signature(input_s:readbuf,output_s:mutbuf,work_s:mutbuf,mode_s:u64,key_ok:u64)
  zero_s:u64 = const() {"value":0}
  invalid:bool = compare.eq(key_ok,zero_s)
  branch invalid result(output_s,work_s,zero_s) decode_r(input_s,output_s,work_s,mode_s)
block decode_r(input_r:readbuf,output_r:mutbuf,work_r:mutbuf,mode_r:u64)
  r_at:u64 = const() {"value":40}
  r_bytes:u64 = const() {"value":140288}
  width_r:u64 = const() {"value":32}
  r_copied:u64 = call(input_r,r_at,work_r,r_bytes,width_r) {"function":"cp_copy"}
  point_r:u64 = const() {"value":134912}
  r_code:u64 = call(work_r,point_r,r_bytes) {"function":"kp_point_decode"}
  zero_r:u64 = const() {"value":0}
  invalid_r:bool = compare.ne(r_code,zero_r)
  branch invalid_r result(output_r,work_r,zero_r) scalars(input_r,output_r,work_r,mode_r)
block scalars(input_b:readbuf,output_b:mutbuf,work_b:mutbuf,mode_b:u64)
  width_b:u64 = const() {"value":32}
  s_at:u64 = const() {"value":72}
  s_dest:u64 = const() {"value":140416}
  s_copy:u64 = call(input_b,s_at,work_b,s_dest,width_b) {"function":"cp_copy"}
  h_at:u64 = const() {"value":104}
  h_dest:u64 = const() {"value":140032}
  h_copy:u64 = call(input_b,h_at,work_b,h_dest,width_b) {"function":"cp_copy"}
  zero_b:u64 = const() {"value":0}
  original:bool = compare.eq(mode_b,zero_b)
  branch original original_equation(output_b,work_b) cached_equation(output_b,work_b)
block original_equation(output_e:mutbuf,work_e:mutbuf)
  original_ok:bool = call(work_e) {"function":"kp_joint2"}
  original_one:u64 = const() {"value":1}
  original_zero:u64 = const() {"value":0}
  original_result:u64 = select(original_ok,original_one,original_zero)
  jump result(output_e,work_e,original_result)
block cached_equation(output_j:mutbuf,work_j:mutbuf)
  cached_ok:bool = call(work_j) {"function":"kp_joint_cached"}
  cached_one:u64 = const() {"value":1}
  cached_zero:u64 = const() {"value":0}
  cached_result:u64 = select(cached_ok,cached_one,cached_zero)
  jump result(output_j,work_j,cached_result)
block result(output_f:mutbuf,work_f:mutbuf,value:u64)
  zero_f:u64 = const() {"value":0}
  result_written:u64 = call(output_f,zero_f,value) {"function":"cp_put"}
  point_f:u64 = const() {"value":134400}
  eight_f:u64 = const() {"value":8}
  point_width:u64 = const() {"value":512}
  point_written:u64 = call(work_f,point_f,output_f,eight_f,point_width) {"function":"cp_wout"}
  success:u32 = const() {"value":0}
  ret(success)
end
'''


def identity(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Arena:
    def __init__(self):
        self.storage = ctypes.create_string_buffer(WORK_BYTES + 128)
        self.pointer = ctypes.c_void_p(ctypes.addressof(self.storage) + 64)
        ctypes.memset(ctypes.addressof(self.storage), 0xA5, 64)
        ctypes.memset(ctypes.addressof(self.storage) + 64 + WORK_BYTES, 0x5A, 64)

    def read(self, start, end):
        return ctypes.string_at(self.pointer.value + start, end - start)

    def guarded(self):
        return (self.storage.raw[:64] == bytes([0xA5]) * 64 and
                self.storage.raw[-64:] == bytes([0x5A]) * 64)

    def point_state(self):
        return self.read(POINT_START, POINT_CURSOR + 8)

    def point_keys(self):
        return [self.read(POINT_START + 552 * slot + 8, POINT_START + 552 * slot + 40)
                for slot in range(4)
                if struct.unpack("<Q", self.read(POINT_START + 552 * slot, POINT_START + 552 * slot + 8))[0] == POINT_MARKER]


def qualify(output):
    output = output.absolute()
    require(__debug__ and output.resolve() == output and not output.exists() and ROOT not in output.parents,
            "Fresh canonical evidence directory outside checkout required")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "trnm.hia.task-store.signature-cache-qualification.v1", "status": "FAIL",
              "finalized": False, "controls": [], "native_calls": 0,
              "public_key_cache_slots": 4, "comb_cache_slots": 3, "private_work_bytes": WORK_BYTES,
              "point_cache_range": [POINT_START, POINT_END], "point_cursor_range": [POINT_CURSOR, POINT_CURSOR + 8],
              "comb_metadata_range": [COMB_START, COMB_END], "comb_cursor_range": [COMB_CURSOR, COMB_CURSOR + 8],
              "comb_tables_range": [163840, WORK_BYTES]}
    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    save()
    try:
        pinned_toolchain()
        from hepta.hia_agent_assembly import assemble_program
        source = output / "cache-harness.hepta"
        source.write_text(HARNESS)
        composer = SourceBuild(output / "compose")
        composer.assemble = assemble_program
        vector_path = Path(__file__).with_name("store_signature_cache_vectors.json")
        for path in [Path(__file__), vector_path, ROOT / "hia/platform/build.py",
                     ROOT / "hia/platform/task_kernel/build_boundary.py", ROOT / "hia/tools/toolchain.py",
                     *[ROOT / "hia" / name for name in PINNED_INPUTS]]:
            composer.capture(path)
        dependencies = [*DEPENDENCIES, ROOT / "hia/src/task_kernel/store_policy.hepta",
                        ROOT / "hia/src/task_kernel/store_signature_cache.hepta",
                        ROOT / "hia/src/crypto/ed25519_public_point_cache.hepta"]
        raw, functions = composer.compose(source, dependencies)
        report["source_before"] = composer.sources.copy()
        report["function_sources"] = functions
        save()
        (output / "composed.hepta").write_bytes(raw)
        compiler = Build(output / "compiler")
        obj = compiler.stage(compiler.compiler, raw, "cache-harness")
        (output / "cache-harness.o").write_bytes(obj)
        composer.stage("link-cache-harness", ["ld", "-shared", "-z", "defs", "-z", "noexecstack",
                       "--build-id=none", output / "cache-harness.o", "-lc", "-o", output / "cache-harness.so"])
        report["native_compiler_stages"] = compiler.stages
        report["link_stages"] = composer.report["stages"]
        report["artifacts"] = {name: identity(output / name) for name in
                               ("cache-harness.hepta", "composed.hepta", "cache-harness.o", "cache-harness.so")}
        library = ctypes.CDLL(str(output / "cache-harness.so"))
        invoke_native = library.f0
        invoke_native.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
        invoke_native.restype = ctypes.c_uint64
        original, cached = Arena(), Arena()
        def invoke(mode, payload, arena):
            data = ctypes.create_string_buffer(struct.pack("<Q", mode) + payload)
            result = ctypes.create_string_buffer(520)
            started = time.monotonic_ns()
            code = invoke_native(data, len(data) - 1, result, 520, arena.pointer, WORK_BYTES)
            elapsed = time.monotonic_ns() - started
            report["native_calls"] += 1
            require(code == 0 and arena.guarded() and data.raw[:-1] == struct.pack("<Q", mode) + payload,
                    "Native ABI, input immutability or arena guard failed")
            out = bytes(result)
            return struct.unpack_from("<Q", out)[0], out[8:], elapsed
        def compare(name, payload, old_mode, new_mode, expected=None, index=None):
            old = invoke(old_mode, payload, original)
            new = invoke(new_mode, payload, cached)
            require(old[0] == new[0], "Cached status differs: " + name)
            if old[0]:
                require(old[1] == new[1], "Decoded point differs: " + name)
            if expected is not None:
                require(old[0] == expected, "Unexpected native acceptance: " + name)
            row = {"name": name, "index": index, "input_hex": payload.hex(),
                   "original_mode": old_mode, "cached_mode": new_mode,
                   "original_result": old[0], "cached_result": new[0],
                   "original_output_hex": old[1].hex(), "cached_output_hex": new[1].hex(),
                   "original_elapsed_ns": old[2], "cached_elapsed_ns": new[2], "arena_guards": True}
            report["controls"].append(row)
            save()
            return row
        vectors = json.loads(vector_path.read_text())
        require(vectors["schema"] == "trnm.hia.task-store.signature-cache-vectors.v1" and
                [v["key"] for v in vectors["vectors"]] == SEQUENCE, "Fixed vector roster differs")
        vectors = vectors["vectors"]
        keys = {v["key"]: bytes.fromhex(v["public_key"]) for v in vectors}
        def point_case(name, key, index):
            before = cached.point_state()
            hit = key in cached.point_keys()
            row = compare(name, key + bytes(96), 3, 2, index=index)
            after = cached.point_state()
            if hit or not row["cached_result"]:
                require(before == after, "Cache hit or failed decode mutated point cache")
            else:
                require(before != after and key in cached.point_keys(), "Successful miss did not bind exact key")
            row.update(point_cache_hit=hit, failed_decode_preserved_cache=not row["cached_result"],
                       point_state_before=before.hex(), point_state_after=after.hex())
        for index, key in enumerate(SEQUENCE):
            point_case("public-key", keys[key], index)
        boundary = [bytes(32), (1).to_bytes(32, "little"), (2).to_bytes(32, "little"),
                    (2**255 - 19).to_bytes(32, "little"), (2**255 - 18).to_bytes(32, "little"),
                    ((1 << 255) + 1).to_bytes(32, "little"), bytes([255]) * 32]
        for index, key in enumerate(boundary):
            point_case("boundary-key", key, index)
            point_case("boundary-key-repeat", key, index)
        for offset in range(32):
            key = bytearray(keys[0]); key[offset] ^= 1
            point_case("changed-key-byte", bytes(key), offset)
        modulus = 2**252 + 27742317777372353535851937790883648493
        for index, vector in enumerate(vectors):
            key, signature, message = (bytes.fromhex(vector[field]) for field in ("public_key", "signature", "message"))
            h = (int.from_bytes(hashlib.sha512(signature[:32] + key + message).digest(), "little") % modulus).to_bytes(32, "little")
            for label, s, challenge in (
                ("valid", signature[32:], h),
                ("changed-s", (int.from_bytes(signature[32:], "little") ^ 1).to_bytes(32, "little"), h),
                ("changed-h", signature[32:], (int.from_bytes(h, "little") ^ 1).to_bytes(32, "little"))):
                compare(label, key + signature[:32] + s + challenge, 0, 1, label == "valid", index)
        vector = vectors[-1]
        key, signature, message = (bytes.fromhex(vector[field]) for field in ("public_key", "signature", "message"))
        variants = [
            ("prepared-valid", key, signature, message, 1),
            ("prepared-message-changed", key, signature, bytes([message[0] ^ 1]) + message[1:], 0),
            ("prepared-r-changed", key, bytes.fromhex(vectors[0]["signature"])[:32] + signature[32:], message, 0),
            ("prepared-s-changed", key, signature[:32] + (int.from_bytes(signature[32:], "little") ^ 1).to_bytes(32, "little"), message, 0),
            ("prepared-s-order", key, signature[:32] + modulus.to_bytes(32, "little"), message, 0),
            ("prepared-s-malleable", key, signature[:32] + (int.from_bytes(signature[32:], "little") + modulus).to_bytes(32, "little"), message, 0),
            ("prepared-r-weak", key, (1).to_bytes(32, "little") + signature[32:], message, 0),
            ("prepared-key-weak", (1).to_bytes(32, "little"), signature, message, 0),
            ("prepared-valid-recovery", key, signature, message, 1),
        ]
        for index, (label, public, sig, msg, expected) in enumerate(variants):
            compare(label, public + struct.pack("<I", 64) + sig + msg, 4, 5, expected, index)
        require(len(report["controls"]) == EXPECTED_CASES and report["native_calls"] == EXPECTED_CASES * 2,
                "Complete cache regression roster differs")
        require(any(row.get("failed_decode_preserved_cache") for row in report["controls"]),
                "No actual decoding failure exercised")
        compiler.check_pin()
        report["source_after"] = {path: identity(path) for path in composer.sources}
        require(report["source_before"] == report["source_after"], "Cache regression source fence differs")
        report.update(status="PASS", finalized=True, cases=len(report["controls"]))
        save()
        return report
    except BaseException as error:
        report.update(status="FAIL", finalized=False, failure=repr(error))
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output)
    print(json.dumps({"status": report["status"], "cases": report["cases"],
                      "native_calls": report["native_calls"], "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
