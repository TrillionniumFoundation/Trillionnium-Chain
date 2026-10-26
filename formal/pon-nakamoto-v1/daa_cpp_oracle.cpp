// Trillionnium PoN ASERT independent C++ research oracle (NON-CONSENSUS).
// This file does not admit blocks, verify W1 proofs, authorize signers or select a chain.
// Input: 8 whitespace-separated tokens per line:
//   anchor_target_hex pow_limit_hex anchor_parent_time parent_time
//   anchor_height candidate_height spacing half_life
// Output: exact lowercase 64-hex target, ERR_PARAMETERS, ERR_RANGE or ERR_FORMAT.
// No JSON, network, filesystem, OpenSSL or Rust dependencies. GNU/Clang C++17 + Boost headers.
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using boost::multiprecision::cpp_int;
constexpr uint64_t RADIX = 65536;
struct BadParameters : std::exception {};
struct BadRange : std::exception {};
struct BadFormat : std::exception {};

uint64_t parse_u64(const std::string& s) {
    if (s.empty() || s.size() > 20) throw BadParameters{};
    uint64_t out = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out, 10);
    if (ec != std::errc() || end != s.data() + s.size()) throw BadParameters{};
    return out;
}
cpp_int parse_u256(const std::string& h) {
    if (h.size() != 64) throw BadParameters{};
    cpp_int out = 0;
    for (char ch : h) {
        int value = (ch >= '0' && ch <= '9') ? ch - '0' :
                    (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 : -1;
        if (value < 0) throw BadParameters{};
        out <<= 4;
        out += value;
    }
    return out;
}
std::string format_u256(cpp_int x) {
    std::string out(64, '0');
    for (int i = 63; i >= 0; --i) {
        const unsigned nibble = static_cast<unsigned>((x & 15).convert_to<uint64_t>());
        out[i] = "0123456789abcdef"[nibble];
        x >>= 4;
    }
    if (x != 0) throw BadRange{};
    return out;
}
struct Input {
    cpp_int anchor_target;
    cpp_int pow_limit;
    uint64_t anchor_time, parent_time, anchor_height, candidate_height, spacing, half_life;
};
Input parse_line(const std::string& line) {
    if (line.empty() || line.size() > 350) throw BadFormat{};
    std::istringstream stream(line);
    std::array<std::string, 8> items{};
    for (auto& item : items) if (!(stream >> item)) throw BadFormat{};
    std::string extra;
    if (stream >> extra) throw BadFormat{};
    return {parse_u256(items[0]), parse_u256(items[1]),
            parse_u64(items[2]), parse_u64(items[3]), parse_u64(items[4]),
            parse_u64(items[5]), parse_u64(items[6]), parse_u64(items[7])};
}
// All numeric behavior is deliberately independently expressed in arbitrary
// integers. It explicitly enforces Rust's i128 checked domains and signed
// division truncation, then clamps before potentially astronomical shifts.
std::string asert(Input in) {
    if (in.anchor_target <= 0 || in.pow_limit <= 0 ||
        in.anchor_target > in.pow_limit ||
        in.anchor_height == 0 || in.candidate_height <= in.anchor_height ||
        in.spacing == 0 || in.half_life == 0)
        throw BadParameters{};
    const cpp_int minimum_i128 = -(cpp_int(1) << 127);
    const cpp_int maximum_i128 = (cpp_int(1) << 127) - 1;
    const auto checked = [&](const cpp_int& x) {
        if (x < minimum_i128 || x > maximum_i128) throw BadRange{};
        return x;
    };
    const cpp_int ideal = checked(cpp_int(in.candidate_height - in.anchor_height) * in.spacing);
    const cpp_int deviation = checked(cpp_int(in.parent_time) - in.anchor_time - ideal);
    const cpp_int scaled = checked(deviation * RADIX);
    // cpp_int division of a signed integer by a positive denominator truncates
    // toward zero. Compute a mathematical floor quotient for 2^16 manually.
    const cpp_int exponent = scaled / cpp_int(in.half_life);
    cpp_int shift = exponent / RADIX;
    if (exponent < 0 && exponent % RADIX != 0) --shift;
    const cpp_int fraction = exponent - shift * RADIX; // always [0, 65535]
    const cpp_int factor = RADIX + (
        cpp_int("195766423245049") * fraction + cpp_int("971821376") * fraction * fraction +
        cpp_int("5127") * fraction * fraction * fraction + (cpp_int(1) << 47)) / (cpp_int(1) << 48);
    if (factor < RADIX || factor > 2 * RADIX) throw BadRange{};
    if (shift >= 256) return format_u256(in.pow_limit);
    if (shift <= -512) return format_u256(1);
    cpp_int result = in.anchor_target * factor;
    const int s = shift.convert_to<int>();
    if (s >= 0) result <<= s;
    else result >>= -s;
    result >>= 16;
    if (result < 1) result = 1;
    if (result > in.pow_limit) result = in.pow_limit;
    return format_u256(result);
}
} // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::string line;
    unsigned count = 0;
    while (std::getline(std::cin, line)) {
        if (++count > 4096) { std::cerr << "research record ceiling exceeded\n"; return 2; }
        try { std::cout << asert(parse_line(line)) << '\n'; }
        catch (const BadFormat&) { std::cout << "ERR_FORMAT\n"; }
        catch (const BadParameters&) { std::cout << "ERR_PARAMETERS\n"; }
        catch (const BadRange&) { std::cout << "ERR_RANGE\n"; }
    }
    return std::cin.bad() ? 2 : 0;
}
