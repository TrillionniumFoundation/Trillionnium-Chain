// Public-seed characterization of unchanged, pinned upstream headers.
// This is not a proof verifier or an ownership attack demonstration.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <zkp/random.hpp>

int main() {
    namespace zkp = ligero::vm::zkp;
    zkp::sha256::digest a, b;
    std::fill(a.begin(), a.end(), uint8_t{1});
    std::fill(b.begin(), b.end(), uint8_t{2});
    zkp::hash_random_engine<zkp::sha256> left(a), right(b);
    std::array<uint8_t, 64> x{}, y{};
    for (size_t i = 0; i < x.size(); ++i) {
        x[i] = left();
        y[i] = right();
    }
    const bool first_equal = std::equal(x.begin(), x.begin() + 32, y.begin());
    const bool second_equal = std::equal(x.begin() + 32, x.end(), y.begin() + 32);
    std::cout << std::boolalpha
              << "first_block_equal=" << first_equal << '\n'
              << "second_block_equal=" << second_equal << '\n';
    for (const auto& bytes : {x, y}) {
        for (uint8_t value : bytes)
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << static_cast<unsigned>(value);
        std::cout << '\n';
    }
    // Successful characterization means the observed issue was reproduced,
    // never that this sampler is qualified for a proof system.
    return first_equal && !second_equal ? 0 : 1;
}
