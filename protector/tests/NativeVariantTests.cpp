#include "core/protection/NativeVariants.hpp"

#include <cstring>
#include <iostream>

using namespace maya::protection;

static void put(std::vector<uint8_t>& bytes, size_t offset, uint32_t instruction) {
    std::memcpy(bytes.data() + offset, &instruction, sizeof(instruction));
}

int main() {
    std::vector<uint8_t> independent(8);
    put(independent, 0, 0x91000400u); // add x0, x0, #1
    put(independent, 4, 0x91000821u); // add x1, x1, #2
    const auto proven = generate_native_variants(independent, independent.size(), {});
    if (proven.candidates.size() != 1 || proven.candidates[0].bytes == independent ||
        proven.candidates[0].proof.find("unsat") == std::string::npos) {
        std::cerr << "independent pair rejected: " << proven.rejection_reason << '\n';
        return 1;
    }
    const auto protected_pair = generate_native_variants(independent, independent.size(), {4});
    if (!protected_pair.candidates.empty())
        return 2;
    std::vector<uint8_t> independent_w(8);
    put(independent_w, 0, 0x11000400u); // add w0, w0, #1
    put(independent_w, 4, 0x11000821u); // add w1, w1, #2
    const auto proven_w = generate_native_variants(independent_w, independent_w.size(), {});
    if (proven_w.candidates.size() != 1)
        return 4;
    std::vector<uint8_t> identity_add(4);
    put(identity_add, 0, 0x91000020u); // add x0, x1, #0 -> mov x0, x1
    const auto equivalent = generate_native_variants(identity_add, identity_add.size(), {});
    if (equivalent.candidates.size() != 1 ||
        equivalent.candidates[0].transformation != "equivalent-arithmetic-logical-encoding" ||
        equivalent.candidates[0].proof.find("\"result\":\"unsat\"") == std::string::npos)
        return 7;
    std::vector<uint8_t> identity_sp(4);
    put(identity_sp, 0, 0x910003e0u); // add x0, sp, #0 must not become mov from xzr
    if (!generate_native_variants(identity_sp, identity_sp.size(), {}).candidates.empty())
        return 8;
    std::vector<uint8_t> rename_fragment(12);
    put(rename_fragment, 0, 0x91000409u); // add x9, x0, #1
    put(rename_fragment, 4, 0x91000920u); // add x0, x9, #2
    put(rename_fragment, 8, 0xd65f03c0u); // ret
    const auto renamed = generate_native_variants(rename_fragment, rename_fragment.size(), {});
    if (renamed.candidates.empty() ||
        renamed.candidates[0].transformation != "whole-fragment-register-renaming" ||
        renamed.candidates[0].proof.find("abi-observable-equivalent") == std::string::npos)
        return 9;
    std::vector<uint8_t> block_layout(20);
    put(block_layout, 0, 0xb4000060u);  // cbz x0, +12
    put(block_layout, 4, 0x91000421u);  // add x1, x1, #1
    put(block_layout, 8, 0x14000002u);  // b +8
    put(block_layout, 12, 0x91000442u); // add x2, x2, #1
    put(block_layout, 16, 0xd65f03c0u); // ret
    const auto permuted = generate_native_variants(block_layout, block_layout.size(), {});
    if (permuted.candidates.empty() ||
        permuted.candidates[0].transformation != "safe-conditional-block-layout" ||
        permuted.candidates[0].proof.find("condition-inverted-blocks-permuted") ==
            std::string::npos)
        return 10;
    std::vector<uint8_t> literal_placement(24);
    put(literal_placement, 0, 0x58000040u); // ldr x0, +8
    put(literal_placement, 4, 0xd65f03c0u); // ret
    put(literal_placement, 8, 0x55667788u);
    put(literal_placement, 12, 0x11223344u);
    put(literal_placement, 16, 0xd503201fu); // nop
    put(literal_placement, 20, 0xd503201fu); // nop
    const auto moved_literal =
        generate_native_variants(literal_placement, literal_placement.size(), {8});
    if (moved_literal.candidates.size() != 1 ||
        moved_literal.candidates[0].transformation != "authenticated-literal-pool-placement" ||
        moved_literal.candidates[0].proof.find("ldr-imm19-reencoded-and-range-validated") ==
            std::string::npos)
        return 11;
    std::vector<uint8_t> dependent(8);
    put(dependent, 0, 0x91000400u); // add x0, x0, #1
    put(dependent, 4, 0x91000801u); // add x1, x0, #2
    const auto rejected = generate_native_variants(dependent, dependent.size(), {});
    if (!rejected.candidates.empty() || rejected.rejection_reason.empty())
        return 3;
    std::vector<uint8_t> three_pairs(24);
    for (size_t index = 0; index < 6; ++index)
        put(three_pairs, index * 4, 0x91000400u + static_cast<uint32_t>(index) * 0x21u);
    const auto bounded = generate_native_variants(three_pairs, three_pairs.size(), {});
    if (bounded.candidates.size() != kNativeVariantLimit)
        return 5;
    for (const auto& candidate : bounded.candidates)
        if (candidate.proof.find("\"resource_limit\":100000") == std::string::npos ||
            candidate.proof.find("\"stack_cfa\":\"unchanged\"") == std::string::npos ||
            candidate.proof.find("\"variant_disassembly\"") == std::string::npos)
            return 6;
    std::cout << "native variant proof tests passed\n";
}
