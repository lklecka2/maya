#include "core/protection/FragmentImage.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace maya::protection;
static void must_fail(const std::function<void()>& f) {
    try {
        f();
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error("negative parse unexpectedly succeeded");
}
int main() {
    FragmentImage image;
    image.regions.push_back({FragmentRegionType::RuntimeRx, 5, 0, 0, 64, 4096, 0, 0});
    image.functions.push_back({kDescriptorVersion, 7, 0, 1});
    image.fragments.push_back({kDescriptorVersion, 7, 0, 1, 0, 32});
    auto bytes = serialize_fragment_image(image);
    auto parsed = parse_fragment_image(bytes);
    if (parsed.functions.size() != 1 || parsed.functions[0].function_id != 7 ||
        parsed.fragments.size() != 1)
        return 1;
    auto truncated = bytes;
    truncated.resize(20);
    must_fail([&] { parse_fragment_image(truncated); });
    auto bad_version = bytes;
    bad_version[8] = 3;
    must_fail([&] { parse_fragment_image(bad_version); });
    auto bad_count = bytes;
    for (int i = 16; i < 20; i++)
        bad_count[i] = 0xff;
    must_fail([&] { parse_fragment_image(bad_count); });
    auto bad_contract = bytes;
    bad_contract[32] = 3;
    must_fail([&] { parse_fragment_image(bad_contract); });
    auto overlap = bytes;
    for (int i = 56; i < 64; i++)
        overlap[i] = bytes[48 + i - 56];
    must_fail([&] { parse_fragment_image(overlap); });
    auto unknown_feature = bytes;
    unknown_feature[28] = 0x80;
    must_fail([&] { parse_fragment_image(unknown_feature); });
    auto bad_reserved = bytes;
    bad_reserved[44] = 1;
    must_fail([&] { parse_fragment_image(bad_reserved); });
    auto duplicate = image;
    duplicate.functions.push_back(duplicate.functions[0]);
    must_fail([&] { parse_fragment_image(serialize_fragment_image(duplicate)); });
    auto wrong_owner = image;
    wrong_owner.fragments[0].function_id = 99;
    must_fail([&] { parse_fragment_image(serialize_fragment_image(wrong_owner)); });
    auto bad_range = image;
    bad_range.functions[0].fragment_count = 2;
    must_fail([&] { parse_fragment_image(serialize_fragment_image(bad_range)); });
    std::cout << "fragment image tests passed\n";
}
