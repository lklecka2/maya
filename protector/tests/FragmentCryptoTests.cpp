#include "core/protection/FragmentCrypto.hpp"

#include <iostream>
#include <stdexcept>

#include "runtime_kdf.h"
#include "xchacha20poly1305.h"

using namespace maya::protection;

int main() {
    auto seed = parse_seed_hex(std::string(64, '1'));
    auto secrets = derive_build_secrets(seed);
    auto nonce0 = derive_fragment_nonce(seed, 1, 2);
    auto nonce1 = derive_fragment_nonce(seed, 1, 3);
    if (nonce0 == nonce1)
        return 1;

    std::vector<uint8_t> plaintext = {1, 2, 3, 4};
    std::vector<uint8_t> aad = {1, 0, 0, 0, 9, 8, 7};
    std::array<uint8_t, 32> runtime_digest{};
    maya_sha256_digest(runtime_digest.data(), aad.data(), aad.size());
    if (runtime_digest != sha256_bytes(aad))
        return 11;
    std::vector<Seed256> domain_keys;
    for (uint32_t value = static_cast<uint32_t>(KeyDomain::Fragment);
         value <= static_cast<uint32_t>(KeyDomain::StateBinding); ++value) {
        domain_keys.push_back(
            derive_domain_key(secrets.root, static_cast<KeyDomain>(value), {4, 3, 2, 1}));
    }
    for (size_t i = 0; i < domain_keys.size(); ++i) {
        for (size_t j = i + 1; j < domain_keys.size(); ++j) {
            if (domain_keys[i] == domain_keys[j])
                return 10;
        }
        secure_zero(domain_keys[i]);
    }
    auto key = derive_sealed_object_key(secrets.root, aad);
    std::array<uint8_t, 32> runtime_key{};
    maya_derive_sealed_object_key(runtime_key.data(), secrets.root.data(), aad.data(), aad.size());
    if (runtime_key != key)
        return 8;
    auto sealed = seal_fragment(plaintext, aad, key, nonce0);
    if (open_fragment(sealed, aad, key) != plaintext)
        return 2;
    std::vector<uint8_t> runtime_plain(plaintext.size());
    if (maya_xchacha20poly1305_open(runtime_plain.data(), sealed.ciphertext.data(),
                                    sealed.ciphertext.size(), aad.data(), aad.size(),
                                    runtime_key.data(), sealed.nonce.data(), sealed.tag.data()) ||
        runtime_plain != plaintext)
        return 5;

    auto legacy = derive_legacy_body_key(secrets.root, 0x12345678, 4097);
    maya_derive_legacy_body_key(runtime_key.data(), secrets.root.data(), 0x12345678, 4097);
    if (runtime_key != legacy)
        return 9;
    secure_zero(legacy);

    sealed.tag[0] ^= 1;
    maya_derive_sealed_object_key(runtime_key.data(), secrets.root.data(), aad.data(), aad.size());
    if (maya_xchacha20poly1305_open(
            runtime_plain.data(), sealed.ciphertext.data(), sealed.ciphertext.size(), aad.data(),
            aad.size(), runtime_key.data(), sealed.nonce.data(), sealed.tag.data()) == 0)
        return 6;

    for (size_t size = 0; size <= 320; ++size) {
        plaintext.resize(size);
        for (size_t i = 0; i < size; ++i)
            plaintext[i] = uint8_t(i * 37 + size);
        aad.resize(4 + (size * 3) % 109);
        aad[0] = 1;
        aad[1] = 0;
        aad[2] = 0;
        aad[3] = 0;
        for (size_t i = 4; i < aad.size(); ++i)
            aad[i] = uint8_t(i * 11);
        auto nonce = derive_fragment_nonce(seed, 9, size);
        key = derive_sealed_object_key(secrets.root, aad);
        auto item = seal_fragment(plaintext, aad, key, nonce);
        runtime_plain.resize(size);
        maya_derive_sealed_object_key(runtime_key.data(), secrets.root.data(), aad.data(),
                                      aad.size());
        if (maya_xchacha20poly1305_open(runtime_plain.data(), item.ciphertext.data(), size,
                                        aad.data(), aad.size(), runtime_key.data(), nonce.data(),
                                        item.tag.data()) ||
            runtime_plain != plaintext) {
            std::cerr << "interop length failed " << size << " aad=" << aad.size() << "\n";
            return 7;
        }
    }
    try {
        open_fragment(sealed, aad, key);
        return 3;
    } catch (const std::runtime_error&) {
    }
    try {
        parse_seed_hex("bad");
        return 4;
    } catch (const std::runtime_error&) {
    }
    std::cout << "fragment crypto tests passed\n";
}
