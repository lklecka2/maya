#include "FragmentCrypto.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mbedtls/chachapoly.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <stdexcept>
#include <string>
#include <sys/random.h>

namespace maya::protection {
namespace {
uint32_t load32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
void store32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++)
        p[i] = uint8_t(v >> (8 * i));
}
uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d = rotl(d ^ a, 16);
    c += d;
    b = rotl(b ^ c, 12);
    a += b;
    d = rotl(d ^ a, 8);
    c += d;
    b = rotl(b ^ c, 7);
}
Seed256 hchacha(const Seed256& key, const uint8_t nonce[16]) {
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; i++)
        x[4 + i] = load32(key.data() + 4 * i);
    for (int i = 0; i < 4; i++)
        x[12 + i] = load32(nonce + 4 * i);
    for (int i = 0; i < 10; i++) {
        qr(x[0], x[4], x[8], x[12]);
        qr(x[1], x[5], x[9], x[13]);
        qr(x[2], x[6], x[10], x[14]);
        qr(x[3], x[7], x[11], x[15]);
        qr(x[0], x[5], x[10], x[15]);
        qr(x[1], x[6], x[11], x[12]);
        qr(x[2], x[7], x[8], x[13]);
        qr(x[3], x[4], x[9], x[14]);
    }
    Seed256 out{};
    int ids[8] = {0, 1, 2, 3, 12, 13, 14, 15};
    for (int i = 0; i < 8; i++)
        store32(out.data() + 4 * i, x[ids[i]]);
    return out;
}
Seed256 hash_label(const Seed256& s, const char* label, uint32_t a = 0, uint32_t b = 0) {
    mbedtls_sha256_context c;
    Seed256 out{};
    mbedtls_sha256_init(&c);
    if (mbedtls_sha256_starts(&c, 0) || mbedtls_sha256_update(&c, s.data(), s.size()) ||
        mbedtls_sha256_update(&c, reinterpret_cast<const uint8_t*>(label), std::strlen(label)) ||
        mbedtls_sha256_update(&c, reinterpret_cast<uint8_t*>(&a), 4) ||
        mbedtls_sha256_update(&c, reinterpret_cast<uint8_t*>(&b), 4) ||
        mbedtls_sha256_finish(&c, out.data())) {
        mbedtls_sha256_free(&c);
        throw std::runtime_error("SHA-256 derivation failed");
    }
    mbedtls_sha256_free(&c);
    return out;
}
} // namespace
Seed256 parse_seed_hex(const std::string& v) {
    if (v.size() != 64)
        throw std::runtime_error("--seed requires exactly 64 hexadecimal characters");
    Seed256 s{};
    auto n = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; i++) {
        int h = n(v[2 * i]), l = n(v[2 * i + 1]);
        if (h < 0 || l < 0)
            throw std::runtime_error("--seed contains a non-hexadecimal character");
        s[i] = uint8_t(h << 4 | l);
    }
    return s;
}
Seed256 random_seed() {
    Seed256 s{};
    size_t o = 0;
    while (o < s.size()) {
        ssize_t n = getrandom(s.data() + o, s.size() - o, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            throw std::runtime_error("OS getrandom failed");
        o += size_t(n);
    }
    return s;
}
BuildSecrets derive_build_secrets(const Seed256& s) {
    return {hash_label(s, "maya-build-root-v1"), hash_label(s, "maya-binary-salt-v1")};
}
Seed256 sha256_bytes(const std::vector<uint8_t>& v) {
    Seed256 out{};
    if (mbedtls_sha256(v.data(), v.size(), out.data(), 0))
        throw std::runtime_error("SHA-256 failed");
    return out;
}
Seed256 hmac_sha256(const Seed256& key, const std::vector<uint8_t>& bytes) {
    Seed256 out{};
    const auto* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr ||
        mbedtls_md_hmac(info, key.data(), key.size(), bytes.data(), bytes.size(), out.data()))
        throw std::runtime_error("HMAC-SHA256 failed");
    return out;
}
Seed256 hkdf_sha256(const Seed256& input, const std::vector<uint8_t>& salt,
                    const std::vector<uint8_t>& info) {
    Seed256 salt_key{};
    if (!salt.empty()) {
        if (salt.size() == salt_key.size())
            std::copy(salt.begin(), salt.end(), salt_key.begin());
        else
            salt_key = sha256_bytes(salt);
    }
    const auto prk = hmac_sha256(salt_key, std::vector<uint8_t>(input.begin(), input.end()));
    std::vector<uint8_t> expand = info;
    expand.push_back(1);
    return hmac_sha256(prk, expand);
}
Seed256 derive_domain_key(const Seed256& root, KeyDomain domain,
                          const std::vector<uint8_t>& context) {
    std::vector<uint8_t> info = {'m', 'a', 'y', 'a', '-', 'd', 'o',
                                 'm', 'a', 'i', 'n', '-', 'v', '1'};
    const auto value = static_cast<uint32_t>(domain);
    for (unsigned i = 0; i < 4; ++i)
        info.push_back(uint8_t(value >> (8 * i)));
    return hkdf_sha256(root, context, info);
}
Seed256 derive_sealed_object_key(const Seed256& root, const std::vector<uint8_t>& aad) {
    if (aad.size() < 4)
        throw std::invalid_argument("sealed object AAD lacks a key-domain tag");
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= uint32_t(aad[i]) << (8 * i);
    const auto domain = static_cast<KeyDomain>(value);
    if (domain != KeyDomain::Fragment && domain != KeyDomain::Variant)
        throw std::invalid_argument("sealed object AAD has an unsupported key domain");
    return derive_domain_key(root, domain, aad);
}
Seed256 derive_legacy_body_key(const Seed256& root, uint64_t address, uint64_t size) {
    std::vector<uint8_t> info = {'m', 'a', 'y', 'a', '-', 'l', 'e', 'g', 'a', 'c',
                                 'y', '-', 'b', 'o', 'd', 'y', '-', 'v', '1'};
    for (unsigned i = 0; i < 8; ++i)
        info.push_back(uint8_t(address >> (8 * i)));
    for (unsigned i = 0; i < 8; ++i)
        info.push_back(uint8_t(size >> (8 * i)));
    return hkdf_sha256(root, {}, info);
}
void secure_zero(Seed256& value) {
    volatile uint8_t* bytes = value.data();
    for (size_t i = 0; i < value.size(); ++i)
        bytes[i] = 0;
    std::atomic_signal_fence(std::memory_order_seq_cst);
}
std::array<uint8_t, 24> derive_fragment_nonce(const Seed256& s, uint32_t f, uint32_t g) {
    auto h = hash_label(s, "maya-fragment-nonce-v1", f, g);
    std::array<uint8_t, 24> n{};
    std::copy_n(h.begin(), 24, n.begin());
    return n;
}
SealedFragment seal_fragment(const std::vector<uint8_t>& p, const std::vector<uint8_t>& aad,
                             const Seed256& k, const std::array<uint8_t, 24>& n) {
    SealedFragment z;
    z.nonce = n;
    z.ciphertext.resize(p.size());
    auto sub = hchacha(k, n.data());
    uint8_t nonce12[12] = {};
    std::copy(n.begin() + 16, n.end(), nonce12 + 4);
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    int rc = mbedtls_chachapoly_setkey(&c, sub.data());
    if (!rc)
        rc = mbedtls_chachapoly_encrypt_and_tag(&c, p.size(), nonce12, aad.data(), aad.size(),
                                                p.data(), z.ciphertext.data(), z.tag.data());
    mbedtls_chachapoly_free(&c);
    if (rc)
        throw std::runtime_error("XChaCha20-Poly1305 encryption failed");
    return z;
}
std::vector<uint8_t> open_fragment(const SealedFragment& z, const std::vector<uint8_t>& aad,
                                   const Seed256& k) {
    std::vector<uint8_t> p(z.ciphertext.size());
    auto sub = hchacha(k, z.nonce.data());
    uint8_t nonce12[12] = {};
    std::copy(z.nonce.begin() + 16, z.nonce.end(), nonce12 + 4);
    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    int rc = mbedtls_chachapoly_setkey(&c, sub.data());
    if (!rc)
        rc = mbedtls_chachapoly_auth_decrypt(&c, p.size(), nonce12, aad.data(), aad.size(),
                                             z.tag.data(), z.ciphertext.data(), p.data());
    mbedtls_chachapoly_free(&c);
    if (rc)
        throw std::runtime_error("XChaCha20-Poly1305 authentication failed");
    return p;
}
} // namespace maya::protection
