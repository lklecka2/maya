#include "core/UpxLayout.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

auto read_u16(const std::vector<uint8_t>& bytes, size_t off) -> uint16_t {
    uint16_t value = 0;
    std::memcpy(&value, bytes.data() + off, sizeof(value));
    return value;
}

auto read_u32(const std::vector<uint8_t>& bytes, size_t off) -> uint32_t {
    uint32_t value = 0;
    std::memcpy(&value, bytes.data() + off, sizeof(value));
    return value;
}

auto read_u64(const std::vector<uint8_t>& bytes, size_t off) -> uint64_t {
    uint64_t value = 0;
    std::memcpy(&value, bytes.data() + off, sizeof(value));
    return value;
}

void write_u16(std::vector<uint8_t>& bytes, size_t off, uint16_t value) {
    std::memcpy(bytes.data() + off, &value, sizeof(value));
}

void write_u32(std::vector<uint8_t>& bytes, size_t off, uint32_t value) {
    std::memcpy(bytes.data() + off, &value, sizeof(value));
}

void write_u64(std::vector<uint8_t>& bytes, size_t off, uint64_t value) {
    std::memcpy(bytes.data() + off, &value, sizeof(value));
}

void write_binary(const std::string& path, const std::vector<uint8_t>& bytes,
                  const std::string& error_message) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error(error_message);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

auto is_little_endian_elf64(const std::vector<uint8_t>& bytes) -> bool {
    return bytes.size() >= 64 &&
           std::memcmp(bytes.data(),
                       "\x7f"
                       "ELF",
                       4) == 0 &&
           bytes[4] == 2 && bytes[5] == 1;
}

void canonicalize_phdr_entry(std::vector<uint8_t>& bytes, uint64_t phoff, uint16_t phentsize,
                             uint16_t phnum) {
    constexpr uint32_t kPtPhdr = 6;
    constexpr uint32_t kPtLoad = 1;
    constexpr uint32_t kPfRead = 4;
    constexpr uint64_t kCanonicalPhOff = 64;

    uint64_t canonical_vaddr = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t off = static_cast<size_t>(phoff + static_cast<uint64_t>(i) * phentsize);
        if (read_u32(bytes, off) != kPtLoad) {
            continue;
        }
        const uint64_t load_off = read_u64(bytes, off + 8);
        const uint64_t load_vaddr = read_u64(bytes, off + 16);
        const uint64_t load_filesz = read_u64(bytes, off + 32);
        if (kCanonicalPhOff >= load_off && kCanonicalPhOff < load_off + load_filesz) {
            canonical_vaddr = load_vaddr + (kCanonicalPhOff - load_off);
            break;
        }
    }
    if (canonical_vaddr == 0) {
        return;
    }

    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t off = static_cast<size_t>(phoff + static_cast<uint64_t>(i) * phentsize);
        if (read_u32(bytes, off) != kPtPhdr) {
            continue;
        }
        const uint64_t table_size = static_cast<uint64_t>(phentsize) * phnum;
        write_u64(bytes, off + 8, kCanonicalPhOff);
        write_u64(bytes, off + 16, canonical_vaddr);
        write_u64(bytes, off + 24, canonical_vaddr);
        write_u64(bytes, off + 32, table_size);
        write_u64(bytes, off + 40, table_size);
        write_u32(bytes, off + 4, kPfRead);
        write_u64(bytes, off + 48, 8);
        return;
    }
}

void normalize_gnu_hash(std::vector<uint8_t>& bytes) {
    constexpr uint32_t kShtDynsym = 11;
    constexpr uint32_t kShtGnuHash = 0x6ffffff6;
    const uint64_t shoff = read_u64(bytes, 0x28);
    const uint16_t shentsize = read_u16(bytes, 0x3a);
    const uint16_t shnum = read_u16(bytes, 0x3c);
    if (shoff == 0 || shentsize == 0 || shnum == 0 ||
        shoff + static_cast<uint64_t>(shentsize) * shnum > bytes.size()) {
        return;
    }

    uint64_t dynsym_size = 0;
    uint64_t dynsym_entsize = 0;
    uint64_t gnu_hash_off = 0;
    uint64_t gnu_hash_size = 0;
    for (uint16_t i = 0; i < shnum; ++i) {
        const size_t off = static_cast<size_t>(shoff + static_cast<uint64_t>(i) * shentsize);
        const uint32_t type = read_u32(bytes, off + 4);
        if (type == kShtDynsym) {
            dynsym_size = read_u64(bytes, off + 32);
            dynsym_entsize = read_u64(bytes, off + 56);
        } else if (type == kShtGnuHash) {
            gnu_hash_off = read_u64(bytes, off + 24);
            gnu_hash_size = read_u64(bytes, off + 32);
        }
    }
    if (dynsym_entsize == 0 || gnu_hash_off == 0 || gnu_hash_size < 16 ||
        gnu_hash_off + gnu_hash_size > bytes.size()) {
        return;
    }

    const uint64_t dynsym_count = dynsym_size / dynsym_entsize;
    const uint32_t symoffset = read_u32(bytes, static_cast<size_t>(gnu_hash_off + 4));
    if (dynsym_count > 1 && symoffset >= dynsym_count) {
        write_u32(bytes, static_cast<size_t>(gnu_hash_off + 4), 1);
    }
}

} // namespace

void maya::compact_upx_program_headers(const std::string& protected_binary_path) {
    std::ifstream in(protected_binary_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to reopen protected binary for UPX header compaction.");
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    if (!is_little_endian_elf64(bytes)) {
        return;
    }

    normalize_gnu_hash(bytes);

    constexpr uint64_t kCanonicalPhOff = 64;
    constexpr uint32_t kPtNote = 4;
    const uint64_t phoff = read_u64(bytes, 0x20);
    const uint16_t phentsize = read_u16(bytes, 0x36);
    const uint16_t phnum = read_u16(bytes, 0x38);
    if (phoff == kCanonicalPhOff || phentsize == 0 || phnum == 0) {
        canonicalize_phdr_entry(bytes, kCanonicalPhOff, phentsize, phnum);
        write_binary(protected_binary_path, bytes, "Failed to write UPX-compatible GNU hash.");
        return;
    }
    if (phoff + static_cast<uint64_t>(phentsize) * phnum > bytes.size()) {
        throw std::runtime_error("Program header table is outside the protected binary.");
    }

    uint64_t first_note_offset = bytes.size();
    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t off = static_cast<size_t>(phoff + static_cast<uint64_t>(i) * phentsize);
        if (read_u32(bytes, off) == kPtNote) {
            first_note_offset = std::min(first_note_offset, read_u64(bytes, off + 8));
        }
    }

    if (first_note_offset <= kCanonicalPhOff) {
        return;
    }
    const uint64_t max_front_headers = (first_note_offset - kCanonicalPhOff) / phentsize;
    if (max_front_headers == 0 || max_front_headers > std::numeric_limits<uint16_t>::max()) {
        return;
    }

    uint64_t required_non_note = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t off = static_cast<size_t>(phoff + static_cast<uint64_t>(i) * phentsize);
        if (read_u32(bytes, off) != kPtNote)
            ++required_non_note;
    }
    // Never discard semantic headers such as PT_TLS, PT_DYNAMIC, or GNU stack/
    // RELRO merely to move the table.  Leave LIEF's valid relocated table in
    // place when only dropping notes cannot make it fit at the front.
    if (required_non_note > max_front_headers) {
        write_binary(protected_binary_path, bytes, "Failed to write normalized protected binary.");
        return;
    }

    std::vector<uint8_t> compacted;
    compacted.reserve(static_cast<size_t>(std::min<uint64_t>(phnum, max_front_headers)) *
                      phentsize);
    uint64_t note_budget = max_front_headers - required_non_note;
    for (uint16_t i = 0; i < phnum; ++i) {
        const size_t off = static_cast<size_t>(phoff + static_cast<uint64_t>(i) * phentsize);
        if (read_u32(bytes, off) == kPtNote) {
            if (note_budget == 0)
                continue;
            --note_budget;
        }
        compacted.insert(compacted.end(), bytes.begin() + off, bytes.begin() + off + phentsize);
    }
    if (compacted.size() / phentsize == 0 || compacted.size() / phentsize >= phnum) {
        return;
    }

    std::fill(bytes.begin() + kCanonicalPhOff, bytes.begin() + first_note_offset, 0);
    std::copy(compacted.begin(), compacted.end(), bytes.begin() + kCanonicalPhOff);
    write_u64(bytes, 0x20, kCanonicalPhOff);
    write_u16(bytes, 0x38, static_cast<uint16_t>(compacted.size() / phentsize));
    canonicalize_phdr_entry(bytes, kCanonicalPhOff, phentsize,
                            static_cast<uint16_t>(compacted.size() / phentsize));

    write_binary(protected_binary_path, bytes, "Failed to write UPX-compatible program headers.");
}
