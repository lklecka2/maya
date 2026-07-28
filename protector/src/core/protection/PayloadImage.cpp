#include "PayloadImage.hpp"

#include <LIEF/ELF.hpp>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

#include "CodeRelocation.hpp"
#include "FragmentCrypto.hpp"
#include "FragmentImage.hpp"
#include "NativeVariants.hpp"
#include "RuntimeStubs.hpp"
#include "V3Vm.hpp"
#include "core/Logger.hpp"
#include "core/RuntimeSchema.hpp"
#include "core/Utils.hpp"
#include "maya_runtime_blob.hpp"

namespace maya::protection {

std::string digest_hex(const std::vector<uint8_t>& bytes) {
    const auto digest = sha256_bytes(bytes);
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : digest)
        stream << std::setw(2) << static_cast<unsigned>(byte);
    return stream.str();
}

void write_at(std::vector<uint8_t>& payload, const PayloadLayout& layout, uint64_t vaddr,
              const std::vector<uint8_t>& bytes) {
    const uint64_t off = vaddr - layout.base_vaddr;
    if (off + bytes.size() > payload.size()) {
        throw std::runtime_error("Payload write out of bounds.");
    }
    std::copy(bytes.begin(), bytes.end(), payload.begin() + off);
}

void write_u64(std::vector<uint8_t>& payload, const PayloadLayout& layout, uint64_t vaddr,
               uint64_t value) {
    const uint64_t off = vaddr - layout.base_vaddr;
    if (off + sizeof(value) > payload.size()) {
        throw std::runtime_error("Payload write out of bounds.");
    }
    std::memcpy(payload.data() + off, &value, sizeof(value));
}

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& bytes, const Seed256& root,
                             uint64_t original_address) {
    std::vector<uint8_t> out = bytes;
    auto key = derive_legacy_body_key(root, original_address, bytes.size());
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] ^= key[i & 31u];
    }
    secure_zero(key);
    return out;
}

std::vector<uint8_t> encode_callsite_meta(const std::vector<CallsiteMetadata>& callsites) {
    std::vector<uint8_t> bytes;
    bytes.reserve(callsites.size() * 32);
    auto append32 = [&](uint32_t value) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
        bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
    };
    auto append64 = [&](uint64_t value) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
        bytes.insert(bytes.end(), ptr, ptr + sizeof(value));
    };
    for (const auto& meta : callsites) {
        append32(meta.caller_func_id);
        append32(meta.callee_func_id);
        append64(meta.original_pc);
        append64(meta.original_return_pc);
        append32(meta.flags);
        append32(meta.reserved);
    }
    return bytes;
}

void emit_payload(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs,
                  const PayloadLayout& layout, const std::vector<CallsiteMetadata>& callsites,
                  std::vector<uint8_t>& payload) {
    (void)ctx;
    write_at(payload, layout, layout.return_stub_vaddr,
             make_return_stub(layout, ctx.runtime_features.slot_strategy));
    write_at(payload, layout, layout.build_root_vaddr,
             std::vector<uint8_t>(ctx.build_root.begin(), ctx.build_root.end()));
    if (maya_runtime_blob_len > kFragmentRuntimeCapacity)
        throw std::runtime_error("Source-built fragment runtime exceeds reserved RX capacity");
    write_at(payload, layout, layout.fragment_runtime_vaddr,
             std::vector<uint8_t>(maya_runtime_blob, maya_runtime_blob + maya_runtime_blob_len));

    for (const auto& func : funcs) {
        write_at(payload, layout, func.stub_vaddr,
                 func.fde_bytes.empty() ? make_entry_stub(func, layout, ctx)
                                        : make_eh_entry_stub(func, layout, ctx));
        if (func.eh_normal_cleanup_vaddr != 0 &&
            func.selected_backend == SelectedBackend::Fragment) {
            write_at(payload, layout, func.eh_normal_cleanup_vaddr,
                     make_eh_cleanup_stub(func, layout));
        }
        for (const auto& thunk : func.interior_thunks) {
            write_at(payload, layout, thunk.thunk_vaddr, make_interior_thunk(func, thunk));
        }
        if (!func.cfg_execution_enabled) {
            write_at(payload, layout, func.enc_vaddr,
                     func.selected_backend == SelectedBackend::Fragment
                         ? func.fragment_ciphertext
                         : encrypt(func.patched_bytes, ctx.build_root, func.original_start));
        }
        if (func.selected_backend == SelectedBackend::Fragment && !func.cfg_execution_enabled) {
            write_at(payload, layout, func.fragment_nonce_vaddr,
                     std::vector<uint8_t>(func.fragment_nonce.begin(), func.fragment_nonce.end()));
            write_at(payload, layout, func.fragment_tag_vaddr,
                     std::vector<uint8_t>(func.fragment_tag.begin(), func.fragment_tag.end()));
            write_at(payload, layout, func.fragment_aad_vaddr, func.fragment_aad);
        }
        if (func.selected_backend == SelectedBackend::Fragment) {
            for (const auto& fragment : func.fragments) {
                write_at(payload, layout, fragment.ciphertext_vaddr, fragment.ciphertext);
                write_at(payload, layout, fragment.nonce_vaddr,
                         std::vector<uint8_t>(fragment.nonce.begin(), fragment.nonce.end()));
                write_at(payload, layout, fragment.tag_vaddr,
                         std::vector<uint8_t>(fragment.tag.begin(), fragment.tag.end()));
                write_at(payload, layout, fragment.aad_vaddr, fragment.aad);
                for (const auto& variant : fragment.variants) {
                    write_at(payload, layout, variant.ciphertext_vaddr, variant.ciphertext);
                    write_at(payload, layout, variant.nonce_vaddr,
                             std::vector<uint8_t>(variant.nonce.begin(), variant.nonce.end()));
                    write_at(payload, layout, variant.tag_vaddr,
                             std::vector<uint8_t>(variant.tag.begin(), variant.tag.end()));
                    write_at(payload, layout, variant.aad_vaddr, variant.aad);
                }
                if (!fragment.vm_ciphertext.empty()) {
                    if (fragment.vm_ciphertext.size() > fragment.vm_storage_capacity ||
                        fragment.vm_aad.size() > kFragmentAadSize)
                        throw std::runtime_error(
                            "V3 VM exceeded its reserved authenticated storage");
                    write_at(payload, layout, fragment.vm_ciphertext_vaddr, fragment.vm_ciphertext);
                    write_at(
                        payload, layout, fragment.vm_nonce_vaddr,
                        std::vector<uint8_t>(fragment.vm_nonce.begin(), fragment.vm_nonce.end()));
                    write_at(payload, layout, fragment.vm_tag_vaddr,
                             std::vector<uint8_t>(fragment.vm_tag.begin(), fragment.vm_tag.end()));
                    write_at(payload, layout, fragment.vm_aad_vaddr, fragment.vm_aad);
                }
            }
        }
        if (!func.metadata_shard.empty()) {
            if (func.metadata_shard.size() > func.metadata_shard_capacity)
                throw std::runtime_error("Controllet metadata shard exceeds derived capacity");
            write_at(payload, layout, func.metadata_shard_vaddr, func.metadata_shard);
        }
        if (!func.v3_shard_envelope.empty()) {
            if (func.v3_shard_envelope.size() > func.v3_shard_capacity)
                throw std::runtime_error("V3 metadata shard exceeds reserved capacity");
            write_at(payload, layout, func.v3_shard_vaddr, func.v3_shard_envelope);
        }
        if (!func.fde_bytes.empty()) {
            if (func.eh_registration_vaddr != 0) {
                write_at(payload, layout, func.eh_registration_vaddr, func.cie_bytes);
            }
            write_at(payload, layout, func.fde_vaddr, func.fde_bytes);
        }
        write_u64(payload, layout, func.active_vaddr, 0);
    }

    auto meta = encode_callsite_meta(callsites);
    if (!meta.empty()) {
        if (layout.callsite_meta_vaddr + meta.size() > layout.thread_states_vaddr) {
            throw std::runtime_error("Callsite metadata exceeded reserved layout space.");
        }
        write_at(payload, layout, layout.callsite_meta_vaddr, meta);
        Log::info("Recorded " + std::to_string(callsites.size()) +
                  " protected direct-call metadata entries.");
    }
    const std::vector<ProtectedFunction> no_global_semantics;
    auto image = make_fragment_image(no_global_semantics, maya_runtime_blob_len);
    auto descriptors = serialize_fragment_image(image);
    if (descriptors.size() > kFragmentDescriptorCapacity)
        throw std::runtime_error("Fragment descriptors exceed reserved RO capacity");
    (void)parse_fragment_image(descriptors);
    write_at(payload, layout, layout.fragment_descriptor_vaddr, descriptors);
}

void add_payload_segment(ProtectionContext& ctx, const PayloadLayout& layout,
                         const std::vector<uint8_t>& payload) {
    if (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator) {
        struct Part {
            uint64_t begin, end;
            bool writable, executable;
            const char* name;
        };
        const Part parts[] = {
            {layout.base_vaddr, layout.rx_end_vaddr, false, true, "payload RX"},
            {layout.ro_start_vaddr, layout.ro_end_vaddr, false, false, "payload RO"},
            {layout.rw_start_vaddr, layout.base_vaddr + layout.total_size, true, false,
             "payload RW"},
        };
        uint64_t prior_mapped_size = 0;
        std::vector<LIEF::ELF::Segment*> static_pie_slots;
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> static_pie_properties;
        if (ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable) {
            for (const auto& segment : ctx.binary->segments()) {
                if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD)
                    continue;
                const std::vector<uint8_t> original(segment.content().begin(),
                                                    segment.content().end());
                if (segment.file_offset() == 0 &&
                    original.size() > 64 + ctx.binary->segments().size() * 56) {
                    const size_t phdr_end = 64 + ctx.binary->segments().size() * 56;
                    ctx.deferred_file_writes.emplace_back(
                        0, std::vector<uint8_t>(original.begin(), original.begin() + 64));
                    ctx.deferred_file_writes.emplace_back(
                        phdr_end,
                        std::vector<uint8_t>(original.begin() + phdr_end, original.end()));
                } else {
                    ctx.deferred_file_writes.emplace_back(segment.file_offset(), original);
                }
            }
            for (auto& segment : ctx.binary->segments()) {
                if (segment.type() == LIEF::ELF::Segment::TYPE::NOTE)
                    static_pie_slots.push_back(&segment);
            }
            // A GNU_PROPERTY program header commonly aliases one of the reusable
            // PT_NOTE byte ranges. Preserve that semantic view after LIEF has
            // repurposed the NOTE header for a payload LOAD segment.
            for (const auto& segment : ctx.binary->segments()) {
                if (segment.type() == LIEF::ELF::Segment::TYPE::GNU_PROPERTY) {
                    static_pie_properties.emplace_back(
                        segment.file_offset(),
                        std::vector<uint8_t>(segment.content().begin(), segment.content().end()));
                }
            }
            if (static_pie_slots.size() < 3)
                throw std::runtime_error("Static PIE payload PT_NOTE slots disappeared.");
        }
        size_t part_index = 0;
        for (const auto& part : parts) {
            if (part.end <= part.begin)
                continue;
            const size_t off = static_cast<size_t>(part.begin - layout.base_vaddr);
            const size_t size = static_cast<size_t>(part.end - part.begin);
            std::vector<uint8_t> bytes(payload.begin() + off, payload.begin() + off + size);
            LIEF::ELF::Segment segment;
            segment.type(LIEF::ELF::Segment::TYPE::LOAD);
            segment.content(bytes);
            segment.add(LIEF::ELF::Segment::FLAGS::R);
            if (part.writable)
                segment.add(LIEF::ELF::Segment::FLAGS::W);
            if (part.executable)
                segment.add(LIEF::ELF::Segment::FLAGS::X);
            const bool pie = ctx.runtime_features.binary_kind == BinaryKind::DynamicPieExecutable ||
                             ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable;
            const uint64_t requested =
                part.begin - ctx.segment_request_bias - (pie ? prior_mapped_size : 0);
            segment.virtual_address(requested);
            segment.physical_address(requested);
            segment.virtual_size(bytes.size());
            segment.alignment(kPageSize);
            LIEF::ELF::Segment* added = nullptr;
            if (ctx.runtime_features.binary_kind == BinaryKind::StaticPieExecutable) {
                added = static_pie_slots[part_index++];
                ctx.deferred_file_writes.emplace_back(
                    added->file_offset(),
                    std::vector<uint8_t>(added->content().begin(), added->content().end()));
                added->type(LIEF::ELF::Segment::TYPE::LOAD);
                added->content(bytes);
                added->clear_flags();
                added->add(LIEF::ELF::Segment::FLAGS::R);
                if (part.writable)
                    added->add(LIEF::ELF::Segment::FLAGS::W);
                if (part.executable)
                    added->add(LIEF::ELF::Segment::FLAGS::X);
                added->virtual_address(part.begin);
                added->physical_address(part.begin);
                const uint64_t static_pie_file_offset = part.begin;
                added->file_offset(static_pie_file_offset);
                added->physical_size(bytes.size());
                added->virtual_size(bytes.size());
                added->alignment(kSegmentAlign);
                ctx.deferred_file_writes.emplace_back(static_pie_file_offset, bytes);
            } else {
                added = ctx.binary->add(segment, requested);
            }
            if (added != nullptr && ctx.options.verbose) {
                Log::info(std::string("  segment ") + part.name + " requested=" + hex(requested) +
                          " assigned=" + hex(part.begin) +
                          " actual=" + hex(added->virtual_address()));
            }
            if (added == nullptr || added->virtual_address() != part.begin) {
                throw std::runtime_error(
                    std::string("Failed to add ") + part.name +
                    " segment at assigned address expected=" + hex(part.begin) + " actual=" +
                    (added == nullptr ? std::string("null") : hex(added->virtual_address())));
            }
            prior_mapped_size += part.end - part.begin;
        }
        ctx.deferred_file_writes.insert(ctx.deferred_file_writes.end(),
                                        static_pie_properties.begin(), static_pie_properties.end());
        return;
    }
    LIEF::ELF::Segment segment;
    segment.type(LIEF::ELF::Segment::TYPE::LOAD);
    segment.content(payload);
    segment.add(LIEF::ELF::Segment::FLAGS::R);
    segment.add(LIEF::ELF::Segment::FLAGS::W);
    segment.add(LIEF::ELF::Segment::FLAGS::X);
    const uint64_t requested_vaddr = layout.base_vaddr - ctx.segment_request_bias;
    segment.virtual_address(requested_vaddr);
    segment.physical_address(requested_vaddr);
    segment.virtual_size(payload.size());
    segment.alignment(kSegmentAlign);

    auto* added = ctx.binary->add(segment, requested_vaddr);
    if (added == nullptr) {
        throw std::runtime_error("Failed to add Maya payload segment.");
    }
    if (added->virtual_address() != layout.base_vaddr) {
        throw std::runtime_error("Maya payload segment placed at unexpected address. expected=" +
                                 hex(layout.base_vaddr) +
                                 " actual=" + hex(added->virtual_address()));
    }
}

namespace {
void add_typed_segment(ProtectionContext& ctx, uint64_t requested,
                       const std::vector<uint8_t>& bytes, bool writable, bool executable,
                       const char* label) {
    LIEF::ELF::Segment segment;
    segment.type(LIEF::ELF::Segment::TYPE::LOAD);
    segment.content(bytes);
    segment.add(LIEF::ELF::Segment::FLAGS::R);
    if (writable)
        segment.add(LIEF::ELF::Segment::FLAGS::W);
    if (executable)
        segment.add(LIEF::ELF::Segment::FLAGS::X);
    segment.virtual_address(requested);
    segment.physical_address(requested);
    segment.virtual_size(bytes.size());
    segment.alignment(kPageSize);
    auto* added = ctx.binary->add(segment, requested);
    if (added == nullptr)
        throw std::runtime_error(std::string("Failed to add fragment ") + label + " segment");
}
} // namespace

void add_fragment_metadata_segments(ProtectionContext& ctx, const PayloadLayout& layout,
                                    const std::vector<ProtectedFunction>& funcs) {
    const std::vector<uint8_t> runtime(maya_runtime_blob,
                                       maya_runtime_blob + maya_runtime_blob_len);
    auto image = make_fragment_image(funcs, runtime.size());
    auto descriptors = serialize_fragment_image(image);
    (void)parse_fragment_image(descriptors);
    const uint64_t rx = layout.fragment_runtime_vaddr;
    const uint64_t ro = Utils::align_to(rx + runtime.size(), kSegmentAlign);
    const uint64_t rw = Utils::align_to(ro + descriptors.size(), kSegmentAlign);
    add_typed_segment(ctx, rx, runtime, false, true, "RX runtime");
    add_typed_segment(ctx, ro, descriptors, false, false, "RO descriptors");
    add_typed_segment(ctx, rw, std::vector<uint8_t>(kPageSize, 0), true, false, "RW state");
}

void patch_original_entries(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs) {
    auto* text = ctx.binary->get_section(".text");
    if (text == nullptr) {
        throw std::runtime_error("Missing .text section.");
    }
    auto content = text->content();
    std::vector<uint8_t> buffer(content.begin(), content.end());
    const uint64_t text_start = text->virtual_address();
    const uint64_t text_end = text_start + buffer.size();

    for (const auto& func : funcs) {
        if (func.original_start < text_start || func.original_start + func.size > text_end) {
            throw std::runtime_error("Protected function is not fully contained in .text: " +
                                     func.name);
        }
        const size_t off = static_cast<size_t>(func.original_start - text_start);
        std::fill(buffer.begin() + off, buffer.begin() + off + func.size, 0x00);
        for (size_t i = 0; i + 4 <= func.size; i += 4) {
            const uint32_t brk = 0xD4200000u;
            std::memcpy(buffer.data() + off + i, &brk, sizeof(brk));
        }
        const uint32_t branch =
            make_b(func.original_start + ctx.final_image_shift, func.stub_vaddr);
        std::memcpy(buffer.data() + off, &branch, sizeof(branch));
    }

    text->content(buffer);

    for (auto& segment : ctx.binary->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) {
            continue;
        }
        const uint64_t seg_start = segment.virtual_address();
        const uint64_t seg_end = seg_start + segment.virtual_size();
        if (text_start < seg_start || text_end > seg_end) {
            continue;
        }
        auto seg_content = segment.content();
        std::vector<uint8_t> seg_buffer(seg_content.begin(), seg_content.end());
        const uint64_t text_off = text_start - seg_start;
        if (text_off + buffer.size() <= seg_buffer.size()) {
            std::copy(buffer.begin(), buffer.end(), seg_buffer.begin() + text_off);
            segment.content(seg_buffer);
        }
        break;
    }
}

void verify_plaintext_removed(ProtectionContext& ctx, std::vector<ProtectedFunction>& funcs,
                              const std::vector<uint8_t>& payload) {
    auto* text = ctx.binary->get_section(".text");
    if (text == nullptr) {
        return;
    }
    auto text_content = text->content();
    std::vector<uint8_t> text_bytes(text_content.begin(), text_content.end());
    const uint64_t text_start = text->virtual_address();
    for (auto& func : funcs) {
        const uint64_t patched_start = func.original_start + ctx.final_image_shift;
        if (patched_start >= text_start &&
            patched_start + std::min<uint64_t>(func.size, 4) <= text_start + text_bytes.size()) {
            const size_t site_off = static_cast<size_t>(patched_start - text_start);
            if (func.original_bytes.size() >= 4 && site_off + 4 <= text_bytes.size() &&
                !std::equal(func.original_bytes.begin(), func.original_bytes.begin() + 4,
                            text_bytes.begin() + site_off)) {
                func.original_site_patched = true;
            }
        }
        if (!func.original_site_patched) {
            throw std::runtime_error("Original function site was not patched for " + func.name);
        }
        if (func.original_bytes.size() < 16) {
            continue;
        }
        const auto needle_begin = func.original_bytes.begin();
        const auto needle_end =
            func.original_bytes.begin() + std::min<size_t>(func.original_bytes.size(), 32);
        const auto text_match =
            std::search(text_bytes.begin(), text_bytes.end(), needle_begin, needle_end);
        if (text_match != text_bytes.end()) {
            const auto match_vaddr =
                text_start + static_cast<uint64_t>(std::distance(text_bytes.begin(), text_match));
            if (match_vaddr >= patched_start && match_vaddr < patched_start + func.size) {
                throw std::runtime_error("Plaintext body prefix still present in .text for " +
                                         func.name);
            }
        }
        if (std::search(payload.begin(), payload.end(), needle_begin, needle_end) !=
            payload.end()) {
            throw std::runtime_error("Plaintext body prefix present in Maya payload for " +
                                     func.name);
        }
        func.plaintext_verified = text_match == text_bytes.end();
    }
}

void write_report(ProtectionContext& ctx, const std::vector<ProtectedFunction>& funcs,
                  const std::vector<CallsiteMetadata>& callsites) {
    const std::string path = ctx.options.report_filename.empty() ? ctx.filename + ".protection.tsv"
                                                                 : ctx.options.report_filename;
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("Failed to write protection report: " + path);
    }
    out << "feature_record\tkey\tvalue\n";
    const bool v3 = ctx.options.profile == ProtectionProfile::ExperimentalV3;
    const bool variant_runtime_active =
        std::any_of(funcs.begin(), funcs.end(), [](const auto& func) {
            return std::any_of(func.fragments.begin(), func.fragments.end(),
                               [](const auto& fragment) { return !fragment.variants.empty(); });
        });
    size_t vm_program_count = 0;
    for (const auto& func : funcs)
        for (const auto& fragment : func.fragments)
            if (!fragment.vm_ciphertext.empty())
                ++vm_program_count;
    const bool vm_runtime_active = vm_program_count != 0;
    size_t protected_count = 0, fragment_count = 0, capability_count = 0;
    size_t fallback_count = 0, rejection_count = 0, native_variant_count = 0;
    size_t eh_metadata_count = 0, gateway_count = 0, edge_count = 0, adapter_count = 0,
           shard_count = 0;
    uint64_t gateway_bytes = 0, fragment_storage_bytes = 0, shard_bytes = 0;
    uint64_t vm_storage_bytes = 0, eh_storage_bytes = 0, variant_storage_bytes = 0;
    std::set<uint32_t> shard_families, gateway_abi_families;
    std::set<std::string> native_variant_families;
    std::vector<uint8_t> vm_digest_material, shard_digest_material;
    std::vector<uint8_t> gateway_digest_material, variant_digest_material;
    auto append_u64 = [](std::vector<uint8_t>& bytes, uint64_t value) {
        for (unsigned index = 0; index < 8; ++index)
            bytes.push_back(static_cast<uint8_t>(value >> (index * 8)));
    };
    for (const auto& func : funcs) {
        if (func.final_outcome == FinalOutcome::Protected) {
            ++protected_count;
            if (func.selected_backend != SelectedBackend::Fragment)
                ++fallback_count;
        } else if (func.final_outcome == FinalOutcome::Rejected)
            ++rejection_count;
        fragment_count += func.fragments.size();
        if (func.cfg_execution_enabled) {
            ++gateway_count;
            ++adapter_count;
            ++shard_count;
            edge_count += func.control_edges.size();
            gateway_bytes += entry_stub_size(func);
            capability_count += func.v3_control_enabled ? func.v3_capability_count : 0;
            shard_families.insert(func.v3_control_enabled ? func.v3_shard_family
                                                          : func.controllet_family);
            gateway_abi_families.insert(func.v3_control_enabled ? func.v3_gateway_abi_family : 0);
            append_u64(gateway_digest_material, func.v3_event_gateway_offset);
            append_u64(gateway_digest_material,
                       func.v3_control_enabled ? func.v3_gateway_abi_family : 0);
            append_u64(gateway_digest_material,
                       func.v3_control_enabled ? func.v3_function_handle : func.event_cookie);
        }
        shard_digest_material.insert(shard_digest_material.end(), func.metadata_shard.begin(),
                                     func.metadata_shard.end());
        shard_digest_material.insert(shard_digest_material.end(), func.v3_shard_envelope.begin(),
                                     func.v3_shard_envelope.end());
        if (func.selected_backend == SelectedBackend::Fragment && !func.fde_bytes.empty())
            ++eh_metadata_count;
        if (func.selected_backend == SelectedBackend::Fragment && !func.fde_bytes.empty())
            eh_storage_bytes +=
                func.cie_bytes.size() + func.fde_bytes.size() + func.eh_metadata.lsda_bytes.size();
        shard_bytes += func.metadata_shard.size() + func.v3_shard_envelope.size();
        for (const auto& fragment : func.fragments) {
            fragment_storage_bytes += fragment.storage_size + fragment.nonce.size() +
                                      fragment.tag.size() + kFragmentAadSize;
            vm_storage_bytes += fragment.vm_storage_capacity
                                    ? fragment.vm_storage_capacity + fragment.vm_nonce.size() +
                                          fragment.vm_tag.size() + kFragmentAadSize
                                    : 0;
            vm_digest_material.insert(vm_digest_material.end(), fragment.vm_ciphertext.begin(),
                                      fragment.vm_ciphertext.end());
            for (const auto& variant : fragment.variants) {
                ++native_variant_count;
                native_variant_families.insert(variant.transformation);
                variant_digest_material.insert(variant_digest_material.end(),
                                               variant.ciphertext.begin(),
                                               variant.ciphertext.end());
                variant_storage_bytes += fragment.storage_size + variant.nonce.size() +
                                         variant.tag.size() + kFragmentAadSize;
            }
        }
    }
    ctx.summary.protected_functions = protected_count;
    ctx.summary.fragments = fragment_count;
    ctx.summary.fallbacks = fallback_count;
    ctx.summary.rejections = rejection_count;
    ctx.summary.native_variants = native_variant_count;

    out << "feature_record\treport_schema_version\t6\n";
    out << "feature_record\toperation\t"
        << (ctx.options.command == CliCommand::Analyze ? "analyze-only" : "protect") << "\n";
    out << "feature_record\tprofile\t"
        << (ctx.options.profile == ProtectionProfile::ExperimentalV3 ? "experimental-v3"
                                                                     : "standard")
        << "\n";
    out << "feature_record\trequested_backend\t";
    switch (ctx.options.backend_policy) {
    case BackendPolicy::Auto:
        out << "auto";
        break;
    case BackendPolicy::FragmentsOnly:
        out << "fragments-only";
        break;
    case BackendPolicy::Compatibility:
        out << "compatibility";
        break;
    }
    out << "\n";
    out << "feature_record\tdiscovered_function_candidates\t" << ctx.discovered_function_count
        << "\n";
    out << "feature_record\tautomatic_roots\t" << ctx.automatic_root_count << "\n";
    out << "feature_record\tbinary_kind\t"
        << maya::binary_kind_name(ctx.runtime_features.binary_kind) << "\n";
    out << "feature_record\tslot_strategy\t"
        << maya::slot_strategy_name(ctx.runtime_features.slot_strategy) << "\n";
    out << "feature_record\tcpp_eh_frame\t" << (ctx.runtime_features.has_eh_frame ? "yes" : "no")
        << "\n";
    out << "feature_record\tcpp_except_table\t"
        << (ctx.runtime_features.has_gcc_except_table ? "yes" : "no") << "\n";
    out << "feature_record\tcpp_eh_protected\t"
        << (ctx.runtime_features.has_gcc_except_table && ctx.runtime_features.has_cpp_personality
                ? "yes"
                : "no")
        << "\n";
    out << "feature_record\teh_forced_unwind_or_cancellation\t"
        << (ctx.runtime_features.has_forced_unwind_or_cancellation ? "detected" : "not-detected")
        << "\n";
    out << "feature_record\teh_unsupported_policy\t"
        << (ctx.runtime_features.has_forced_unwind_or_cancellation
                ? (ctx.options.execution_mode == ExecutionMode::Legacy
                       ? "auto-fixed-slot-protected-fallback"
                       : "fragment-required-exact-rejection")
                : "not-applicable")
        << "\n";
    const size_t fragment_eh_count =
        std::count_if(funcs.begin(), funcs.end(), [](const auto& func) {
            return func.selected_backend == SelectedBackend::Fragment && !func.fde_bytes.empty() &&
                   func.eh_normal_cleanup_vaddr != 0;
        });
    out << "feature_record\teh_schema_version\t" << (v3 ? 1 : (fragment_eh_count ? 1 : 0)) << "\n";
    out << "feature_record\tfragment_native_eh_runtime_active\t"
        << (fragment_eh_count ? "yes" : "no") << "\n";
    out << "feature_record\teh_registration_policy\t"
        << (fragment_eh_count ? "loader-owned-relocated-fde-before-launch" : "inactive") << "\n";
    out << "feature_record\teh_cleanup_policy\t"
        << (fragment_eh_count ? "refcounted-normal-unwind-throw-rx-rw-wipe-rx" : "inactive")
        << "\n";
    out << "feature_record\tupx_compatible_layout\t"
        << (ctx.runtime_features.upx_compatible_layout ? "yes" : "no") << "\n";
    out << "feature_record\tslot_storage\t"
        << (ctx.runtime_features.slot_strategy == SlotStrategy::RuntimeAllocator
                ? "runtime-arena"
                : "payload-fixed-address")
        << "\n";
    out << "feature_record\tfragment_image_version\t" << kFragmentImageVersion << "\n";
    out << "feature_record\tdescriptor_version\t" << kDescriptorVersion << "\n";
    out << "feature_record\tstate_contract_version\t" << kStateContractVersion << "\n";
    out << "feature_record\tcontinuation_contract_version\t" << kContinuationContractVersion
        << "\n";
    out << "feature_record\tfault_contract_version\t" << kFaultContractVersion << "\n";
    out << "feature_record\tstate_binding\tthread-epoch-path-frame-continuation-checkpoint\n";
    out << "feature_record\ttransition_policy\tprivate-prepare-retire-auth-rx-sync-release-publish-"
           "launch\n";
    out << "feature_record\tcontrol_token_encoding\t"
        << (v3 ? "opaque-128-state-bound-hmac256" : "state-bound-v2-controllets") << "\n";
    out << "feature_record\tnucleus_abi_version\t1\n";
    out << "feature_record\tcontrollet_contract_version\t1\n";
    out << "feature_record\tcluster_selection\tseed-stable-rotated-7\n";
    out << "feature_record\tresolver_families\t3\n";
    out << "feature_record\tgateway_families\t3\n";
    out << "feature_record\tgateway_abi_families\t" << (v3 ? 4 : 1) << "\n";
    out << "feature_record\tmetadata_sharding\t"
        << (v3 ? "v3-aead-opaque-multi-family" : "per-cluster-authenticated-aad") << "\n";
    out << "feature_record\tkey_schedule_families\t"
        << (v3 ? "hkdf-sha256-domain-separated" : "3-domain-separated") << "\n";
    out << "feature_record\tbuild_secret_storage\tsingle-ro-build-root\n";
    out << "feature_record\tsealed_object_keys\thkdf-sha256-aad-derived-use-wipe\n";
    out << "feature_record\tlegacy_body_keys\thkdf-sha256-address-size-derived-use-wipe\n";
    out << "feature_record\tnative_variants\t"
        << (ctx.options.native_variants ? "enabled" : "disabled") << "\n";
    out << "feature_record\tnative_variant_schema_version\t"
        << (v3 ? kNativeVariantSchemaVersion
               : (ctx.options.native_variants ? kNativeVariantSchemaVersion : 0))
        << "\n";
    out << "feature_record\tnative_variant_runtime_active\t"
        << (variant_runtime_active ? "yes" : "no") << "\n";
    out << "feature_record\truntime_vm_schema_version\t"
        << (v3 ? kV3VmSchemaVersion : (vm_runtime_active ? kV3VmSchemaVersion : 0)) << "\n";
    out << "feature_record\truntime_vm_active\t"
        << (v3 && vm_runtime_active  ? "yes-full-control-transition"
            : variant_runtime_active ? "yes-bounded-variant-selection"
                                     : "no")
        << "\n";
    out << "feature_record\truntime_vm_program_count\t" << vm_program_count << "\n";
    out << "feature_record\truntime_vm_reachability\t"
        << (v3 && vm_runtime_active  ? "every-protected-fragment-dispatch"
            : variant_runtime_active ? "variant-fragments"
                                     : "none")
        << "\n";
    out << "feature_record\truntime_vm_key_derivation\t"
        << (vm_runtime_active ? "hkdf-sha256-root-owner-cluster" : "n/a") << "\n";
    out << "feature_record\truntime_vm_key_lifecycle\t"
        << (vm_runtime_active ? "derive-use-wipe" : "inactive") << "\n";
    out << "feature_record\truntime_vm_ciphertext_aggregate_sha256\t"
        << (vm_digest_material.empty() ? "-" : digest_hex(vm_digest_material)) << "\n";
    out << "feature_record\tshard_ciphertext_aggregate_sha256\t"
        << (shard_digest_material.empty() ? "-" : digest_hex(shard_digest_material)) << "\n";
    out << "feature_record\tgateway_encoding_aggregate_sha256\t"
        << (gateway_digest_material.empty() ? "-" : digest_hex(gateway_digest_material)) << "\n";
    out << "feature_record\tnative_variant_ciphertext_aggregate_sha256\t"
        << (variant_digest_material.empty() ? "-" : digest_hex(variant_digest_material)) << "\n";
    if (v3) {
        out << "feature_record\tstate_schema_version\t3\n";
        out << "feature_record\tcapability_schema_version\t1\n";
        out << "feature_record\tshard_schema_version\t1\n";
        out << "feature_record\tgateway_schema_version\t1\n";
        out << "feature_record\tcapability_bits\t128\n";
        out << "feature_record\tcapability_authentication\thmac-sha256\n";
        out << "feature_record\tcapability_runtime_active\t"
            << (capability_count ? "yes-materialize-validate-consume-wipe" : "no") << "\n";
        out << "feature_record\tshard_runtime_active\t"
            << (shard_count ? "yes-authenticated-whole-open-selected-record-decode" : "no") << "\n";
        out << "feature_record\tgenerated_gateway_runtime_active\t"
            << (gateway_count ? "yes" : "no") << "\n";
    } else {
        out << "feature_record\tstate_schema_version\t" << kStateContractVersion << "\n";
        out << "feature_record\tcapability_schema_version\t0\n";
        out << "feature_record\tshard_schema_version\t0\n";
        out << "feature_record\tgateway_schema_version\t1\n";
        out << "feature_record\tcapability_runtime_active\tno-legacy-state-token\n";
        out << "feature_record\tshard_runtime_active\tyes-legacy-metadata-shard\n";
        out << "feature_record\tgenerated_gateway_runtime_active\tyes\n";
    }
    out << "feature_record\tfragment_crypto\txchacha20-poly1305-v1\n";
    out << "feature_record\tfragment_key_bits\t256\n";
    out << "feature_record\tfragment_nonce_bits\t192\n";
    out << "feature_record\tfragment_tag_bits\t128\n";
    out << "feature_record\tseed_source\t"
        << (ctx.options.seed_hex.empty() ? "os-csprng" : "deterministic-cli") << "\n";
    out << "feature_record\tfragment_scratch_lifecycle\tRW-RX-RW-wipe-unmap\n";
    out << "feature_record\tfragment_thread_state\tdynamic-tpidr-locked-wipe-unmap-on-teardown\n";
    out << "coverage_record\tmetric\tcount\n";
    out << "coverage_record\tprotected_functions\t" << protected_count << "\n";
    out << "coverage_record\tfragments\t" << fragment_count << "\n";
    out << "coverage_record\tcapabilities\t" << capability_count << "\n";
    out << "coverage_record\tgenerated_gateways\t" << gateway_count << "\n";
    out << "coverage_record\tcontrol_edges\t" << edge_count << "\n";
    out << "coverage_record\tadapters\t" << adapter_count << "\n";
    out << "coverage_record\tshards\t" << shard_count << "\n";
    out << "coverage_record\tvm_programs\t" << vm_program_count << "\n";
    out << "coverage_record\tactive_shard_families\t" << shard_families.size() << "\n";
    out << "coverage_record\tactive_gateway_abi_families\t" << gateway_abi_families.size() << "\n";
    out << "coverage_record\tnative_variants\t" << native_variant_count << "\n";
    out << "coverage_record\tnative_variant_families\t" << native_variant_families.size() << "\n";
    out << "coverage_record\teh_functions\t" << eh_metadata_count << "\n";
    out << "coverage_record\tgateway_bytes\t" << gateway_bytes << "\n";
    out << "coverage_record\tfragment_storage_bytes\t" << fragment_storage_bytes << "\n";
    out << "coverage_record\tshard_bytes\t" << shard_bytes << "\n";
    out << "coverage_record\tvm_storage_bytes\t" << vm_storage_bytes << "\n";
    out << "coverage_record\teh_storage_bytes\t" << eh_storage_bytes << "\n";
    out << "coverage_record\tvariant_storage_bytes\t" << variant_storage_bytes << "\n";
    out << "coverage_record\tfallbacks\t" << fallback_count << "\n";
    out << "coverage_record\trejections\t" << rejection_count << "\n";
    out << "segment_record\tregion\tpermissions\n";
    out << "segment_record\tfragment_runtime\tRX\n";
    out << "segment_record\tfragment_descriptors\tRO\n";
    out << "segment_record\tfragment_state\tRW\n";
    auto is_protected_row = [](const ProtectedFunction& func) {
        return (func.protection_mode == ProtectionMode::FragmentEligible ||
                func.protection_mode == ProtectionMode::LegacyFunctionOnly) &&
               func.stub_vaddr != 0;
    };
    auto hex_or_dash = [](uint64_t value, bool present) {
        return present ? hex(value) : std::string("-");
    };
    auto u64_or_dash = [](uint64_t value, bool present) {
        return present ? std::to_string(value) : std::string("-");
    };
    auto selected_target_id = [&](uint64_t target) {
        for (const auto& func : funcs) {
            if (target >= func.original_start && target < func.original_start + func.size) {
                return std::to_string(func.selected_id);
            }
        }
        return std::string("-");
    };
    auto materialization_policy = [](SelectedBackend backend) {
        switch (backend) {
        case SelectedBackend::Fragment:
            return "authenticated-runtime-fragment";
        case SelectedBackend::LegacyRuntimeAllocator:
            return "legacy-runtime-allocator";
        case SelectedBackend::LegacyFixedSlot:
            return "legacy-fixed-slot";
        case SelectedBackend::None:
            return "rejected-or-unselected";
        }
        return "unknown";
    };

    out << "function_record\tselected_id\treserved\taddress\tsize\tname\tentry_stub\tslot\tslot_"
           "size\tencrypted"
        << "\tbody_size\trelocation_count\tveneer_count\tliteral_pool_bytes\tallocator_size_class"
        << "\teligibility\tbackend\texecution_model\toutcome\treason_codes\treason_detail"
        << "\tdirect_calls\ttail_calls\tindirect_calls\tentry_pointer_refs\tplaintext_"
           "removed\tactive_state"
        << "\tmaterialization_policy\n";
    for (const auto& func : funcs) {
        const bool protected_row = is_protected_row(func);
        const uint64_t pages =
            protected_row ? Utils::align_to(func.slot_size, kPageSize) / kPageSize : 0;
        std::string reason_codes;
        for (size_t i = 0; i < func.reason_codes.size(); ++i) {
            if (i)
                reason_codes += ",";
            reason_codes += reason_code_name(func.reason_codes[i]);
        }
        out << "function_record\t" << func.selected_id << "\t"
            << "-\t" << hex(func.original_start) << "\t" << func.size << "\t" << func.name << "\t"
            << hex_or_dash(func.stub_vaddr, protected_row) << "\t"
            << hex_or_dash(func.slot_vaddr, protected_row) << "\t"
            << u64_or_dash(func.slot_size, protected_row) << "\t"
            << hex_or_dash(func.enc_vaddr, protected_row && func.enc_vaddr != 0) << "\t"
            << u64_or_dash(func.body_size, protected_row) << "\t"
            << u64_or_dash(func.runtime_relocations, protected_row) << "\t"
            << u64_or_dash(func.veneer_count, protected_row) << "\t"
            << u64_or_dash(func.literal_pool_bytes, protected_row) << "\t"
            << (protected_row ? std::to_string(pages) + "-page" : std::string("-")) << "\t"
            << protection_mode_name(func.protection_mode) << "\t"
            << selected_backend_name(func.selected_backend) << "\t"
            << (ctx.options.command == CliCommand::Analyze
                    ? (func.selected_backend == SelectedBackend::Fragment ? "predicted-fragment"
                                                                          : "predicted-legacy")
                    : (func.cfg_execution_enabled ? "cfg-fragment-events"
                                                  : "function-materialization"))
            << "\t" << final_outcome_name(func.final_outcome) << "\t" << reason_codes << "\t"
            << func.protection_reason << "\t" << u64_or_dash(func.direct_calls, protected_row)
            << "\t" << u64_or_dash(func.tail_calls, protected_row) << "\t"
            << u64_or_dash(func.indirect_calls, protected_row) << "\t"
            << u64_or_dash(func.entry_pointer_refs, protected_row) << "\t"
            << (protected_row
                    ? (func.plaintext_verified
                           ? "yes"
                           : (func.original_site_patched ? "site-only" : "small-function"))
                    : "-")
            << "\t" << hex_or_dash(func.active_vaddr, protected_row) << "\t"
            << materialization_policy(func.selected_backend) << "\n";
    }

    out << "exception_record\tfunction_id\tschema\tpc_range\tcall_sites\tactions\ttypes\tcie_cfi_"
           "bytes\tfde_cfi_bytes\tlsda_bytes\tregistration\tcleanup_gateways\n";
    for (const auto& func : funcs) {
        if (func.selected_backend != SelectedBackend::Fragment || func.fde_bytes.empty())
            continue;
        out << "exception_record\t" << func.selected_id << "\t" << func.eh_metadata.schema << "\t"
            << func.eh_metadata.pc_range << "\t" << func.eh_metadata.call_sites.size() << "\t"
            << func.eh_metadata.actions.size() << "\t" << func.eh_metadata.types.size() << "\t"
            << func.eh_metadata.cie_cfi.size() << "\t" << func.eh_metadata.fde_cfi.size() << "\t"
            << func.eh_metadata.lsda_bytes.size()
            << "\tloader-indexed\tnormal,unwind,throw,rethrow\n";
    }

    out << "controllet_record\tfunction_id\tcluster_id\tcontrollet_family\tmetadata_shard\tshard_"
           "address\tshard_size\tadapter\tgateway_abi_family\n";
    for (const auto& func : funcs) {
        if (!func.cfg_execution_enabled)
            continue;
        out << "controllet_record\t" << func.selected_id << "\t" << func.cluster_id << "\t"
            << func.controllet_family << "\tshard-" << func.cluster_id << "\t"
            << hex(func.metadata_shard_vaddr) << "\t" << func.metadata_shard.size()
            << "\tstate-bound-typed-v1\t" << (v3 ? std::to_string(func.v3_gateway_abi_family) : "0")
            << "\n";
    }
    if (v3) {
        out << "v3_shard_record\towner_index\tcluster_id\tfamily\tshard_address\tshard_"
               "size\tpurpose\tcapability_count\tencrypted\n";
        for (const auto& func : funcs) {
            if (!func.cfg_execution_enabled)
                continue;
            out << "v3_shard_record\t" << func.selected_id << "\t" << func.cluster_id << "\t"
                << func.v3_shard_family << "\t" << hex(func.v3_shard_vaddr) << "\t"
                << func.v3_shard_envelope.size() << "\tcontrol-resolution\t"
                << func.v3_capability_count << "\tyes\n";
        }
    }
    if (ctx.options.native_variants) {
        out << "native_variant_record\tfunction_id\tfragment_id\tvariant_index\tvariant_"
               "count\ttransformation\tproof\tchanged_offset\trejection_reason\tselection\tsealed_"
               "independently\n";
        for (const auto& func : funcs) {
            for (const auto& fragment : func.fragments) {
                if (fragment.variants.empty()) {
                    out << "native_variant_record\t" << func.selected_id << "\t"
                        << fragment.fragment_id << "\t-\t1\t-\t-\t-\t"
                        << (fragment.variant_rejection_reason.empty()
                                ? "no-proven-candidate"
                                : fragment.variant_rejection_reason)
                        << "\tsingle-proven-safe\tn/a\n";
                    continue;
                }
                for (size_t index = 0; index < fragment.variants.size(); ++index) {
                    const auto& variant = fragment.variants[index];
                    out << "native_variant_record\t" << func.selected_id << "\t"
                        << fragment.fragment_id << "\t" << (index + 1) << "\t"
                        << (fragment.variants.size() + 1) << "\t" << variant.transformation << "\t"
                        << variant.proof << "\t" << variant.changed_offset << "\t"
                        << "-\tauthenticated-two-bit-index\tyes\n";
                }
            }
        }
    }

    out << "interior_pointer_record\tfunction_id\tsource\toriginal_target\tfragment_id\tstable_"
           "thunk\tpolicy\n";
    for (const auto& func : funcs) {
        for (const auto& thunk : func.interior_thunks) {
            out << "interior_pointer_record\t" << func.selected_id << "\t" << thunk.source << "\t"
                << hex(thunk.original_target) << "\t" << thunk.fragment_id << "\t"
                << hex(thunk.thunk_vaddr) << "\tsymbolic-fragment-entry\n";
        }
    }

    out << "analysis\tfacts\tid\tname\tdirect_branches\tconditional_branches\tdirect_calls\treturns"
        << "\tadr\tadrp\tadrp_pairs\tliteral_pool_refs\tpc_relative_loads\tjump_table_candidates"
        << "\tindirect_branches\tindirect_calls\tfunction_pointer_materializations"
        << "\tgot_refs\tplt_refs\ttls_refs\texternal_refs\tstack_frame_setup\tstack_frame_teardown"
        << "\tsimd_fpu_use\tsve_sme_use\tdecode_failures\n";
    for (const auto& func : funcs) {
        const auto& f = func.instruction_facts;
        out << "analysis\tfacts\t" << func.selected_id << "\t" << func.name << "\t"
            << f.direct_branches << "\t" << f.conditional_branches << "\t" << f.direct_calls << "\t"
            << f.returns << "\t" << f.adr << "\t" << f.adrp << "\t" << f.adrp_pairs << "\t"
            << f.literal_pool_refs << "\t" << f.pc_relative_loads << "\t" << f.jump_table_candidates
            << "\t" << f.indirect_branches << "\t" << f.indirect_calls << "\t"
            << f.function_pointer_materializations << "\t" << f.got_refs << "\t" << f.plt_refs
            << "\t" << f.tls_refs << "\t" << f.external_refs << "\t" << f.stack_frame_setup << "\t"
            << f.stack_frame_teardown << "\t" << f.simd_fpu_use << "\t" << f.sve_sme_use << "\t"
            << f.decode_failures << "\n";
    }

    if (!v3)
        out << "analysis\tcontrol_edge\tfunc_id\truntime_id\tpc\ttarget\tkind\ttarget_"
               "domain\ttarget_symbol\ttarget_section\ttarget_selected_id\ttarget_runtime_id\n";
    for (const auto& func : funcs) {
        if (v3)
            break;
        const bool protected_row = is_protected_row(func);
        for (const auto& edge : func.control_edges) {
            out << "analysis\tcontrol_edge\t" << func.selected_id << "\t"
                << (protected_row ? std::to_string(func.id) : std::string("-")) << "\t"
                << hex(edge.pc) << "\t" << (edge.target == 0 ? std::string("-") : hex(edge.target))
                << "\t" << control_edge_kind_name(edge.kind) << "\t"
                << control_target_domain_name(edge.target_domain) << "\t"
                << (edge.target_symbol.empty() ? std::string("-") : edge.target_symbol) << "\t"
                << (edge.target_section.empty() ? std::string("-") : edge.target_section) << "\t"
                << (edge.target == 0 ? std::string("-") : selected_target_id(edge.target)) << "\t"
                << (edge.target_func_id == UINT32_MAX ? std::string("-")
                                                      : std::to_string(edge.target_func_id))
                << "\n";
        }
    }

    out << "analysis\tdata_ref\tfunc_id\tpc\ttarget\tkind\n";
    for (const auto& func : funcs) {
        for (const auto& ref : func.data_refs) {
            out << "analysis\tdata_ref\t" << func.selected_id << "\t" << hex(ref.pc) << "\t"
                << (ref.target == 0 ? std::string("-") : hex(ref.target)) << "\t"
                << data_ref_kind_name(ref.kind) << "\n";
        }
    }

    out << "fragment_record\tfunction_id\tfragment_id\tstart\tsize\texecution_size\tstorage_"
           "size\texit_count\tciphertext\tnonce\ttag\taad_size\n";
    if (!v3)
        out << "fragment_exit_record\tfunction_id\tfragment_id\tsite_id\tpc\tkind\ttarget_function_"
               "id\ttarget_fragment_id\tcontinuation_fragment_id\n";
    if (!v3)
        out << "symbolic_value_record\tfunction_id\tfragment_id\toffset\ttype\tstate_bound\tload_"
               "bias\n";
    for (const auto& func : funcs) {
        for (const auto& fragment : func.fragments) {
            out << "fragment_record\t" << func.selected_id << "\t" << fragment.fragment_id << "\t"
                << hex(fragment.original_start) << "\t" << fragment.size << "\t"
                << fragment.execution_bytes.size() << "\t" << fragment.storage_size << "\t"
                << fragment.exits.size() << "\t" << hex(fragment.ciphertext_vaddr) << "\t"
                << hex(fragment.nonce_vaddr) << "\t" << hex(fragment.tag_vaddr) << "\t"
                << fragment.aad.size() << "\n";
            for (const auto& exit : fragment.exits) {
                if (v3)
                    break;
                auto id = [](uint32_t value) {
                    return value == UINT32_MAX ? std::string("-") : std::to_string(value);
                };
                out << "fragment_exit_record\t" << func.selected_id << "\t" << fragment.fragment_id
                    << "\t" << exit.site_id << "\t" << hex(exit.pc) << "\t"
                    << fragment_exit_kind_name(exit.kind) << "\t" << id(exit.target_function_id)
                    << "\t" << id(exit.target_fragment_id) << "\t"
                    << id(exit.continuation_fragment_id) << "\n";
            }
            for (size_t i = 0; i < fragment.state_token_offsets.size(); ++i) {
                if (v3)
                    break;
                out << "symbolic_value_record\t" << func.selected_id << "\t" << fragment.fragment_id
                    << "\t" << fragment.state_token_offsets[i] << "\t"
                    << ((i & 1) == 0 ? "successor" : "continuation") << "\tyes\t"
                    << (fragment.state_token_load_bias[i] ? "yes" : "no") << "\n";
            }
        }
    }

    out << "callsite\tmetadata\tcaller_id\tcallee_id\tpc\treturn_pc\tflags\treserved\n";
    for (const auto& meta : callsites) {
        out << "callsite\tmetadata\t" << meta.caller_func_id << "\t" << meta.callee_func_id << "\t"
            << hex(meta.original_pc) << "\t" << hex(meta.original_return_pc) << "\t" << meta.flags
            << "\t" << meta.reserved << "\n";
    }
}

} // namespace maya::protection
