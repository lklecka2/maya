#include "FragmentEvents.hpp"
namespace maya::protection {
uint64_t encode_fragment_token(uint32_t f, uint32_t g, uint64_t cookie) {
    uint64_t raw = (uint64_t(f) << 32) | g;
    raw ^= cookie;
    return (raw << 17) | (raw >> (64 - 17));
}
bool decode_fragment_token(uint64_t token, uint64_t cookie, uint32_t& f, uint32_t& g) {
    uint64_t raw = (token >> 17) | (token << (64 - 17));
    raw ^= cookie;
    f = uint32_t(raw >> 32);
    g = uint32_t(raw);
    return true;
}
EventFault validate_exit_event(const ProtectedFragment& fragment, const FragmentExitEvent& e,
                               uint64_t cookie) {
    if (e.version != kExitEventVersion)
        return EventFault::BadVersion;
    if (e.kind == FragmentExitKind::Fault)
        return EventFault::BadKind;
    for (const auto& allowed : fragment.exits) {
        if (allowed.site_id != e.site_id || allowed.kind != e.kind)
            continue;
        uint32_t f = 0, g = 0;
        if (e.kind == FragmentExitKind::NextFragment) {
            decode_fragment_token(e.target_token, cookie, f, g);
            if (g != allowed.target_fragment_id)
                return EventFault::BadTarget;
        } else if (e.kind == FragmentExitKind::CallProtected ||
                   e.kind == FragmentExitKind::TailcallProtected) {
            decode_fragment_token(e.target_token, cookie, f, g);
            if (f != allowed.target_function_id || g != 0)
                return EventFault::BadTarget;
        }
        if (e.kind == FragmentExitKind::CallProtected) {
            decode_fragment_token(e.continuation_token, cookie, f, g);
            if (g != allowed.continuation_fragment_id)
                return EventFault::BadTarget;
        }
        return EventFault::None;
    }
    return EventFault::BadSite;
}
EventFault validate_continuation(const SymbolicContinuation& v, uint32_t function,
                                 uint32_t fragment, uint64_t generation, uint64_t parent) {
    if (v.version != kContinuationContractVersion)
        return EventFault::BadVersion;
    if (v.function_id != function || v.fragment_id != fragment)
        return EventFault::BadContinuation;
    if (v.generation < generation)
        return EventFault::StaleEpoch;
    if (v.generation != generation)
        return EventFault::BadDepth;
    if (v.parent_commitment != parent)
        return EventFault::BadPath;
    return EventFault::None;
}
EventFault ContinuationStack::push(SymbolicContinuation v) {
    if (values_.size() >= limit_)
        return EventFault::StackOverflow;
    values_.push_back(v);
    return EventFault::None;
}
EventFault ContinuationStack::pop(SymbolicContinuation& v) {
    if (values_.empty())
        return EventFault::StackUnderflow;
    v = values_.back();
    values_.pop_back();
    return EventFault::None;
}
} // namespace maya::protection
