#include "core/protection/FragmentEvents.hpp"
#include <iostream>
using namespace maya::protection;
int main() {
    uint64_t c = 0x123456789abcdef0ULL;
    uint32_t f = 0, g = 0;
    auto t = encode_fragment_token(7, 9, c);
    decode_fragment_token(t, c, f, g);
    if (f != 7 || g != 9)
        return 1;
    ProtectedFragment p;
    p.fragment_id = 2;
    p.exits.push_back({FragmentExitKind::NextFragment, 4, UINT32_MAX, 3, UINT32_MAX, 0x1000});
    FragmentExitEvent e;
    e.kind = FragmentExitKind::NextFragment;
    e.site_id = 4;
    e.target_token = encode_fragment_token(7, 3, c);
    if (validate_exit_event(p, e, c) != EventFault::None)
        return 2;
    e.target_token = encode_fragment_token(7, 5, c);
    if (validate_exit_event(p, e, c) != EventFault::BadTarget)
        return 3;
    e.version = 1;
    if (validate_exit_event(p, e, c) != EventFault::BadVersion)
        return 4;
    ContinuationStack s(2);
    if (s.push({kContinuationContractVersion, 1, 2, 3, 4, 5}) != EventFault::None ||
        s.push({kContinuationContractVersion, 5, 6, 7, 8, 9}) != EventFault::None ||
        s.push({}) != EventFault::StackOverflow)
        return 5;
    SymbolicContinuation x;
    if (s.pop(x) != EventFault::None || x.function_id != 5 || s.pop(x) != EventFault::None ||
        s.pop(x) != EventFault::StackUnderflow)
        return 6;
    SymbolicContinuation v{kContinuationContractVersion, 7, 8, 9, 10, 11};
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::None)
        return 7;
    v.version = 1;
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::BadVersion)
        return 8;
    v = {kContinuationContractVersion, 9, 8, 9, 10, 11};
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::BadContinuation)
        return 9;
    v = {kContinuationContractVersion, 7, 8, 9, 9, 11};
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::StaleEpoch)
        return 10;
    v.generation = 12;
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::BadDepth)
        return 11;
    v.generation = 10;
    v.parent_commitment = 12;
    if (validate_continuation(v, 7, 8, 10, 11) != EventFault::BadPath)
        return 12;
    std::cout << "fragment event tests passed\n";
}
