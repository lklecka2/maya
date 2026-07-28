#pragma once
#include "ProtectionTypes.hpp"
#include "StateBinding.hpp"
#include <cstdint>
#include <vector>
namespace maya::protection {
inline constexpr uint32_t kExitEventVersion = 2;
enum class EventFault : uint32_t {
    None = 0,
    BadVersion = 1,
    BadKind = 2,
    BadSite = 3,
    BadTarget = 4,
    StackOverflow = 5,
    StackUnderflow = 6,
    BadThread = 7,
    StaleEpoch = 8,
    BadPath = 9,
    BadDepth = 10,
    BadContinuation = 11
};
struct FragmentExitEvent {
    uint32_t version = kExitEventVersion;
    FragmentExitKind kind = FragmentExitKind::Fault;
    uint32_t site_id = 0;
    uint32_t flags = 0;
    uint64_t target_token = 0;
    uint64_t continuation_token = 0;
    EventFault fault = EventFault::None;
};
struct SymbolicContinuation {
    uint32_t version = kContinuationContractVersion;
    uint32_t function_id = 0;
    uint32_t fragment_id = 0;
    uint32_t continuation_id = 0;
    uint64_t generation = 0;
    uint64_t parent_commitment = 0;
};
uint64_t encode_fragment_token(uint32_t function_id, uint32_t fragment_id, uint64_t cookie);
bool decode_fragment_token(uint64_t token, uint64_t cookie, uint32_t& function_id,
                           uint32_t& fragment_id);
EventFault validate_exit_event(const ProtectedFragment& fragment, const FragmentExitEvent& event,
                               uint64_t cookie);
EventFault validate_continuation(const SymbolicContinuation& value, uint32_t expected_function,
                                 uint32_t expected_fragment, uint64_t expected_generation,
                                 uint64_t expected_parent_commitment);
class ContinuationStack {
  public:
    explicit ContinuationStack(size_t limit) : limit_(limit) {}
    EventFault push(SymbolicContinuation value);
    EventFault pop(SymbolicContinuation& value);
    size_t size() const { return values_.size(); }

  private:
    size_t limit_;
    std::vector<SymbolicContinuation> values_;
};
} // namespace maya::protection
