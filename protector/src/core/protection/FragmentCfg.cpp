#include "FragmentCfg.hpp"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>

namespace maya::protection {
namespace {
bool unconditional_b(uint32_t insn) { return (insn & 0xfc000000u) == 0x14000000u; }
} // namespace
const char* fragment_exit_kind_name(FragmentExitKind kind) {
    switch (kind) {
    case FragmentExitKind::NextFragment:
        return "next-fragment";
    case FragmentExitKind::CallProtected:
        return "call-protected";
    case FragmentExitKind::ReturnProtected:
        return "return-protected";
    case FragmentExitKind::TailcallProtected:
        return "tailcall-protected";
    case FragmentExitKind::ExitFunction:
        return "exit-function";
    case FragmentExitKind::CallExternal:
        return "call-external";
    case FragmentExitKind::SetjmpExternal:
        return "setjmp-external";
    case FragmentExitKind::LongjmpExternal:
        return "longjmp-external";
    case FragmentExitKind::Fault:
        return "fault";
    }
    return "unknown";
}

void build_fragment_cfg(std::vector<ProtectedFunction>& funcs) {
    for (auto& f : funcs) {
        f.fragments.clear();
        if (f.selected_backend != SelectedBackend::Fragment || !f.fde_bytes.empty())
            continue;
        if ((f.size & 3) || f.original_bytes.size() != f.size)
            throw std::runtime_error("CFG function is not complete aligned code: " + f.name);
        std::set<uint64_t> b{f.original_start, f.original_start + f.size};
        std::vector<std::pair<uint64_t, uint64_t>> data;
        for (const auto& r : f.data_refs)
            if (r.kind == DataRefKind::LiteralPoolEntry && r.target >= f.original_start &&
                r.target + 8 <= f.original_start + f.size) {
                data.push_back({r.target, r.target + 8});
                b.insert(r.target);
                b.insert(r.target + 8);
            }
        for (const auto& e : f.control_edges) {
            if (e.pc < f.original_start || e.pc + 4 > f.original_start + f.size)
                throw std::runtime_error("CFG edge PC outside function: " + f.name);
            b.insert(e.pc + 4);
            if (e.kind == ControlEdgeKind::IntraFunction) {
                if (e.target < f.original_start || e.target >= f.original_start + f.size ||
                    ((e.target - f.original_start) & 3))
                    throw std::runtime_error("Invalid intra-function CFG target: " + f.name);
                b.insert(e.target);
            }
        }
        std::vector<uint64_t> v(b.begin(), b.end());
        for (size_t i = 0; i + 1 < v.size(); ++i) {
            if (v[i] == v[i + 1])
                continue;
            const bool excluded = std::any_of(data.begin(), data.end(), [&](const auto& r) {
                return v[i] >= r.first && v[i + 1] <= r.second;
            });
            if (excluded)
                continue;
            ProtectedFragment g;
            g.fragment_id = f.fragments.size();
            g.original_start = v[i];
            g.size = v[i + 1] - v[i];
            const size_t off = g.original_start - f.original_start;
            g.plaintext.assign(f.original_bytes.begin() + off,
                               f.original_bytes.begin() + off + g.size);
            f.fragments.push_back(g);
        }
        auto frag_at = [&](uint64_t a) -> uint32_t {
            for (const auto& g : f.fragments)
                if (g.original_start == a)
                    return g.fragment_id;
            throw std::runtime_error("CFG target is not a fragment entry: " + std::to_string(a));
        };
        uint32_t site = 0;
        for (auto& g : f.fragments) {
            const uint64_t last = g.original_start + g.size - 4;
            const ControlEdge* edge = nullptr;
            for (const auto& e : f.control_edges)
                if (e.pc == last) {
                    edge = &e;
                    break;
                }
            FragmentExit x;
            x.site_id = site++;
            x.pc = last;
            if (!edge) {
                const auto next = std::find_if(
                    f.fragments.begin(), f.fragments.end(), [&](const auto& candidate) {
                        return candidate.original_start == g.original_start + g.size;
                    });
                if (next != f.fragments.end()) {
                    x.kind = FragmentExitKind::NextFragment;
                    x.pc = g.original_start + g.size;
                    x.target_fragment_id = next->fragment_id;
                    g.exits.push_back(x);
                }
                continue;
            }
            if (edge->kind == ControlEdgeKind::ProtectedReturn) {
                x.kind = FragmentExitKind::ExitFunction;
                g.exits.push_back(x);
                continue;
            }
            if (edge->kind == ControlEdgeKind::ProtectedToProtectedCall) {
                x.kind = FragmentExitKind::CallProtected;
                x.target_function_id = edge->target_func_id;
                x.continuation_fragment_id = frag_at(last + 4);
                g.exits.push_back(x);
                continue;
            }
            if (edge->kind == ControlEdgeKind::ProtectedTailCall) {
                x.kind = FragmentExitKind::TailcallProtected;
                x.target_function_id = edge->target_func_id;
                g.exits.push_back(x);
                continue;
            }
            if (edge->kind == ControlEdgeKind::ExternalCall) {
                x.kind = FragmentExitKind::CallExternal;
                if (edge->target_symbol.find("longjmp") != std::string::npos)
                    x.kind = FragmentExitKind::LongjmpExternal;
                else if (edge->target_symbol.find("setjmp") != std::string::npos)
                    x.kind = FragmentExitKind::SetjmpExternal;
                else if (last + 4 == f.original_start + f.size)
                    x.kind = FragmentExitKind::LongjmpExternal;
                x.compatibility_target = edge->target;
                x.continuation_fragment_id =
                    x.kind == FragmentExitKind::LongjmpExternal ? UINT32_MAX : frag_at(last + 4);
                g.exits.push_back(x);
                continue;
            }
            if (edge->kind == ControlEdgeKind::ExternalTailCall) {
                x.kind = FragmentExitKind::CallExternal;
                x.compatibility_target = edge->target;
                x.continuation_fragment_id = UINT32_MAX;
                g.exits.push_back(x);
                continue;
            }
            if (edge->kind == ControlEdgeKind::IntraFunction) {
                x.kind = FragmentExitKind::NextFragment;
                x.target_fragment_id = frag_at(edge->target);
                g.exits.push_back(x);
                uint32_t raw = 0;
                std::memcpy(&raw, f.original_bytes.data() + (last - f.original_start), 4);
                if (!unconditional_b(raw)) {
                    x.site_id = site++;
                    x.target_fragment_id = frag_at(last + 4);
                    g.exits.push_back(x);
                }
                continue;
            }
            throw std::runtime_error("Unsupported edge in fragment CFG: " + f.name);
        }
    }
}
} // namespace maya::protection
