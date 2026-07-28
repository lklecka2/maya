#include "core/protection/FragmentCfg.hpp"
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace maya::protection;
static void put(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    std::memcpy(b.data() + off, &v, 4);
}
static ProtectedFunction base() {
    ProtectedFunction f;
    f.name = "cfg";
    f.original_start = 0x1000;
    f.size = 24;
    f.original_bytes.resize(24);
    f.selected_backend = SelectedBackend::Fragment;
    return f;
}
int main() {
    {
        auto f = base();
        put(f.original_bytes, 4, 0x54000000);
        put(f.original_bytes, 16, 0x14000000);
        put(f.original_bytes, 20, 0xd65f03c0);
        f.control_edges = {
            {ControlEdgeKind::IntraFunction, 0x1004, 0x1010, 0, ControlTargetDomain::SameFunction},
            {ControlEdgeKind::IntraFunction, 0x1010, 0x1000, 0, ControlTargetDomain::SameFunction},
            {ControlEdgeKind::ProtectedReturn, 0x1014, 0, UINT32_MAX,
             ControlTargetDomain::SameFunction}};
        std::vector<ProtectedFunction> v{f};
        build_fragment_cfg(v);
        if (v[0].fragments.size() != 4 || v[0].fragments[0].exits.size() != 2 ||
            v[0].fragments[2].exits[0].target_fragment_id != 0)
            return 1;
        uint64_t bytes = 0;
        for (auto& g : v[0].fragments)
            bytes += g.size;
        if (bytes != f.size)
            return 2;
    }
    {
        auto f = base();
        put(f.original_bytes, 0, 0x94000000);
        put(f.original_bytes, 4, 0xd65f03c0);
        f.control_edges = {{ControlEdgeKind::ProtectedToProtectedCall, 0x1000, 0x2000, 1,
                            ControlTargetDomain::ProtectedFunction},
                           {ControlEdgeKind::ProtectedReturn, 0x1004, 0, UINT32_MAX,
                            ControlTargetDomain::SameFunction}};
        std::vector<ProtectedFunction> v{f};
        build_fragment_cfg(v);
        auto& e = v[0].fragments[0].exits[0];
        if (e.kind != FragmentExitKind::CallProtected || e.target_function_id != 1 ||
            e.continuation_fragment_id != 1)
            return 3;
    }
    {
        auto f = base();
        put(f.original_bytes, 0, 0x14000000);
        f.control_edges = {
            {ControlEdgeKind::IntraFunction, 0x1000, 0x1002, 0, ControlTargetDomain::SameFunction}};
        std::vector<ProtectedFunction> v{f};
        try {
            build_fragment_cfg(v);
            return 4;
        } catch (const std::runtime_error&) {
        }
    }
    std::cout << "fragment cfg tests passed\n";
}
