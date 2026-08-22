#pragma once

#include "compass/core/function.hpp"
#include "compass/core/types.hpp"

#include <string>
#include <vector>

namespace compass::core {

struct Symbol {
    Address address = 0;
    std::string name;
    bool isFunction = false;
};

struct Section {
    std::string name;
    Address vaddr = 0;
    std::uint64_t size = 0;
    bool executable = false;
    bool writable = false;
};

/// A loaded binary: everything the analysis backend extracted about the
/// file, plus discovered functions. Filled in by IAnalysisBackend; owns no
/// backend-specific state itself (deliberately, to keep this header
/// backend-agnostic).
struct Binary {
    std::string path;
    std::string format;   // e.g. "elf64", "pe", "mach064" — as reported by the backend
    Architecture arch = Architecture::Unknown;
    Address entryPoint = 0;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<Function> functions;

    /// Exact match first; falls back to matching after stripping common
    /// backend name prefixes (radare2/Rizin prefix discovered functions
    /// with "sym.", "dbg." when debug info is present, "sym.imp." for
    /// imports, "fcn." for unnamed ones) so callers can look up `main`
    /// without knowing which prefix this particular binary got tagged
    /// with. This is a display/lookup convenience only — Function::name
    /// always stores the backend's full name.
    const Function* functionNamed(const std::string& name) const {
        for (const auto& f : functions) {
            if (f.name == name) return &f;
        }
        static const char* prefixes[] = {"sym.imp.", "dbg.", "sym.", "fcn."};
        for (const auto& f : functions) {
            for (const char* prefix : prefixes) {
                std::string p = prefix;
                if (f.name.size() > p.size() && f.name.compare(0, p.size(), p) == 0 &&
                    f.name.compare(p.size(), std::string::npos, name) == 0) {
                    return &f;
                }
            }
        }
        return nullptr;
    }

    const Function* functionAt(Address addr) const {
        for (const auto& f : functions) {
            if (f.entry == addr) return &f;
        }
        return nullptr;
    }
};

} // namespace compass::core
