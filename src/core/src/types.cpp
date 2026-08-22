#include "compass/core/types.hpp"

namespace compass::core {

std::string toString(Architecture arch) {
    switch (arch) {
        case Architecture::X86: return "x86";
        case Architecture::X86_64: return "x86_64";
        case Architecture::ARM32: return "arm32";
        case Architecture::ARM64: return "arm64";
        case Architecture::MIPS: return "mips";
        case Architecture::Unknown: default: return "unknown";
    }
}

} // namespace compass::core
