#pragma once

#include <cstdint>
#include <string>

namespace compass::core {

/// A virtual address within a loaded binary's address space.
using Address = std::uint64_t;

/// Architecture identifiers Compass understands at the IL layer.
/// Deliberately small today (Milestone 0 validates x86-64 only) — extended
/// as MLIL/HLIL and more lifters come online. See docs/ROADMAP.md.
enum class Architecture {
    Unknown,
    X86,
    X86_64,
    ARM32,
    ARM64,
    MIPS,
};

std::string toString(Architecture arch);

/// CPU register width in bytes, used by the IL to size Reg/SetReg nodes.
using RegisterId = std::string;

} // namespace compass::core
