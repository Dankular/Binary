#pragma once

#include "compass/core/types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace compass::core {

/// A single decoded instruction. Deliberately backend-agnostic: whatever
/// analysis backend produced this (radare2 today, Rizin later) fills in
/// these fields, and nothing above this layer needs to know which backend
/// it was.
struct Instruction {
    Address address = 0;
    std::uint32_t size = 0;
    std::string mnemonic;     // e.g. "mov"
    std::string operandsText; // e.g. "rax, rbx" — human-readable, for display
    std::string esil;         // backend's ESIL semantics string, input to the LLIL lifter
    std::string opType;       // backend's coarse classification, e.g. "mov", "cjmp", "call", "ret"
    std::vector<std::uint8_t> bytes;

    /// True if this instruction ends a basic block (branch/call/ret/etc.)
    bool isBlockTerminator = false;
    /// Static successor addresses if statically known (branch targets,
    /// fallthrough). Empty for indirect branches/rets.
    std::vector<Address> successors;

    /// For branch-classified instructions (jmp/cjmp/call), the backend's
    /// structured branch-taken and branch-not-taken targets — used directly
    /// by the LLIL lifter to build If/Goto/Call nodes instead of parsing
    /// branch conditions out of ESIL text. Absent for straight-line
    /// instructions and for indirect branches with no statically known
    /// target.
    std::optional<Address> jumpTarget;
    std::optional<Address> failTarget; // cjmp's not-taken (fallthrough) target
};

} // namespace compass::core
