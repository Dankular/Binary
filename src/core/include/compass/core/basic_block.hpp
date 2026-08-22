#pragma once

#include "compass/core/instruction.hpp"
#include "compass/core/types.hpp"

#include <string>
#include <vector>

namespace compass::core {

/// A maximal straight-line run of instructions: single entry, single exit
/// (control flow only enters at the top and leaves at the bottom).
struct BasicBlock {
    Address start = 0;
    Address end = 0; // exclusive
    std::vector<Instruction> instructions;
    std::vector<Address> successors;   // block start addresses
    std::vector<Address> predecessors; // block start addresses

    /// Free-form findings attributed to this specific block — same
    /// deliberately-simple design as Function::annotations (see there).
    /// Populated by annotation_merge.hpp today for dynamic-analysis
    /// coverage (see docs/ANNOTATIONS.md); workflow passes may use it too.
    std::vector<std::string> annotations;
};

} // namespace compass::core
