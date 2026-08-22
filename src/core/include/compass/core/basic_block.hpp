#pragma once

#include "compass/core/instruction.hpp"
#include "compass/core/types.hpp"

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
};

} // namespace compass::core
