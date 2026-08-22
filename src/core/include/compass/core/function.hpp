#pragma once

#include "compass/core/basic_block.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/medium_level_il.hpp"
#include "compass/core/types.hpp"

#include <optional>
#include <string>
#include <vector>

namespace compass::core {

struct Function {
    Address entry = 0;
    std::string name;
    std::vector<BasicBlock> basicBlocks;

    /// Lifted lazily by IAnalysisBackend::liftLowLevelIL(); absent until
    /// then.
    std::optional<il::LLILFunction> llil;

    /// Built from `llil` by il::buildMlil() / il::buildMlilSsa() (requires
    /// `llil` to be populated first). HLIL follows the same
    /// optional-until-computed pattern — see il/hlil_builder.hpp.
    std::optional<il::MLILFunction> mlil;
    std::optional<il::MLILSSAFunction> mlilSsa;

    const BasicBlock* blockAt(Address addr) const {
        for (const auto& bb : basicBlocks) {
            if (addr >= bb.start && addr < bb.end) return &bb;
        }
        return nullptr;
    }
};

} // namespace compass::core
