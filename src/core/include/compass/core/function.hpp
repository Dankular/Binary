#pragma once

#include "compass/core/basic_block.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/high_level_il.hpp"
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
    /// `llil` to be populated first).
    std::optional<il::MLILFunction> mlil;
    std::optional<il::MLILSSAFunction> mlilSsa;

    /// Built from `mlil` (the plain, non-SSA form) by il::buildHlil().
    std::optional<il::HLILFunction> hlil;

    /// Free-form findings appended by IAnalysisPass::run() — e.g. "calls
    /// 0x1169", "IO caller: printf". Deliberately simple (human-readable
    /// strings, not a typed property bag): the passes implemented so far
    /// don't need structured queries over this, and adding real structure
    /// (typed annotation kinds, a query API) is easy to do later without
    /// disturbing existing passes, whereas guessing a schema now risks
    /// designing it around passes that don't exist yet.
    std::vector<std::string> annotations;

    const BasicBlock* blockAt(Address addr) const {
        for (const auto& bb : basicBlocks) {
            if (addr >= bb.start && addr < bb.end) return &bb;
        }
        return nullptr;
    }
};

} // namespace compass::core
