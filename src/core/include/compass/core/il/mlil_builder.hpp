#pragma once

#include "compass/core/function.hpp"
#include "compass/core/il/medium_level_il.hpp"

namespace compass::core::il {

/// LLIL -> MLIL: promotes Reg/Flag reads and SetReg/SetFlag writes to named
/// Vars, and recognizes stack-relative Load/Store (address shaped like
/// `frame_reg +/- constant`, for a small set of common stack/frame
/// register names) as reads/writes of a named stack variable instead of
/// raw memory access. Requires `fn.llil` to already be populated
/// (backend->liftLowLevelIL(fn)).
MLILFunction buildMlil(const Function& fn);

/// MLIL -> MLIL SSA: classic Cytron-et-al. construction (dominance-frontier
/// phi placement + dominator-tree-driven renaming) over `mlil`'s own block
/// graph. Every variable definition gets a fresh version; control-flow
/// join points get explicit Phi expressions.
MLILSSAFunction buildMlilSsa(const MLILFunction& mlil);

} // namespace compass::core::il
