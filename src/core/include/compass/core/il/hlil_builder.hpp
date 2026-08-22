#pragma once

#include "compass/core/il/high_level_il.hpp"
#include "compass/core/il/medium_level_il.hpp"

namespace compass::core::il {

/// MLIL -> HLIL: structures the block graph into If/While statements using
/// DominatorTree-based loop (back-edge) and if/else-diamond detection. This
/// is a bounded structuring pass, not a general one — it recognizes:
///   - if/else diamonds: a conditional branch whose two arms (by following
///     single-successor chains) reconverge at a common block
///   - simple loops: a back edge into a header whose own conditional
///     branch has exactly one target inside the loop body and one outside
/// Anything else (irreducible control flow, multi-exit loops, switch-like
/// dispatch) falls back to an explicit Goto/Label pair — an honest
/// degradation consistent with the rest of this IL stack's philosophy
/// (see docs/ARCHITECTURE.md), not a silent misstructuring.
HLILFunction buildHlil(const MLILFunction& mlil);

} // namespace compass::core::il
