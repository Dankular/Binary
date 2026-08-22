#pragma once

#include "compass/core/function.hpp"

namespace compass::core::il {

/// Lifts LLIL for every instruction in `fn` and stores it in `fn.llil`.
/// See docs/ARCHITECTURE.md "Low-Level IL" for the coverage this
/// implements and the Unimplemented-node policy for everything else.
void liftFunctionLLIL(Function& fn);

} // namespace compass::core::il
