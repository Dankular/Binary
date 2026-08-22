#pragma once

#include "compass/core/il/medium_level_il.hpp"

namespace compass::core::il {

/// Type system v1's "propagate through MLIL" step — scoped honestly, not
/// aspirationally: assigns an unsigned integer Type to every Stack
/// variable, sized from the memory-access width it was recovered from
/// (MLILVar::widthHint, set at promotion time in mlil_builder.cpp). That's
/// real evidence, so it's a real assignment, not a guess.
///
/// Deliberately does NOT attempt: signedness (needs usage-context inference
/// — comparisons, sign-extension patterns — not built yet), Register/Flag
/// variable types (needs arch-specific register-width metadata this
/// milestone doesn't consume from the backend yet), or pointer/struct
/// recovery (needs cross-reference and usage analysis — real work, planned
/// for when the Ghidra decompiler integration (Milestone 3) can take this
/// further). Extending any of those is the natural next step, not a
/// rewrite of this pass.
void attachTypes(MLILFunction& mlil);

} // namespace compass::core::il
