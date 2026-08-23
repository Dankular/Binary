#pragma once

#include "compass/core/il/medium_level_il.hpp"

namespace compass::core::il {

/// Type system v1's "propagate through MLIL" step — scoped honestly, not
/// aspirationally: assigns an integer Type to every Stack variable, sized
/// from the memory-access width it was recovered from (MLILVar::widthHint,
/// set at promotion time in mlil_builder.cpp). That's real evidence, so
/// it's a real assignment, not a guess.
///
/// Signedness is inferred from real evidence too, not defaulted to
/// unsigned: a Stack variable is marked signed if it's a direct operand of
/// Sar/SDiv/SMod (arithmetic-shift/signed-division/signed-modulo — LLIL
/// ops that only exist because the underlying ESIL genuinely distinguishes
/// them from their unsigned counterparts: x86 `sar` lifts to a different
/// ESIL operator than `shr`, `idiv` a different one than `div` — see
/// llil_lifter.cpp), or is the destination of a `var = sar(...)`/
/// `sdiv(...)`/`smod(...)` assignment — *or*, the case that actually fires
/// on real -O0 code (a signed op's operand is essentially always a
/// register freshly copied from the stack slot, never the stack slot
/// itself), if it's the most recent stack-variable source of a register
/// later used as a signed operand. That register-copy provenance is
/// tracked per basic block in instruction order (see
/// type_inference.cpp's collectSignedEvidence()) and resolves x86-64
/// sub-register aliasing (`eax`/`ax`/`al`/`ah` all naming the same
/// physical storage as `rax`) so a stack-to-register copy and a later
/// signed use of that register at a different width are still recognized
/// as the same register. Deliberately shallow beyond that one hop — not a
/// full taint analysis through arbitrary arithmetic — so a positive is
/// always real, traceable evidence, not an inference chain that could just
/// as easily be wrong. A variable with no such evidence defaults to
/// unsigned, same as before.
///
/// Still deliberately out of scope: Register/Flag variable types (needs
/// arch-specific register-width metadata this milestone doesn't consume
/// from the backend yet), and pointer/struct recovery (needs cross-
/// reference and usage analysis — real work, worth revisiting now that the
/// Ghidra decompiler integration (Milestone 3) exists to cross-check
/// against). Extending either is the natural next step, not a rewrite of
/// this pass.
void attachTypes(MLILFunction& mlil);

} // namespace compass::core::il
