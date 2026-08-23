#pragma once

#include "compass/core/il/medium_level_il.hpp"
#include "compass/core/types.hpp"

#include <string>

namespace compass::core::il {

/// Result of translating rz-ghidra's p-code AST (its `pdgx` command's XML)
/// for one function into Compass's own MLIL — the "p-code → MLIL
/// translation" item docs/DECOMPILER.md tracked as deferred, real,
/// separate follow-on work. `success` is false when the XML wasn't
/// parseable or had no `<ast>` block for this function (rz-ghidra not
/// installed, or the function otherwise failed to decompile), with `error`
/// set; `mlil` is only meaningful when `success` is true.
struct PcodeTranslationResult {
    bool success = false;
    std::string error;
    MLILFunction mlil;
};

/// Parses `pdgxXml` (the raw XML text rz-ghidra's `pdgx @ <entry>` command
/// returns for the function at `entry`) and translates its `<ast>` p-code
/// into an MLILFunction — a genuinely different, second MLIL from
/// mlil_builder.cpp's own ESIL-driven one: this one is built from Ghidra's
/// own p-code, after Ghidra's decompiler has already done its own SSA
/// construction and calling-convention-aware parameter/local recovery, so
/// it tends to be cleaner (real phi merges, symbol names Ghidra itself
/// chose) but depends on rz-ghidra being installed, unlike the
/// always-available ESIL-based pipeline. See docs/DECOMPILER.md for the
/// full design (opcode mapping table, what's deliberately left
/// Unimplemented, and the three real p-code op-orderings this was verified
/// against).
PcodeTranslationResult translatePcode(const std::string& pdgxXml, Address entry);

} // namespace compass::core::il
