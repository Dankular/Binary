#pragma once

#include "compass/core/il/medium_level_il.hpp"

#include <vector>

namespace compass::core::il {

/// HLIL is a statement tree, not an expression-per-instruction list like
/// LLIL/MLIL — that's the actual point of it: control flow is *structure*
/// (If/While nesting) instead of Goto/If-with-block-targets. See
/// hlil_builder.hpp for how (and how much of) that structure gets
/// recovered.
enum class HLILStatementKind {
    Expr,   // a single non-control-flow MLIL expression (SetVar/Call/Store/...)
    If,     // condition (in `expr`) + thenBody + elseBody (elseBody empty = no else)
    While,  // condition (in `expr`) + body
    Goto,   // structuring gave up on this edge — honest fallback, see hlil_builder.cpp
    Label,  // target of some Goto reaches here
    Return,
};

struct HLILStatement {
    HLILStatementKind kind = HLILStatementKind::Expr;
    Address originAddress = 0; // originating instruction/block address, for display
    MLILExprPtr expr;          // Expr's payload, or If/While's condition
    std::vector<HLILStatement> thenBody; // If
    std::vector<HLILStatement> elseBody; // If
    std::vector<HLILStatement> body;     // While
    Address target = 0;                  // Goto/Label
};
using HLILBody = std::vector<HLILStatement>;

struct HLILFunction {
    HLILBody statements;
};

/// Pseudo-C-ish rendering with indentation — for CLI/debug output, not the
/// final GUI presentation.
std::string render(const HLILFunction& fn);

} // namespace compass::core::il
