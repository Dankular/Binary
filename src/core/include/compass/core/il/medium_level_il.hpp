#pragma once

#include "compass/core/type.hpp"
#include "compass/core/types.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace compass::core::il {

enum class MLILVarKind { Register, Flag, Stack };

/// A named variable: either a passthrough of an LLIL register/flag, or a
/// recovered stack slot (e.g. `var_4` for what LLIL saw as
/// `[sub(rbp, 4)].4`). `version` is -1 in plain (non-SSA) MLIL and >=0 once
/// MLILSSAFunction assigns SSA versions — same Var type for both so a
/// caller can tell at a glance whether they're holding SSA or non-SSA data.
struct MLILVar {
    MLILVarKind kind = MLILVarKind::Register;
    std::string name;
    int version = -1;

    /// Byte width of the memory access this variable was recovered from
    /// (set at promotion time for Stack vars, from the originating LLIL
    /// Load/Store size — see mlil_builder.cpp). 0 = unknown. Left unset for
    /// Register/Flag vars: their width depends on arch-specific register
    /// metadata this milestone doesn't yet consume — see
    /// il::attachTypes()'s doc comment for exactly what is and isn't
    /// inferred, rather than guessing.
    std::uint32_t widthHint = 0;

    /// Populated by il::attachTypes() from `widthHint` where available.
    /// nullptr until that pass runs, and stays nullptr for variables it has
    /// no evidence for.
    TypePtr type;

    bool operator==(const MLILVar& o) const {
        return kind == o.kind && name == o.name && version == o.version;
    }
};

enum class MLILOp {
    Const,
    Var,     // read a variable (var field set; version -1 outside SSA)
    Load,    // memory read for anything NOT recognized as a stack variable
              // (globals, heap, computed addresses) — operands[0] = address
    Store,   // memory write, same caveat — operands = {address, value}
    SetVar,  // var = operands[0]
    Add, Sub, And, Or, Xor, Shl, Shr, Mul, Div, Cmp,
    If,      // operands[0] = condition; trueTarget/falseTarget = block addresses
    Goto,
    Call,    // operands[0] = target
    Ret,
    Nop,
    Phi,     // SSA only: var = destination SSA var, operands = incoming SSA Var reads
    Unimplemented,
};

std::string toString(MLILOp op);

struct MLILExpr {
    MLILOp op = MLILOp::Nop;
    std::uint64_t constValue = 0;
    MLILVar var; // meaningful for Var / SetVar / Phi
    std::vector<std::shared_ptr<MLILExpr>> operands;
    Address trueTarget = 0;
    Address falseTarget = 0;
    std::string text; // Unimplemented's original LLIL text, for debugging

    static std::shared_ptr<MLILExpr> make(MLILOp op) {
        auto e = std::make_shared<MLILExpr>();
        e->op = op;
        return e;
    }
};
using MLILExprPtr = std::shared_ptr<MLILExpr>;

struct MLILInstruction {
    Address address = 0;
    std::vector<MLILExprPtr> expressions;
};

struct MLILBasicBlock {
    Address start = 0;
    Address end = 0;
    std::vector<Address> successors;
    std::vector<Address> predecessors;
    std::vector<MLILInstruction> instructions;
};

/// Plain (non-SSA) MLIL for a function: LLIL with registers/flags promoted
/// to named Vars and stack-relative Load/Store recognized as named stack
/// variable reads/writes. One variable name can still be assigned many
/// times (no SSA versioning yet) — see MLILSSAFunction for that.
struct MLILFunction {
    Address entry = 0;
    std::vector<MLILBasicBlock> basicBlocks;
};

/// SSA-form MLIL: every MLILVar has version >= 0, each assigned exactly
/// once; control-flow join points get explicit Phi expressions. Built from
/// an MLILFunction via ssaFromMlil() (mlil_ssa_builder.cpp) using
/// DominatorTree for correct phi placement.
struct MLILSSAFunction {
    Address entry = 0;
    std::vector<MLILBasicBlock> basicBlocks;
};

std::string render(const MLILExpr& expr);
std::string render(const MLILFunction& fn);
std::string render(const MLILSSAFunction& fn);

} // namespace compass::core::il
