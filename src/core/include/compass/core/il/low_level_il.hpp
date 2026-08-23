#pragma once

#include "compass/core/types.hpp"

#include <memory>
#include <string>
#include <vector>

namespace compass::core::il {

/// LLIL: the lowest IL layer, close to 1:1 with instructions. This is the
/// first rung of what Binary Ninja calls BNIL (LLIL -> MLIL -> MLIL SSA ->
/// HLIL -> HLIL SSA). Only LLIL exists so far — see docs/ARCHITECTURE.md
/// and docs/ROADMAP.md for the rest of the stack.
enum class LLILOp {
    Const,   // literal value
    Reg,     // read a register
    Flag,    // read a flag
    Load,    // memory read: operand[0] = address expr
    Store,   // memory write: operand[0] = address expr, operand[1] = value expr
    SetReg,  // operand[0] = value expr, targetReg set
    SetFlag, // operand[0] = value expr, targetReg (flag name) set
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,  // logical (unsigned) right shift — ESIL `>>`
    Sar,  // arithmetic (signed) right shift — ESIL `>>>>`; real evidence the
          // operand/result is signed, see il::attachTypes()
    Mul,
    Div,  // unsigned division — ESIL `/`
    SDiv, // signed division — ESIL `~/`; same signedness-evidence role as Sar
    Mod,  // unsigned modulo — ESIL `%`
    SMod, // signed modulo — ESIL `~%`; same signedness-evidence role as Sar
    Cmp, // sets flags as a side effect (backend-specific until MLIL models flags properly)
    If,      // operand[0] = condition expr; trueTarget/falseTarget addresses
    Goto,    // trueTarget = target address
    Call,    // operand[0] = target expr (const target or register for indirect)
    Ret,
    Push,    // operand[0] = value expr
    Pop,
    Nop,
    /// Emitted instead of guessing when the lifter doesn't yet cover an ESIL
    /// construct. `text` carries the original ESIL for debugging/extension.
    Unimplemented,
};

std::string toString(LLILOp op);

struct LLILExpr {
    LLILOp op = LLILOp::Nop;
    std::uint64_t constValue = 0;
    std::string regOrFlag;                 // for Reg/Flag/SetReg/SetFlag
    std::vector<std::shared_ptr<LLILExpr>> operands;
    Address trueTarget = 0;
    Address falseTarget = 0;
    std::string text; // raw ESIL text, populated for Unimplemented

    static std::shared_ptr<LLILExpr> make(LLILOp op) {
        auto e = std::make_shared<LLILExpr>();
        e->op = op;
        return e;
    }
};

using LLILExprPtr = std::shared_ptr<LLILExpr>;

/// One instruction's worth of lifted LLIL. An instruction can lift to
/// several LLIL expressions (e.g. `push rax` -> [SetReg rsp, Store]).
struct LLILInstruction {
    Address address = 0;
    std::vector<LLILExprPtr> expressions;
};

/// LLIL for an entire function, in address order.
struct LLILFunction {
    std::vector<LLILInstruction> instructions;
};

/// Pretty-prints an LLILExpr tree as a Lisp-ish s-expression, for CLI
/// output and tests. Not meant to be the final GUI rendering.
std::string render(const LLILExpr& expr);
std::string render(const LLILFunction& fn);

} // namespace compass::core::il
