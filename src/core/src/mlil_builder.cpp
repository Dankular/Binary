// LLIL -> MLIL: variable promotion. See mlil_builder.hpp.

#include "compass/core/il/mlil_builder.hpp"

#include <optional>
#include <set>
#include <sstream>

namespace compass::core::il {

namespace {

// Registers commonly used as a stack or frame pointer, across the
// architectures the multi-arch smoke test exercises (x86: rsp/rbp/esp/ebp;
// ARM/ARM64: sp/fp/x29; MIPS: sp/fp — radare2/Rizin's own register naming
// for $29/$30). Recognizing a Load/Store address as `one of these +/- a
// constant` is what turns raw memory access into a named stack variable.
bool isFrameRegister(const std::string& name) {
    static const std::set<std::string> regs = {
        "rsp", "rbp", "esp", "ebp", "sp", "fp", "x29",
    };
    return regs.count(name) != 0;
}

/// If `addr` is shaped like `frame_reg + K`, `frame_reg - K`, or a bare
/// `frame_reg`, returns the stack variable name to use (`arg_K`/`var_K`/
/// `var_0`) — matching Binary Ninja's own var_/arg_ naming convention:
/// negative (subtracted) offsets are locals, positive (added) offsets are
/// incoming args / outgoing call slots. Same name for repeated accesses at
/// the same offset is exactly what makes this a variable and not just
/// cosmetic — later loads/stores of "the same slot" become the same Var.
std::optional<std::string> stackVarName(const LLILExpr& addr) {
    auto hex = [](std::uint64_t v) {
        std::ostringstream os;
        os << std::hex << v;
        return os.str();
    };
    if (addr.op == LLILOp::Reg && isFrameRegister(addr.regOrFlag)) {
        return "var_0";
    }
    if ((addr.op == LLILOp::Add || addr.op == LLILOp::Sub) && addr.operands.size() == 2) {
        const LLILExpr* reg = nullptr;
        const LLILExpr* konst = nullptr;
        for (auto& o : addr.operands) {
            if (o->op == LLILOp::Reg && isFrameRegister(o->regOrFlag)) reg = o.get();
            if (o->op == LLILOp::Const) konst = o.get();
        }
        if (reg && konst) {
            return (addr.op == LLILOp::Sub ? "var_" : "arg_") + hex(konst->constValue);
        }
    }
    return std::nullopt;
}

MLILOp mapBinOp(LLILOp op) {
    switch (op) {
        case LLILOp::Add: return MLILOp::Add;
        case LLILOp::Sub: return MLILOp::Sub;
        case LLILOp::And: return MLILOp::And;
        case LLILOp::Or: return MLILOp::Or;
        case LLILOp::Xor: return MLILOp::Xor;
        case LLILOp::Shl: return MLILOp::Shl;
        case LLILOp::Shr: return MLILOp::Shr;
        case LLILOp::Mul: return MLILOp::Mul;
        case LLILOp::Div: return MLILOp::Div;
        case LLILOp::Cmp: return MLILOp::Cmp;
        default: return MLILOp::Unimplemented;
    }
}

MLILExprPtr transform(const LLILExprPtr& e) {
    if (!e) return MLILExpr::make(MLILOp::Nop);

    switch (e->op) {
        case LLILOp::Const: {
            auto m = MLILExpr::make(MLILOp::Const);
            m->constValue = e->constValue;
            return m;
        }
        case LLILOp::Reg: {
            auto m = MLILExpr::make(MLILOp::Var);
            m->var = {MLILVarKind::Register, e->regOrFlag, -1, 0, nullptr};
            return m;
        }
        case LLILOp::Flag: {
            auto m = MLILExpr::make(MLILOp::Var);
            m->var = {MLILVarKind::Flag, e->regOrFlag, -1, 0, nullptr};
            return m;
        }
        case LLILOp::Load: {
            if (!e->operands.empty()) {
                if (auto name = stackVarName(*e->operands[0])) {
                    auto m = MLILExpr::make(MLILOp::Var);
                    m->var = {MLILVarKind::Stack, *name, -1, static_cast<std::uint32_t>(e->constValue), nullptr};
                    return m;
                }
            }
            auto m = MLILExpr::make(MLILOp::Load);
            m->constValue = e->constValue;
            if (!e->operands.empty()) m->operands = {transform(e->operands[0])};
            return m;
        }
        case LLILOp::Store: {
            // operands = {address, value}
            if (e->operands.size() == 2) {
                if (auto name = stackVarName(*e->operands[0])) {
                    auto m = MLILExpr::make(MLILOp::SetVar);
                    m->var = {MLILVarKind::Stack, *name, -1, static_cast<std::uint32_t>(e->constValue), nullptr};
                    m->operands = {transform(e->operands[1])};
                    return m;
                }
            }
            auto m = MLILExpr::make(MLILOp::Store);
            m->constValue = e->constValue;
            for (auto& o : e->operands) m->operands.push_back(transform(o));
            return m;
        }
        case LLILOp::SetReg:
        case LLILOp::SetFlag: {
            auto m = MLILExpr::make(MLILOp::SetVar);
            m->var = {e->op == LLILOp::SetReg ? MLILVarKind::Register : MLILVarKind::Flag, e->regOrFlag, -1, 0, nullptr};
            if (!e->operands.empty()) m->operands = {transform(e->operands[0])};
            return m;
        }
        case LLILOp::If: {
            auto m = MLILExpr::make(MLILOp::If);
            m->trueTarget = e->trueTarget;
            m->falseTarget = e->falseTarget;
            if (!e->operands.empty()) m->operands = {transform(e->operands[0])};
            return m;
        }
        case LLILOp::Goto: {
            auto m = MLILExpr::make(MLILOp::Goto);
            m->trueTarget = e->trueTarget;
            return m;
        }
        case LLILOp::Call: {
            auto m = MLILExpr::make(MLILOp::Call);
            if (!e->operands.empty()) m->operands = {transform(e->operands[0])};
            return m;
        }
        case LLILOp::Ret:
            return MLILExpr::make(MLILOp::Ret);
        case LLILOp::Nop:
            return MLILExpr::make(MLILOp::Nop);
        case LLILOp::Add:
        case LLILOp::Sub:
        case LLILOp::And:
        case LLILOp::Or:
        case LLILOp::Xor:
        case LLILOp::Shl:
        case LLILOp::Shr:
        case LLILOp::Mul:
        case LLILOp::Div:
        case LLILOp::Cmp: {
            auto m = MLILExpr::make(mapBinOp(e->op));
            for (auto& o : e->operands) m->operands.push_back(transform(o));
            return m;
        }
        case LLILOp::Push:
        case LLILOp::Pop:
        case LLILOp::Unimplemented:
        default: {
            auto m = MLILExpr::make(MLILOp::Unimplemented);
            m->text = e->text.empty() ? toString(e->op) : e->text;
            for (auto& o : e->operands) m->operands.push_back(transform(o));
            return m;
        }
    }
}

} // namespace

MLILFunction buildMlil(const Function& fn) {
    MLILFunction mlil;
    if (!fn.llil) return mlil;

    for (auto& bb : fn.basicBlocks) {
        MLILBasicBlock mbb;
        mbb.start = bb.start;
        mbb.end = bb.end;
        mbb.successors = bb.successors;
        mbb.predecessors = bb.predecessors;
        mlil.basicBlocks.push_back(std::move(mbb));
    }

    // fn.llil is a flat, address-ordered instruction list (see lifter.hpp);
    // bucket it back into the per-block structure MLIL needs for CFG-aware
    // passes (SSA, and later HLIL structuring) downstream.
    for (auto& li : fn.llil->instructions) {
        for (auto& mbb : mlil.basicBlocks) {
            if (li.address >= mbb.start && li.address < mbb.end) {
                MLILInstruction mi;
                mi.address = li.address;
                for (auto& e : li.expressions) mi.expressions.push_back(transform(e));
                mbb.instructions.push_back(std::move(mi));
                break;
            }
        }
    }
    return mlil;
}

} // namespace compass::core::il
