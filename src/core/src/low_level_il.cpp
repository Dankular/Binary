#include "compass/core/il/low_level_il.hpp"

#include <sstream>

namespace compass::core::il {

std::string toString(LLILOp op) {
    switch (op) {
        case LLILOp::Const: return "const";
        case LLILOp::Reg: return "reg";
        case LLILOp::Flag: return "flag";
        case LLILOp::Load: return "load";
        case LLILOp::Store: return "store";
        case LLILOp::SetReg: return "set_reg";
        case LLILOp::SetFlag: return "set_flag";
        case LLILOp::Add: return "add";
        case LLILOp::Sub: return "sub";
        case LLILOp::And: return "and";
        case LLILOp::Or: return "or";
        case LLILOp::Xor: return "xor";
        case LLILOp::Shl: return "shl";
        case LLILOp::Shr: return "shr";
        case LLILOp::Sar: return "sar";
        case LLILOp::Mul: return "mul";
        case LLILOp::Div: return "div";
        case LLILOp::SDiv: return "sdiv";
        case LLILOp::Mod: return "mod";
        case LLILOp::SMod: return "smod";
        case LLILOp::Cmp: return "cmp";
        case LLILOp::If: return "if";
        case LLILOp::Goto: return "goto";
        case LLILOp::Call: return "call";
        case LLILOp::Ret: return "ret";
        case LLILOp::Push: return "push";
        case LLILOp::Pop: return "pop";
        case LLILOp::Nop: return "nop";
        case LLILOp::Unimplemented: return "unimplemented";
    }
    return "?";
}

namespace {

void renderTo(const LLILExpr& e, std::ostringstream& os) {
    switch (e.op) {
        case LLILOp::Const:
            os << "0x" << std::hex << e.constValue << std::dec;
            return;
        case LLILOp::Reg:
        case LLILOp::Flag:
            os << e.regOrFlag;
            return;
        case LLILOp::Unimplemented:
            os << "unimplemented(\"" << e.text << "\"";
            for (auto& o : e.operands) {
                os << ", ";
                renderTo(*o, os);
            }
            os << ")";
            return;
        case LLILOp::SetReg:
            os << e.regOrFlag << " = ";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            return;
        case LLILOp::SetFlag:
            os << e.regOrFlag << " = ";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            return;
        case LLILOp::Load:
            os << "[";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << "]." << e.constValue;
            return;
        case LLILOp::Store:
            os << "[";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << "]." << e.constValue << " = ";
            if (e.operands.size() > 1) renderTo(*e.operands[1], os);
            return;
        case LLILOp::If:
            os << "if (";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << ") goto 0x" << std::hex << e.trueTarget << " else 0x" << e.falseTarget << std::dec;
            return;
        case LLILOp::Goto:
            os << "goto 0x" << std::hex << e.trueTarget << std::dec;
            return;
        case LLILOp::Call:
            os << "call(";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << ")";
            return;
        case LLILOp::Ret:
            os << "<return>";
            return;
        case LLILOp::Nop:
            os << "nop";
            return;
        default:
            break;
    }
    // Generic binary/n-ary op rendering: op(a, b, ...)
    os << toString(e.op) << "(";
    for (std::size_t i = 0; i < e.operands.size(); ++i) {
        if (i) os << ", ";
        renderTo(*e.operands[i], os);
    }
    os << ")";
}

} // namespace

std::string render(const LLILExpr& expr) {
    std::ostringstream os;
    renderTo(expr, os);
    return os.str();
}

std::string render(const LLILFunction& fn) {
    std::ostringstream os;
    for (auto& insn : fn.instructions) {
        for (auto& e : insn.expressions) {
            os << "0x" << std::hex << insn.address << std::dec << "  " << render(*e) << "\n";
        }
    }
    return os.str();
}

} // namespace compass::core::il
