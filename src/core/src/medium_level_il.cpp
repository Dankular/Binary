#include "compass/core/il/medium_level_il.hpp"

#include <sstream>

namespace compass::core::il {

std::string toString(MLILOp op) {
    switch (op) {
        case MLILOp::Const: return "const";
        case MLILOp::Var: return "var";
        case MLILOp::Load: return "load";
        case MLILOp::Store: return "store";
        case MLILOp::SetVar: return "set_var";
        case MLILOp::Add: return "add";
        case MLILOp::Sub: return "sub";
        case MLILOp::And: return "and";
        case MLILOp::Or: return "or";
        case MLILOp::Xor: return "xor";
        case MLILOp::Shl: return "shl";
        case MLILOp::Shr: return "shr";
        case MLILOp::Sar: return "sar";
        case MLILOp::Mul: return "mul";
        case MLILOp::Div: return "div";
        case MLILOp::SDiv: return "sdiv";
        case MLILOp::Mod: return "mod";
        case MLILOp::SMod: return "smod";
        case MLILOp::Cmp: return "cmp";
        case MLILOp::If: return "if";
        case MLILOp::Goto: return "goto";
        case MLILOp::Call: return "call";
        case MLILOp::Ret: return "ret";
        case MLILOp::Nop: return "nop";
        case MLILOp::Phi: return "phi";
        case MLILOp::Unimplemented: return "unimplemented";
    }
    return "?";
}

namespace {

std::string varName(const MLILVar& v) {
    std::string n = v.name;
    if (v.version >= 0) n += "#" + std::to_string(v.version);
    return n;
}

void renderTo(const MLILExpr& e, std::ostringstream& os) {
    switch (e.op) {
        case MLILOp::Const:
            os << "0x" << std::hex << e.constValue << std::dec;
            return;
        case MLILOp::Var:
            os << varName(e.var);
            return;
        case MLILOp::SetVar:
            if (e.var.type) os << render(*e.var.type) << " ";
            os << varName(e.var) << " = ";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            return;
        case MLILOp::Phi: {
            os << varName(e.var) << " = phi(";
            for (std::size_t i = 0; i < e.operands.size(); ++i) {
                if (i) os << ", ";
                if (e.operands[i]) renderTo(*e.operands[i], os);
                else os << "?";
            }
            os << ")";
            return;
        }
        case MLILOp::Load:
            os << "[";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << "]." << e.constValue;
            return;
        case MLILOp::Store:
            os << "[";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << "]." << e.constValue << " = ";
            if (e.operands.size() > 1) renderTo(*e.operands[1], os);
            return;
        case MLILOp::If:
            os << "if (";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << ") goto 0x" << std::hex << e.trueTarget << " else 0x" << e.falseTarget << std::dec;
            return;
        case MLILOp::Goto:
            os << "goto 0x" << std::hex << e.trueTarget << std::dec;
            return;
        case MLILOp::Call:
            os << "call(";
            if (!e.operands.empty()) renderTo(*e.operands[0], os);
            os << ")";
            return;
        case MLILOp::Ret:
            os << "<return>";
            return;
        case MLILOp::Nop:
            os << "nop";
            return;
        case MLILOp::Unimplemented:
            os << "unimplemented(\"" << e.text << "\"";
            for (auto& o : e.operands) {
                os << ", ";
                renderTo(*o, os);
            }
            os << ")";
            return;
        default:
            break;
    }
    os << toString(e.op) << "(";
    for (std::size_t i = 0; i < e.operands.size(); ++i) {
        if (i) os << ", ";
        renderTo(*e.operands[i], os);
    }
    os << ")";
}

std::string renderFn(const std::vector<MLILBasicBlock>& blocks) {
    std::ostringstream os;
    for (auto& bb : blocks) {
        for (auto& insn : bb.instructions) {
            for (auto& e : insn.expressions) {
                os << "0x" << std::hex << insn.address << std::dec << "  ";
                renderTo(*e, os);
                os << "\n";
            }
        }
    }
    return os.str();
}

} // namespace

std::string render(const MLILExpr& expr) {
    std::ostringstream os;
    renderTo(expr, os);
    return os.str();
}

std::string render(const MLILFunction& fn) { return renderFn(fn.basicBlocks); }
std::string render(const MLILSSAFunction& fn) { return renderFn(fn.basicBlocks); }

} // namespace compass::core::il
