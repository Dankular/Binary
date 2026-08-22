#include "compass/core/il/type_inference.hpp"

namespace compass::core::il {

namespace {

void visit(const MLILExprPtr& e) {
    if (!e) return;
    if ((e->op == MLILOp::Var || e->op == MLILOp::SetVar || e->op == MLILOp::Phi) &&
        e->var.kind == MLILVarKind::Stack && e->var.widthHint > 0 && !e->var.type) {
        e->var.type = Type::makeInt(e->var.widthHint, /*isSigned=*/false);
    }
    for (auto& o : e->operands) visit(o);
}

} // namespace

void attachTypes(MLILFunction& mlil) {
    for (auto& bb : mlil.basicBlocks) {
        for (auto& instr : bb.instructions) {
            for (auto& e : instr.expressions) visit(e);
        }
    }
}

} // namespace compass::core::il
