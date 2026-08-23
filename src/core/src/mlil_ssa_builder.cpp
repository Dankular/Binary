// MLIL -> MLIL SSA. Classic Cytron/Ferrante/Rosen/Zadeck construction:
// dominance-frontier-driven phi placement, then a dominator-tree-order
// renaming pass. See mlil_builder.hpp for the public entry point and
// docs/ARCHITECTURE.md for how this fits into the IL stack.

#include "compass/core/analysis/dominators.hpp"
#include "compass/core/il/mlil_builder.hpp"

#include <functional>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace compass::core::il {

namespace {

std::string varKey(const MLILVar& v) {
    char k = 'r';
    switch (v.kind) {
        case MLILVarKind::Register: k = 'r'; break;
        case MLILVarKind::Flag: k = 'f'; break;
        case MLILVarKind::Stack: k = 's'; break;
        case MLILVarKind::Temp: k = 't'; break;
    }
    return std::string(1, k) + ":" + v.name;
}

MLILExprPtr deepCopy(const MLILExprPtr& e) {
    if (!e) return e;
    auto c = std::make_shared<MLILExpr>(*e); // copies scalar fields (op, constValue, var, targets, text)
    c->operands.clear();
    for (auto& o : e->operands) c->operands.push_back(deepCopy(o));
    return c;
}

/// Builds the throwaway compass::core::Function shape DominatorTree needs,
/// directly from an MLILFunction's own block graph — no dependency on the
/// original Function beyond what MLIL already carries.
Function adaptForDominatorTree(Address entry, const std::vector<MLILBasicBlock>& blocks) {
    Function fn;
    fn.entry = entry;
    for (auto& mbb : blocks) {
        BasicBlock bb;
        bb.start = mbb.start;
        bb.end = mbb.end;
        bb.successors = mbb.successors;
        fn.basicBlocks.push_back(std::move(bb));
    }
    return fn;
}

void collectVarsRecursive(const MLILExprPtr& e, std::unordered_map<std::string, MLILVar>& seen) {
    if (!e) return;
    if (e->op == MLILOp::Var || e->op == MLILOp::SetVar) seen[varKey(e->var)] = e->var;
    for (auto& o : e->operands) collectVarsRecursive(o, seen);
}

} // namespace

MLILSSAFunction buildMlilSsa(const MLILFunction& mlil) {
    MLILSSAFunction ssa;
    if (mlil.basicBlocks.empty()) return ssa;
    ssa.entry = mlil.entry;

    // Deep-copy the whole block/instruction/expr structure so renaming can
    // mutate freely (assigning versions in place) without touching the
    // plain MLILFunction it came from.
    std::unordered_map<Address, MLILBasicBlock*> byAddr;
    for (auto& mbb : mlil.basicBlocks) {
        MLILBasicBlock copy;
        copy.start = mbb.start;
        copy.end = mbb.end;
        copy.successors = mbb.successors;
        copy.predecessors = mbb.predecessors;
        for (auto& instr : mbb.instructions) {
            MLILInstruction ic;
            ic.address = instr.address;
            for (auto& e : instr.expressions) ic.expressions.push_back(deepCopy(e));
            copy.instructions.push_back(std::move(ic));
        }
        ssa.basicBlocks.push_back(std::move(copy));
    }
    for (auto& mbb : ssa.basicBlocks) byAddr[mbb.start] = &mbb;

    Function domShape = adaptForDominatorTree(ssa.entry, ssa.basicBlocks);
    analysis::DominatorTree dom(domShape);

    // --- Phi placement ---
    // defBlocks[var] = blocks containing a SetVar for that variable.
    std::unordered_map<std::string, std::unordered_set<Address>> defBlocks;
    std::unordered_map<std::string, MLILVar> varProto;
    for (auto& mbb : ssa.basicBlocks) {
        for (auto& instr : mbb.instructions) {
            for (auto& e : instr.expressions) {
                std::unordered_map<std::string, MLILVar> seen;
                collectVarsRecursive(e, seen);
                for (auto& [key, v] : seen) {
                    varProto[key] = v;
                    if (e->op == MLILOp::SetVar && varKey(e->var) == key) defBlocks[key].insert(mbb.start);
                }
            }
        }
    }

    std::unordered_map<std::string, std::unordered_set<Address>> hasPhi;
    std::unordered_map<Address, std::vector<MLILExprPtr>> phisByBlock;
    for (auto& [key, defs] : defBlocks) {
        std::queue<Address> worklist;
        for (auto b : defs) worklist.push(b);
        while (!worklist.empty()) {
            Address b = worklist.front();
            worklist.pop();
            for (Address d : dom.dominanceFrontier(b)) {
                if (hasPhi[key].count(d)) continue;
                hasPhi[key].insert(d);
                auto phi = MLILExpr::make(MLILOp::Phi);
                phi->var = varProto[key];
                phi->var.version = -1; // assigned during renaming
                phi->operands.assign(byAddr[d]->predecessors.size(), nullptr);
                phisByBlock[d].push_back(phi);
                if (!defBlocks[key].count(d)) worklist.push(d);
            }
        }
    }
    for (auto& [addr, phis] : phisByBlock) {
        MLILInstruction phiInstr;
        phiInstr.address = addr;
        phiInstr.expressions = phis;
        byAddr[addr]->instructions.insert(byAddr[addr]->instructions.begin(), std::move(phiInstr));
    }

    // --- Renaming ---
    // Dominator-tree children, derived from idom().
    std::unordered_map<Address, std::vector<Address>> domChildren;
    for (Address b : dom.reversePostorder()) {
        Address idom = dom.immediateDominator(b);
        if (idom != b) domChildren[idom].push_back(b);
    }

    std::unordered_map<std::string, std::vector<int>> stacks;
    std::unordered_map<std::string, int> nextVersion;
    // Version 0 is reserved for "read with no preceding definition on this
    // path" (function parameters, callee-saved registers read before any
    // local write, etc.) — every variable that appears anywhere starts
    // with an implicit version-0 value available to read.
    for (auto& [key, v] : varProto) {
        stacks[key] = {0};
        nextVersion[key] = 1;
    }

    std::function<MLILExprPtr(const MLILExprPtr&)> renameReads =
        [&](const MLILExprPtr& e) -> MLILExprPtr {
        if (!e) return e;
        if (e->op == MLILOp::Var) {
            auto& st = stacks[varKey(e->var)];
            e->var.version = st.empty() ? 0 : st.back();
            return e;
        }
        for (auto& o : e->operands) o = renameReads(o);
        return e;
    };

    std::function<void(Address)> renameBlock = [&](Address addr) {
        MLILBasicBlock& bb = *byAddr[addr];
        std::unordered_map<std::string, int> pushedCount;
        auto pushDef = [&](MLILVar& var) {
            std::string key = varKey(var);
            int v = nextVersion[key]++;
            stacks[key].push_back(v);
            pushedCount[key]++;
            var.version = v;
        };

        for (auto& instr : bb.instructions) {
            for (auto& e : instr.expressions) {
                if (e->op == MLILOp::Phi) {
                    pushDef(e->var);
                } else if (e->op == MLILOp::SetVar) {
                    if (!e->operands.empty()) e->operands[0] = renameReads(e->operands[0]);
                    pushDef(e->var);
                } else {
                    for (auto& o : e->operands) o = renameReads(o);
                }
            }
        }

        for (Address succAddr : bb.successors) {
            auto it = byAddr.find(succAddr);
            if (it == byAddr.end()) continue;
            MLILBasicBlock& succ = *it->second;
            int predIndex = -1;
            for (std::size_t i = 0; i < succ.predecessors.size(); ++i) {
                if (succ.predecessors[i] == addr) {
                    predIndex = static_cast<int>(i);
                    break;
                }
            }
            if (predIndex < 0) continue;
            for (auto& instr : succ.instructions) {
                for (auto& e : instr.expressions) {
                    if (e->op != MLILOp::Phi) continue;
                    std::string key = varKey(e->var);
                    auto& st = stacks[key];
                    auto read = MLILExpr::make(MLILOp::Var);
                    read->var = e->var;
                    read->var.version = st.empty() ? 0 : st.back();
                    e->operands[static_cast<std::size_t>(predIndex)] = read;
                }
            }
        }

        for (Address child : domChildren[addr]) renameBlock(child);

        for (auto& [key, count] : pushedCount) {
            auto& st = stacks[key];
            for (int i = 0; i < count; ++i) st.pop_back();
        }
    };

    renameBlock(domShape.entry);
    return ssa;
}

} // namespace compass::core::il
