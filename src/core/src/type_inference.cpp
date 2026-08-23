#include "compass/core/il/type_inference.hpp"

#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace compass::core::il {

namespace {

/// Identifies a variable by (kind, name), ignoring `version` — safe in
/// plain (non-SSA) MLIL, where version is always -1 and one name can be
/// assigned many times; every assignment/read of that name is the same
/// logical variable for typing purposes.
std::string varKey(const MLILVar& v) {
    return v.name + "#" + std::to_string(static_cast<int>(v.kind));
}

bool isSignedOp(MLILOp op) { return op == MLILOp::Sar || op == MLILOp::SDiv || op == MLILOp::SMod; }

/// Canonicalizes an x86-64 sub-register name to its full 64-bit name
/// (`eax`/`ax`/`al`/`ah` -> `rax`) — real, ISA-defined register aliasing
/// (all name the same physical storage), not a guess, and load-bearing
/// here: a value moved into a stack variable's register copy and a later
/// signed op's operand routinely name the *same* physical register at
/// *different* widths (verified directly: `rax = var_rbp_4` followed by
/// `sdiv(eax, ...)` in real -O0 output for the exact same register,
/// because `mov eax, [mem]` zero-extends into the full rax and ESIL names
/// the destination accordingly, while a later instruction's ESIL names its
/// own operand at whatever width *that* instruction actually reads).
/// Falls through unchanged for anything not in this table — other
/// architectures' registers, or already-canonical names — so this is
/// purely additive, never destructive of a name that didn't need aliasing.
const std::string& canonicalRegister(const std::string& name) {
    static const std::unordered_map<std::string, std::string> aliases = {
        {"eax", "rax"}, {"ax", "rax"}, {"al", "rax"}, {"ah", "rax"},
        {"ebx", "rbx"}, {"bx", "rbx"}, {"bl", "rbx"}, {"bh", "rbx"},
        {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"}, {"ch", "rcx"},
        {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"}, {"dh", "rdx"},
        {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"},
        {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"},
        {"ebp", "rbp"}, {"bp", "rbp"}, {"bpl", "rbp"},
        {"esp", "rsp"}, {"sp", "rsp"}, {"spl", "rsp"},
        {"r8d", "r8"}, {"r8w", "r8"}, {"r8b", "r8"},
        {"r9d", "r9"}, {"r9w", "r9"}, {"r9b", "r9"},
        {"r10d", "r10"}, {"r10w", "r10"}, {"r10b", "r10"},
        {"r11d", "r11"}, {"r11w", "r11"}, {"r11b", "r11"},
        {"r12d", "r12"}, {"r12w", "r12"}, {"r12b", "r12"},
        {"r13d", "r13"}, {"r13w", "r13"}, {"r13b", "r13"},
        {"r14d", "r14"}, {"r14w", "r14"}, {"r14b", "r14"},
        {"r15d", "r15"}, {"r15w", "r15"}, {"r15b", "r15"},
    };
    auto it = aliases.find(name);
    return it != aliases.end() ? it->second : name;
}

/// Collects every Var read reachable from `e` (recursing through the whole
/// expression tree, not just direct operands) — needed because a signed
/// op's actual operand is rarely a bare Var: even at -O0, x86's
/// div/idiv widen their dividend first (`add(eax, shl(edx, 0x20))`), so the
/// register reads this cares about sit a couple of levels down.
void collectVarReads(const MLILExprPtr& e, std::vector<MLILVar>& out) {
    if (!e) return;
    if (e->op == MLILOp::Var) out.push_back(e->var);
    for (auto& o : e->operands) collectVarReads(o, out);
}

/// Pass 1: collects the identity of every Stack variable with evidence of
/// being used as a signed value, walked per-block in instruction order so
/// register-copy provenance (`reg = stack_var`) can be tracked locally.
/// This local tracking is the difference between this actually firing on
/// real compiled code and not: at -O0 (what every fixture in this project
/// is built with), a signed op's operands are essentially always registers
/// loaded from a stack slot earlier in the same block
/// (`rax = var_rbp_4` ... `sdiv(eax, ...)`), never the stack variable
/// itself — checked directly against real `sdiv`/`sar` output, not
/// assumed, after an earlier version of this pass (matching only *direct*
/// stack-variable operands) turned out to never fire on any real fixture.
///
/// Still deliberately shallow beyond that one hop: a Stack variable
/// directly operated on, or a Register immediately and most-recently
/// copied from one. Not a full dataflow/taint analysis through arbitrary
/// arithmetic — so a positive here is always real, traceable evidence.
void collectSignedEvidence(MLILBasicBlock& bb, std::set<std::string>& signedVars) {
    std::unordered_map<std::string, std::string> lastCopiedFromStack; // register name -> stack var name

    std::function<void(const MLILExprPtr&)> walk = [&](const MLILExprPtr& e) {
        if (!e) return;

        // Post-order: a statement's value expression is evaluated before
        // the assignment it feeds "happens", so evidence inside that value
        // (e.g. a nested Sar/SDiv/SMod) must be collected using the
        // register-copy mapping as it stood *before* this statement's own
        // update below — not after. Getting this backwards was a real bug:
        // `eax = sar(eax, 0x2)` erased eax's mapping (its new value isn't
        // a plain stack-var copy) before the nested sar(eax, ...) had a
        // chance to look eax up, silently losing exactly the evidence this
        // pass exists to catch — caught by checking that sar_test's own
        // single variable actually came out signed, not by inspection.
        for (auto& o : e->operands) walk(o);

        if (isSignedOp(e->op)) {
            std::vector<MLILVar> reads;
            for (auto& o : e->operands) collectVarReads(o, reads);
            for (auto& v : reads) {
                if (v.kind == MLILVarKind::Stack) {
                    signedVars.insert(varKey(v));
                } else if (v.kind == MLILVarKind::Register) {
                    auto it = lastCopiedFromStack.find(canonicalRegister(v.name));
                    if (it != lastCopiedFromStack.end()) {
                        signedVars.insert(it->second + "#" +
                                           std::to_string(static_cast<int>(MLILVarKind::Stack)));
                    }
                }
            }
        }

        if (e->op == MLILOp::SetVar && e->var.kind == MLILVarKind::Stack && !e->operands.empty()) {
            auto& value = e->operands[0];
            if (value && isSignedOp(value->op)) signedVars.insert(varKey(e->var));
        }

        if (e->op == MLILOp::SetVar && e->var.kind == MLILVarKind::Register && !e->operands.empty()) {
            std::string reg = canonicalRegister(e->var.name);
            auto& value = e->operands[0];
            if (value && value->op == MLILOp::Var && value->var.kind == MLILVarKind::Stack) {
                lastCopiedFromStack[reg] = value->var.name;
            } else {
                // Register now holds something else — stale provenance
                // would misattribute a later signed use back to the wrong
                // stack variable, so drop it rather than leave it stale.
                lastCopiedFromStack.erase(reg);
            }
        }
    };

    for (auto& instr : bb.instructions) {
        for (auto& e : instr.expressions) walk(e);
    }
}

/// Pass 2: same width-based Stack-variable typing this pass has always
/// done, now assigning isSigned from pass 1's evidence instead of always
/// false.
void visit(const MLILExprPtr& e, const std::set<std::string>& signedVars) {
    if (!e) return;
    if ((e->op == MLILOp::Var || e->op == MLILOp::SetVar || e->op == MLILOp::Phi) &&
        e->var.kind == MLILVarKind::Stack && e->var.widthHint > 0 && !e->var.type) {
        bool isSigned = signedVars.count(varKey(e->var)) != 0;
        e->var.type = Type::makeInt(e->var.widthHint, isSigned);
    }
    for (auto& o : e->operands) visit(o, signedVars);
}

} // namespace

void attachTypes(MLILFunction& mlil) {
    std::set<std::string> signedVars;
    for (auto& bb : mlil.basicBlocks) collectSignedEvidence(bb, signedVars);
    for (auto& bb : mlil.basicBlocks) {
        for (auto& instr : bb.instructions) {
            for (auto& e : instr.expressions) visit(e, signedVars);
        }
    }
}

} // namespace compass::core::il
