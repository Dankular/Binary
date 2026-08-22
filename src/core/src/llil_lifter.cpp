// ESIL -> LLIL lifter.
//
// ESIL (radare2/Rizin's instruction semantics language) is a comma-separated
// RPN stack machine. This file implements a generic evaluator over the
// operator subset needed to correctly lift straight-line data flow for
// common x86-64 instructions (mov/lea/arithmetic/push/pop/flag-assignment),
// plus dedicated handling of control-flow instructions (jmp/cjmp/call/ret)
// which is driven by the backend's structured jump/fail targets rather than
// by parsing branch conditions out of ESIL text — more robust, and matches
// how a real disassembly backend's structured output should be consumed.
//
// Anything outside that operator subset (comparison-flag pseudo-ops like
// $z/$s/$o, indirect branch targets, etc.) lifts to an explicit
// `Unimplemented` leaf carrying the original ESIL token rather than being
// silently misinterpreted. See docs/ARCHITECTURE.md for the rationale.

#include "compass/core/il/lifter.hpp"

#include <cctype>
#include <cstdlib>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace compass::core::il {

namespace {

bool isFlagName(const std::string& tok) {
    static const std::set<std::string> flags = {"zf", "cf", "sf", "of", "pf", "af", "df", "if", "tf"};
    return flags.count(tok) != 0;
}

/// Number of stack arguments a `$`-prefixed ESIL pseudo-op consumes, beyond
/// pushing its (unmodeled) result. Only the ones actually observed in
/// practice are listed; anything else defaults to 0 so the stack discipline
/// stays balanced for whatever chain of flag assignments follows it.
int pseudoOpArgCount(const std::string& tok) {
    if (tok == "$b" || tok == "$c") return 1;
    return 0;
}

std::optional<std::uint64_t> parseNumber(const std::string& tok) {
    if (tok.empty()) return std::nullopt;
    char* end = nullptr;
    unsigned long long v = std::strtoull(tok.c_str(), &end, 0);
    if (end != tok.c_str() + tok.size()) return std::nullopt;
    return static_cast<std::uint64_t>(v);
}

/// Parses a `[n]` or `=[n]` token, returning (isStore, sizeInBytes).
std::optional<std::pair<bool, int>> parseMemToken(const std::string& tok) {
    bool store = false;
    std::string t = tok;
    if (!t.empty() && t[0] == '=') {
        store = true;
        t = t.substr(1);
    }
    if (t.size() < 3 || t.front() != '[' || t.back() != ']') return std::nullopt;
    std::string inner = t.substr(1, t.size() - 2);
    auto n = parseNumber(inner);
    if (!n) return std::nullopt;
    return std::make_pair(store, static_cast<int>(*n));
}

std::vector<std::string> splitEsil(const std::string& esil) {
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : esil) {
        if (c == ',') {
            tokens.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

/// Generic ESIL RPN evaluator. Pushes value expressions onto `stack`;
/// side-effecting ops (assignments, stores) are appended to `out` as
/// standalone statements as they're encountered.
class EsilEvaluator {
public:
    explicit EsilEvaluator(std::vector<LLILExprPtr>& stack, std::vector<LLILExprPtr>& out)
        : stack_(stack), out_(out) {}

    void run(const std::vector<std::string>& tokens) {
        std::size_t i = 0;
        while (i < tokens.size()) {
            const std::string& tok = tokens[i];
            if (tok == "?{") {
                // Conditional block: pop the condition (its truth value
                // governs whether the following block executes at ESIL
                // *evaluation* time). We don't model that trace-time
                // conditionality, so — conservatively, and honestly —
                // skip the block's body entirely rather than evaluating it
                // unconditionally: branch instructions (cjmp) never reach
                // here (see liftInstruction), so any "?{" seen here belongs
                // to a straight-line instruction we don't yet model well
                // enough to get right (e.g. setcc-style conditional
                // assignment); its effect is recorded as Unimplemented.
                pop();
                auto e = LLILExpr::make(LLILOp::Unimplemented);
                e->text = "conditional-block";
                out_.push_back(e);
                std::size_t depth = 1;
                ++i;
                while (i < tokens.size() && depth > 0) {
                    if (tokens[i] == "?{") ++depth;
                    else if (tokens[i] == "}") --depth;
                    ++i;
                }
                continue;
            }
            step(tok);
            ++i;
        }
    }

private:
    std::vector<LLILExprPtr>& stack_;
    std::vector<LLILExprPtr>& out_;

    LLILExprPtr pop() {
        if (stack_.empty()) {
            auto e = LLILExpr::make(LLILOp::Unimplemented);
            e->text = "<stack underflow>";
            return e;
        }
        auto v = stack_.back();
        stack_.pop_back();
        return v;
    }

    void push(LLILExprPtr e) { stack_.push_back(std::move(e)); }

    LLILExprPtr binOp(LLILOp op) {
        // Per ESIL's stack convention (verified against real radare2 output
        // in docs/ARCHITECTURE.md's development notes): for "A,B,OP" the
        // result is B OP A — i.e. (first-popped == top == B) op
        // (second-popped == A).
        auto b = pop();
        auto a = pop();
        auto e = LLILExpr::make(op);
        e->operands = {b, a};
        return e;
    }

    void assign(bool isCompound, LLILOp compoundOp) {
        auto target = pop();
        auto value = pop();

        LLILExprPtr finalValue = value;
        if (isCompound) {
            auto e = LLILExpr::make(compoundOp);
            auto targetRead = LLILExpr::make(target->op); // Reg or Flag read of the same name
            targetRead->regOrFlag = target->regOrFlag;
            e->operands = {targetRead, value};
            finalValue = e;
        }

        if (target->op == LLILOp::Reg) {
            auto s = LLILExpr::make(LLILOp::SetReg);
            s->regOrFlag = target->regOrFlag;
            s->operands = {finalValue};
            out_.push_back(s);
        } else if (target->op == LLILOp::Flag) {
            auto s = LLILExpr::make(LLILOp::SetFlag);
            s->regOrFlag = target->regOrFlag;
            s->operands = {finalValue};
            out_.push_back(s);
        } else {
            auto s = LLILExpr::make(LLILOp::Unimplemented);
            s->text = "assign-to-non-lvalue";
            s->operands = {target, finalValue};
            out_.push_back(s);
        }
    }

    void step(const std::string& tok) {
        if (tok.empty()) return;

        if (auto n = parseNumber(tok)) {
            auto e = LLILExpr::make(LLILOp::Const);
            e->constValue = *n;
            push(e);
            return;
        }

        if (tok == "=" || tok == ":=") {
            assign(false, LLILOp::Nop);
            return;
        }

        static const std::vector<std::pair<std::string, LLILOp>> compound = {
            {"+=", LLILOp::Add}, {"-=", LLILOp::Sub}, {"*=", LLILOp::Mul}, {"/=", LLILOp::Div},
            {"&=", LLILOp::And}, {"|=", LLILOp::Or},  {"^=", LLILOp::Xor}, {"<<=", LLILOp::Shl},
            {">>=", LLILOp::Shr},
        };
        for (auto& [sym, op] : compound) {
            if (tok == sym) {
                assign(true, op);
                return;
            }
        }

        static const std::vector<std::pair<std::string, LLILOp>> binops = {
            {"+", LLILOp::Add}, {"-", LLILOp::Sub}, {"*", LLILOp::Mul}, {"/", LLILOp::Div},
            {"&", LLILOp::And}, {"|", LLILOp::Or},  {"^", LLILOp::Xor}, {"<<", LLILOp::Shl},
            {">>", LLILOp::Shr}, {"==", LLILOp::Cmp}, {"<", LLILOp::Cmp}, {">", LLILOp::Cmp},
            {"<=", LLILOp::Cmp}, {">=", LLILOp::Cmp},
        };
        for (auto& [sym, op] : binops) {
            if (tok == sym) {
                push(binOp(op));
                return;
            }
        }

        if (tok == "!") {
            auto a = pop();
            auto e = LLILExpr::make(LLILOp::Unimplemented);
            e->text = "!";
            e->operands = {a};
            push(e);
            return;
        }

        if (auto mem = parseMemToken(tok)) {
            auto [isStore, size] = *mem;
            if (isStore) {
                auto address = pop();
                auto value = pop();
                auto s = LLILExpr::make(LLILOp::Store);
                s->constValue = static_cast<std::uint64_t>(size);
                s->operands = {address, value};
                out_.push_back(s);
            } else {
                auto address = pop();
                auto e = LLILExpr::make(LLILOp::Load);
                e->constValue = static_cast<std::uint64_t>(size);
                e->operands = {address};
                push(e);
            }
            return;
        }

        if (!tok.empty() && tok[0] == '$') {
            for (int i = 0; i < pseudoOpArgCount(tok); ++i) pop();
            auto e = LLILExpr::make(LLILOp::Unimplemented);
            e->text = tok;
            push(e);
            return;
        }

        // Bare identifier: register or flag read.
        bool isIdent = std::isalpha(static_cast<unsigned char>(tok[0])) || tok[0] == '_';
        if (isIdent) {
            auto e = LLILExpr::make(isFlagName(tok) ? LLILOp::Flag : LLILOp::Reg);
            e->regOrFlag = tok;
            push(e);
            return;
        }

        // Unknown token shape (radare2 has many more ESIL operators than
        // this milestone models — e.g. "DUP", "POP", "CLEAR", trap/syscall
        // pseudo-ops). Recorded honestly rather than guessed.
        auto e = LLILExpr::make(LLILOp::Unimplemented);
        e->text = tok;
        push(e);
    }
};

LLILExprPtr constAddr(Address a) {
    auto e = LLILExpr::make(LLILOp::Const);
    e->constValue = a;
    return e;
}

void liftInstruction(const Instruction& insn, LLILInstruction& out) {
    out.address = insn.address;

    // Control-flow instructions: synthesize dedicated LLIL nodes from the
    // backend's structured targets instead of interpreting branch-condition
    // ESIL. This is both more robust and closer to how BNIL actually
    // presents these (`jump(...)`, `if (...) then ... else ...`,
    // `call(...)`, `<return>`) rather than raw register assignments.
    const std::string& t = insn.opType;
    if (t == "jmp" || t == "ujmp" || t == "irjmp" || t == "rjmp") {
        auto e = LLILExpr::make(LLILOp::Goto);
        if (insn.jumpTarget) {
            e->trueTarget = *insn.jumpTarget;
        } else {
            e->op = LLILOp::Unimplemented;
            e->text = "indirect-jmp";
        }
        out.expressions.push_back(e);
        return;
    }
    if (t == "cjmp") {
        auto e = LLILExpr::make(LLILOp::If);
        if (insn.jumpTarget) e->trueTarget = *insn.jumpTarget;
        if (insn.failTarget) e->falseTarget = *insn.failTarget;
        // Best-effort condition: evaluate the esil prefix up to "?{" so the
        // reader sees *something* of the flag logic, even though individual
        // flag reads may themselves be Unimplemented leaves (see above).
        std::vector<LLILExprPtr> stack, discardedStatements;
        EsilEvaluator eval(stack, discardedStatements);
        auto tokens = splitEsil(insn.esil);
        for (auto& tok : tokens) {
            if (tok == "?{") break;
            eval.run({tok});
        }
        e->operands = {stack.empty() ? LLILExpr::make(LLILOp::Unimplemented) : stack.back()};
        out.expressions.push_back(e);
        return;
    }
    if (t == "call" || t == "ucall" || t == "rcall" || t == "icall") {
        auto e = LLILExpr::make(LLILOp::Call);
        if (insn.jumpTarget) {
            e->operands = {constAddr(*insn.jumpTarget)};
        } else {
            auto u = LLILExpr::make(LLILOp::Unimplemented);
            u->text = "indirect-call";
            e->operands = {u};
        }
        out.expressions.push_back(e);
        return;
    }
    if (t == "ret" || t == "cret") {
        out.expressions.push_back(LLILExpr::make(LLILOp::Ret));
        return;
    }

    // Straight-line instruction: run the generic ESIL evaluator. Any
    // side-effecting op (SetReg/SetFlag/Store) it encounters is appended to
    // out.expressions directly; a purely value-producing tail (e.g. `nop`,
    // or a comparison whose result only feeds unmodeled flag pseudo-ops) is
    // fine to leave unconsumed.
    auto tokens = splitEsil(insn.esil);
    if (tokens.empty()) {
        out.expressions.push_back(LLILExpr::make(LLILOp::Nop));
        return;
    }
    std::vector<LLILExprPtr> stack;
    EsilEvaluator eval(stack, out.expressions);
    eval.run(tokens);
    if (out.expressions.empty()) {
        // Nothing side-effecting happened (e.g. a bare comparison) — still
        // record something so `pdj`-style output isn't silently dropped.
        auto e = LLILExpr::make(LLILOp::Nop);
        out.expressions.push_back(e);
    }
}

} // namespace

void liftFunctionLLIL(Function& fn) {
    LLILFunction llil;
    for (auto& bb : fn.basicBlocks) {
        for (auto& insn : bb.instructions) {
            LLILInstruction li;
            liftInstruction(insn, li);
            llil.instructions.push_back(std::move(li));
        }
    }
    fn.llil = std::move(llil);
}

} // namespace compass::core::il
