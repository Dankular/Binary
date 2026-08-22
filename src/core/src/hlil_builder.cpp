// MLIL -> HLIL structuring. See hlil_builder.hpp for scope. The two shapes
// recognized (if/else diamonds, simple while loops) are each detected via
// DominatorTree, not by pattern-matching instruction sequences — that's
// what makes this work unmodified across architectures, same as the
// LLIL/MLIL passes below it.

#include "compass/core/analysis/dominators.hpp"
#include "compass/core/il/hlil_builder.hpp"

#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace compass::core::il {

namespace {

struct ExitInfo {
    enum class Kind { If, Goto, Return, Fallthrough, Dead } kind = Kind::Dead;
    MLILExprPtr condition;
    Address trueTarget = 0, falseTarget = 0;
    Address gotoTarget = 0;
};

/// Splits a block into its ordinary statements plus how control leaves it.
/// Call is deliberately treated as an ordinary mid-block statement (not a
/// terminator) — it doesn't end a basic block in this backend's model
/// (radare2/Rizin only split blocks at jmp/cjmp/ret), matching what
/// mlil_builder.cpp/llil_lifter.cpp already assume.
///
/// The control-flow expression (If/Goto/Ret) is found by scanning the
/// *whole* block for the last one, not by assuming it's the last
/// instruction's last expression — that assumption broke on real MIPS
/// binaries (multiarch_smoke_test.sh): a branch's delay-slot instruction
/// is placed *after* the branch in program order, so the If expression
/// sat second-to-last, not last. The naive version silently fell through
/// to treating that If as an ordinary Expr statement — which renders using
/// MLIL's raw `if (cond) goto X else Y` form since that's what
/// render(MLILExpr) produces for a bare If node, so it looked plausible
/// enough to be easy to miss, and the block's real exit was left `Dead`
/// (no structuring, no fallback goto — silently truncated CFG). Scanning
/// for the last control-flow expression regardless of position fixes the
/// detection; the delay-slot instruction still renders as an ordinary
/// statement, just not necessarily in its hardware-accurate position
/// relative to the branch — a known, minor simplification, not a silent
/// CFG error.
std::pair<HLILBody, ExitInfo> flattenBlock(const MLILBasicBlock& bb) {
    struct Flat {
        Address instrAddress;
        MLILExprPtr expr;
    };
    std::vector<Flat> flat;
    for (const auto& instr : bb.instructions) {
        for (const auto& e : instr.expressions) flat.push_back({instr.address, e});
    }

    std::optional<std::size_t> exitIndex;
    for (std::size_t i = 0; i < flat.size(); ++i) {
        auto op = flat[i].expr->op;
        if (op == MLILOp::If || op == MLILOp::Goto || op == MLILOp::Ret) exitIndex = i;
    }

    ExitInfo exit;
    HLILBody stmts;
    for (std::size_t i = 0; i < flat.size(); ++i) {
        if (exitIndex && i == *exitIndex) {
            const auto& e = flat[i].expr;
            if (e->op == MLILOp::If) {
                exit.kind = ExitInfo::Kind::If;
                exit.condition = e->operands.empty() ? nullptr : e->operands[0];
                exit.trueTarget = e->trueTarget;
                exit.falseTarget = e->falseTarget;
            } else if (e->op == MLILOp::Goto) {
                exit.kind = ExitInfo::Kind::Goto;
                exit.gotoTarget = e->trueTarget;
            } else {
                exit.kind = ExitInfo::Kind::Return;
            }
            continue;
        }
        HLILStatement s;
        s.kind = HLILStatementKind::Expr;
        s.expr = flat[i].expr;
        s.originAddress = flat[i].instrAddress;
        stmts.push_back(std::move(s));
    }
    if (exit.kind == ExitInfo::Kind::Dead && bb.successors.size() == 1) {
        exit.kind = ExitInfo::Kind::Fallthrough;
        exit.gotoTarget = bb.successors[0];
    }
    return {std::move(stmts), exit};
}

struct Ctx {
    std::unordered_map<Address, const MLILBasicBlock*> byAddr;
    analysis::DominatorTree* dom = nullptr;
    std::unordered_set<Address> loopHeaders;
    std::unordered_map<Address, std::vector<Address>> loopBody; // header -> body (incl. header)
    std::unordered_set<Address> emitted;
};

/// Finds the merge point of a branch at `header` with arms `t`/`f`: the
/// nearest block whose immediate dominator is `header` itself (not `t` or
/// `f`) and which has more than one predecessor — the standard signature
/// of "both arms flow back together here" (see hlil_builder.hpp's header
/// comment; if T or F alone dominated it, it would belong to one arm, not
/// be a reconvergence). Returns nullopt if no such block exists (an
/// unstructurable/irreducible shape) — the caller falls back to Goto.
std::optional<Address> findMerge(Address header, Ctx& ctx) {
    auto& rpo = ctx.dom->reversePostorder();
    for (Address candidate : rpo) {
        if (candidate == header) continue;
        if (!ctx.byAddr.count(candidate)) continue;
        if (ctx.dom->immediateDominator(candidate) != header) continue;
        if (ctx.byAddr[candidate]->predecessors.size() < 2) continue;
        return candidate;
    }
    return std::nullopt;
}

HLILBody structureRegion(Address start, std::optional<Address> continuation, Ctx& ctx);

HLILStatement makeGoto(Address target) {
    HLILStatement g;
    g.kind = HLILStatementKind::Goto;
    g.target = target;
    return g;
}

MLILExprPtr negate(const MLILExprPtr& cond) {
    // No dedicated Not op in MLIL (mirrors LLIL's same choice, see
    // llil_lifter.cpp) — wrapped in Unimplemented rather than guessed, but
    // still carries the real condition as its operand so it's not opaque.
    auto n = MLILExpr::make(MLILOp::Unimplemented);
    n->text = "!";
    n->operands = {cond};
    return n;
}

HLILBody structureRegion(Address start, std::optional<Address> continuation, Ctx& ctx) {
    HLILBody result;
    Address current = start;
    bool stop = false;

    while (!stop) {
        if (continuation && current == *continuation) break;
        if (!ctx.byAddr.count(current)) break;
        if (ctx.emitted.count(current)) {
            result.push_back(makeGoto(current));
            break;
        }

        if (ctx.loopHeaders.count(current) && !ctx.emitted.count(current)) {
            ctx.emitted.insert(current);
            const auto& bb = *ctx.byAddr[current];
            auto [stmts, exit] = flattenBlock(bb);
            for (auto& s : stmts) result.push_back(std::move(s));

            const auto& body = ctx.loopBody[current];
            std::unordered_set<Address> bodySet(body.begin(), body.end());

            bool structured = false;
            if (exit.kind == ExitInfo::Kind::If) {
                bool trueInBody = bodySet.count(exit.trueTarget) != 0;
                bool falseInBody = bodySet.count(exit.falseTarget) != 0;
                if (trueInBody != falseInBody) {
                    Address bodyEntry = trueInBody ? exit.trueTarget : exit.falseTarget;
                    Address exitTarget = trueInBody ? exit.falseTarget : exit.trueTarget;
                    MLILExprPtr cond = trueInBody ? exit.condition : negate(exit.condition);

                    HLILStatement w;
                    w.kind = HLILStatementKind::While;
                    w.expr = cond;
                    w.originAddress = current;
                    w.body = structureRegion(bodyEntry, current, ctx);
                    result.push_back(std::move(w));
                    current = exitTarget;
                    structured = true;
                }
            }

            if (!structured) {
                // Honest fallback: couldn't cleanly extract a single
                // condition/exit — emit the header as a label and its
                // branch as explicit gotos rather than mislabeling this as
                // a clean while loop.
                HLILStatement label;
                label.kind = HLILStatementKind::Label;
                label.target = current;
                result.push_back(std::move(label));
                for (Address a : body) {
                    if (a != current) ctx.emitted.insert(a);
                }
                if (exit.kind == ExitInfo::Kind::If) {
                    HLILStatement ifs;
                    ifs.kind = HLILStatementKind::If;
                    ifs.expr = exit.condition;
                    ifs.originAddress = current;
                    ifs.thenBody.push_back(makeGoto(exit.trueTarget));
                    ifs.elseBody.push_back(makeGoto(exit.falseTarget));
                    result.push_back(std::move(ifs));
                } else if (exit.kind == ExitInfo::Kind::Goto || exit.kind == ExitInfo::Kind::Fallthrough) {
                    result.push_back(makeGoto(exit.gotoTarget));
                } else if (exit.kind == ExitInfo::Kind::Return) {
                    HLILStatement r;
                    r.kind = HLILStatementKind::Return;
                    result.push_back(std::move(r));
                }
                stop = true;
            }
            continue;
        }

        ctx.emitted.insert(current);
        const auto& bb = *ctx.byAddr[current];
        auto [stmts, exit] = flattenBlock(bb);
        for (auto& s : stmts) result.push_back(std::move(s));

        switch (exit.kind) {
            case ExitInfo::Kind::Return: {
                HLILStatement r;
                r.kind = HLILStatementKind::Return;
                result.push_back(std::move(r));
                stop = true;
                break;
            }
            case ExitInfo::Kind::Goto:
            case ExitInfo::Kind::Fallthrough:
                current = exit.gotoTarget;
                break;
            case ExitInfo::Kind::If: {
                auto merge = findMerge(current, ctx);
                HLILStatement ifs;
                ifs.kind = HLILStatementKind::If;
                ifs.expr = exit.condition;
                ifs.originAddress = current;
                ifs.thenBody = structureRegion(exit.trueTarget, merge, ctx);
                if (!(merge && *merge == exit.falseTarget)) {
                    ifs.elseBody = structureRegion(exit.falseTarget, merge, ctx);
                }
                result.push_back(std::move(ifs));
                if (merge) {
                    current = *merge;
                } else {
                    stop = true;
                }
                break;
            }
            case ExitInfo::Kind::Dead:
                stop = true;
                break;
        }
    }
    return result;
}

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

} // namespace

HLILFunction buildHlil(const MLILFunction& mlil) {
    HLILFunction hlil;
    if (mlil.basicBlocks.empty()) return hlil;

    Ctx ctx;
    for (auto& bb : mlil.basicBlocks) ctx.byAddr[bb.start] = &bb;

    Function domShape = adaptForDominatorTree(mlil.entry, mlil.basicBlocks);
    analysis::DominatorTree dom(domShape);
    ctx.dom = &dom;

    // Back edges: B -> H where H dominates B. Natural loop body of H =
    // union, over every such B, of {H} plus every block that can reach B
    // by walking predecessors without passing through H.
    std::unordered_map<Address, std::unordered_set<Address>> loopBodySets;
    for (auto& bb : mlil.basicBlocks) {
        for (Address succ : bb.successors) {
            if (ctx.byAddr.count(succ) && dom.dominates(succ, bb.start)) {
                Address header = succ;
                auto& body = loopBodySets[header];
                if (body.empty()) body.insert(header);
                if (body.insert(bb.start).second) {
                    std::vector<Address> worklist = {bb.start};
                    while (!worklist.empty()) {
                        Address m = worklist.back();
                        worklist.pop_back();
                        auto it = ctx.byAddr.find(m);
                        if (it == ctx.byAddr.end()) continue;
                        for (Address p : it->second->predecessors) {
                            if (body.insert(p).second) worklist.push_back(p);
                        }
                    }
                }
            }
        }
    }
    for (auto& [header, set] : loopBodySets) {
        ctx.loopHeaders.insert(header);
        ctx.loopBody[header].assign(set.begin(), set.end());
    }

    hlil.statements = structureRegion(mlil.entry, std::nullopt, ctx);
    return hlil;
}

} // namespace compass::core::il
