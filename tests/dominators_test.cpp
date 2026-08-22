// Unit test for DominatorTree against hand-built CFGs with known answers —
// isolates bugs here before MLIL SSA (phi placement) and HLIL (loop/if-else
// structuring) build on top of it, where a dominator bug would be much
// harder to trace back to its source.
#include "compass/core/analysis/dominators.hpp"

#include <cstdio>
#include <cstdlib>

using namespace compass::core;
using namespace compass::core::analysis;

namespace {

int failures = 0;

void check(bool cond, const char* what) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

BasicBlock block(Address start, Address end, std::vector<Address> successors) {
    BasicBlock bb;
    bb.start = start;
    bb.end = end;
    bb.successors = std::move(successors);
    return bb;
}

// Diamond: A -> {B, C}, B -> D, C -> D. Classic if/else shape.
void testDiamond() {
    Function fn;
    fn.entry = 0x100;
    fn.basicBlocks = {
        block(0x100, 0x110, {0x200, 0x300}),
        block(0x200, 0x210, {0x400}),
        block(0x300, 0x310, {0x400}),
        block(0x400, 0x410, {}),
    };
    DominatorTree dom(fn);
    check(dom.immediateDominator(0x100) == 0x100, "diamond: A idom is itself");
    check(dom.immediateDominator(0x200) == 0x100, "diamond: B idom is A");
    check(dom.immediateDominator(0x300) == 0x100, "diamond: C idom is A");
    check(dom.immediateDominator(0x400) == 0x100, "diamond: D idom is A (not B or C)");
    check(dom.dominates(0x100, 0x400), "diamond: A dominates D");
    check(!dom.dominates(0x200, 0x400), "diamond: B does NOT dominate D");
    // D has two preds (B, C); dominance frontier of B and C is {D}.
    check(dom.dominanceFrontier(0x200).count(0x400) == 1, "diamond: DF(B) contains D");
    check(dom.dominanceFrontier(0x300).count(0x400) == 1, "diamond: DF(C) contains D");
    check(dom.dominanceFrontier(0x100).empty(), "diamond: DF(A) is empty");
}

// Natural loop: A -> B, B -> C, C -> B (back edge), C -> D (exit).
void testLoop() {
    Function fn;
    fn.entry = 0x100;
    fn.basicBlocks = {
        block(0x100, 0x110, {0x200}),
        block(0x200, 0x210, {0x300}),
        block(0x300, 0x310, {0x200, 0x400}), // back edge to header B
        block(0x400, 0x410, {}),
    };
    DominatorTree dom(fn);
    check(dom.immediateDominator(0x200) == 0x100, "loop: header B idom is A");
    check(dom.immediateDominator(0x300) == 0x200, "loop: C idom is B");
    check(dom.immediateDominator(0x400) == 0x300, "loop: exit D idom is C");
    check(dom.dominates(0x200, 0x300), "loop: header dominates body");
    check(dom.dominates(0x200, 0x200), "loop: block dominates itself");
    // Back edge C->B means B is in the dominance frontier of C (and of B
    // itself, since the edge B->C->B loops back to B without C
    // dominating B).
    check(dom.dominanceFrontier(0x300).count(0x200) == 1, "loop: DF(C) contains header B (back edge)");
}

// Unreachable block: E has no path from entry.
void testUnreachable() {
    Function fn;
    fn.entry = 0x100;
    fn.basicBlocks = {
        block(0x100, 0x110, {0x200}),
        block(0x200, 0x210, {}),
        block(0x900, 0x910, {}), // unreachable
    };
    DominatorTree dom(fn);
    check(dom.immediateDominator(0x900) == 0, "unreachable block has no idom");
    check(!dom.dominates(0x100, 0x900), "entry does not dominate an unreachable block");
}

} // namespace

int main() {
    testDiamond();
    testLoop();
    testUnreachable();
    if (failures == 0) {
        std::printf("ALL DOMINATOR TESTS PASSED\n");
        return 0;
    }
    std::fprintf(stderr, "%d dominator test(s) FAILED\n", failures);
    return 1;
}
