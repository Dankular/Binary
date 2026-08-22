#pragma once

#include "compass/core/function.hpp"
#include "compass/core/types.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace compass::core::analysis {

/// Dominator tree + dominance frontiers over a Function's basic-block CFG,
/// keyed by block start address. Used by MLIL SSA construction (phi
/// placement) and HLIL loop structuring (back-edge / natural-loop
/// detection). Computed with the Cooper/Harvey/Kennedy iterative algorithm
/// ("A Simple, Fast Dominance Algorithm") — a fixpoint iteration over
/// reverse postorder, which is correct for irreducible CFGs too (just
/// converges in more iterations), not only the structured/reducible case.
class DominatorTree {
public:
    explicit DominatorTree(const Function& fn);

    /// Immediate dominator of `block`; equals `block` itself for the entry
    /// block, 0/not-found for unreachable blocks.
    Address immediateDominator(Address block) const;

    /// True if `a` dominates `b` (every path from the entry to `b` passes
    /// through `a`); every block dominates itself.
    bool dominates(Address a, Address b) const;

    /// Dominance frontier of `block`: the set of blocks where `block`'s
    /// dominance "runs out" — exactly the blocks phi functions for
    /// variables defined in `block` need to be placed at.
    const std::unordered_set<Address>& dominanceFrontier(Address block) const;

    /// All blocks in reverse postorder from the entry (unreachable blocks
    /// excluded) — a safe traversal order for most forward dataflow.
    const std::vector<Address>& reversePostorder() const { return rpo_; }

private:
    std::unordered_map<Address, Address> idom_;
    std::unordered_map<Address, std::unordered_set<Address>> domFrontier_;
    std::vector<Address> rpo_;
};

} // namespace compass::core::analysis
