#include "compass/core/analysis/dominators.hpp"

#include <algorithm>

namespace compass::core::analysis {

namespace {

void dfsPostorder(Address start, const std::unordered_map<Address, const BasicBlock*>& byAddr,
                   std::unordered_set<Address>& visited, std::vector<Address>& postorder) {
    // Iterative DFS to avoid stack-depth issues on large functions.
    struct Frame {
        Address addr;
        std::size_t nextSuccessor;
    };
    std::vector<Frame> stack;
    visited.insert(start);
    stack.push_back({start, 0});
    while (!stack.empty()) {
        auto& frame = stack.back();
        auto it = byAddr.find(frame.addr);
        const auto& successors = (it != byAddr.end()) ? it->second->successors : std::vector<Address>{};
        if (frame.nextSuccessor < successors.size()) {
            Address succ = successors[frame.nextSuccessor++];
            if (byAddr.count(succ) && visited.insert(succ).second) {
                stack.push_back({succ, 0});
            }
        } else {
            postorder.push_back(frame.addr);
            stack.pop_back();
        }
    }
}

} // namespace

DominatorTree::DominatorTree(const Function& fn) {
    if (fn.basicBlocks.empty()) return;

    std::unordered_map<Address, const BasicBlock*> byAddr;
    for (auto& bb : fn.basicBlocks) byAddr[bb.start] = &bb;

    Address entry = fn.entry;
    if (!byAddr.count(entry)) entry = fn.basicBlocks.front().start;

    std::unordered_set<Address> visited;
    std::vector<Address> postorder;
    dfsPostorder(entry, byAddr, visited, postorder);
    rpo_.assign(postorder.rbegin(), postorder.rend());

    std::unordered_map<Address, int> rpoIndex;
    for (std::size_t i = 0; i < rpo_.size(); ++i) rpoIndex[rpo_[i]] = static_cast<int>(i);

    // Predecessors restricted to reachable blocks, in RPO-friendly form.
    std::unordered_map<Address, std::vector<Address>> preds;
    for (auto addr : rpo_) {
        auto* bb = byAddr.at(addr);
        for (auto succ : bb->successors) {
            if (rpoIndex.count(succ)) preds[succ].push_back(addr);
        }
    }

    auto intersect = [&](Address a, Address b) -> Address {
        while (a != b) {
            while (rpoIndex[a] > rpoIndex[b]) a = idom_.at(a);
            while (rpoIndex[b] > rpoIndex[a]) b = idom_.at(b);
        }
        return a;
    };

    idom_[entry] = entry;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto addr : rpo_) {
            if (addr == entry) continue;
            Address newIdom = 0;
            bool first = true;
            for (auto pred : preds[addr]) {
                if (!idom_.count(pred)) continue; // not yet processed this round
                if (first) {
                    newIdom = pred;
                    first = false;
                } else {
                    newIdom = intersect(newIdom, pred);
                }
            }
            if (!first && (!idom_.count(addr) || idom_[addr] != newIdom)) {
                idom_[addr] = newIdom;
                changed = true;
            }
        }
    }

    // Dominance frontiers (Cytron et al.): for each block with >1
    // predecessor, walk up from each predecessor to (but not including) its
    // idom, adding this block to each visited block's frontier.
    for (auto addr : rpo_) {
        if (preds[addr].size() < 2) continue;
        for (auto pred : preds[addr]) {
            if (!idom_.count(pred)) continue;
            Address runner = pred;
            while (runner != idom_.at(addr)) {
                domFrontier_[runner].insert(addr);
                if (!idom_.count(runner) || idom_.at(runner) == runner) break;
                runner = idom_.at(runner);
            }
        }
    }
}

Address DominatorTree::immediateDominator(Address block) const {
    auto it = idom_.find(block);
    return it != idom_.end() ? it->second : 0;
}

bool DominatorTree::dominates(Address a, Address b) const {
    if (!idom_.count(a) || !idom_.count(b)) return false;
    Address cur = b;
    while (true) {
        if (cur == a) return true;
        Address next = idom_.at(cur);
        if (next == cur) return cur == a; // reached entry
        cur = next;
    }
}

const std::unordered_set<Address>& DominatorTree::dominanceFrontier(Address block) const {
    static const std::unordered_set<Address> empty;
    auto it = domFrontier_.find(block);
    return it != domFrontier_.end() ? it->second : empty;
}

} // namespace compass::core::analysis
