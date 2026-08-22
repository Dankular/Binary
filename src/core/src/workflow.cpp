#include "compass/core/workflow.hpp"

#include "compass/core/il/hlil_builder.hpp"
#include "compass/core/il/mlil_builder.hpp"
#include "compass/core/il/type_inference.hpp"

#include <sstream>

namespace compass::core {

PassRegistry& PassRegistry::instance() {
    static PassRegistry registry;
    return registry;
}

void PassRegistry::registerPass(std::shared_ptr<IAnalysisPass> pass) {
    passes_[pass->name()] = std::move(pass);
}

std::shared_ptr<IAnalysisPass> PassRegistry::find(const std::string& name) const {
    auto it = passes_.find(name);
    return it != passes_.end() ? it->second : nullptr;
}

std::vector<std::string> PassRegistry::names() const {
    std::vector<std::string> out;
    out.reserve(passes_.size());
    for (auto& [name, pass] : passes_) out.push_back(name);
    return out;
}

std::vector<std::string> Workflow::run(const Binary& binary, Function& fn) const {
    std::vector<std::string> problems;
    for (auto& name : passNames_) {
        auto pass = PassRegistry::instance().find(name);
        if (!pass) {
            problems.push_back("pass not found: " + name);
            continue;
        }
        pass->run(binary, fn);
    }
    return problems;
}

namespace {

/// Ensures fn.mlil (and, transitively, HLIL if requested) is populated —
/// most passes want to work over MLIL, not raw LLIL, but shouldn't each
/// have to duplicate "lift it if it's missing."
void ensureMlil(Function& fn) {
    if (!fn.mlil && fn.llil) {
        fn.mlil = il::buildMlil(fn);
        il::attachTypes(*fn.mlil);
    }
}

/// Built-in pass: makes sure llil/mlil/hlil are all populated. Useful as
/// an explicit first step in a workflow that also runs passes assuming
/// they already are, without every one of those passes needing its own
/// lifting fallback.
class LiftAllPass final : public IAnalysisPass {
public:
    std::string name() const override { return "lift-all"; }
    std::string description() const override {
        return "Populates llil/mlil/hlil for the function if not already present.";
    }
    void run(const Binary&, Function& fn) const override {
        ensureMlil(fn);
        if (!fn.hlil && fn.mlil) fn.hlil = il::buildHlil(*fn.mlil);
    }
};

/// Built-in pass: records every statically-known call target as an
/// annotation ("calls 0x1169 (dbg.add)" when a symbol name is known,
/// "calls 0x401234" otherwise). The seed of a real call graph — this
/// milestone doesn't build the graph data structure itself, just proves
/// passes can extract and record this kind of cross-function fact.
class CallGraphPass final : public IAnalysisPass {
public:
    std::string name() const override { return "callgraph"; }
    std::string description() const override {
        return "Annotates the function with every statically-known call target it makes.";
    }
    void run(const Binary& binary, Function& fn) const override {
        ensureMlil(fn);
        if (!fn.mlil) return;
        for (auto& bb : fn.mlil->basicBlocks) {
            for (auto& instr : bb.instructions) {
                for (auto& e : instr.expressions) {
                    visit(binary, fn, e);
                }
            }
        }
    }

private:
    static void visit(const Binary& binary, Function& fn, const il::MLILExprPtr& e) {
        if (!e) return;
        if (e->op == il::MLILOp::Call && !e->operands.empty() &&
            e->operands[0]->op == il::MLILOp::Const) {
            Address target = e->operands[0]->constValue;
            std::ostringstream os;
            os << "calls 0x" << std::hex << target;
            for (auto& sym : binary.symbols) {
                if (sym.address == target && !sym.name.empty()) {
                    os << " (" << sym.name << ")";
                    break;
                }
            }
            fn.annotations.push_back(os.str());
        }
        for (auto& o : e->operands) visit(binary, fn, o);
    }
};

// Registered at static-init time — this is what makes a "built-in" pass
// available without any plugin needing to be loaded. Plugin-provided
// passes register the same way, just later (during PluginManager::
// loadPlugin's call to IPlugin::onLoad()) and from a different
// translation unit — see plugin.hpp/plugin_manager.cpp.
struct BuiltinPassRegistration {
    BuiltinPassRegistration() {
        PassRegistry::instance().registerPass(std::make_shared<LiftAllPass>());
        PassRegistry::instance().registerPass(std::make_shared<CallGraphPass>());
    }
} g_builtinPassRegistration;

} // namespace

} // namespace compass::core
