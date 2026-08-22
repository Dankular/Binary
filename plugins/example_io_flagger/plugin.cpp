// Example Compass plugin, built as a standalone .so — demonstrates the
// real extension path (dlopen, not a compiled-in special case): a
// third-party analysis pass a plugin registers at load time, with no
// changes to compass-core itself. See docs/ARCHITECTURE.md's Plugin API
// section and scripts/plugin_smoke_test.sh, which builds this exact
// plugin and loads it into compass-cli via dlopen to prove the mechanism
// end to end.
//
// What it does: flags any function that calls a well-known I/O-ish
// function (printf/puts/write/send/...) — the kind of thing a real
// malware-triage or auditing plugin would do, kept small enough to be a
// clear example rather than a serious detector.

#include "compass/core/plugin.hpp"

#include <set>

using namespace compass::core;

namespace {

bool looksLikeIoFunction(const std::string& symbolName) {
    static const std::set<std::string> ioFunctionNames = {
        "printf", "fprintf", "sprintf", "snprintf", "puts", "fputs", "write", "send", "sendto",
        "recv", "recvfrom", "read", "fread", "fwrite",
    };
    // Symbol names carry backend-specific prefixes ("sym.imp.printf",
    // "dbg.printf", ...) — match on suffix rather than requiring an exact
    // name, same convention Binary::functionNamed() already uses.
    for (auto& io : ioFunctionNames) {
        if (symbolName.size() >= io.size() &&
            symbolName.compare(symbolName.size() - io.size(), io.size(), io) == 0) {
            return true;
        }
    }
    return false;
}

class FlagIoCallersPass final : public IAnalysisPass {
public:
    std::string name() const override { return "flag-io-callers"; }
    std::string description() const override {
        return "Flags functions that call a well-known I/O function (printf/puts/write/...).";
    }

    void run(const Binary& binary, Function& fn) const override {
        if (!fn.mlil) return; // expects lift-all (or --mlil) to have run first
        for (auto& bb : fn.mlil->basicBlocks) {
            for (auto& instr : bb.instructions) {
                for (auto& e : instr.expressions) visit(binary, fn, e);
            }
        }
    }

private:
    static void visit(const Binary& binary, Function& fn, const il::MLILExprPtr& e) {
        if (!e) return;
        if (e->op == il::MLILOp::Call && !e->operands.empty() &&
            e->operands[0]->op == il::MLILOp::Const) {
            Address target = e->operands[0]->constValue;
            for (auto& sym : binary.symbols) {
                if (sym.address == target && looksLikeIoFunction(sym.name)) {
                    fn.annotations.push_back("IO caller: " + sym.name);
                }
            }
        }
        for (auto& o : e->operands) visit(binary, fn, o);
    }
};

class ExampleIoFlaggerPlugin final : public IPlugin {
public:
    std::string name() const override { return "example-io-flagger"; }
    std::string version() const override { return "0.1.0"; }
    void onLoad(PluginContext& ctx) override {
        ctx.registerPass(std::make_shared<FlagIoCallersPass>());
    }
};

} // namespace

COMPASS_DECLARE_PLUGIN(ExampleIoFlaggerPlugin)
