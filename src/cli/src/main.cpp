// compass-cli: headless entry point into compass-core. Exists to prove the
// core engine works end-to-end without any GUI (see docs/ROADMAP.md
// Milestone 0), and to give the smoke test something to assert against.

#include "compass/core/backend.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/hlil_builder.hpp"
#include "compass/core/il/mlil_builder.hpp"
#include "compass/core/il/type_inference.hpp"
#include "compass/core/plugin_manager.hpp"
#include "compass/core/workflow.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace compass::core;

namespace {

void printUsage(const char* argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " --list-functions <binary>\n"
              << "  " << argv0 << " --function <name> [--il] [--mlil] [--mlil-ssa] [--hlil] <binary>\n"
              << "  " << argv0 << " --function <name> [--plugin <path.so>]... --run-pass <name>... <binary>\n"
              << "  " << argv0 << " --list-passes [--plugin <path.so>]...\n"
              << "  " << argv0 << " --export-signatures <path> <binary>\n"
              << "  " << argv0 << " --apply-signatures <path> <binary>\n"
              << "  " << argv0 << " --info <binary>\n";
}

void printInfo(const Binary& bin) {
    std::cout << "path:   " << bin.path << "\n"
              << "format: " << bin.format << "\n"
              << "arch:   " << toString(bin.arch) << "\n"
              << "entry:  0x" << std::hex << bin.entryPoint << std::dec << "\n"
              << "sections: " << bin.sections.size() << "\n"
              << "symbols:  " << bin.symbols.size() << "\n"
              << "functions: " << bin.functions.size() << "\n";
}

void printFunctionDisasm(const Function& fn) {
    std::cout << "function " << fn.name << " @ 0x" << std::hex << fn.entry << std::dec
              << " (" << fn.basicBlocks.size() << " basic blocks)\n";
    for (auto& bb : fn.basicBlocks) {
        std::cout << "block 0x" << std::hex << bb.start << "-0x" << bb.end << std::dec << " -> [";
        for (std::size_t i = 0; i < bb.successors.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << "0x" << std::hex << bb.successors[i] << std::dec;
        }
        std::cout << "]\n";
        for (auto& insn : bb.instructions) {
            std::cout << "  0x" << std::hex << insn.address << std::dec << "  " << insn.mnemonic;
            if (!insn.operandsText.empty()) std::cout << " " << insn.operandsText;
            std::cout << "\n";
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    bool listFunctions = false, showInfo = false, showIL = false, showMLIL = false, showMLILSSA = false,
         showHLIL = false, listPasses = false;
    std::string functionName, path, exportSignaturesPath, applySignaturesPath;
    std::vector<std::string> pluginPaths, passNames;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--list-functions") listFunctions = true;
        else if (args[i] == "--info") showInfo = true;
        else if (args[i] == "--il") showIL = true;
        else if (args[i] == "--mlil") showMLIL = true;
        else if (args[i] == "--mlil-ssa") showMLILSSA = true;
        else if (args[i] == "--hlil") showHLIL = true;
        else if (args[i] == "--list-passes") listPasses = true;
        else if (args[i] == "--function" && i + 1 < args.size()) functionName = args[++i];
        else if (args[i] == "--plugin" && i + 1 < args.size()) pluginPaths.push_back(args[++i]);
        else if (args[i] == "--run-pass" && i + 1 < args.size()) passNames.push_back(args[++i]);
        else if (args[i] == "--export-signatures" && i + 1 < args.size()) exportSignaturesPath = args[++i];
        else if (args[i] == "--apply-signatures" && i + 1 < args.size()) applySignaturesPath = args[++i];
        else path = args[i];
    }

    PluginManager pluginManager;
    for (auto& p : pluginPaths) {
        std::string error;
        if (!pluginManager.loadPlugin(p, error)) {
            std::cerr << "error: failed to load plugin " << p << ": " << error << "\n";
            return 1;
        }
    }
    for (auto& info : pluginManager.loaded()) {
        std::cerr << "loaded plugin: " << info.name << " " << info.version << " (" << info.path << ")\n";
    }

    if (listPasses) {
        auto names = PassRegistry::instance().names();
        std::sort(names.begin(), names.end());
        for (auto& n : names) {
            auto pass = PassRegistry::instance().find(n);
            std::cout << n << "\t" << (pass ? pass->description() : "") << "\n";
        }
        return 0;
    }

    if (path.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    auto backend = makeDefaultAnalysisBackend();
    if (!backend->load(path)) {
        std::cerr << "error: " << backend->lastError() << "\n";
        return 1;
    }

    if (!exportSignaturesPath.empty()) {
        std::string error;
        if (!backend->exportSignatures(exportSignaturesPath, error)) {
            std::cerr << "error: failed to export signatures: " << error << "\n";
            return 1;
        }
        std::cout << "wrote signatures to " << exportSignaturesPath << "\n";
        return 0;
    }

    if (!applySignaturesPath.empty()) {
        std::string error;
        auto matches = backend->applySignatures(applySignaturesPath, error);
        if (!error.empty()) {
            std::cerr << "error: failed to apply signatures: " << error << "\n";
            return 1;
        }
        for (auto& m : matches) {
            std::cout << "0x" << std::hex << m.address << std::dec << "  " << m.matchedName << "\n";
        }
        std::cout << matches.size() << " function(s) matched\n";
        return 0;
    }

    const Binary& bin = backend->binary();

    if (showInfo) {
        printInfo(bin);
        return 0;
    }

    if (listFunctions) {
        for (auto& fn : bin.functions) {
            std::cout << "0x" << std::hex << fn.entry << std::dec << "  " << fn.name
                      << "  (" << fn.basicBlocks.size() << " blocks)\n";
        }
        return 0;
    }

    if (!functionName.empty()) {
        const Function* found = bin.functionNamed(functionName);
        if (!found) {
            std::cerr << "error: function not found: " << functionName << "\n";
            return 1;
        }
        Function fn = *found; // copy so we can lift IL into it
        printFunctionDisasm(fn);
        if (showIL || showMLIL || showMLILSSA || showHLIL) {
            backend->liftLowLevelIL(fn);
        }
        if (showIL) {
            std::cout << "\n-- LLIL --\n" << il::render(*fn.llil);
        }
        if (showMLIL || showMLILSSA || showHLIL) {
            fn.mlil = il::buildMlil(fn);
            il::attachTypes(*fn.mlil);
        }
        if (showMLIL) {
            std::cout << "\n-- MLIL --\n" << il::render(*fn.mlil);
        }
        if (showMLILSSA) {
            fn.mlilSsa = il::buildMlilSsa(*fn.mlil);
            std::cout << "\n-- MLIL SSA --\n" << il::render(*fn.mlilSsa);
        }
        if (showHLIL) {
            fn.hlil = il::buildHlil(*fn.mlil);
            std::cout << "\n-- HLIL --\n" << il::render(*fn.hlil);
        }

        if (!passNames.empty()) {
            if (!fn.llil) backend->liftLowLevelIL(fn);
            Workflow workflow;
            for (auto& p : passNames) workflow.addPass(p);
            auto problems = workflow.run(bin, fn);
            for (auto& p : problems) std::cerr << "warning: " << p << "\n";
            std::cout << "\n-- annotations --\n";
            for (auto& a : fn.annotations) std::cout << a << "\n";
        }
        return 0;
    }

    printUsage(argv[0]);
    return 1;
}
