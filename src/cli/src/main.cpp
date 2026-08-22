// compass-cli: headless entry point into compass-core. Exists to prove the
// core engine works end-to-end without any GUI (see docs/ROADMAP.md
// Milestone 0), and to give the smoke test something to assert against.

#include "compass/core/backend.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/hlil_builder.hpp"
#include "compass/core/il/mlil_builder.hpp"
#include "compass/core/il/type_inference.hpp"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace compass::core;

namespace {

void printUsage(const char* argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " --list-functions <binary>\n"
              << "  " << argv0 << " --function <name> [--il] [--mlil] [--mlil-ssa] <binary>\n"
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
         showHLIL = false;
    std::string functionName, path;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--list-functions") listFunctions = true;
        else if (args[i] == "--info") showInfo = true;
        else if (args[i] == "--il") showIL = true;
        else if (args[i] == "--mlil") showMLIL = true;
        else if (args[i] == "--mlil-ssa") showMLILSSA = true;
        else if (args[i] == "--hlil") showHLIL = true;
        else if (args[i] == "--function" && i + 1 < args.size()) functionName = args[++i];
        else path = args[i];
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
        return 0;
    }

    printUsage(argv[0]);
    return 1;
}
