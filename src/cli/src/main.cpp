// compass-cli: headless entry point into compass-core. Exists to prove the
// core engine works end-to-end without any GUI (see docs/ROADMAP.md
// Milestone 0), and to give the smoke test something to assert against.

#include "compass/core/annotation_merge.hpp"
#include "compass/core/backend.hpp"
#include "compass/core/debugger.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/hlil_builder.hpp"
#include "compass/core/il/mlil_builder.hpp"
#include "compass/core/il/type_inference.hpp"
#include "compass/core/plugin_manager.hpp"
#include "compass/core/sandbox.hpp"
#include "compass/core/workflow.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace compass::core;

namespace {

/// Parses --raw's architecture argument — same spellings toString(Architecture)
/// produces, so a value copied from --info's own "arch:" line round-trips.
std::optional<Architecture> archFromString(const std::string& s) {
    if (s == "x86") return Architecture::X86;
    if (s == "x86_64") return Architecture::X86_64;
    if (s == "arm32") return Architecture::ARM32;
    if (s == "arm64") return Architecture::ARM64;
    if (s == "mips") return Architecture::MIPS;
    return std::nullopt;
}

void printUsage(const char* argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " --list-functions <binary>\n"
              << "  " << argv0 << " --function <name> [--il] [--mlil] [--mlil-ssa] [--hlil] <binary>\n"
              << "  " << argv0 << " --function <name> [--plugin <path.so>]... --run-pass <name>... <binary>\n"
              << "  " << argv0 << " --list-passes [--plugin <path.so>]...\n"
              << "  " << argv0 << " --export-signatures <path> <binary>\n"
              << "  " << argv0 << " --apply-signatures <path> <binary>\n"
              << "  " << argv0 << " --info <binary>\n"
              << "  " << argv0 << " [--function <name> [--il]...] --raw <arch> [--base-addr <hex>] <blob>\n"
              << "      (arch: x86, x86_64, arm32, arm64, mips — for a headerless firmware/shellcode blob)\n"
              << "  " << argv0 << " --detonate <sample> [--guest-image <qcow2>] [--timeout <secs>] [--merge-annotations]\n"
              << "  " << argv0 << " --detonate <sample> --windows-iso <path-or-VERSION> [--timeout <secs>]\n"
              << "  " << argv0 << " --function <name> --decompile <binary>\n"
              << "  " << argv0 << " --function <name> --pcode-mlil <binary>\n"
              << "  " << argv0 << " --debug <path> [--debug-arg <arg>]... [--break <symbol>]...\n"
              << "      [--watch <symbol-or-0xaddr>[:size[:perm]]]... [--continue <N>] [--timeout <secs>] [--poke-stack <hexbytes>]\n";
}

void printDetonationReport(const DetonationReport& r) {
    if (!r.completed) {
        std::cout << "completed: false\nerror: " << r.error << "\n";
        return;
    }
    std::cout << "completed: true\n"
              << "syscalls: " << r.syscalls.size() << "\n"
              << "fileEvents: " << r.fileEvents.size() << "\n"
              << "networkEvents: " << r.networkEvents.size() << "\n\n";
    for (auto& e : r.fileEvents) {
        std::cout << "[file] t+" << e.timestampMs << "ms  " << e.operation << "  " << e.path << "\n";
    }
    for (auto& e : r.networkEvents) {
        std::cout << "[net]  t+" << e.timestampMs << "ms  " << e.protocol << "  " << e.destination << "\n";
    }
    for (auto& e : r.syscalls) {
        std::cout << "[sys]  t+" << e.timestampMs << "ms  " << e.name << "(" << e.argsText << ")\n";
    }
}

void printDecompiledFunction(const DecompiledFunction& d) {
    if (!d.success) {
        std::cout << "error: " << d.error << "\n";
        return;
    }
    std::cout << d.code;
}

#ifdef COMPASS_HAVE_RIZIN
void printDebugStopEvent(const DebugStopEvent& ev) {
    switch (ev.reason) {
        case DebugStopEvent::Reason::Breakpoint:
            std::cout << "stopped: breakpoint\npc: 0x" << std::hex << ev.pc << std::dec << "\n";
            break;
        case DebugStopEvent::Reason::Watchpoint:
            std::cout << "stopped: watchpoint\npc: 0x" << std::hex << ev.pc << std::dec << "\n";
            break;
        case DebugStopEvent::Reason::Exited:
            std::cout << "stopped: exited\nexitCode: " << ev.exitCode << "\n";
            break;
        case DebugStopEvent::Reason::Timeout:
            std::cout << "stopped: timeout\n";
            break;
        case DebugStopEvent::Reason::Error:
            std::cout << "stopped: error\nerror: " << ev.error << "\n";
            break;
        case DebugStopEvent::Reason::Unknown:
            std::cout << "stopped: unknown\npc: 0x" << std::hex << ev.pc << std::dec << "\n";
            break;
    }
}
#endif

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
         showHLIL = false, listPasses = false, showDecompile = false, showPcodeMlil = false,
         mergeAnnotations = false;
    std::string functionName, path, exportSignaturesPath, applySignaturesPath;
    std::string detonatePath, guestImagePath, windowsIsoOrVersion;
    std::string debugPath;
    std::string pokeHex;
    std::string rawArch, baseAddrHex;
    int timeoutSeconds = 30;
    bool timeoutExplicit = false;
    std::vector<std::string> pluginPaths, passNames, debugArgs, breakSymbols, watchSpecs;
    int maxStops = 1;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--list-functions") listFunctions = true;
        else if (args[i] == "--info") showInfo = true;
        else if (args[i] == "--il") showIL = true;
        else if (args[i] == "--detonate" && i + 1 < args.size()) detonatePath = args[++i];
        else if (args[i] == "--guest-image" && i + 1 < args.size()) guestImagePath = args[++i];
        else if (args[i] == "--windows-iso" && i + 1 < args.size()) windowsIsoOrVersion = args[++i];
        else if (args[i] == "--timeout" && i + 1 < args.size()) {
            timeoutSeconds = std::stoi(args[++i]);
            timeoutExplicit = true;
        }
        else if (args[i] == "--merge-annotations") mergeAnnotations = true;
        else if (args[i] == "--mlil") showMLIL = true;
        else if (args[i] == "--mlil-ssa") showMLILSSA = true;
        else if (args[i] == "--hlil") showHLIL = true;
        else if (args[i] == "--decompile") showDecompile = true;
        else if (args[i] == "--pcode-mlil") showPcodeMlil = true;
        else if (args[i] == "--list-passes") listPasses = true;
        else if (args[i] == "--function" && i + 1 < args.size()) functionName = args[++i];
        else if (args[i] == "--plugin" && i + 1 < args.size()) pluginPaths.push_back(args[++i]);
        else if (args[i] == "--run-pass" && i + 1 < args.size()) passNames.push_back(args[++i]);
        else if (args[i] == "--export-signatures" && i + 1 < args.size()) exportSignaturesPath = args[++i];
        else if (args[i] == "--apply-signatures" && i + 1 < args.size()) applySignaturesPath = args[++i];
        else if (args[i] == "--debug" && i + 1 < args.size()) debugPath = args[++i];
        else if (args[i] == "--debug-arg" && i + 1 < args.size()) debugArgs.push_back(args[++i]);
        else if (args[i] == "--break" && i + 1 < args.size()) breakSymbols.push_back(args[++i]);
        else if (args[i] == "--watch" && i + 1 < args.size()) watchSpecs.push_back(args[++i]);
        else if (args[i] == "--continue" && i + 1 < args.size()) maxStops = std::stoi(args[++i]);
        else if (args[i] == "--poke-stack" && i + 1 < args.size()) pokeHex = args[++i];
        else if (args[i] == "--raw" && i + 1 < args.size()) rawArch = args[++i];
        else if (args[i] == "--base-addr" && i + 1 < args.size()) baseAddrHex = args[++i];
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

    if (!detonatePath.empty()) {
        std::unique_ptr<ISandboxProvider> provider;
        if (!windowsIsoOrVersion.empty()) {
            provider = makeWindowsSandboxProvider(windowsIsoOrVersion);
            // A from-scratch Windows install under TCG genuinely takes on
            // the order of an hour (verified directly — see
            // docs/SANDBOX.md) — the CLI's general 30s default (fine for
            // the Linux provider's much lighter boot) would silently
            // report "never came up" on every unmodified invocation
            // otherwise. Only applied when the caller didn't pass
            // --timeout explicitly.
            if (!timeoutExplicit) timeoutSeconds = 3600;
        } else {
            if (guestImagePath.empty()) {
                const char* cacheEnv = std::getenv("COMPASS_SANDBOX_GUEST_IMAGE");
                guestImagePath = cacheEnv ? cacheEnv : "./.cache/debian-12-nocloud-amd64.qcow2";
            }
            provider = makeQemuTcgSandboxProvider(guestImagePath);
        }
        SandboxProfile profile;
        profile.timeoutSeconds = static_cast<std::uint32_t>(timeoutSeconds);
        auto report = provider->detonate(detonatePath, profile);
        printDetonationReport(report);

        if (mergeAnnotations) {
            auto backend = makeDefaultAnalysisBackend();
            if (!backend->load(detonatePath)) {
                std::cerr << "warning: couldn't statically load " << detonatePath
                          << " for annotation merge: " << backend->lastError() << "\n";
            } else {
                Binary bin = backend->binary(); // copy — free to mutate, backend keeps its own
                mergeDetonationReport(bin, report);
                std::cout << "\n-- merged annotations --\n";
                for (auto& a : bin.annotations) {
                    std::cout << "[binary] " << a << "\n";
                }
                for (auto& fn : bin.functions) {
                    for (auto& a : fn.annotations) {
                        std::cout << "[" << fn.name << "] " << a << "\n";
                    }
                    for (auto& bb : fn.basicBlocks) {
                        for (auto& a : bb.annotations) {
                            std::cout << "[" << fn.name << " @ 0x" << std::hex << bb.start << std::dec
                                       << "] " << a << "\n";
                        }
                    }
                }
            }
        }

        return report.completed ? 0 : 1;
    }

    if (!debugPath.empty()) {
#ifdef COMPASS_HAVE_RIZIN
        auto debugger = makeRizinDebuggerBackend();
        std::string error;
        if (!debugger->launch(debugPath, debugArgs, error)) {
            std::cerr << "error: " << error << "\n";
            return 1;
        }
        for (auto& sym : breakSymbols) {
            auto addr = debugger->resolveSymbol(sym);
            if (!addr) {
                std::cerr << "error: couldn't resolve breakpoint symbol: " << sym << "\n";
                return 1;
            }
            if (!debugger->addBreakpoint(*addr)) {
                std::cerr << "error: failed to set breakpoint at " << sym << " (0x" << std::hex << *addr
                           << std::dec << ")\n";
                return 1;
            }
            std::cerr << "breakpoint set: " << sym << " @ 0x" << std::hex << *addr << std::dec << "\n";
        }
        // --watch <symbol-or-0xaddr>[:size[:perm]] — size defaults to 4
        // bytes, perm to "rw" (both read and write trigger the watchpoint)
        // when omitted.
        for (auto& spec : watchSpecs) {
            std::string target = spec, sizeStr, permStr;
            auto c1 = spec.find(':');
            if (c1 != std::string::npos) {
                target = spec.substr(0, c1);
                auto c2 = spec.find(':', c1 + 1);
                sizeStr = c2 != std::string::npos ? spec.substr(c1 + 1, c2 - c1 - 1) : spec.substr(c1 + 1);
                if (c2 != std::string::npos) permStr = spec.substr(c2 + 1);
            }
            std::size_t size = sizeStr.empty() ? 4 : static_cast<std::size_t>(std::stoul(sizeStr));
            bool onRead = permStr.empty() || permStr.find('r') != std::string::npos;
            bool onWrite = permStr.empty() || permStr.find('w') != std::string::npos;

            std::optional<Address> addr;
            if (target.rfind("0x", 0) == 0) {
                addr = std::stoull(target, nullptr, 16);
            } else {
                addr = debugger->resolveSymbol(target);
            }
            if (!addr) {
                std::cerr << "error: couldn't resolve watchpoint target: " << target << "\n";
                return 1;
            }
            if (!debugger->addWatchpoint(*addr, size, onRead, onWrite)) {
                std::cerr << "error: failed to set watchpoint at " << target << " (0x" << std::hex << *addr
                           << std::dec << ")\n";
                return 1;
            }
            std::cerr << "watchpoint set: " << target << " @ 0x" << std::hex << *addr << std::dec << " size="
                       << size << " perm=" << (onRead ? "r" : "") << (onWrite ? "w" : "") << "\n";
        }

        // Multi-stop session control: continueExec() itself already
        // supports being called repeatedly (see docs/DEBUGGER.md) — this
        // loop is what actually exercises that from one CLI invocation,
        // instead of requiring a fresh process per breakpoint/watchpoint
        // hit. Defaults to 1 (maxStops's default), so a plain --debug
        // invocation with no --continue behaves exactly as before.
        DebugStopEvent stop;
        for (int stopNum = 1; stopNum <= maxStops; ++stopNum) {
            stop = debugger->continueExec(static_cast<std::uint32_t>(timeoutSeconds));
            if (maxStops > 1) std::cout << "-- stop " << stopNum << " --\n";
            printDebugStopEvent(stop);
            if (stop.reason == DebugStopEvent::Reason::Breakpoint ||
                stop.reason == DebugStopEvent::Reason::Watchpoint) {
                std::cout << "\nregisters:\n";
                for (auto& reg : debugger->registers()) {
                    std::cout << "  " << reg.name << " = 0x" << std::hex << reg.value << std::dec << "\n";
                }
                if (!pokeHex.empty()) {
                    std::vector<std::uint8_t> bytes;
                    for (std::size_t i = 0; i + 1 < pokeHex.size(); i += 2) {
                        bytes.push_back(
                            static_cast<std::uint8_t>(std::stoul(pokeHex.substr(i, 2), nullptr, 16)));
                    }
                    auto rsp = debugger->registerValue("rsp");
                    if (!rsp) {
                        std::cerr << "error: couldn't read rsp for --poke-stack\n";
                        return 1;
                    }
                    bool wrote = debugger->writeMemory(*rsp, bytes);
                    auto readBack = debugger->readMemory(*rsp, bytes.size());
                    std::cout << "\npoke-stack: wrote=" << (wrote ? "true" : "false") << " readback=";
                    for (auto b : readBack) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                    }
                    std::cout << std::dec << "\n";
                }
            } else {
                break; // exited/timeout/error/unknown — nothing more to continue past
            }
            if (maxStops > 1) std::cout << "\n";
        }
        return stop.reason == DebugStopEvent::Reason::Error ? 1 : 0;
#else
        std::cerr << "error: this build has no Rizin backend, so --debug is unavailable "
                      "(see docs/DEBUGGER.md; run scripts/build_rizin.sh)\n";
        return 1;
#endif
    }

    if (path.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    auto backend = makeDefaultAnalysisBackend();
    if (!rawArch.empty()) {
        auto arch = archFromString(rawArch);
        if (!arch) {
            std::cerr << "error: unknown --raw architecture: " << rawArch
                       << " (expected one of: x86, x86_64, arm32, arm64, mips)\n";
            return 1;
        }
        Address baseAddr = baseAddrHex.empty() ? 0 : std::stoull(baseAddrHex, nullptr, 16);
        if (!backend->loadRaw(path, *arch, 0, baseAddr)) {
            std::cerr << "error: " << backend->lastError() << "\n";
            return 1;
        }
    } else if (!backend->load(path)) {
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
        if (showDecompile) {
            auto decompiled = backend->decompile(fn.entry);
            std::cout << "\n-- decompiled --\n";
            printDecompiledFunction(decompiled);
            if (!decompiled.success) return 1;
        }
        if (showPcodeMlil) {
            auto translated = backend->pcodeMlil(fn.entry);
            std::cout << "\n-- p-code MLIL --\n";
            if (!translated.success) {
                std::cout << "error: " << translated.error << "\n";
                return 1;
            }
            std::cout << il::render(translated.mlil);
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
