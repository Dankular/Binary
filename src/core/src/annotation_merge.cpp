#include "compass/core/annotation_merge.hpp"

namespace compass::core {

void mergeDetonationReport(Binary& binary, const DetonationReport& report) {
    if (!report.completed) {
        binary.annotations.push_back("dynamic: detonation did not complete: " + report.error);
        return;
    }

    // File/network events are process-level observations, not tied to a
    // call site (no provider today records which instruction made a given
    // syscall — see the SyscallEvent handling below) — they attach to the
    // binary as a whole rather than any one function.
    for (auto& e : report.fileEvents) {
        binary.annotations.push_back("dynamic: file " + e.operation + " " + e.path + " (t+" +
                                      std::to_string(e.timestampMs) + "ms)");
    }
    for (auto& e : report.networkEvents) {
        binary.annotations.push_back("dynamic: network " + e.protocol + " to " + e.destination +
                                      " (t+" + std::to_string(e.timestampMs) + "ms)");
    }

    // SyscallEvent::callSite is a real field but no current provider
    // populates it — see docs/schemas/detonation_report.schema.json and
    // docs/ANNOTATIONS.md: strace (QemuTcgSandboxProvider's data source)
    // reports syscall arguments, not the guest instruction pointer at the
    // point of the call, so there is nothing to attribute today. This
    // loop is a no-op against every provider that exists right now; it's
    // here so a provider that does record call sites (e.g. QEMU TCG plugin
    // instrumentation, or a ptrace-based provider using
    // PTRACE_PEEKUSER on rip at syscall-stop) gets real per-block
    // attribution for free, without another round of changes here.
    for (auto& e : report.syscalls) {
        if (e.callSite == 0) continue;
        Function* fn = binary.functionContaining(e.callSite);
        if (!fn) continue;
        std::string note = "dynamic: syscall " + e.name + "(" + e.argsText + ") (t+" +
                            std::to_string(e.timestampMs) + "ms)";
        if (BasicBlock* bb = fn->blockAt(e.callSite)) {
            bb->annotations.push_back(note);
        } else {
            fn->annotations.push_back(note);
        }
    }

    // executedBlocks: same caveat as callSite above — always empty from
    // every provider today (see sandbox.hpp's note on DetonationReport;
    // populating it needs QEMU TCG plugin instrumentation or a debugger,
    // neither of which QemuTcgSandboxProvider currently runs alongside the
    // detonation). Also assumes these addresses already share the
    // statically-loaded Binary's address space (true for a non-PIE
    // target; a PIE target's guest-runtime addresses would need
    // normalizing against its ASLR base first, the same problem
    // RizinDebuggerBackend::launch() solved for local debugging — see
    // docs/ANNOTATIONS.md).
    for (Address addr : report.executedBlocks) {
        Function* fn = binary.functionContaining(addr);
        if (!fn) continue;
        BasicBlock* bb = fn->blockAt(addr);
        if (!bb) continue;
        std::string note = "dynamic: block executed at runtime (coverage)";
        // Don't spam the same block with a duplicate note if it was hit
        // more than once — coverage is boolean, not a hit count, in v1.
        bool already = false;
        for (auto& a : bb->annotations) {
            if (a == note) { already = true; break; }
        }
        if (!already) bb->annotations.push_back(note);
    }
}

} // namespace compass::core
