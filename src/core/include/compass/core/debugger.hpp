#pragma once

#include "compass/core/types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace compass::core {

struct RegisterValue {
    std::string name;
    std::uint64_t value = 0;
};

/// Why a `continueExec()` call returned control. Deliberately small (v1) —
/// mirrors DetonationReport's scoping in sandbox.hpp: enough to build and
/// test a real debugger loop against today, extended as real use (watchpoints,
/// signal-specific handling, ...) demands more.
struct DebugStopEvent {
    enum class Reason {
        Breakpoint,
        Exited,
        Timeout,
        Error,
        Unknown, // process stopped for a reason we didn't classify (e.g. an
                 // unhandled signal) — see docs/DEBUGGER.md
    };
    Reason reason = Reason::Unknown;
    Address pc = 0;         // valid for Breakpoint/Unknown
    int exitCode = 0;       // valid for Exited
    std::string error;      // valid for Error
};

/// Backend for local (and, eventually, remote) process debugging. Mirrors
/// IAnalysisBackend/ISandboxProvider's shape: one narrow interface over a
/// real subsystem (RzDebug, over ptrace on Linux today), not a reimplemented
/// debugger. See docs/DEBUGGER.md.
///
/// A session is single-target and single-threaded-caller: launch() once,
/// then addBreakpoint()/continueExec()/registers()/readMemory() against the
/// same live debuggee until it exits or is killed.
class IDebuggerBackend {
public:
    virtual ~IDebuggerBackend() = default;

    /// Spawns `path` (with `args`) under the debugger (ptrace on Linux) and
    /// stops it at its entry point. Runs a light analysis pass against the
    /// live debug session afterward so resolveSymbol() has something to
    /// resolve against — this also sidesteps PIE/ASLR entirely: symbol
    /// addresses are read back from the actual running process's memory
    /// map, never assumed from a separate static load. See docs/DEBUGGER.md.
    virtual bool launch(const std::string& path, const std::vector<std::string>& args,
                         std::string& error) = 0;

    /// Resolves a function/symbol name to its address *within this live
    /// debug session* (see launch()'s note on why this exists instead of
    /// taking a static address).
    virtual std::optional<Address> resolveSymbol(const std::string& name) = 0;

    virtual bool addBreakpoint(Address addr) = 0;
    virtual bool removeBreakpoint(Address addr) = 0;

    /// Resumes execution until a breakpoint, process exit, or timeoutSeconds
    /// elapses (0 = no timeout). A timeout forcibly kills the debuggee (see
    /// docs/DEBUGGER.md) and returns Reason::Timeout.
    virtual DebugStopEvent continueExec(std::uint32_t timeoutSeconds) = 0;

    virtual std::vector<RegisterValue> registers() = 0;
    virtual std::optional<std::uint64_t> registerValue(const std::string& name) = 0;

    virtual std::vector<std::uint8_t> readMemory(Address addr, std::size_t size) = 0;

    /// True once the debuggee has exited (or was killed) and no further
    /// continueExec() calls are meaningful.
    virtual bool exited() const = 0;
};

#ifdef COMPASS_HAVE_RIZIN
/// The real provider: RzDebug (librz), opened in-process via a `dbg://` core
/// (the same mechanism `rizin -d` uses) — native ptrace on Linux. See
/// docs/DEBUGGER.md for why this is Rizin-only (radare2's r_debug is a
/// structurally separate subsystem, same divergence already documented for
/// signature matching in docs/ARCHITECTURE.md) and only declared/built when
/// COMPASS_HAVE_RIZIN is set (CMake sets this when librz is found — see
/// src/core/CMakeLists.txt).
std::unique_ptr<IDebuggerBackend> makeRizinDebuggerBackend();
#endif

} // namespace compass::core
