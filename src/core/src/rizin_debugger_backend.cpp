// IDebuggerBackend implementation over Rizin's librz — RzDebug opened
// in-process via a `dbg://` core, the exact mechanism `rizin -d` uses (see
// docs/DEBUGGER.md for how this was confirmed: read straight out of
// rizin's own librz/main/rizin.c rather than assumed). Only compiled when
// COMPASS_HAVE_RIZIN is defined, same as rizin_backend.cpp.
//
// Rizin-only, not radare2: the two projects' debug subsystems (RzDebug vs
// RDebug) are a structurally separate fork, same divergence already
// documented for signature matching in docs/ARCHITECTURE.md, and Rizin is
// this project's target production backend.

#include "compass/core/debugger.hpp"

#include <rz_core.h>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace compass::core {

namespace {

using json = nlohmann::json;

std::vector<std::uint8_t> hexDecode(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

} // namespace

class RizinDebuggerBackend final : public IDebuggerBackend {
public:
    ~RizinDebuggerBackend() override {
        if (core_) {
            // Best-effort: if the debuggee is still alive, kill it before
            // tearing down the core — otherwise it's leaked as an orphaned
            // stopped/traced process.
            if (!exited_ && pid_ > 0) ::kill(pid_, SIGKILL);
            rz_core_free(core_);
        }
    }

    bool launch(const std::string& path, const std::vector<std::string>& args,
                std::string& error) override {
        core_ = rz_core_new();
        if (!core_) {
            error = "rz_core_new failed";
            return false;
        }
        rz_config_set_b(core_->config, "scr.interactive", false);
        rz_config_set(core_->config, "scr.color", "0");
        rz_config_set(core_->config, "cfg.debug", "true");
        rz_config_set(core_->config, "search.in", "dbg.map");

        // See rizin_backend.cpp's load() for why this call is required —
        // rz_core_new() alone never dlopen's dir.plugins.
        rz_core_loadlibs(core_, RZ_CORE_LOADLIBS_ALL);

        std::string uri = "dbg://" + path;
        for (auto& a : args) uri += " " + a;

        RzCoreFile* fh = rz_core_file_open(core_, uri.c_str(), RZ_PERM_RWX, 0);
        if (!fh) {
            error = "failed to launch under the debugger: " + path;
            return false;
        }

        // Found by direct repro, not assumed: without these two calls a
        // dynamically-linked PIE target runs to completion right here,
        // unimpeded, before this function even returns — read straight out
        // of rizin's own librz/main/rizin.c (the exact sequence `rizin -d`
        // uses, which does NOT exhibit this) to find what was missing.
        // rz_debug_use() selects/initializes the actual debug backend
        // (breakpoint architecture, register profile, ...); without it,
        // something downstream apparently has nothing to stop the target
        // at and it just free-runs. rz_debug_get_baddr() is what resolves
        // the PIE binary's ASLR-randomized load address — passing that
        // (not UT64_MAX) into rz_core_bin_load() is also load-bearing: a
        // static/non-PIE target happened to work without either of these
        // (its fixed load address needs no resolution, which is what made
        // this easy to miss), but a PIE one does not.
        rz_debug_use(core_->dbg, "native");
        std::uint64_t baddr = rz_debug_get_baddr(core_->dbg, path.c_str());
        rz_core_bin_load(core_, path.c_str(), baddr);
        pid_ = core_->dbg->pid;

        // Symbol resolution below (resolveSymbol) reads straight out of
        // this analysis — run it once now, against the live debug
        // session's own memory map, not a separate static load. This is
        // what makes resolveSymbol() correct regardless of PIE/ASLR: the
        // addresses it returns are the ones this exact running process
        // actually has mapped (see debugger.hpp's note on launch()).
        char* out = rz_core_cmd_str(core_, "aa");
        free(out);
        return true;
    }

    std::optional<Address> resolveSymbol(const std::string& name) override {
        auto j = runJson("aflj");
        if (!j) return std::nullopt;
        for (auto& fn : *j) {
            std::string fname = fn.value("name", "");
            // Matches a bare name ("main") or a "sym."/"fcn."-prefixed one
            // ("sym.add") by its suffix after the last '.', same convention
            // signature_smoke_test.sh already relies on for these listings.
            if (fname == name) return fn.value("offset", Address{0});
            auto dot = fname.rfind('.');
            if (dot != std::string::npos && fname.substr(dot + 1) == name) {
                return fn.value("offset", Address{0});
            }
        }
        return std::nullopt;
    }

    bool addBreakpoint(Address addr) override {
        seek(addr);
        std::string out = runCmd("db");
        return out.find("Cannot") == std::string::npos; // rz_bp_add failures say so; empty output is success
    }

    bool removeBreakpoint(Address addr) override {
        seek(addr);
        runCmd("db-");
        return true;
    }

    DebugStopEvent continueExec(std::uint32_t timeoutSeconds) override {
        DebugStopEvent ev;
        if (!core_ || exited_) {
            ev.reason = DebugStopEvent::Reason::Error;
            ev.error = "no active debug session (already exited, or launch() failed)";
            return ev;
        }

        // RzDebug's exit-status message (which process, which code) is only
        // ever eprintf'd by librz/debug/p/native/linux/linux_debug.c — it
        // is not stored anywhere on RzDebug/RzDebugReason we can read back
        // via the API (checked directly against the source, not assumed).
        // Capture stderr for the duration of the `dc` call and pull the
        // exit code back out of that text, the same text-log-parsing
        // pattern already used for the sandbox's strace output.
        char stderrTemplate[] = "/tmp/compass_dbg_stderr_XXXXXX";
        int stderrFd = mkstemp(stderrTemplate);
        int savedStderr = dup(STDERR_FILENO);
        if (stderrFd >= 0) {
            fflush(stderr);
            dup2(stderrFd, STDERR_FILENO);
        }

        // Timeout watchdog: sends a raw SIGKILL to the tracee's pid from a
        // separate thread rather than touching RzCore/RzDebug state
        // concurrently with the `dc` call still running on this thread —
        // RzCore isn't designed for concurrent command execution, but a
        // plain kill(2) on a pid read once at launch() and never mutated
        // is safe to issue from another thread.
        std::atomic<bool> done{false};
        std::atomic<bool> timedOut{false};
        std::thread watchdog;
        if (timeoutSeconds > 0) {
            watchdog = std::thread([&] {
                const auto deadline =
                    std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
                while (!done.load() && std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (!done.load()) {
                    timedOut = true;
                    ::kill(pid_, SIGKILL);
                }
            });
        }

        char* out = rz_core_cmd_str(core_, "dc");
        free(out);
        done = true;
        if (watchdog.joinable()) watchdog.join();

        std::string stderrText;
        if (stderrFd >= 0) {
            fflush(stderr);
            dup2(savedStderr, STDERR_FILENO);
            close(savedStderr);
            std::ifstream f(stderrTemplate);
            std::stringstream ss;
            ss << f.rdbuf();
            stderrText = ss.str();
            std::remove(stderrTemplate);
        }

        if (timedOut.load()) {
            ev.reason = DebugStopEvent::Reason::Timeout;
            exited_ = true; // SIGKILL'd — no further continueExec() calls are meaningful
            return ev;
        }

        // dbg->reason.type is NOT a reliable exit signal: rz_debug_wait()
        // (librz/debug/debug.c) returns RZ_DEBUG_REASON_DEAD early, on the
        // path taken for a plain process exit, *before* the one line
        // (`dbg->reason.type = reason;`) that would ever write DEAD into
        // this field — checked directly against the source, not assumed,
        // after this exact case (a --debug run with no breakpoints, so the
        // process simply ran to completion) came back classified as
        // Unknown instead of Exited. The exit-status text captured above is
        // the only signal this file treats as authoritative for exit.
        int reasonType = core_->dbg->reason.type;
        auto exitCode = parseExitCode(stderrText);
        if (exitCode.has_value()) {
            ev.reason = DebugStopEvent::Reason::Exited;
            ev.exitCode = *exitCode;
            exited_ = true;
        } else if (reasonType == RZ_DEBUG_REASON_BREAKPOINT) {
            ev.reason = DebugStopEvent::Reason::Breakpoint;
            ev.pc = core_->dbg->reason.bp_addr ? core_->dbg->reason.bp_addr : core_->dbg->stopaddr;
        } else if (!processAlive()) {
            // Fallback for an exit whose text this build's two known
            // message formats didn't match (see parseExitCode) — still
            // real evidence (the pid is gone), just without a recovered
            // exit code.
            ev.reason = DebugStopEvent::Reason::Exited;
            ev.exitCode = -1;
            exited_ = true;
        } else {
            ev.reason = DebugStopEvent::Reason::Unknown;
            ev.pc = core_->dbg->stopaddr;
        }
        return ev;
    }

    std::vector<RegisterValue> registers() override {
        std::vector<RegisterValue> out;
        auto j = runJson("drj");
        if (!j || !j->is_object()) return out;
        for (auto it = j->begin(); it != j->end(); ++it) {
            if (!it.value().is_number_unsigned() && !it.value().is_number_integer()) continue;
            RegisterValue rv;
            rv.name = it.key();
            rv.value = it.value().is_number_integer() && it.value().get<std::int64_t>() < 0
                           ? static_cast<std::uint64_t>(it.value().get<std::int64_t>())
                           : it.value().get<std::uint64_t>();
            out.push_back(rv);
        }
        return out;
    }

    std::optional<std::uint64_t> registerValue(const std::string& name) override {
        for (auto& r : registers()) {
            if (r.name == name) return r.value;
        }
        return std::nullopt;
    }

    std::vector<std::uint8_t> readMemory(Address addr, std::size_t size) override {
        std::string hex = runCmd("p8 " + std::to_string(size) + " @ " + std::to_string(addr));
        // p8's output is a single line of raw hex with no separators —
        // trailing whitespace/newline stripped defensively (same class of
        // trailing-junk bug documented in docs/SANDBOX.md for strace's \r).
        while (!hex.empty() && !std::isxdigit(static_cast<unsigned char>(hex.back()))) hex.pop_back();
        return hexDecode(hex);
    }

    bool exited() const override { return exited_; }

private:
    RzCore* core_ = nullptr;
    int pid_ = -1;
    bool exited_ = false;

    void seek(Address addr) {
        std::string out = runCmd("s " + std::to_string(addr));
        (void)out;
    }

    std::string runCmd(const std::string& cmd) const {
        char* out = rz_core_cmd_str(core_, cmd.c_str());
        std::string result = out ? out : "";
        free(out);
        return result;
    }

    std::optional<json> runJson(const std::string& cmd) const {
        std::string out = runCmd(cmd);
        auto start = out.find_first_of("{[");
        if (start == std::string::npos) return std::nullopt;
        try {
            return json::parse(out.substr(start));
        } catch (const json::parse_error&) {
            return std::nullopt;
        }
    }

    bool processAlive() const {
        if (pid_ <= 0) return false;
        return ::kill(pid_, 0) == 0;
    }

    // Returns the exit code if `stderrText` contains either of RzDebug's
    // two exit messages (see continueExec()'s comment on why this text is
    // the authoritative exit signal, not dbg->reason.type), std::nullopt
    // if the debuggee is still running. Two distinct message formats exist
    // upstream for this: the PTRACE_EVENT_EXIT path this build actually
    // takes (hex) and a plain WIFEXITED path (decimal) that exists in the
    // same source for configurations that don't enable
    // PTRACE_O_TRACEEXIT — the two carry the exit code differently, both
    // confirmed by direct repro (a fixture whose real exit code, 42, was
    // being reported as 10752 = 42 << 8 before this fix):
    //   - The hex message prints PTRACE_GETEVENTMSG's raw value verbatim,
    //     which per ptrace(2) is the same word wait(2) would return in
    //     `status`, i.e. exit code in bits 8-15 — WEXITSTATUS(status),
    //     `(raw >> 8) & 0xff`, not `raw` itself.
    //   - The decimal message already has WEXITSTATUS(status) applied
    //     before it's printed (see linux_debug.c), so it needs no shift.
    static std::optional<int> parseExitCode(const std::string& stderrText) {
        static const std::regex hexRe(R"(Process exited with status=0x([0-9a-fA-F]+))");
        static const std::regex decRe(R"(Process (?:terminated|[Cc]hild terminated) with status (\d+))");
        std::smatch m;
        if (std::regex_search(stderrText, m, hexRe)) {
            unsigned long raw = std::stoul(m[1].str(), nullptr, 16);
            return static_cast<int>((raw >> 8) & 0xff);
        }
        if (std::regex_search(stderrText, m, decRe)) {
            return std::stoi(m[1].str());
        }
        return std::nullopt;
    }
};

std::unique_ptr<IDebuggerBackend> makeRizinDebuggerBackend() {
    return std::make_unique<RizinDebuggerBackend>();
}

} // namespace compass::core
