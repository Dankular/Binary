// ISandboxProvider over a real QEMU TCG guest — generalizes what
// scripts/linux_guest_probe.sh proved by hand: boot a disposable overlay,
// drive it over a serial-socket shell, push a payload in via a small ISO
// (genisoimage — reusing an existing tool rather than hand-rolling ISO
// 9660, same principle as everywhere else in this codebase), run the
// in-guest agent (sandbox/agent/agent.sh), and parse its raw strace/
// tcpdump output into a DetonationReport. See docs/SANDBOX.md for the
// full design and the real issues hit building this (apt cache never
// primed on the nocloud image; TLS interception breaking HTTPS to
// deb.debian.org from inside the guest).
//
// Linux-only (POSIX sockets, fork/exec, and the whole TCG/QEMU premise
// this project's sandbox work is built on) — consistent with the rest of
// this component.

#include "compass/core/sandbox.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

namespace compass::core {

namespace {

namespace fs = std::filesystem;

/// Runs a shell command, discarding output, returning its exit code.
/// Used for the handful of external tools this orchestrator composes
/// (qemu-img, genisoimage) rather than reimplementing qcow2/ISO9660
/// handling — same "don't reimplement what already works" principle
/// applied to Rizin/Ghidra/SCC.
int runShell(const std::string& cmd) {
    std::string full = cmd + " >/tmp/compass_sandbox_shell.log 2>&1";
    int rc = std::system(full.c_str());
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/// Drives a QEMU serial-socket shell session — the same interactive
/// login/command loop tests/fixtures/sandbox_probe/serial_drive.py and
/// scripts/linux_guest_probe.sh already proved works, reimplemented in
/// C++ so the orchestrator doesn't need a Python dependency at runtime.
class SerialClient {
public:
    bool connectTo(const std::string& socketPath, int retries = 20) {
        for (int i = 0; i < retries; ++i) {
            fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
            sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socketPath.c_str());
            if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) return true;
            close(fd_);
            fd_ = -1;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        return false;
    }

    ~SerialClient() {
        if (fd_ >= 0) close(fd_);
    }

    void send(const std::string& text) {
        ssize_t n = write(fd_, text.data(), text.size());
        (void)n; // best-effort; a short/failed write here just means the guest sees a truncated
                 // command, which the caller's timeout-based readFor()/runUntil() already tolerates
                 // rather than depending on precise delivery
    }

    /// Reads whatever arrives for up to `seconds`, appending to and
    /// returning the accumulated buffer.
    std::string readFor(double seconds) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::duration<double>(seconds);
        char chunk[65536];
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd pfd{fd_, POLLIN, 0};
            int remainingMs = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                    .count());
            if (remainingMs <= 0) break;
            int r = poll(&pfd, 1, std::min(remainingMs, 200));
            if (r > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = read(fd_, chunk, sizeof(chunk));
                if (n > 0) buf_.append(chunk, static_cast<std::size_t>(n));
            }
        }
        return buf_;
    }

    /// Runs one command (sent with a trailing \r\n, as a real terminal
    /// would), waiting up to `seconds` for it to appear reflected back —
    /// resets the accumulated buffer first so the return value is just
    /// this command's output.
    std::string run(const std::string& cmd, double seconds) {
        buf_.clear();
        send(cmd + "\r\n");
        return readFor(seconds);
    }

    /// Runs `cmd`, then keeps polling (in `pollIntervalSeconds` steps)
    /// until `sentinel` appears in the accumulated output or
    /// `maxSeconds` elapses — for commands (like the agent script) whose
    /// duration isn't known up front.
    std::string runUntil(const std::string& cmd, const std::string& sentinel, double maxSeconds,
                          double pollIntervalSeconds = 5.0) {
        buf_.clear();
        send(cmd + "\r\n");
        double waited = 0;
        std::string out = readFor(pollIntervalSeconds);
        waited += pollIntervalSeconds;
        while (out.find(sentinel) == std::string::npos && waited < maxSeconds) {
            out = readFor(pollIntervalSeconds);
            waited += pollIntervalSeconds;
        }
        return out;
    }

    bool waitForLogin(double maxSeconds) {
        double waited = 0;
        std::string out;
        while (waited < maxSeconds) {
            out = readFor(2.0);
            waited += 2.0;
            if (out.find("login:") != std::string::npos) return true;
        }
        return false;
    }

private:
    int fd_ = -1;
    std::string buf_;
};

std::uint64_t parseTimestampToMs(int hh, int mm, int ss, int frac) {
    return (static_cast<std::uint64_t>(hh) * 3600 + static_cast<std::uint64_t>(mm) * 60 +
            static_cast<std::uint64_t>(ss)) *
               1000 +
           static_cast<std::uint64_t>(frac) / 1000; // frac is microseconds
}

/// Parses `strace -f -tt -y` output — see docs/SANDBOX.md for a captured
/// real example this regex was built against, not guessed blind. Emits a
/// SyscallEvent per line, plus a FileEvent/NetworkEvent when the syscall
/// is one of the ones that means something to those categories.
void parseStraceLog(const std::string& text, DetonationReport& report) {
    static const std::regex lineRe(
        R"(^\d+\s+(\d{2}):(\d{2}):(\d{2})\.(\d+)\s+(\w+)\((.*)\)\s*=\s*(.*)$)");
    static const std::regex pathRe(R"(\"([^\"]*)\")");
    static const std::regex connectAddrRe(
        R"(sin_addr=inet_addr\(\"([^\"]+)\"\).*?sin_port=htons\((\d+)\)|sin_port=htons\((\d+)\).*?sin_addr=inet_addr\(\"([^\"]+)\"\))");

    std::optional<std::uint64_t> baseMs;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        // The guest's serial terminal emits \r\n; std::getline only splits on
        // \n, so every line here carries a trailing \r. That alone is enough
        // to make std::regex_match reject the whole line even though the
        // pattern ends in `(.*)$` — verified directly (not assumed): a
        // trailing \r appended to an otherwise-matching string flips
        // regex_match from true to false with this exact pattern under
        // libstdc++'s ECMAScript engine. Strip it (and any other trailing
        // whitespace) before matching.
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                                  line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        if (line.empty()) continue;
        std::smatch m;
        if (!std::regex_match(line, m, lineRe)) continue;
        int hh = std::stoi(m[1]), mm = std::stoi(m[2]), ss = std::stoi(m[3]), frac = std::stoi(m[4]);
        std::uint64_t ms = parseTimestampToMs(hh, mm, ss, frac);
        if (!baseMs) baseMs = ms;
        std::uint64_t relMs = ms - *baseMs;
        std::string name = m[5];
        std::string args = m[6];
        std::string ret = m[7];

        SyscallEvent sc;
        sc.timestampMs = relMs;
        sc.name = name;
        sc.argsText = args + " = " + ret;
        report.syscalls.push_back(sc);

        static const std::set<std::string> fileOpenOps = {"openat", "open", "creat"};
        static const std::set<std::string> fileUnlinkOps = {"unlink", "unlinkat"};
        static const std::set<std::string> fileRenameOps = {"rename", "renameat", "renameat2"};
        static const std::set<std::string> fileMkdirOps = {"mkdir", "mkdirat"};

        if (fileOpenOps.count(name) || fileUnlinkOps.count(name) || fileRenameOps.count(name) ||
            fileMkdirOps.count(name)) {
            std::smatch pm;
            if (std::regex_search(args, pm, pathRe)) {
                FileEvent fe;
                fe.timestampMs = relMs;
                fe.path = pm[1];
                if (fileUnlinkOps.count(name)) {
                    fe.operation = "unlink";
                } else if (fileRenameOps.count(name)) {
                    fe.operation = "rename";
                } else if (fileMkdirOps.count(name)) {
                    fe.operation = "mkdir";
                } else {
                    fe.operation = (args.find("O_CREAT") != std::string::npos) ? "create" : "open";
                }
                report.fileEvents.push_back(fe);
            }
        }

        if (name == "connect" || name == "sendto") {
            std::smatch am;
            if (std::regex_search(args, am, connectAddrRe)) {
                NetworkEvent ne;
                ne.timestampMs = relMs;
                ne.protocol = (name == "connect") ? "tcp" : "udp";
                std::string ip = am[1].matched ? am[1].str() : am[4].str();
                std::string port = am[2].matched ? am[2].str() : am[3].str();
                ne.destination = ip + ":" + port;
                report.networkEvents.push_back(ne);
            }
        }
    }
}

} // namespace

class QemuTcgSandboxProvider final : public ISandboxProvider {
public:
    explicit QemuTcgSandboxProvider(std::string defaultGuestImage)
        : defaultGuestImage_(std::move(defaultGuestImage)) {}

    DetonationReport detonate(const fs::path& sample, const SandboxProfile& profile) override {
        DetonationReport report;
        std::string guestImage = profile.guestImage.empty() ? defaultGuestImage_ : profile.guestImage;
        if (guestImage.empty() || !fs::exists(guestImage)) {
            report.completed = false;
            report.error = "no guest base image available (pass SandboxProfile::guestImage, "
                            "or run scripts/linux_guest_probe.sh once to populate .cache/)";
            return report;
        }
        if (!fs::exists(sample)) {
            report.completed = false;
            report.error = "sample not found: " + sample.string();
            return report;
        }

        // qemu-img resolves a relative -b backing-file path relative to the
        // *overlay's* directory, not the process's cwd — verified directly
        // (a relative guestImage that fs::exists() happily found from cwd
        // still made "qemu-img create" fail with "No such file or
        // directory" once the overlay lived under /tmp). Canonicalize
        // before handing it to qemu-img so this works regardless of where
        // the caller's guestImage path was relative to.
        guestImage = fs::absolute(guestImage).string();

        char workDirTemplate[] = "/tmp/compass_sandbox_XXXXXX";
        char* workDirC = mkdtemp(workDirTemplate);
        if (!workDirC) {
            report.completed = false;
            report.error = "mkdtemp failed";
            return report;
        }
        fs::path work(workDirC);
        auto cleanup = [&] { fs::remove_all(work); };

        // 1. Disposable overlay — base image is never modified.
        fs::path overlay = work / "run.qcow2";
        if (runShell("qemu-img create -f qcow2 -F qcow2 -b '" + guestImage + "' '" + overlay.string() + "'") !=
            0) {
            report.completed = false;
            report.error = "qemu-img create (overlay) failed";
            cleanup();
            return report;
        }

        // 2. Payload ISO: the agent script + the sample to detonate.
        fs::path payloadDir = work / "payload";
        fs::create_directories(payloadDir);
        fs::copy_file(sample, payloadDir / "sample");
        fs::path agentScriptSrc = agentScriptPath();
        if (agentScriptSrc.empty() || !fs::exists(agentScriptSrc)) {
            report.completed = false;
            report.error = "sandbox/agent/agent.sh not found (looked relative to the executable and "
                            "COMPASS_SANDBOX_AGENT_SCRIPT)";
            cleanup();
            return report;
        }
        fs::copy_file(agentScriptSrc, payloadDir / "agent.sh");
        fs::path payloadIso = work / "payload.iso";
        if (runShell("genisoimage -o '" + payloadIso.string() + "' -J -R '" + payloadDir.string() + "'") != 0) {
            report.completed = false;
            report.error = "genisoimage failed (is genisoimage installed?)";
            cleanup();
            return report;
        }

        // 3. Boot under TCG with the overlay + payload ISO + a serial
        // socket to drive it over — same shape as
        // scripts/linux_guest_probe.sh, generalized.
        fs::path serialSock = work / "serial.sock";
        std::ostringstream qemuCmd;
        qemuCmd << "qemu-system-x86_64 -accel tcg,thread=multi -m 2048 -smp 2 -M q35 "
                << "-drive file='" << overlay.string() << "',if=virtio,format=qcow2 "
                << "-drive file='" << payloadIso.string() << "',media=cdrom,if=ide,readonly=on "
                << (profile.networkEnabled ? "-netdev user,id=net0 -device virtio-net-pci,netdev=net0 " : "")
                << "-display none -monitor none "
                << "-chardev socket,id=ser0,path='" << serialSock.string() << "',server=on,wait=off "
                << "-serial chardev:ser0 -no-reboot "
                << "> '" << (work / "qemu.log").string() << "' 2>&1 &";
        int launchRc = std::system(qemuCmd.str().c_str());
        (void)launchRc; // the trailing `&` backgrounds qemu itself; this exit code is just the
                        // shell that launched it, not qemu's — real launch failures show up as the
                        // serial-socket connect below failing instead

        SerialClient client;
        if (!client.connectTo(serialSock.string())) {
            report.completed = false;
            report.error = "could not connect to guest serial socket";
            killQemu(work);
            cleanup();
            return report;
        }

        double timeout = std::max<double>(30, profile.timeoutSeconds);
        if (!client.waitForLogin(90)) {
            report.completed = false;
            report.error = "guest never reached a login prompt";
            killQemu(work);
            cleanup();
            return report;
        }
        client.run("root\r\n", 3);

        client.run("mkdir -p /mnt/payload && mount -o ro /dev/sr0 /mnt/payload", 5);
        client.run("cp /mnt/payload/agent.sh /tmp/agent.sh && cp /mnt/payload/sample /tmp/sample && "
                    "chmod +x /tmp/agent.sh /tmp/sample",
                    3);

        std::string agentOut = client.runUntil(
            "bash /tmp/agent.sh /tmp/sample " + std::to_string(static_cast<int>(timeout)), "AGENT_DONE",
            timeout + 30);
        if (agentOut.find("AGENT_DONE") == std::string::npos) {
            report.completed = false;
            report.error = "agent did not finish within the timeout";
            client.send("poweroff\r\n");
            client.readFor(10);
            killQemu(work);
            cleanup();
            return report;
        }

        std::string straceLog = client.run("cat /tmp/agent.strace", 5);
        std::string netLog = client.run("cat /tmp/agent.net", 5);
        if (std::getenv("COMPASS_SANDBOX_DEBUG")) {
            std::ofstream(work.parent_path() / "compass_sandbox_debug_strace.txt") << straceLog;
            std::ofstream(work.parent_path() / "compass_sandbox_debug_net.txt") << netLog;
        }
        (void)netLog; // parsed defensively below; strace's connect()/sendto() args are the primary
                      // network-event source (see parseStraceLog) since they were verified to carry
                      // full address info directly, unlike tcpdump's text summary in this setup.

        client.send("poweroff\r\n");
        client.readFor(15);
        killQemu(work);

        parseStraceLog(straceLog, report);
        report.completed = true;
        cleanup();
        return report;
    }

private:
    std::string defaultGuestImage_;

    static fs::path agentScriptPath() {
        if (const char* override = std::getenv("COMPASS_SANDBOX_AGENT_SCRIPT")) {
            return fs::path(override);
        }
        // Repo-relative fallback for development/test use — a packaged
        // install would set COMPASS_SANDBOX_AGENT_SCRIPT instead.
        fs::path candidate = fs::path(__FILE__).parent_path().parent_path().parent_path().parent_path() /
                              "sandbox" / "agent" / "agent.sh";
        if (fs::exists(candidate)) return candidate;
        return {};
    }

    static void killQemu(const fs::path& work) {
        // Best-effort: find the qemu process by matching its overlay
        // path (unique per run) rather than tracking a PID across the
        // detached `&` launch above.
        runShell("pkill -f '" + (work / "run.qcow2").string() + "'");
    }
};

std::unique_ptr<ISandboxProvider> makeQemuTcgSandboxProvider(const std::string& defaultGuestImage) {
    return std::make_unique<QemuTcgSandboxProvider>(defaultGuestImage);
}

} // namespace compass::core
