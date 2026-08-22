// ISandboxProvider wrapping dockur/windows's actual bootstrap (via
// `docker run docker.io/dockurr/windows`) rather than reimplementing
// Windows unattended-install automation — see docs/SANDBOX.md for the
// full design and the real findings behind it (its TCG fallback path is
// real, and this environment's intercepting TLS proxy breaks its
// in-container ISO downloader, both verified directly).
//
// v1 scope, honestly limited (see sandbox.hpp's note on
// makeWindowsSandboxProvider): this proves the guest boots under TCG and
// becomes reachable over a real RDP handshake — it does not yet deliver
// or execute a sample inside the guest, so detonate() never reports
// completed = true, even on a fully successful boot.
//
// Linux-only (POSIX sockets, `docker` CLI, `popen`) — consistent with the
// rest of this component.

#include "compass/core/sandbox.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <thread>

namespace compass::core {

namespace {

namespace fs = std::filesystem;

/// Runs a shell command, discarding output, returning its exit code. Same
/// helper shape as qemu_tcg_sandbox_provider.cpp's runShell().
int runShell(const std::string& cmd) {
    std::string full = cmd + " >/tmp/compass_windows_sandbox_shell.log 2>&1";
    int rc = std::system(full.c_str());
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/// Runs a shell command and captures its stdout — used for `docker port`/
/// `docker logs`, whose output this file actually needs to read, unlike
/// runShell()'s fire-and-forget commands.
std::string runCapture(const std::string& cmd) {
    std::string result;
    std::array<char, 512> buf{};
    FILE* pipe = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!pipe) return result;
    while (fgets(buf.data(), buf.size(), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    return result;
}

/// A real RDP X.224 Connection Request, the same first packet mstsc/
/// xfreerdp send. Used instead of a plain TCP connect: dockur/windows's
/// own port-forwarding proxy accepts TCP connections on 3389 immediately
/// on container start, long before Windows itself is installed or ready —
/// confirmed directly (a plain `connect()` succeeded within the first
/// second of a real run, while the actual OS install was still hours from
/// done) — so only a real protocol-level response is treated as "up".
bool rdpHandshakeOk(const std::string& host, int port, int timeoutSeconds) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct timeval tv{};
    tv.tv_sec = timeoutSeconds;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return false;
    }

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }

    static const unsigned char cr[] = {
        0x03, 0x00, 0x00, 0x13,                         // TPKT: v3, reserved, length=19
        0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,        // X.224 CR (Connection Request)
        0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,  // RDP negotiation request (empty)
    };
    // Best-effort: a failed/short send just means the recv below times out
    // or gets a response that doesn't parse as a real X.224 CC, which
    // rdpHandshakeOk() already treats as "not up" either way.
    ssize_t sent = ::send(fd, cr, sizeof(cr), 0);
    (void)sent;

    unsigned char resp[64];
    ssize_t got = ::recv(fd, resp, sizeof(resp), 0);
    ::close(fd);

    // A real RDP server answers with an X.224 Connection Confirm TPDU:
    // TPKT header (0x03 0x00 ...) followed by an X.224 code byte 0xD0 at
    // offset 5. Anything else (including dockur's forwarding proxy just
    // closing the connection before Windows is listening) fails this.
    return got >= 6 && resp[0] == 0x03 && resp[5] == 0xD0;
}

int parseDockerPort(const std::string& out) {
    // `docker port <name> 3389/tcp` prints one line per bound address,
    // e.g. "0.0.0.0:34567\n[::]:34567\n" — the port number is always the
    // last ':'-separated field on whichever line, IPv6 brackets included.
    auto pos = out.rfind(':');
    if (pos == std::string::npos) return -1;
    try {
        return std::stoi(out.substr(pos + 1));
    } catch (const std::exception&) {
        return -1;
    }
}

std::string trimTrailingNewlines(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

} // namespace

class WindowsSandboxProvider final : public ISandboxProvider {
public:
    explicit WindowsSandboxProvider(std::string isoOrVersion) : isoOrVersion_(std::move(isoOrVersion)) {}

    DetonationReport detonate(const fs::path& sample, const SandboxProfile& profile) override {
        DetonationReport report;

        // Accepted for ISandboxProvider conformance; not yet delivered
        // into the guest — see this file's header comment and
        // docs/SANDBOX.md for why.
        (void)sample;

        if (runShell("command -v docker") != 0) {
            report.completed = false;
            report.error = "docker CLI not found — this provider wraps docker.io/dockurr/windows "
                            "rather than reimplementing its bootstrap (see docs/SANDBOX.md)";
            return report;
        }

        bool localIso = fs::exists(isoOrVersion_) && fs::is_regular_file(isoOrVersion_);

        char workDirTemplate[] = "/tmp/compass_windows_sandbox_XXXXXX";
        char* workDirC = mkdtemp(workDirTemplate);
        if (!workDirC) {
            report.completed = false;
            report.error = "mkdtemp failed";
            return report;
        }
        fs::path work(workDirC);
        fs::path storage = work / "storage";
        fs::create_directories(storage);
        auto cleanupWork = [&] { fs::remove_all(work); };

        std::string containerName =
            "compass-win-" + std::to_string(::getpid()) + "-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        auto cleanupContainer = [&] { runShell("docker rm -f " + containerName); };

        std::ostringstream cmd;
        cmd << "docker run -d --name " << containerName << " -e KVM=N -e RAM_SIZE=1G -e DISK_SIZE=8G"
            << " -p 3389 -p 8006 --device=/dev/net/tun --cap-add NET_ADMIN --stop-timeout 30"
            << " -v " << storage.string() << ":/storage";
        if (localIso) {
            cmd << " -v " << fs::absolute(isoOrVersion_).string() << ":/custom.iso:ro";
        } else {
            cmd << " -e VERSION=" << isoOrVersion_;
        }
        cmd << " docker.io/dockurr/windows";

        if (runShell(cmd.str()) != 0) {
            report.completed = false;
            report.error = "docker run failed to start the Windows container "
                            "(see /tmp/compass_windows_sandbox_shell.log)";
            cleanupContainer();
            cleanupWork();
            return report;
        }

        int rdpPort = parseDockerPort(runCapture("docker port " + containerName + " 3389/tcp"));
        if (rdpPort <= 0) {
            report.completed = false;
            report.error = "couldn't determine the host port docker assigned for the guest's RDP port";
            cleanupContainer();
            cleanupWork();
            return report;
        }

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(profile.timeoutSeconds);
        bool up = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (rdpHandshakeOk("127.0.0.1", rdpPort, 5)) {
                up = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        // See this file's header comment and sandbox.hpp: booting != a
        // completed detonation, so this is never true yet — the error
        // text is what actually distinguishes "it worked, as far as this
        // provider goes today" from a real failure.
        report.completed = false;
        if (up) {
            report.error = "Windows guest booted successfully under TCG and answered a real RDP "
                            "handshake on port " +
                            std::to_string(rdpPort) +
                            " — in-guest sample delivery/execution is not yet implemented, see "
                            "docs/SANDBOX.md";
        } else {
            std::string logs =
                trimTrailingNewlines(runCapture("docker logs --tail 5 " + containerName));
            report.error = "Windows guest never answered a real RDP handshake within " +
                            std::to_string(profile.timeoutSeconds) +
                            "s (recent container log lines: " + logs + ")";
        }

        cleanupContainer();
        cleanupWork();
        return report;
    }

private:
    std::string isoOrVersion_;
};

std::unique_ptr<ISandboxProvider> makeWindowsSandboxProvider(const std::string& isoOrVersion) {
    return std::make_unique<WindowsSandboxProvider>(isoOrVersion);
}

} // namespace compass::core
