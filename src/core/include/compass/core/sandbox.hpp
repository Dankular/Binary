#pragma once

#include "compass/core/types.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace compass::core {

/// One observed syscall/API call during detonation, attributed back to the
/// (guest virtual) address that made it where known.
struct SyscallEvent {
    std::uint64_t timestampMs = 0;
    Address callSite = 0;
    std::string name;
    std::string argsText; // human-readable, backend-formatted for now
};

struct NetworkEvent {
    std::uint64_t timestampMs = 0;
    std::string protocol; // "tcp", "udp", "dns", "http", ...
    std::string destination; // host:port or domain, as observed
    std::uint64_t bytesSent = 0;
    std::uint64_t bytesReceived = 0;
};

struct FileEvent {
    std::uint64_t timestampMs = 0;
    std::string path;
    std::string operation; // "create", "write", "delete", "registry-set", ...
};

/// Everything a detonation run produced, in a form the core engine can
/// merge onto a Binary's Function/BasicBlock model as annotations (dynamic
/// coverage, per-call-site syscalls, IOCs). See docs/SANDBOX.md.
struct DetonationReport {
    bool completed = false;
    std::string error; // non-empty if completed == false

    std::vector<Address> executedBlocks;
    std::vector<SyscallEvent> syscalls;
    std::vector<NetworkEvent> networkEvents;
    std::vector<FileEvent> fileEvents;
};

/// What kind of guest/run to detonate in. Deliberately sparse today — grows
/// as real providers (see docs/SANDBOX.md) need more knobs.
struct SandboxProfile {
    std::string guestImage; // path to a qcow2 base image
    std::uint32_t timeoutSeconds = 60;
    bool networkEnabled = true; // via -netdev user, see docs/SANDBOX.md
};

/// Backend for the dynamic-analysis sandbox. Mirrors IAnalysisBackend's
/// shape: one narrow interface, swappable implementation. The real
/// implementation (QemuTcgSandboxProvider, launching qemu-system-x86_64
/// with -accel tcg and driving it over QMP) is planned but not yet built —
/// see docs/SANDBOX.md's roadmap for exactly what's missing (chiefly: a
/// prepared guest image and an in-guest agent). MockSandboxProvider below
/// exists so code consuming DetonationReport can be built and tested now.
class ISandboxProvider {
public:
    virtual ~ISandboxProvider() = default;
    virtual DetonationReport detonate(const std::filesystem::path& sample,
                                       const SandboxProfile& profile) = 0;
};

/// Returns a fixed, hand-authored DetonationReport regardless of input —
/// useful for exercising annotation-merging code without a real guest VM.
std::unique_ptr<ISandboxProvider> makeMockSandboxProvider();

} // namespace compass::core
