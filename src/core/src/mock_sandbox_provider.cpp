#include "compass/core/sandbox.hpp"

namespace compass::core {

namespace {

class MockSandboxProvider final : public ISandboxProvider {
public:
    DetonationReport detonate(const std::filesystem::path& /*sample*/,
                               const SandboxProfile& /*profile*/) override {
        // Fixed, plausible-looking report so annotation-merging code has
        // something real to chew on. Not derived from the sample in any
        // way — see docs/SANDBOX.md for the real QemuTcgSandboxProvider
        // this stands in for.
        DetonationReport report;
        report.completed = true;
        report.executedBlocks = {0x1181, 0x11ac, 0x11d6};
        report.syscalls = {
            {0, 0x119e, "connect", "fd=3, addr=93.184.216.34:443"},
            {5, 0x11c0, "write", "fd=1, buf=\"big 9\\n\", len=6"},
        };
        report.networkEvents = {
            {0, "tcp", "93.184.216.34:443", 512, 2048},
        };
        report.fileEvents = {
            {2, "/tmp/.cache/dropped.bin", "create"},
        };
        return report;
    }
};

} // namespace

std::unique_ptr<ISandboxProvider> makeMockSandboxProvider() {
    return std::make_unique<MockSandboxProvider>();
}

} // namespace compass::core
