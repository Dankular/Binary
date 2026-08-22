// Unit test for mergeDetonationReport() against hand-built Binary/
// DetonationReport data with known answers. Exists because the real
// dynamic-analysis pipeline (QemuTcgSandboxProvider) doesn't populate
// SyscallEvent::callSite or DetonationReport::executedBlocks yet (see
// docs/ANNOTATIONS.md) — this test proves the merge logic itself is
// correct (address-to-block attribution, binary-vs-function-vs-block
// placement, dedup) using addresses a provider *would* produce once it
// tracks them, rather than leaving that code path untested until then.
#include "compass/core/annotation_merge.hpp"

#include <cstdio>
#include <cstdlib>

using namespace compass::core;

namespace {

int failures = 0;

void check(bool cond, const char* what) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

bool contains(const std::vector<std::string>& v, const std::string& needle) {
    for (auto& s : v) {
        if (s.find(needle) != std::string::npos) return true;
    }
    return false;
}

BasicBlock block(Address start, Address end) {
    BasicBlock bb;
    bb.start = start;
    bb.end = end;
    return bb;
}

Binary buildBinary() {
    Binary bin;
    bin.path = "test";

    Function add;
    add.entry = 0x1149;
    add.name = "sym.add";
    add.basicBlocks = {block(0x1149, 0x1161)};

    Function main;
    main.entry = 0x1161;
    main.name = "main";
    main.basicBlocks = {block(0x1161, 0x1180), block(0x1180, 0x11a0)};

    bin.functions = {add, main};
    return bin;
}

void testFileAndNetworkEventsAttachToBinary() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = true;
    report.fileEvents.push_back({100, "/tmp/dropped.txt", "create"});
    report.networkEvents.push_back({200, "tcp", "93.184.216.34:80", 0, 0});

    mergeDetonationReport(bin, report);

    check(contains(bin.annotations, "dropped.txt"), "file event lands on Binary::annotations");
    check(contains(bin.annotations, "93.184.216.34:80"), "network event lands on Binary::annotations");
    check(bin.functions[0].annotations.empty(), "file/network events don't leak onto functions");
    check(bin.functions[1].annotations.empty(), "file/network events don't leak onto functions (2)");
}

void testUncompletedReportRecordsError() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = false;
    report.error = "guest never reached a login prompt";

    mergeDetonationReport(bin, report);

    check(contains(bin.annotations, "did not complete"), "uncompleted report recorded on Binary::annotations");
    check(contains(bin.annotations, "login prompt"), "uncompleted report keeps the real error text");
}

void testSyscallCallSiteAttachesToTheRightBlock() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = true;
    SyscallEvent sc;
    sc.timestampMs = 50;
    sc.callSite = 0x1155; // inside add()'s only block
    sc.name = "openat";
    sc.argsText = "AT_FDCWD, \"/etc/passwd\"";
    report.syscalls.push_back(sc);

    mergeDetonationReport(bin, report);

    check(contains(bin.functions[0].basicBlocks[0].annotations, "openat"),
          "syscall with a callSite lands on the containing block, not the function or binary");
    check(bin.functions[0].annotations.empty(), "callSite'd syscall doesn't also duplicate onto Function::annotations");
    check(bin.annotations.empty(), "callSite'd syscall doesn't also duplicate onto Binary::annotations");
}

void testSyscallWithoutCallSiteIsANoOp() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = true;
    SyscallEvent sc;
    sc.callSite = 0; // unset — see mergeDetonationReport's comment on why this is the common case today
    sc.name = "brk";
    report.syscalls.push_back(sc);

    mergeDetonationReport(bin, report);

    check(bin.functions[0].basicBlocks[0].annotations.empty(), "no callSite means no attribution anywhere");
    check(bin.functions[0].annotations.empty(), "no callSite means no attribution anywhere (fn)");
    check(bin.annotations.empty(), "no callSite means no attribution anywhere (binary)");
}

void testExecutedBlocksAttachAndDedup() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = true;
    // main()'s second block, hit twice — should produce exactly one note,
    // not two (coverage is boolean in v1, see mergeDetonationReport).
    report.executedBlocks = {0x1185, 0x1185};

    mergeDetonationReport(bin, report);

    auto& notes = bin.functions[1].basicBlocks[1].annotations;
    check(notes.size() == 1, "repeated coverage of the same block produces exactly one annotation, not one per hit");
    check(!notes.empty() && notes[0].find("coverage") != std::string::npos, "coverage annotation mentions coverage");
    check(bin.functions[1].basicBlocks[0].annotations.empty(), "coverage doesn't leak onto a block that wasn't executed");
}

void testAddressOutsideAnyFunctionIsIgnored() {
    Binary bin = buildBinary();
    DetonationReport report;
    report.completed = true;
    report.executedBlocks = {0xdeadbeef};
    SyscallEvent sc;
    sc.callSite = 0xdeadbeef;
    sc.name = "write";
    report.syscalls.push_back(sc);

    mergeDetonationReport(bin, report); // must not crash, and must attribute nothing

    for (auto& fn : bin.functions) {
        check(fn.annotations.empty(), "out-of-range address doesn't land on any function");
        for (auto& bb : fn.basicBlocks) {
            check(bb.annotations.empty(), "out-of-range address doesn't land on any block");
        }
    }
    check(bin.annotations.empty(), "out-of-range address doesn't fall back to Binary::annotations either");
}

} // namespace

int main() {
    testFileAndNetworkEventsAttachToBinary();
    testUncompletedReportRecordsError();
    testSyscallCallSiteAttachesToTheRightBlock();
    testSyscallWithoutCallSiteIsANoOp();
    testExecutedBlocksAttachAndDedup();
    testAddressOutsideAnyFunctionIsIgnored();

    if (failures) {
        std::fprintf(stderr, "%d annotation-merge test(s) failed\n", failures);
        return 1;
    }
    std::printf("ALL ANNOTATION MERGE TESTS PASSED\n");
    return 0;
}
