// IAnalysisBackend implementation over radare2's libr.
//
// Deliberately drives radare2 through its JSON command output (aflj, agfj,
// ij, iSj, isj) rather than walking RAnalFunction/RAnalBlock/RAnalOp C
// structs directly. Those structs' field layouts differ between radare2 and
// Rizin (and across radare2 versions), while the JSON command surface is
// the stable, documented integration point both projects support — so this
// choice is what actually makes "swap radare2 for Rizin" a small change
// (see docs/ARCHITECTURE.md) rather than an ABI-matching exercise.

#include "compass/core/backend.hpp"
#include "compass/core/il/lifter.hpp"

#include <r_core.h>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>

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

Architecture archFromInfo(const std::string& arch, int bits) {
    if (arch == "x86" && bits == 64) return Architecture::X86_64;
    if (arch == "x86") return Architecture::X86;
    if (arch == "arm" && bits == 64) return Architecture::ARM64;
    if (arch == "arm") return Architecture::ARM32;
    if (arch == "mips") return Architecture::MIPS;
    return Architecture::Unknown;
}

/// Splits "mov rax, rbx" into ("mov", "rax, rbx"); a bare mnemonic like
/// "ret" splits into ("ret", "").
std::pair<std::string, std::string> splitMnemonic(const std::string& opcode) {
    auto pos = opcode.find(' ');
    if (pos == std::string::npos) return {opcode, ""};
    return {opcode.substr(0, pos), opcode.substr(pos + 1)};
}

class Radare2Backend final : public IAnalysisBackend {
public:
    ~Radare2Backend() override {
        if (core_) r_core_free(core_);
    }

    bool load(const std::string& path) override {
        core_ = r_core_new();
        if (!core_) {
            error_ = "r_core_new failed";
            return false;
        }
        // Keep JSON command output free of progress spinners/ANSI escapes.
        r_config_set_b(core_->config, "scr.interactive", false);
        r_config_set(core_->config, "scr.color", "0");

        RIODesc* fd = r_core_file_open(core_, path.c_str(), R_PERM_R, 0);
        if (!fd) {
            error_ = "failed to open file: " + path;
            return false;
        }
        r_core_bin_load(core_, nullptr, UT64_MAX);
        runCmd("aaa"); // full auto-analysis: functions, xrefs, call args, ...

        binary_.path = path;
        if (!loadInfo() || !loadSections() || !loadSymbols() || !loadFunctions()) {
            return false;
        }
        return true;
    }

    const std::string& lastError() const override { return error_; }
    const Binary& binary() const override { return binary_; }

    void liftLowLevelIL(Function& fn) const override {
        // Implemented in llil_lifter.cpp against the already-populated
        // Instruction::esil/opType/jumpTarget/failTarget fields — no
        // further backend calls needed here.
        il::liftFunctionLLIL(fn);
    }

private:
    RCore* core_ = nullptr;
    Binary binary_;
    std::string error_;

    std::string runCmd(const std::string& cmd) {
        char* out = r_core_cmd_str(core_, cmd.c_str());
        std::string s = out ? out : "";
        if (out) free(out);
        return s;
    }

    std::optional<json> runJson(const std::string& cmd) {
        std::string s = runCmd(cmd);
        if (s.empty()) return json::array();
        try {
            return json::parse(s);
        } catch (const json::parse_error&) {
            return std::nullopt;
        }
    }

    bool loadInfo() {
        auto j = runJson("ij");
        if (!j) {
            error_ = "failed to parse `ij` output";
            return false;
        }
        auto bin = (*j).value("bin", json::object());
        auto core = (*j).value("core", json::object());
        binary_.format = core.value("format", "");
        std::string arch = bin.value("arch", "");
        int bits = bin.value("bits", 0);
        binary_.arch = archFromInfo(arch, bits);

        auto ej = runJson("iej");
        if (ej && !ej->empty() && (*ej)[0].contains("vaddr")) {
            binary_.entryPoint = (*ej)[0].value("vaddr", 0ULL);
        }
        return true;
    }

    bool loadSections() {
        auto j = runJson("iSj");
        if (!j) return true; // non-fatal: some formats (raw) have no sections
        for (auto& s : *j) {
            Section sec;
            sec.name = s.value("name", "");
            sec.vaddr = s.value("vaddr", 0ULL);
            sec.size = s.value("vsize", 0ULL);
            std::string perm = s.value("perm", "");
            sec.executable = perm.find('x') != std::string::npos;
            sec.writable = perm.find('w') != std::string::npos;
            binary_.sections.push_back(std::move(sec));
        }
        return true;
    }

    bool loadSymbols() {
        auto j = runJson("isj");
        if (!j) return true;
        for (auto& s : *j) {
            Symbol sym;
            sym.name = s.value("realname", s.value("name", ""));
            sym.address = s.value("vaddr", 0ULL);
            sym.isFunction = s.value("type", "") == "FUNC";
            binary_.symbols.push_back(std::move(sym));
        }
        return true;
    }

    bool loadFunctions() {
        auto listing = runJson("aflj");
        if (!listing) {
            error_ = "failed to parse `aflj` output";
            return false;
        }
        for (auto& fnEntry : *listing) {
            Address entry = fnEntry.value("offset", 0ULL);
            Function fn;
            fn.entry = entry;
            fn.name = fnEntry.value("name", "");
            if (!loadFunctionGraph(entry, fn)) {
                // Skip functions radare2 couldn't produce a graph for
                // (rare, e.g. some plt stubs) rather than failing the load.
                continue;
            }
            binary_.functions.push_back(std::move(fn));
        }
        return true;
    }

    bool loadFunctionGraph(Address entry, Function& fn) {
        auto graph = runJson("agfj @ " + std::to_string(entry));
        if (!graph || graph->empty()) return false;
        auto& fnJson = (*graph)[0];
        for (auto& blockJson : fnJson.value("blocks", json::array())) {
            BasicBlock bb;
            bb.start = blockJson.value("offset", 0ULL);
            bb.end = bb.start + blockJson.value("size", 0ULL);
            if (blockJson.contains("jump") && !blockJson["jump"].is_null()) {
                bb.successors.push_back(blockJson["jump"].get<Address>());
            }
            if (blockJson.contains("fail") && !blockJson["fail"].is_null()) {
                bb.successors.push_back(blockJson["fail"].get<Address>());
            }

            auto ops = blockJson.value("ops", json::array());
            for (std::size_t i = 0; i < ops.size(); ++i) {
                auto& op = ops[i];
                Instruction insn;
                insn.address = op.value("offset", 0ULL);
                insn.size = op.value("size", 0U);
                auto [mnem, operandsText] = splitMnemonic(op.value("opcode", ""));
                insn.mnemonic = mnem;
                insn.operandsText = operandsText;
                insn.esil = op.value("esil", "");
                insn.opType = op.value("type", "");
                if (op.contains("bytes")) insn.bytes = hexDecode(op["bytes"].get<std::string>());

                if (op.contains("jump") && !op["jump"].is_null()) {
                    insn.jumpTarget = op["jump"].get<Address>();
                }
                if (op.contains("fail") && !op["fail"].is_null()) {
                    insn.failTarget = op["fail"].get<Address>();
                }
                insn.isBlockTerminator = (i + 1 == ops.size());
                if (insn.isBlockTerminator) insn.successors = bb.successors;

                bb.instructions.push_back(std::move(insn));
            }
            fn.basicBlocks.push_back(std::move(bb));
        }
        // predecessors from successors, now that all blocks are known
        for (auto& bb : fn.basicBlocks) {
            for (auto succ : bb.successors) {
                for (auto& other : fn.basicBlocks) {
                    if (other.start == succ) other.predecessors.push_back(bb.start);
                }
            }
        }
        return true;
    }
};

} // namespace

std::unique_ptr<IAnalysisBackend> makeRadare2Backend() {
    return std::make_unique<Radare2Backend>();
}

} // namespace compass::core
