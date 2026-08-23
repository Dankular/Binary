// IAnalysisBackend implementation over Rizin's librz — the target
// production backend (see docs/ARCHITECTURE.md). Only compiled when
// COMPASS_HAVE_RIZIN is defined (CMake sets this when librz is found via
// pkg-config), so the project still builds against radare2 alone in
// environments without Rizin packaged.
//
// This is, as docs/ARCHITECTURE.md predicted when this backend didn't
// exist yet, a close mechanical port of radare2_backend.cpp: same JSON
// command surface (aflj/agfj/ij/iSj/isj/iej — Rizin kept these compatible
// with radare2's command language), same parsing logic, just Rz-prefixed
// types and functions. The two are intentionally NOT factored into one
// shared template — the underlying structs (RCore vs RzCore, RIODesc vs
// RzCoreFile, ...) are opaque to this file either way (only their API
// surface is used), so a shared abstraction would buy indirection without
// removing real duplication risk from two upstream projects whose command
// surfaces can still drift.

#include "compass/core/backend.hpp"
#include "compass/core/il/lifter.hpp"

#include <rz_core.h>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <unordered_map>

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

std::pair<std::string, std::string> splitMnemonic(const std::string& opcode) {
    auto pos = opcode.find(' ');
    if (pos == std::string::npos) return {opcode, ""};
    return {opcode.substr(0, pos), opcode.substr(pos + 1)};
}

class RizinBackend final : public IAnalysisBackend {
public:
    ~RizinBackend() override {
        if (core_) rz_core_free(core_);
    }

    bool load(const std::string& path) override {
        core_ = rz_core_new();
        if (!core_) {
            error_ = "rz_core_new failed";
            return false;
        }
        rz_config_set_b(core_->config, "scr.interactive", false);
        rz_config_set(core_->config, "scr.color", "0");

        // rz_core_new() does NOT dlopen dir.plugins itself (confirmed
        // directly, not assumed: it only calls rz_core_loadlibs_init(),
        // which sets up the loader machinery — the actual directory scan
        // is a separate call the `rizin` CLI's own main() makes that
        // nothing in rz_core_new()'s path replicates). Without this,
        // dlopen'd plugins like rz-ghidra (core_ghidra.so) silently never
        // load — `pdgj` just isn't a recognized command — while plugins
        // statically compiled into a librz_*.so (e.g. debug_native) work
        // fine either way, which is what made this easy to miss: decompile()
        // below depends on it. See docs/DECOMPILER.md.
        rz_core_loadlibs(core_, RZ_CORE_LOADLIBS_ALL);

        if (!rz_core_file_open_load(core_, path.c_str(), 0, RZ_PERM_R, false)) {
            error_ = "failed to open file: " + path;
            return false;
        }
        runCmd("aaa");

        binary_.path = path;
        if (!loadInfo() || !loadSections() || !loadSymbols() || !loadFunctions()) {
            return false;
        }
        return true;
    }

    const std::string& lastError() const override { return error_; }
    const Binary& binary() const override { return binary_; }

    void liftLowLevelIL(Function& fn) const override { il::liftFunctionLLIL(fn); }

    // Rizin's signature subsystem is a real FLIRT implementation
    // (librz/sign/flirt.c) — the same .sig format IDA Pro's FLIRT uses —
    // under the `F` command prefix, not the `z`-prefixed zignatures
    // radare2's backend uses (see backend.hpp's note: the two file
    // formats aren't interchangeable). `Fc <path>` creates a signature
    // file from the current binary's analyzed functions; `Fs <path>`
    // opens one and applies it against the current binary.
    bool exportSignatures(const std::string& outputPath, std::string& error) const override {
        std::string out = runCmd("Fc " + outputPath);
        if (out.find("Error") != std::string::npos || out.find("error") != std::string::npos) {
            error = out;
            return false;
        }
        return true;
    }

    std::vector<SignatureMatch> applySignatures(const std::string& path, std::string& error) override {
        std::unordered_map<Address, std::string> before;
        for (auto& fn : binary_.functions) before[fn.entry] = fn.name;

        std::string out = runCmd("Fs " + path);
        if (out.find("Error") != std::string::npos || out.find("Cannot") != std::string::npos) {
            error = out.empty() ? ("failed to apply signature file: " + path) : out;
            return {};
        }

        binary_.functions.clear();
        loadFunctions();

        std::vector<SignatureMatch> matches;
        for (auto& fn : binary_.functions) {
            auto it = before.find(fn.entry);
            if (it != before.end() && it->second != fn.name) {
                matches.push_back({fn.entry, fn.name});
            }
        }
        return matches;
    }

    // rz-ghidra (docs/DECOMPILER.md): a self-contained port of Ghidra's C++
    // decompiler that librz dlopen's as a plugin (see
    // scripts/build_rz_ghidra.sh) — no Java/full Ghidra install involved.
    // `pdgj @ <addr>` decompiles the function containing <addr> and
    // returns {"code": "...", "annotations": [...]}; we only need `code`
    // for this v1 (see DecompiledFunction's note on scope). If the plugin
    // isn't installed, `pdgj` isn't a recognized command and runJson finds
    // no parseable JSON in the output — that's the signal used below to
    // report a clear "not installed" error rather than an opaque parse
    // failure.
    DecompiledFunction decompile(Address entry) override {
        DecompiledFunction result;
        auto j = runJson("pdgj @ " + std::to_string(entry));
        if (!j || !j->contains("code")) {
            result.success = false;
            result.error = "rz-ghidra doesn't appear to be installed (pdgj produced no JSON) — "
                            "see scripts/build_rz_ghidra.sh";
            return result;
        }
        result.success = true;
        result.code = j->value("code", "");
        return result;
    }

    // `pdgx @ <addr>` dumps the same rz-ghidra decompilation's *p-code AST*
    // as XML (not the JSON pdgj above) — see il::translatePcode() and
    // pcode_translator.cpp's file header for the schema this is built on
    // and how each opcode maps to Compass's own MLIL. Raw text via
    // runCmd(), not runJson(): pdgx's output is XML, not JSON.
    il::PcodeTranslationResult pcodeMlil(Address entry) override {
        std::string xml = runCmd("pdgx @ " + std::to_string(entry));
        return il::translatePcode(xml, entry);
    }

private:
    RzCore* core_ = nullptr;
    Binary binary_;
    std::string error_;

    std::string runCmd(const std::string& cmd) const {
        char* out = rz_core_cmd_str(core_, cmd.c_str());
        std::string s = out ? out : "";
        if (out) free(out);
        return s;
    }

    std::optional<json> runJson(const std::string& cmd) const {
        std::string s = runCmd(cmd);
        if (s.empty()) return json::array();
        // Some Rizin commands (pdj/afbj among them; not observed on
        // radare2) prefix their output with a stray ANSI "erase line"
        // escape (ESC[2K) even with scr.color/scr.interactive off — a
        // console-rendering artifact, not JSON. Parse from the first
        // '{'/'[' rather than the start of the string so it doesn't matter
        // which commands do this or why.
        auto start = s.find_first_of("{[");
        if (start == std::string::npos) return std::nullopt;
        try {
            return json::parse(s.substr(start));
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
        if (!j) return true;
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
            if (!loadFunctionGraph(entry, fn)) continue;
            binary_.functions.push_back(std::move(fn));
        }
        return true;
    }

    // Rizin doesn't have radare2's `agfj` (a single command returning
    // blocks-with-embedded-ops, each op carrying esil/type/jump/fail).
    // Its closest equivalent, `agf json`/`agf json_disasm`, turned out to
    // be a genuinely different schema — a generic node/edge graph with
    // pre-rendered (ANSI-colored, even with colors off) disassembly text
    // blobs per node, not per-instruction structured data. Instead this
    // composes two commands that do carry the same structured fields
    // radare2's did: `afbj` for block boundaries + successors, `pdj
    // <ninstr> @ <block>` per block for its instructions (verified to
    // return the same offset/esil/opcode/type/jump/fail shape as
    // radare2's — Rizin keeping `pdj`'s per-instruction schema compatible
    // is what makes this workable at all). One extra round trip per block
    // versus radare2's single call; not a problem at the scale validated
    // here (see docs/ROADMAP.md for revisiting if it matters on huge
    // functions).
    bool loadFunctionGraph(Address entry, Function& fn) {
        auto blocksJson = runJson("afbj @ " + std::to_string(entry));
        if (!blocksJson || blocksJson->empty()) return false;

        for (auto& blockJson : *blocksJson) {
            BasicBlock bb;
            bb.start = blockJson.value("addr", 0ULL);
            bb.end = bb.start + blockJson.value("size", 0ULL);
            if (blockJson.contains("jump") && !blockJson["jump"].is_null()) {
                bb.successors.push_back(blockJson["jump"].get<Address>());
            }
            if (blockJson.contains("fail") && !blockJson["fail"].is_null()) {
                bb.successors.push_back(blockJson["fail"].get<Address>());
            }
            int ninstr = blockJson.value("ninstr", 0);

            auto ops = runJson("pdj " + std::to_string(ninstr) + " @ " + std::to_string(bb.start));
            if (ops) {
                for (std::size_t i = 0; i < ops->size(); ++i) {
                    auto& op = (*ops)[i];
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
                    insn.isBlockTerminator = (i + 1 == ops->size());
                    if (insn.isBlockTerminator) insn.successors = bb.successors;

                    bb.instructions.push_back(std::move(insn));
                }
            }
            fn.basicBlocks.push_back(std::move(bb));
        }
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

std::unique_ptr<IAnalysisBackend> makeRizinBackend() {
    return std::make_unique<RizinBackend>();
}

} // namespace compass::core
