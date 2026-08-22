// Python bindings for compass-core, via pybind11.
//
// Deliberately binds a flat, plain-Python-types API (str/int/list/dict) —
// "load a binary, list functions, disassemble one, get its IL as text,
// run a workflow and read its annotations" — rather than exposing the
// full C++ object graph (Function/BasicBlock/Instruction/MLILExpr as
// live Python classes referencing into a shared Binary). That richer
// binding is real, useful future work (a Python plugin wanting to build
// its own analysis over the IL tree needs it), but it also means solving
// real ownership/lifetime questions — who keeps a Binary alive while
// Python holds a reference to one of its Functions, what happens if
// Python mutates a Function via the same passes the CLI runs, etc. The
// flat API mirrors what compass-cli itself already does (render IL to
// text, run a workflow, read fn.annotations), which is a real, working,
// substantially simpler slice to bind correctly first.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "compass/core/backend.hpp"
#include "compass/core/il/hlil_builder.hpp"
#include "compass/core/il/low_level_il.hpp"
#include "compass/core/il/mlil_builder.hpp"
#include "compass/core/il/type_inference.hpp"
#include "compass/core/plugin_manager.hpp"
#include "compass/core/workflow.hpp"

namespace py = pybind11;
using namespace compass::core;

namespace {

/// Finds a copy of the named function, lifting llil/mlil/hlil into the
/// copy on demand — same pattern compass-cli's main.cpp uses (see its
/// `--function` handling), reimplemented here rather than shared because
/// the two have different output shapes (CLI prints to stdout; this
/// returns Python values) and the lifting logic itself is a few lines.
class Session {
public:
    bool load(const std::string& path) {
        backend_ = makeDefaultAnalysisBackend();
        return backend_->load(path);
    }

    std::string lastError() const { return backend_ ? backend_->lastError() : "no backend"; }

    py::dict info() const {
        py::dict d;
        auto& bin = backend_->binary();
        d["path"] = bin.path;
        d["format"] = bin.format;
        d["arch"] = toString(bin.arch);
        d["entry"] = bin.entryPoint;
        d["sections"] = bin.sections.size();
        d["symbols"] = bin.symbols.size();
        d["functions"] = bin.functions.size();
        return d;
    }

    py::list listFunctions() const {
        py::list out;
        for (auto& fn : backend_->binary().functions) {
            out.append(py::make_tuple(fn.name, fn.entry, fn.basicBlocks.size()));
        }
        return out;
    }

    py::list disassemble(const std::string& functionName) const {
        py::list out;
        const Function* fn = findOrThrow(functionName);
        for (auto& bb : fn->basicBlocks) {
            for (auto& insn : bb.instructions) {
                py::dict d;
                d["address"] = insn.address;
                d["mnemonic"] = insn.mnemonic;
                d["operands"] = insn.operandsText;
                d["bytes_size"] = insn.size;
                out.append(d);
            }
        }
        return out;
    }

    std::string liftLlil(const std::string& functionName) const {
        Function fn = *findOrThrow(functionName);
        backend_->liftLowLevelIL(fn);
        return il::render(*fn.llil);
    }

    std::string liftMlil(const std::string& functionName, bool ssa) const {
        Function fn = *findOrThrow(functionName);
        backend_->liftLowLevelIL(fn);
        fn.mlil = il::buildMlil(fn);
        il::attachTypes(*fn.mlil);
        if (!ssa) return il::render(*fn.mlil);
        auto ssaFn = il::buildMlilSsa(*fn.mlil);
        return il::render(ssaFn);
    }

    std::string liftHlil(const std::string& functionName) const {
        Function fn = *findOrThrow(functionName);
        backend_->liftLowLevelIL(fn);
        fn.mlil = il::buildMlil(fn);
        il::attachTypes(*fn.mlil);
        auto hlilFn = il::buildHlil(*fn.mlil);
        return il::render(hlilFn);
    }

    /// Loads `plugins` (paths to .so files), runs `passes` (by name)
    /// against the named function, and returns the annotations they
    /// produced. Each call gets a fresh PluginManager — plugins stay
    /// loaded for that call's lifetime (see PluginManager's own docs on
    /// why they're never unloaded), so calling this repeatedly with the
    /// same plugin path reloads it each time rather than reusing a
    /// previous load. Fine for the workflow this is meant for (a script
    /// running a one-shot analysis); a session wanting to reuse loaded
    /// plugins across many calls is real, separate future API surface.
    py::list runPasses(const std::string& functionName, const std::vector<std::string>& plugins,
                        const std::vector<std::string>& passes) {
        PluginManager pm;
        for (auto& p : plugins) {
            std::string error;
            if (!pm.loadPlugin(p, error)) {
                throw std::runtime_error("failed to load plugin " + p + ": " + error);
            }
        }
        Function fn = *findOrThrow(functionName);
        backend_->liftLowLevelIL(fn);
        Workflow workflow;
        for (auto& p : passes) workflow.addPass(p);
        auto problems = workflow.run(backend_->binary(), fn);
        py::list out;
        for (auto& a : fn.annotations) out.append(a);
        for (auto& p : problems) out.append(py::str("warning: " + p));
        return out;
    }

private:
    const Function* findOrThrow(const std::string& name) const {
        const Function* fn = backend_->binary().functionNamed(name);
        if (!fn) throw std::runtime_error("function not found: " + name);
        return fn;
    }

    std::unique_ptr<IAnalysisBackend> backend_;
};

} // namespace

PYBIND11_MODULE(compass, m) {
    m.doc() = "Compass core engine — headless reverse-engineering IL stack (see docs/ARCHITECTURE.md)";

    py::class_<Session>(m, "Session")
        .def(py::init<>())
        .def("load", &Session::load, py::arg("path"),
             "Loads a binary. Returns True on success; check .last_error() on failure.")
        .def("last_error", &Session::lastError)
        .def("info", &Session::info, "Returns a dict: path/format/arch/entry/sections/symbols/functions")
        .def("list_functions", &Session::listFunctions,
             "Returns a list of (name, entry_address, basic_block_count) tuples")
        .def("disassemble", &Session::disassemble, py::arg("function_name"),
             "Returns a list of {address, mnemonic, operands, bytes_size} dicts")
        .def("lift_llil", &Session::liftLlil, py::arg("function_name"), "Rendered LLIL text")
        .def("lift_mlil", &Session::liftMlil, py::arg("function_name"), py::arg("ssa") = false,
             "Rendered MLIL text; pass ssa=True for SSA form")
        .def("lift_hlil", &Session::liftHlil, py::arg("function_name"), "Rendered HLIL text")
        .def("run_passes", &Session::runPasses, py::arg("function_name"), py::arg("plugins"),
             py::arg("passes"),
             "Loads the given plugin .so paths, runs the named passes against the function, "
             "returns its resulting annotations");
}
