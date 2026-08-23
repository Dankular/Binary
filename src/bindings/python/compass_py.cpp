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

#include <utility>
#include <vector>

namespace py = pybind11;
using namespace compass::core;

namespace {

// ---------------------------------------------------------------------
// Python-side plugin loading (docs/ROADMAP.md Milestone 2): lets a pass
// be authored *in* Python — an importlib-discovered .py module calling
// compass.register_pass() with a Python subclass of compass.AnalysisPass
// — and have it run through the exact same PassRegistry/Workflow every
// C++ .so plugin's passes already run through. No changes needed to
// Session::runPasses() below for this to work: PassRegistry::instance()
// is one process-wide singleton Workflow::run() resolves pass names
// against at run time, regardless of whether the pass was registered by
// a dlopen'd C++ plugin or from Python — see workflow.hpp's own note on
// exactly that property. The importlib discovery loop itself is pure
// Python (see compass_plugins.py next to this module) — nothing to bind
// for that part.
//
// Deliberately NOT exposing the full IL tree here (that's the separate
// "richer Python bindings" roadmap item) — a Python pass gets the same
// flat disassembly view Session.disassemble() already gives Python
// callers, plus symbol lookup and fn.add_annotation(), which is enough
// for a real pass (see plugins/example_py_io_flagger/io_flagger.py) —
// not the MLIL/HLIL trees, which would need the ownership/lifetime
// design that item is scoped around.

/// Trampoline letting a Python class override IAnalysisPass's virtuals —
/// this is what makes a Python-authored pass indistinguishable to
/// PassRegistry/Workflow from a C++ one.
class PyAnalysisPass : public IAnalysisPass {
public:
    using IAnalysisPass::IAnalysisPass;

    std::string name() const override { PYBIND11_OVERRIDE_PURE(std::string, IAnalysisPass, name); }
    std::string description() const override {
        PYBIND11_OVERRIDE_PURE(std::string, IAnalysisPass, description);
    }

    // Not PYBIND11_OVERRIDE_PURE here — a real bug found running this
    // against an actual pass, not a hypothetical: that macro casts its
    // arguments with return_value_policy::automatic_reference, which
    // pybind11's own cast() resolves to *copy* for any lvalue-reference
    // argument (see cast.h — only a raw pointer gets `reference`). Since
    // `fn` is a `Function&`, every override(...) call was silently
    // handing the Python override a throwaway copy: a pass's
    // fn.add_annotation(...) appeared to work (no error, correct data
    // visible inside run()) but the mutation never reached the real
    // Function back in Workflow::run() — Session.run_passes() always
    // came back with zero annotations from a Python pass. Confirmed by
    // comparing against the identical C++-plugin path (which never
    // crosses into Python and worked correctly all along). Fixed by
    // building the call by hand with an explicit `reference` policy on
    // both arguments, bypassing the macro's default entirely.
    void run(const Binary& binary, Function& fn) const override {
        pybind11::gil_scoped_acquire gil;
        pybind11::function override_fn = pybind11::get_override(static_cast<const IAnalysisPass*>(this), "run");
        if (!override_fn) {
            pybind11::pybind11_fail("Tried to call pure virtual function \"IAnalysisPass::run\"");
        }
        override_fn(pybind11::cast(binary, pybind11::return_value_policy::reference),
                     pybind11::cast(fn, pybind11::return_value_policy::reference));
    }
};

/// binary.symbol_name_at(address) — the same address->name lookup
/// plugins/example_io_flagger/plugin.cpp does by hand over binary.symbols;
/// exposed as a method so a Python pass doesn't need binary.symbols'
/// full struct layout bound just for this one lookup.
py::object symbolNameAt(const Binary& b, Address address) {
    for (auto& sym : b.symbols) {
        if (sym.address == address) return py::str(sym.name);
    }
    return py::none();
}

/// Passes registered from Python, pinned here for the process's lifetime.
///
/// Real bug found running this against an actual pass, not hypothetical:
/// without this, a pass constructed and registered inside a function (the
/// normal shape — see compass_plugins.py's register() convention) with no
/// Python variable outstanding afterward was garbage-collected as soon as
/// that function returned, *despite* PassRegistry still holding a
/// std::shared_ptr<IAnalysisPass> to it — pybind11's shared_ptr holder
/// does not, in this configuration, keep a Python-constructed trampoline
/// instance's underlying PyObject alive for as long as C++-side shared_ptr
/// copies of it exist. First call into the (by-then-destroyed) instance
/// raised "Tried to call pure virtual function \"IAnalysisPass::run\"" —
/// reproduced directly with a minimal register()-shaped repro (construct,
/// register, return, gc.collect(), then run) before trusting this
/// diagnosis. Fixed the straightforward way: hold a real, independent
/// Python reference to every registered pass ourselves, exactly the same
/// "registered means kept alive for good" contract
/// compass::core::PluginManager already has for .so plugins (see its own
/// doc note on never unloading one), just via Python refcounting instead
/// of dlopen.
///
/// Deliberately a leaked heap pointer, not a plain static std::vector: a
/// plain static's destructor runs at process exit in unspecified order
/// relative to Py_Finalize() — hit directly running this (Fatal Python
/// error: PyThreadState_Get called with no GIL/thread state, tearing down
/// after the interpreter itself had already finalized). Same root cause
/// and same fix PluginManager's own destructor doc note describes for
/// never dlclose()-ing: destroying something whose lifetime the runtime
/// (Python's finalizer, there a plugin's unmapped .so) has already ended
/// crashes, so don't run that destructor at all — let the OS reclaim it
/// at process exit instead.
std::vector<py::object>& pinnedPythonPasses() {
    static auto* pinned = new std::vector<py::object>();
    return *pinned;
}

/// fn.disassembly() — same {address, mnemonic, operands, bytes_size}
/// shape Session.disassemble() returns, plus jump_target (None for
/// non-branches/indirect branches): a Python pass resolving a call's
/// target (see the example plugin) needs the structured target, not a
/// text-parse of `operands` — Instruction::operandsText is a bare hex
/// address for calls in this backend's disassembly text, verified
/// directly rather than assumed, so it's not name-bearing text to match
/// against in the first place.
py::list functionDisassembly(const Function& fn) {
    py::list out;
    for (auto& bb : fn.basicBlocks) {
        for (auto& insn : bb.instructions) {
            py::dict d;
            d["address"] = insn.address;
            d["mnemonic"] = insn.mnemonic;
            d["operands"] = insn.operandsText;
            d["bytes_size"] = insn.size;
            d["jump_target"] = insn.jumpTarget ? py::object(py::int_(*insn.jumpTarget)) : py::none();
            out.append(d);
        }
    }
    return out;
}

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

    // Python-side plugin loading (docs/ROADMAP.md Milestone 2) — see this
    // file's earlier comment block and compass_plugins.py for the full
    // design. Binary/Function here are the narrow, pass-writing-facing
    // facade (path/format/symbol lookup; name/entry/disassembly/
    // add_annotation) — not the full object graph.
    py::class_<Binary>(m, "Binary")
        .def_property_readonly("path", [](const Binary& b) { return b.path; })
        .def_property_readonly("format", [](const Binary& b) { return b.format; })
        .def("symbol_name_at", &symbolNameAt, py::arg("address"),
             "Symbol name at this address, or None if there isn't one.");

    py::class_<Function>(m, "Function")
        .def_property_readonly("name", [](const Function& f) { return f.name; })
        .def_property_readonly("entry", [](const Function& f) { return f.entry; })
        .def("disassembly", &functionDisassembly,
             "Returns a list of {address, mnemonic, operands, bytes_size, jump_target} dicts.")
        .def(
            "add_annotation", [](Function& f, const std::string& text) { f.annotations.push_back(text); },
            py::arg("text"), "Appends a finding to this function's annotations, same as a C++ pass would.");

    py::class_<IAnalysisPass, PyAnalysisPass, std::shared_ptr<IAnalysisPass>>(m, "AnalysisPass",
        "Subclass this, implement name()/description()/run(binary, function), then pass an "
        "instance to compass.register_pass() — see compass_plugins.py.")
        .def(py::init<>())
        .def("name", &IAnalysisPass::name)
        .def("description", &IAnalysisPass::description)
        .def("run", &IAnalysisPass::run, py::arg("binary"), py::arg("function"));

    m.def(
        "register_pass",
        [](py::object passObj) {
            auto pass = passObj.cast<std::shared_ptr<IAnalysisPass>>();
            PassRegistry::instance().registerPass(pass);
            // See pinnedPythonPasses()'s doc comment above — this is
            // load-bearing, not defensive-programming boilerplate.
            pinnedPythonPasses().push_back(std::move(passObj));
        },
        py::arg("pass"),
        "Registers a pass (typically a Python AnalysisPass subclass) into the process-wide "
        "PassRegistry, exactly like a C++ plugin's IPlugin::onLoad() does — from then on it's "
        "resolvable by name from Session.run_passes(), indistinguishable from a C++-supplied pass.");

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
