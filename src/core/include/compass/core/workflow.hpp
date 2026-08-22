#pragma once

#include "compass/core/binary.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace compass::core {

/// One unit of analysis a Workflow can run against a function. Binary
/// Ninja's "workflows" are the model here: a named, independently
/// runnable, user-registerable step over the IL — not hardcoded into the
/// core engine.
///
/// A pass may assume `fn.llil` is already populated (the CLI/caller lifts
/// it once per function before running any workflow) but should lift
/// mlil/hlil itself on demand if it needs them and they're absent, rather
/// than crashing — see BuiltinPasses in workflow.cpp for the pattern.
class IAnalysisPass {
public:
    virtual ~IAnalysisPass() = default;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;
    /// `binary` is passed alongside `fn` (rather than `fn` alone) because
    /// useful passes need cross-function context — symbol names for call
    /// targets, other functions' addresses — not just one function in
    /// isolation.
    virtual void run(const Binary& binary, Function& fn) const = 0;
};

/// Where every pass — built into compass-core (workflow.cpp) or supplied
/// by a plugin (see plugin.hpp) — ends up, keyed by name. One process-wide
/// instance; registration happens at static-init time for built-ins and
/// during IPlugin::onLoad() for plugin-supplied passes.
class PassRegistry {
public:
    static PassRegistry& instance();

    /// Last registration for a given name wins (a plugin can deliberately
    /// override a built-in pass by reusing its name) — logged by the
    /// caller if that matters to them, not silently forbidden here.
    void registerPass(std::shared_ptr<IAnalysisPass> pass);
    std::shared_ptr<IAnalysisPass> find(const std::string& name) const;
    std::vector<std::string> names() const;

private:
    std::unordered_map<std::string, std::shared_ptr<IAnalysisPass>> passes_;
};

/// An ordered pipeline of passes (by name, resolved against PassRegistry
/// at run time — so a pass registered by a plugin loaded after the
/// Workflow was built still resolves correctly) run over one function.
class Workflow {
public:
    void addPass(std::string name) { passNames_.push_back(std::move(name)); }
    const std::vector<std::string>& passNames() const { return passNames_; }

    /// Runs each pass in order; a name PassRegistry doesn't recognize is
    /// reported in the returned list rather than thrown — a workflow
    /// referencing an unavailable plugin pass shouldn't take down
    /// everything else in the pipeline.
    std::vector<std::string> run(const Binary& binary, Function& fn) const;

private:
    std::vector<std::string> passNames_;
};

} // namespace compass::core
