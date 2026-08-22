#pragma once

#include "compass/core/binary.hpp"
#include "compass/core/il/low_level_il.hpp"

#include <memory>
#include <string>

namespace compass::core {

/// Everything above this interface (domain model, IL, and eventually the
/// GUI) is written once against this contract. Today's implementation
/// (RadareBackend, src/core/src/radare2_backend.cpp) wraps libr; the target
/// production backend is Rizin's librz — see docs/ARCHITECTURE.md for why
/// they're not the same thing yet in this environment, and why swapping one
/// for the other is a single-file change.
class IAnalysisBackend {
public:
    virtual ~IAnalysisBackend() = default;

    /// Loads a file and runs auto-analysis (function discovery, etc).
    /// Returns false (with getLastError() set) on failure.
    virtual bool load(const std::string& path) = 0;

    virtual const std::string& lastError() const = 0;

    /// Full binary model: sections, symbols, functions with basic blocks
    /// and per-instruction ESIL already populated.
    virtual const Binary& binary() const = 0;

    /// Lifts LLIL for a function in place (fn.llil). Separate from load()
    /// because LLIL lifting is comparatively expensive and callers (CLI,
    /// future GUI) may only want it for a handful of functions.
    virtual void liftLowLevelIL(Function& fn) const = 0;
};

std::unique_ptr<IAnalysisBackend> makeRadare2Backend();

} // namespace compass::core
