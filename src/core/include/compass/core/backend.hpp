#pragma once

#include "compass/core/binary.hpp"
#include "compass/core/il/low_level_il.hpp"

#include <memory>
#include <string>
#include <vector>

namespace compass::core {

/// One function a signature file matched against the currently loaded
/// binary — see IAnalysisBackend::applySignatures().
struct SignatureMatch {
    Address address;
    std::string matchedName;
};

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

    /// Generates a function-signature file from the currently loaded
    /// binary's analyzed functions, written to `outputPath`. The file
    /// format is backend-specific — Rizin writes its own FLIRT `.sig`
    /// format (the same one IDA Pro's FLIRT uses); radare2 writes its own
    /// zignature format. A signature file made by one backend is NOT
    /// portable to the other (different serialization entirely, not just
    /// a naming difference) — this is a real, documented limitation, not
    /// an oversight; see docs/ARCHITECTURE.md.
    virtual bool exportSignatures(const std::string& outputPath, std::string& error) const = 0;

    /// Loads a signature file (same backend-specific format
    /// exportSignatures wrote) and attempts to match it against functions
    /// in the currently loaded binary — the actual "was this stripped/
    /// unknown function seen before" use case. Matched functions have
    /// their name updated in binary() to reflect the match, and are
    /// returned here as (address, matchedName) pairs — the same
    /// information, just without requiring the caller to diff binary()
    /// before and after to notice what changed.
    virtual std::vector<SignatureMatch> applySignatures(const std::string& path, std::string& error) = 0;
};

std::unique_ptr<IAnalysisBackend> makeRadare2Backend();

#ifdef COMPASS_HAVE_RIZIN
/// The target production backend (see docs/ARCHITECTURE.md) — only
/// declared when CMake found librz via pkg-config (COMPASS_HAVE_RIZIN).
std::unique_ptr<IAnalysisBackend> makeRizinBackend();
#endif

/// Picks Rizin when this build was compiled against it, radare2 otherwise
/// — the CLI and anything else that just wants "the best backend
/// available" should call this instead of naming one directly.
std::unique_ptr<IAnalysisBackend> makeDefaultAnalysisBackend();

} // namespace compass::core
