#pragma once

#include "compass/core/binary.hpp"
#include "compass/core/sandbox.hpp"

namespace compass::core {

/// Merges a completed sandbox run's DetonationReport onto a
/// statically-loaded Binary, as human-readable annotations — the same
/// deliberately-simple free-form-string design Function::annotations
/// already uses for workflow-pass findings. See docs/ANNOTATIONS.md for
/// what's attributable to a specific function/block today versus what
/// only attaches at the binary level, and why.
///
/// `binary` must be the result of statically loading the exact same
/// sample the report was produced from (IAnalysisBackend::load() against
/// the path passed to ISandboxProvider::detonate()) — this function does
/// not check that itself.
void mergeDetonationReport(Binary& binary, const DetonationReport& report);

} // namespace compass::core
