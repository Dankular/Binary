#pragma once

#include "compass/core/workflow.hpp"

#include <memory>
#include <string>

namespace compass::core {

/// Bumped when this header's interface changes incompatibly (a virtual
/// function added/removed/reordered on IPlugin or PluginContext, an ABI-
/// affecting change anywhere a plugin might touch). PluginManager checks a
/// loaded .so's compass_plugin_abi_version() against this before calling
/// anything else on it.
///
/// What this version check does NOT cover: building the plugin with a
/// different compiler or standard-library version than the host process.
/// Passing C++ objects (IPlugin*, shared_ptr, std::string, std::vector)
/// across a .so boundary only works when both sides agree on their layout
/// — in practice, "compiled with the same compiler and the same
/// standard-library ABI as compass-core," the same constraint most C++
/// plugin systems live with (Qt, LLVM passes, etc.). This isn't attempting
/// the stronger guarantee a C-only ABI (or a stable-ABI layer like COM)
/// would give; that's real, separate work, not a gap being glossed over.
constexpr int kPluginAbiVersion = 1;

/// What a plugin gets access to during IPlugin::onLoad() — deliberately
/// narrow today (just pass registration). Grows as plugins need more
/// (config access, logging, event hooks) rather than being speculatively
/// broad now.
class PluginContext {
public:
    void registerPass(std::shared_ptr<IAnalysisPass> pass) {
        PassRegistry::instance().registerPass(std::move(pass));
    }
};

/// A plugin's entry point. One instance is created per loaded .so (see
/// PluginManager); `onLoad` is where it registers whatever it provides —
/// today that's analysis passes, since that's the only extension point
/// this milestone built. See plugins/example_io_flagger/ for a complete,
/// real (if small) example, and COMPASS_DECLARE_PLUGIN below for the
/// boilerplate every plugin .so needs to export.
class IPlugin {
public:
    virtual ~IPlugin() = default;
    virtual std::string name() const = 0;
    virtual std::string version() const = 0;
    virtual void onLoad(PluginContext& ctx) = 0;
};

} // namespace compass::core

/// Every plugin .so must export these three `extern "C"` symbols —
/// PluginManager looks them up by name via dlsym, so their names and
/// signatures are the actual ABI boundary (not the C++ vtable layout,
/// which is why this is `extern "C"`: name mangling and calling
/// convention are otherwise compiler/version-specific in ways this
/// project can't control on the plugin author's side).
///
/// Usage in a plugin's .cpp file:
///   class MyPlugin : public compass::core::IPlugin { ... };
///   COMPASS_DECLARE_PLUGIN(MyPlugin)
#define COMPASS_DECLARE_PLUGIN(ClassName)                                                   \
    extern "C" int compass_plugin_abi_version() { return compass::core::kPluginAbiVersion; } \
    extern "C" compass::core::IPlugin* compass_plugin_create() { return new ClassName(); }    \
    extern "C" void compass_plugin_destroy(compass::core::IPlugin* p) { delete p; }
