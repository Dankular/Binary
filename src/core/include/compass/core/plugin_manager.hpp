#pragma once

#include "compass/core/plugin.hpp"

#include <string>
#include <vector>

namespace compass::core {

/// Loads plugin .so files via dlopen, validates their ABI version, and
/// calls IPlugin::onLoad() (which registers whatever passes/etc. the
/// plugin provides into PassRegistry).
///
/// Once loaded, a plugin's .so is intentionally never dlclose()-d — not
/// even when this PluginManager is destroyed — because PassRegistry (a
/// process-lifetime singleton, so it can outlive any individual
/// PluginManager) may hold shared_ptr<IAnalysisPass>s whose vtable and
/// destructor code live inside that .so. Unmapping the code while a
/// still-live reference to it exists is a real, verified-not-theoretical
/// crash (segfault in the registry's static destructor at process exit,
/// caught with gdb while building this): the fix is the same one most
/// C++ plugin systems (LLVM, Qt) settle on — load, never unload, let
/// process exit reclaim it. See plugin_manager.cpp for the mechanics.
class PluginManager {
public:
    ~PluginManager();

    /// Loads one plugin. Returns true on success; on failure returns false
    /// and puts a human-readable reason in `error` (file not found, dlopen
    /// error, missing entry symbols, ABI version mismatch).
    bool loadPlugin(const std::string& path, std::string& error);

    /// Loads every `*.so` directly inside `dir` (non-recursive). Returns
    /// the number successfully loaded; failures are appended to `errors`
    /// (one file failing doesn't stop the rest from loading).
    int loadPluginsFromDirectory(const std::string& dir, std::vector<std::string>& errors);

    struct LoadedInfo {
        std::string path;
        std::string name;
        std::string version;
    };
    const std::vector<LoadedInfo>& loaded() const { return loadedInfo_; }

private:
    struct Loaded {
        void* handle = nullptr;
        IPlugin* plugin = nullptr;
        void (*destroy)(IPlugin*) = nullptr;
    };
    std::vector<Loaded> plugins_;
    std::vector<LoadedInfo> loadedInfo_;
};

} // namespace compass::core
