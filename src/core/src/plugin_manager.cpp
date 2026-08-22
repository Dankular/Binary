#include "compass/core/plugin_manager.hpp"

#include <dlfcn.h>
#include <dirent.h>

#include <cstring>
#include <mutex>

namespace compass::core {

namespace {

/// Ensures the object containing compass-core's own code is loaded with
/// RTLD_GLOBAL, so a plugin's undefined references back into it (e.g.
/// PassRegistry::instance()) can actually resolve. Needed because that
/// object isn't always the main executable:
///
/// - In compass-cli, compass-core is statically linked into the
///   executable, and ENABLE_EXPORTS (-rdynamic, see src/cli/CMakeLists.txt)
///   already makes an executable's own symbols globally visible to
///   anything it dlopen()s — this call is a harmless no-op there.
/// - In the Python bindings, compass-core is statically linked into
///   compass.so, which Python's import machinery loads with RTLD_LOCAL by
///   default. A plugin dlopen()d from there previously failed outright
///   ("undefined symbol: PassRegistry::registerPass") — RTLD_NOW makes
///   dlopen() itself fail eagerly on any unresolved symbol, rather than
///   deferring the failure to first use. Caught by actually running the
///   plugin smoke test through the Python bindings, not anticipated up
///   front.
///
/// dladdr finds which loaded object contains this very function; dlopen()
/// on an already-loaded object (matched by path) just bumps its refcount
/// and returns the existing handle — this doesn't map a second copy.
void promoteSelfToGlobalScope() {
    static std::once_flag once;
    std::call_once(once, [] {
        Dl_info info;
        if (dladdr(reinterpret_cast<void*>(&promoteSelfToGlobalScope), &info) && info.dli_fname) {
            dlopen(info.dli_fname, RTLD_NOW | RTLD_GLOBAL);
        }
    });
}

} // namespace

PluginManager::~PluginManager() {
    // Deliberately does NOT dlclose() — see the header's real-bug note.
    // Short version: PassRegistry's process-lifetime singleton can (and,
    // once a plugin registers a pass, does) hold a shared_ptr<IAnalysisPass>
    // whose vtable and destructor code live inside the plugin's .so.
    // dlclose()-ing while that reference is still outstanding leaves it
    // pointing at unmapped memory; destroying it later (e.g. during the
    // registry's static-destructor run at process exit) segfaults —
    // caught via gdb while validating this exact mechanism, not
    // theoretical. Calling destroy(plugin) is still safe and worthwhile
    // here (the .so is still mapped at this point), it's specifically
    // *unloading the code* that isn't.
    for (auto& p : plugins_) {
        if (p.plugin && p.destroy) p.destroy(p.plugin);
    }
}

bool PluginManager::loadPlugin(const std::string& path, std::string& error) {
    promoteSelfToGlobalScope();

    // RTLD_NOW (not LAZY): a plugin with an unresolved symbol should fail
    // to load loudly, right here, rather than crash later mid-analysis the
    // first time the missing symbol is actually called.
    void* handle = dlopen(path.c_str(), RTLD_NOW);
    if (!handle) {
        // dlerror() clears its stored message as a side effect of being
        // read — `dlerror() ? dlerror() : ...` calls it twice, so the
        // second call (the one actually used) always sees it already
        // cleared and returns null. Assigning that null to a std::string
        // crashes. Caught by an actual dlopen failure hitting this path
        // during Python-bindings testing (see promoteSelfToGlobalScope()
        // above for what that real failure was) — read it exactly once.
        const char* msg = dlerror();
        error = msg ? msg : "dlopen failed";
        return false;
    }

    dlerror(); // clear any prior error before dlsym, per dlsym(3)'s recipe
    auto abiVersionFn = reinterpret_cast<int (*)()>(dlsym(handle, "compass_plugin_abi_version"));
    const char* dlsymErr = dlerror();
    if (!abiVersionFn || dlsymErr) {
        error = "missing compass_plugin_abi_version() — not a Compass plugin, or built against a "
                "different ABI helper";
        dlclose(handle);
        return false;
    }
    int pluginAbi = abiVersionFn();
    if (pluginAbi != kPluginAbiVersion) {
        error = "ABI version mismatch: plugin built for " + std::to_string(pluginAbi) +
                ", this build is " + std::to_string(kPluginAbiVersion);
        dlclose(handle);
        return false;
    }

    auto createFn = reinterpret_cast<IPlugin* (*)()>(dlsym(handle, "compass_plugin_create"));
    auto destroyFn = reinterpret_cast<void (*)(IPlugin*)>(dlsym(handle, "compass_plugin_destroy"));
    if (!createFn || !destroyFn) {
        error = "missing compass_plugin_create()/compass_plugin_destroy() — use "
                "COMPASS_DECLARE_PLUGIN in the plugin's source";
        dlclose(handle);
        return false;
    }

    IPlugin* plugin = createFn();
    if (!plugin) {
        error = "compass_plugin_create() returned null";
        dlclose(handle);
        return false;
    }

    PluginContext ctx;
    plugin->onLoad(ctx);

    loadedInfo_.push_back({path, plugin->name(), plugin->version()});
    plugins_.push_back({handle, plugin, destroyFn});
    return true;
}

int PluginManager::loadPluginsFromDirectory(const std::string& dir, std::vector<std::string>& errors) {
    DIR* d = opendir(dir.c_str());
    if (!d) {
        errors.push_back("cannot open plugin directory: " + dir);
        return 0;
    }
    int count = 0;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name.size() < 3 || name.substr(name.size() - 3) != ".so") continue;
        std::string full = dir + "/" + name;
        std::string error;
        if (loadPlugin(full, error)) {
            ++count;
        } else {
            errors.push_back(full + ": " + error);
        }
    }
    closedir(d);
    return count;
}

} // namespace compass::core
