#include "compass/core/plugin_manager.hpp"

#include <dlfcn.h>
#include <dirent.h>

#include <cstring>

namespace compass::core {

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
    // RTLD_NOW (not LAZY): a plugin with an unresolved symbol should fail
    // to load loudly, right here, rather than crash later mid-analysis the
    // first time the missing symbol is actually called.
    void* handle = dlopen(path.c_str(), RTLD_NOW);
    if (!handle) {
        error = dlerror() ? dlerror() : "dlopen failed";
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
