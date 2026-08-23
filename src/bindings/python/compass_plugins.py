"""Python-side plugin loading (docs/ROADMAP.md Milestone 2).

The C++ plugin path (compass::core::PluginManager, plugin_manager.cpp)
dlopen's .so files whose IPlugin::onLoad() registers passes into the
process-wide PassRegistry. This is that same idea for plugins written
*in* Python instead of calling the C++ API from Python: importlib
discovers .py files in a directory, imports each, and calls its
register() function — the Python-side equivalent of IPlugin::onLoad().

A Python plugin file looks like:

    import compass

    class MyPass(compass.AnalysisPass):
        def name(self):
            return "my-pass"
        def description(self):
            return "..."
        def run(self, binary, function):
            function.add_annotation("visited " + function.name)

    def register():
        compass.register_pass(MyPass())

See plugins/example_py_io_flagger/io_flagger.py for a complete, real
example, and scripts/python_smoke_test.sh for this loader driving it
end to end.

Once register()'d, a Python pass is resolvable by name from
compass.Session.run_passes() exactly like a C++ plugin's pass would be:
PassRegistry is one process-wide singleton Workflow resolves pass names
against at run time, regardless of which side registered a given name —
see workflow.hpp's own note on that property. Nothing in Session or the
C++ side needed to change for this to work.
"""

import importlib.util
import os


def load_directory(directory):
    """Imports every .py file directly inside `directory` (not recursive)
    and calls its register() function. Returns the list of module names
    (filename without .py) that were loaded, in the order they were found.

    Raises RuntimeError if a .py file has no register() function — a
    plugin directory containing a file that doesn't follow the convention
    is a real authoring mistake, not something to silently skip.
    """
    loaded = []
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        module_name = filename[:-3]
        path = os.path.join(directory, filename)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"couldn't create an import spec for plugin file: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        register = getattr(module, "register", None)
        if register is None:
            raise RuntimeError(
                f"{filename} has no register() function — see compass_plugins.py's plugin "
                "convention (a register() calling compass.register_pass(...))"
            )
        register()
        loaded.append(module_name)
    return loaded
