"""Example Python-authored Compass plugin — the Python-side counterpart to
plugins/example_io_flagger/plugin.cpp (see that file's own comment for the
"why" this kind of pass is realistic). Same idea, same detection, deliberately
NOT the same implementation: this one works entirely off disassembly-level
data (Function.disassembly()'s jump_target + Binary.symbol_name_at()) rather
than the MLIL tree, since the Python bindings deliberately don't expose that
(see compass_py.cpp's file header) — this is what a Python pass can actually
do with today's bindings, not a translation of the C++ one.

Loaded via compass_plugins.load_directory() — see scripts/python_smoke_test.sh
for this exact plugin driven end to end through compass.Session.run_passes().
"""

import compass

IO_FUNCTION_NAMES = {
    "printf", "fprintf", "sprintf", "snprintf", "puts", "fputs", "write", "send", "sendto",
    "recv", "recvfrom", "read", "fread", "fwrite",
}


def _looks_like_io_function(symbol_name):
    # Symbol names carry backend-specific prefixes ("sym.imp.printf",
    # "dbg.printf", ...) — match on suffix, same convention
    # Binary::functionNamed() (and the C++ example plugin) use.
    return any(symbol_name.endswith(io) for io in IO_FUNCTION_NAMES)


class FlagIoCallersPass(compass.AnalysisPass):
    def name(self):
        return "py-flag-io-callers"

    def description(self):
        return "Python-authored: flags functions that call a well-known I/O function (printf/puts/write/...)."

    def run(self, binary, function):
        for insn in function.disassembly():
            if insn["mnemonic"] != "call" or insn["jump_target"] is None:
                continue
            symbol_name = binary.symbol_name_at(insn["jump_target"])
            if symbol_name is not None and _looks_like_io_function(symbol_name):
                function.add_annotation(f"IO caller (py): {symbol_name}")


def register():
    compass.register_pass(FlagIoCallersPass())
