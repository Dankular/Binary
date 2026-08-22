add_library(compass-core STATIC
    src/types.cpp
    src/low_level_il.cpp
    src/llil_lifter.cpp
    src/radare2_backend.cpp
    src/backend_selection.cpp
    src/mock_sandbox_provider.cpp
    src/qemu_tcg_sandbox_provider.cpp
    src/windows_sandbox_provider.cpp
    src/annotation_merge.cpp
    src/dominators.cpp
    src/medium_level_il.cpp
    src/mlil_builder.cpp
    src/mlil_ssa_builder.cpp
    src/type.cpp
    src/type_inference.cpp
    src/high_level_il.cpp
    src/hlil_builder.cpp
    src/workflow.cpp
    src/plugin_manager.cpp
)

target_include_directories(compass-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Threads REQUIRED)

target_link_libraries(compass-core
    PUBLIC PkgConfig::R_CORE
    PRIVATE nlohmann_json::nlohmann_json
    PUBLIC ${CMAKE_DL_LIBS}
    PUBLIC Threads::Threads
)

# Rizin (librz) is the target production backend (see docs/ARCHITECTURE.md)
# — used automatically when pkg-config finds it (e.g. after `ninja install`
# from a from-source build; see scripts/build_rizin.sh), radare2 otherwise.
# Optional/quiet: this must not fail the configure step in environments
# without Rizin packaged.
pkg_check_modules(RZ_CORE QUIET IMPORTED_TARGET rz_core)
if(RZ_CORE_FOUND)
    message(STATUS "Compass: Rizin (librz) found — building rizin_backend.cpp, it becomes the default backend")
    target_sources(compass-core PRIVATE
        src/rizin_backend.cpp
        src/rizin_debugger_backend.cpp
    )
    target_link_libraries(compass-core PUBLIC PkgConfig::RZ_CORE)
    target_compile_definitions(compass-core PUBLIC COMPASS_HAVE_RIZIN)

    # rz-ghidra (Milestone 3 decompiler) is a *plugin* librz dlopen's from
    # its plugin directory at runtime (see scripts/build_rz_ghidra.sh) —
    # unlike Rizin itself above, it isn't a library this target links
    # against, so there's nothing to pkg-config-gate at configure time.
    # RizinBackend::decompile() (in rizin_backend.cpp) checks at runtime
    # whether the plugin actually loaded and reports a clear error if not,
    # rather than failing the build.
else()
    message(STATUS "Compass: Rizin (librz) not found via pkg-config — radare2 remains the default backend")
endif()

target_compile_options(compass-core PRIVATE -Wall -Wextra)
