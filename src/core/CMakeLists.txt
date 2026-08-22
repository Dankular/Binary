add_library(compass-core STATIC
    src/types.cpp
    src/low_level_il.cpp
    src/llil_lifter.cpp
    src/radare2_backend.cpp
    src/backend_selection.cpp
    src/mock_sandbox_provider.cpp
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

target_link_libraries(compass-core
    PUBLIC PkgConfig::R_CORE
    PRIVATE nlohmann_json::nlohmann_json
    PUBLIC ${CMAKE_DL_LIBS}
)

# Rizin (librz) is the target production backend (see docs/ARCHITECTURE.md)
# — used automatically when pkg-config finds it (e.g. after `ninja install`
# from a from-source build; see scripts/build_rizin.sh), radare2 otherwise.
# Optional/quiet: this must not fail the configure step in environments
# without Rizin packaged.
pkg_check_modules(RZ_CORE QUIET IMPORTED_TARGET rz_core)
if(RZ_CORE_FOUND)
    message(STATUS "Compass: Rizin (librz) found — building rizin_backend.cpp, it becomes the default backend")
    target_sources(compass-core PRIVATE src/rizin_backend.cpp)
    target_link_libraries(compass-core PUBLIC PkgConfig::RZ_CORE)
    target_compile_definitions(compass-core PUBLIC COMPASS_HAVE_RIZIN)
else()
    message(STATUS "Compass: Rizin (librz) not found via pkg-config — radare2 remains the default backend")
endif()

target_compile_options(compass-core PRIVATE -Wall -Wextra)
