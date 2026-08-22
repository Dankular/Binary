add_library(compass-core STATIC
    src/types.cpp
    src/low_level_il.cpp
    src/llil_lifter.cpp
    src/radare2_backend.cpp
    src/mock_sandbox_provider.cpp
    src/dominators.cpp
    src/medium_level_il.cpp
    src/mlil_builder.cpp
    src/mlil_ssa_builder.cpp
    src/type.cpp
    src/type_inference.cpp
    src/high_level_il.cpp
    src/hlil_builder.cpp
)

target_include_directories(compass-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(compass-core
    PUBLIC PkgConfig::R_CORE
    PRIVATE nlohmann_json::nlohmann_json
)

target_compile_options(compass-core PRIVATE -Wall -Wextra)
