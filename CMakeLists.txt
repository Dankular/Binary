cmake_minimum_required(VERSION 3.16)
project(compass LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# compass-core is a static library that ends up linked into both regular
# executables (compass-cli) and a shared object (the Python module,
# src/bindings/python) — the latter requires every object file that goes
# into it to be position-independent, which a static library isn't by
# default. Building everything PIC from the start avoids needing a
# separate PIC-only build of compass-core just for the Python bindings.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(COMPASS_BUILD_TESTS "Build smoke/unit test targets" ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(R_CORE REQUIRED IMPORTED_TARGET r_core)
find_package(nlohmann_json 3.9 REQUIRED)

add_subdirectory(src/core)
add_subdirectory(src/cli)
add_subdirectory(plugins/example_io_flagger)
add_subdirectory(src/bindings/python)

if(COMPASS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# src/core/CMakeLists.txt already reports which analysis backend this
# configure picked (Rizin if pkg-config found it, radare2 otherwise) —
# see the "Compass: Rizin (librz) found/not found" message above.
