cmake_minimum_required(VERSION 3.16)
project(compass LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(COMPASS_BUILD_TESTS "Build smoke/unit test targets" ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(R_CORE REQUIRED IMPORTED_TARGET r_core)
find_package(nlohmann_json 3.9 REQUIRED)

add_subdirectory(src/core)
add_subdirectory(src/cli)

if(COMPASS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# src/core/CMakeLists.txt already reports which analysis backend this
# configure picked (Rizin if pkg-config found it, radare2 otherwise) —
# see the "Compass: Rizin (librz) found/not found" message above.
