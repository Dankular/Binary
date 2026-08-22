# Pin to python3.11 explicitly rather than letting find_package guess:
# this environment has python3.10/3.11/3.12/3.13 all installed side by
# side (deadsnakes PPA + Ubuntu's own), and the `python3` binary that
# actually runs (/usr/local/bin/python3 -> /usr/bin/python3.11) does not
# match what plain `python3-config`/find_package(Python3) resolve to by
# default (3.12) in this environment — building against the wrong
# version's headers produces a module that either fails to import or,
# worse, imports with a subtly incompatible ABI. If your system has one
# unambiguous python3, this pin is unnecessary; it's cheap insurance here.
find_package(Python3 3.11 EXACT COMPONENTS Interpreter Development)
if(NOT Python3_FOUND)
    message(STATUS "Compass: Python 3.11 dev headers not found — skipping Python bindings (COMPASS_BUILD_PYTHON_BINDINGS stays off)")
    return()
endif()

find_package(pybind11 CONFIG QUIET)
if(NOT pybind11_FOUND)
    message(STATUS "Compass: pybind11 not found — skipping Python bindings")
    return()
endif()

message(STATUS "Compass: building Python bindings against Python ${Python3_VERSION}")

pybind11_add_module(compass_python compass_py.cpp)
target_link_libraries(compass_python PRIVATE compass-core)
set_target_properties(compass_python PROPERTIES OUTPUT_NAME "compass")
target_compile_options(compass_python PRIVATE -Wall -Wextra)
