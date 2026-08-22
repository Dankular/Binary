add_executable(compass-cli src/main.cpp)
target_link_libraries(compass-cli PRIVATE compass-core)
target_compile_options(compass-cli PRIVATE -Wall -Wextra)

# Exports this executable's symbols (-rdynamic) so a plugin .so it dlopen()s
# at runtime can resolve calls back into compass-core's code (e.g.
# PassRegistry::instance()) against compass-cli's own already-linked copy,
# instead of needing — and getting a disconnected second copy of — its own.
# See plugins/example_io_flagger/CMakeLists.txt for the full explanation.
set_target_properties(compass-cli PROPERTIES ENABLE_EXPORTS ON)
