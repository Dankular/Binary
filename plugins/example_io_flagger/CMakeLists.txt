# Deliberately does NOT `target_link_libraries(... compass-core)` — that
# would statically link a second copy of compass-core's object code into
# this .so, including its own private PassRegistry::instance() singleton,
# disconnected from the one compass-cli's Workflow::run() looks passes up
# in. That's a real bug this project's first draft of this file had: the
# plugin would load and "successfully" register its pass into a singleton
# nothing else could see, and every pass lookup at run time would silently
# report "pass not found."
#
# The correct shape (the standard C++ plugin pattern): compile only
# against compass-core's headers here, leave symbols like
# PassRegistry::instance() undefined in this .so, and let them resolve at
# dlopen time against the same compass-core object code already linked
# into the host process — compass-cli is built with ENABLE_EXPORTS (see
# src/cli/CMakeLists.txt) specifically so those symbols are visible for
# exactly this resolution to happen.
add_library(example_io_flagger MODULE plugin.cpp)
target_include_directories(example_io_flagger PRIVATE
    $<TARGET_PROPERTY:compass-core,INTERFACE_INCLUDE_DIRECTORIES>
)
target_compile_options(example_io_flagger PRIVATE -Wall -Wextra)
set_target_properties(example_io_flagger PROPERTIES PREFIX "" OUTPUT_NAME "example_io_flagger")
