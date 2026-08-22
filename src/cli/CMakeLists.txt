add_executable(compass-cli src/main.cpp)
target_link_libraries(compass-cli PRIVATE compass-core)
target_compile_options(compass-cli PRIVATE -Wall -Wextra)
