add_executable(dominators_test dominators_test.cpp)
target_link_libraries(dominators_test PRIVATE compass-core)

add_test(NAME dominators_test COMMAND dominators_test)
