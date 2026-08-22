add_executable(dominators_test dominators_test.cpp)
target_link_libraries(dominators_test PRIVATE compass-core)

add_test(NAME dominators_test COMMAND dominators_test)

add_executable(annotation_merge_test annotation_merge_test.cpp)
target_link_libraries(annotation_merge_test PRIVATE compass-core)

add_test(NAME annotation_merge_test COMMAND annotation_merge_test)
