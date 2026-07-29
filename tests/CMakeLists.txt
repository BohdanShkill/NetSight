add_executable(netsight_tests main_test.cpp)

target_link_libraries(netsight_tests PRIVATE netsight_warnings)

target_include_directories(netsight_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_test(NAME netsight_tests COMMAND netsight_tests)