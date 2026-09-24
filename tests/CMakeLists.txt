include(GoogleTest)

function(netsight_add_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
        target_link_libraries(${test_name} PRIVATE netsight_warnings GTest::gtest_main)
        gtest_discover_tests(${test_name} DISCOVERY_MODE PRE_TEST)
endfunction()

netsight_add_test(smoke test_smoke.cpp)
netsight_add_test(types test_core_types.cpp)