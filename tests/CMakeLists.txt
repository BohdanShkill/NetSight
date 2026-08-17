include(GoogleTest)

function(netsight_add_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_link_libraries(${test_name} PRIVATE netsight_warnings GTest::gtest_main)
        gtest_discover_tests(${test_name} DISCOVERY_MODE PRE_TEST)
endfunction()

netsight_add_test(smoke test_smoke.cpp)