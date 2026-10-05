include(GoogleTest)

function(netsight_add_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_include_directories(${test_name} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${PROJECT_SOURCE_DIR}/tests
        )
        target_link_libraries(${test_name} PRIVATE
            netsight_core 
            netsight_warnings 
            GTest::gtest_main
        )
        gtest_discover_tests(${test_name} DISCOVERY_MODE PRE_TEST)
endfunction()

netsight_add_test(smoke test_smoke.cpp)
netsight_add_test(core_types test_core_types.cpp)
netsight_add_test(packet_source test_packet_source.cpp)
netsight_add_test(capture_config test_capture_config.cpp)