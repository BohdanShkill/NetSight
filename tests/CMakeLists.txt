include(GoogleTest)

function(netsight_add_test test_name source_file)
    cmake_parse_arguments(PARSE_ARGV 2 TEST "" "" "LIBS;LABELS")

    add_executable(${test_name} ${source_file})
    target_include_directories(${test_name} PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
    )
    target_compile_definitions(${test_name} PRIVATE
        NETSIGHT_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/tests/data"
    )
    target_link_libraries(${test_name} PRIVATE
        netsight_core 
        netsight_warnings 
        GTest::gtest_main
        ${TEST_LIBS}
    )
    if(TEST_LABELS)
        gtest_discover_tests(${test_name}
            DISCOVERY_MODE PRE_TEST
            PROPERTIES LABELS "${TEST_LABELS}"
        )
    else()
        gtest_discover_tests(${test_name} DISCOVERY_MODE PRE_TEST)
    endif()
endfunction()

netsight_add_test(smoke test_smoke.cpp)
netsight_add_test(core_types test_core_types.cpp)
netsight_add_test(packet_source test_packet_source.cpp)
netsight_add_test(capture_config test_capture_config.cpp)
netsight_add_test(byte_reader test_byte_reader.cpp)
netsight_add_test(pcap_file_reader test_pcap_file_reader.cpp)
netsight_add_test(bounded_queue test_bounded_queue.cpp)
netsight_add_test(parser_link test_parser_link.cpp)
netsight_add_test(parser_network test_parser_network.cpp)

set(CAPTURE_LIVE_EXTRA_LIBS netsight_capture)
if(WIN32)
    list(APPEND CAPTURE_LIVE_EXTRA_LIBS ws2_32)
endif()

netsight_add_test(capture_live test_capture_live.cpp
    LIBS ${CAPTURE_LIVE_EXTRA_LIBS}
    LABELS integration
)