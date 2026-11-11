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
netsight_add_test(packet_filter test_packet_filter.cpp)
netsight_add_test(capture_session test_capture_session.cpp)
netsight_add_test(stats_aggregator test_stats_aggregator.cpp)
netsight_add_test(syn_flood_detector test_syn_flood_detector.cpp)
netsight_add_test(port_scan_detector test_port_scan_detector.cpp)
netsight_add_test(traffic_analyzer test_traffic_analyzer.cpp)
netsight_add_test(distributed_aggregator test_distributed_aggregator.cpp)
netsight_add_test(interval_tracker test_interval_tracker.cpp
    LIBS nlohmann_json::nlohmann_json
)
netsight_add_test(agent_poller test_agent_poller.cpp
    LIBS httplib::httplib nlohmann_json::nlohmann_json
)
netsight_add_test(time test_time.cpp)
netsight_add_test(csv_writer test_csv_writer.cpp)
netsight_add_test(json_serializer test_json_serializer.cpp
    LIBS nlohmann_json::nlohmann_json
)

netsight_add_test(rest_server test_rest_server.cpp
    LIBS httplib::httplib nlohmann_json::nlohmann_json
)

set(CAPTURE_LIVE_EXTRA_LIBS netsight_capture)
if(WIN32)
    list(APPEND CAPTURE_LIVE_EXTRA_LIBS ws2_32)
endif()

netsight_add_test(capture_live test_capture_live.cpp
    LIBS ${CAPTURE_LIVE_EXTRA_LIBS}
    LABELS integration
)

netsight_add_test(cli test_cli.cpp
    LIBS netsight_app
)

netsight_add_test(signals test_signals.cpp
    LIBS netsight_app
)

netsight_add_test(app_lifecycle test_app_lifecycle.cpp
    LIBS netsight_app httplib::httplib nlohmann_json::nlohmann_json
)

target_compile_definitions(app_lifecycle PRIVATE
    NETSIGHT_EXE_PATH="$<TARGET_FILE:netsight>"
)

add_dependencies(app_lifecycle netsight)