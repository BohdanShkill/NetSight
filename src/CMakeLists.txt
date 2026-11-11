add_library(netsight_core STATIC 
    core/Types.cpp
    core/IpAddress.cpp
    core/Time.cpp
    export/CsvWriter.cpp
    export/JsonSerializer.cpp
    export/RestServer.cpp
    export/AgentPoller.cpp
    parser/PacketParser.cpp
    source/ThreadedPacketSource.cpp
    source/PcapFileReader.cpp
    pipeline/PacketFilter.cpp
    pipeline/CaptureSession.cpp
    analytics/StatsAggregator.cpp
    analytics/SynFloodDetector.cpp
    analytics/PortScanDetector.cpp
    analytics/TrafficAnalyzer.cpp
    analytics/DistributedAggregator.cpp
    analytics/IntervalTracker.cpp
)

target_include_directories(netsight_core PUBLIC 
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netsight_core PRIVATE
    netsight_warnings
    nlohmann_json::nlohmann_json
    httplib::httplib
)

target_compile_features(netsight_core PUBLIC 
    cxx_std_17
)

add_library(netsight_capture STATIC
    capture/Devices.cpp
    capture/PcapRuntime.cpp
    capture/PcapLiveSource.cpp
)

target_link_libraries(netsight_capture PUBLIC
    netsight_core
)

target_link_libraries(netsight_capture PRIVATE  
    netsight_warnings PCAP::PCAP
)

find_package(Threads REQUIRED)

target_link_libraries(netsight_core PUBLIC
    Threads::Threads
)

if(WIN32)
    target_link_libraries(netsight_core PRIVATE ws2_32)
    target_compile_definitions(netsight_core PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    target_compile_definitions(netsight_capture PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

if(MSVC)
    target_link_options(netsight_capture INTERFACE "/DELAYLOAD:wpcap.dll")
    target_link_libraries(netsight_capture INTERFACE delayimp)
endif()