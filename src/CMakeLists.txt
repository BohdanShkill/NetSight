add_library(netsight_core STATIC 
    core/Types.cpp
    core/IpAddress.cpp
    parser/PacketParser.cpp
    source/ThreadedPacketSource.cpp
    source/PcapFileReader.cpp
)

target_include_directories(netsight_core PUBLIC 
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(netsight_core PRIVATE
    netsight_warnings
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
    target_compile_definitions(netsight_capture PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    )
endif()

if(MSVC)
    target_link_options(netsight_capture INTERFACE "/DELAYLOAD:wpcap.dll")
    target_link_libraries(netsight_capture INTERFACE delayimp)
endif()