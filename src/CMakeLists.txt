add_library(netsight_core STATIC 
    core/Types.cpp
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
)

target_link_libraries(netsight_capture PUBLIC
    netsight_core
)

target_link_libraries(netsight_capture PRIVATE  
    netsight_warnings PCAP::PCAP
)

if(WIN32)
    target_compile_definitions(netsight_capture PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    )
endif()