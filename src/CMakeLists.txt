add_executable(netsight main.cpp)

target_link_libraries(netsight PRIVATE  
    netsight_warnings PCAP::PCAP
)

target_include_directories(netsight PRIVATE 
    ${CMAKE_SOURCE_DIR}/include 
)

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