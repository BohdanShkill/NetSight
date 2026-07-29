add_executable(netsight main.cpp)

target_link_libraries(netsight PRIVATE netsight_warnings)

target_include_directories(netsight PRIVATE ${CMAKE_SOURCE_DIR}/include)